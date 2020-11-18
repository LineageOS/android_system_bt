/*
 * Copyright 2020 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include "common/bind.h"
#include "crypto_toolbox/crypto_toolbox.h"
#include "hci/acl_manager/assembler.h"
#include "hci/acl_manager/round_robin_scheduler.h"
#include "hci/le_address_manager.h"
#include "os/alarm.h"
#include "os/rand.h"

using bluetooth::crypto_toolbox::Octet16;

namespace bluetooth {
namespace hci {
namespace acl_manager {

using common::BindOnce;

struct le_acl_connection {
  le_acl_connection(
      AddressWithType address_with_type, AclConnection::QueueDownEnd* queue_down_end, os::Handler* handler)
      : assembler_(address_with_type, queue_down_end, handler), address_with_type_(address_with_type) {}
  ~le_acl_connection() = default;
  struct acl_manager::assembler assembler_;
  AddressWithType address_with_type_;
  LeConnectionManagementCallbacks* le_connection_management_callbacks_ = nullptr;
};

struct le_impl : public bluetooth::hci::LeAddressManagerCallback {
  le_impl(HciLayer* hci_layer, Controller* controller, os::Handler* handler, RoundRobinScheduler* round_robin_scheduler)
      : hci_layer_(hci_layer), controller_(controller), round_robin_scheduler_(round_robin_scheduler) {
    hci_layer_ = hci_layer;
    controller_ = controller;
    handler_ = handler;
    le_acl_connection_interface_ = hci_layer_->GetLeAclConnectionInterface(
        handler_->BindOn(this, &le_impl::on_le_event),
        handler_->BindOn(this, &le_impl::on_le_disconnect),
        handler_->BindOn(this, &le_impl::on_le_read_remote_version_information));
    le_address_manager_ = new LeAddressManager(
        common::Bind(&le_impl::enqueue_command, common::Unretained(this)),
        handler_,
        controller->GetMacAddress(),
        controller->GetLeConnectListSize(),
        controller->GetLeResolvingListSize());
  }

  ~le_impl() {
    for (auto subevent_code : LeConnectionManagementEvents) {
      hci_layer_->UnregisterLeEventHandler(subevent_code);
    }
    if (address_manager_registered) {
      le_address_manager_->Unregister(this);
    }
    delete le_address_manager_;
    le_acl_connections_.clear();
  }

  void on_le_event(LeMetaEventView event_packet) {
    SubeventCode code = event_packet.GetSubeventCode();
    switch (code) {
      case SubeventCode::CONNECTION_COMPLETE:
        on_le_connection_complete(event_packet);
        break;
      case SubeventCode::ENHANCED_CONNECTION_COMPLETE:
        on_le_enhanced_connection_complete(event_packet);
        break;
      case SubeventCode::CONNECTION_UPDATE_COMPLETE:
        on_le_connection_update_complete(event_packet);
        break;
      case SubeventCode::PHY_UPDATE_COMPLETE:
        LOG_INFO("PHY_UPDATE_COMPLETE");
        break;
      case SubeventCode::DATA_LENGTH_CHANGE:
        on_data_length_change(event_packet);
        break;
      case SubeventCode::REMOTE_CONNECTION_PARAMETER_REQUEST:
        on_remote_connection_parameter_request(event_packet);
        break;
      default:
        LOG_ALWAYS_FATAL("Unhandled event code %s", SubeventCodeText(code).c_str());
    }
  }

  void on_le_disconnect(uint16_t handle, ErrorCode reason) {
    if (le_acl_connections_.count(handle) == 1) {
      auto& connection = le_acl_connections_.find(handle)->second;
      round_robin_scheduler_->Unregister(handle);
      connection.le_connection_management_callbacks_->OnDisconnection(reason);
      le_acl_connections_.erase(handle);
    }
  }

  void on_common_le_connection_complete(AddressWithType address_with_type) {
    auto connecting_addr_with_type = connecting_le_.find(address_with_type);
    if (connecting_addr_with_type == connecting_le_.end()) {
      LOG_WARN("No prior connection request for %s", address_with_type.ToString().c_str());
    } else {
      connecting_le_.erase(connecting_addr_with_type);
    }
  }

  void on_le_connection_complete(LeMetaEventView packet) {
    LeConnectionCompleteView connection_complete = LeConnectionCompleteView::Create(packet);
    ASSERT(connection_complete.IsValid());
    auto status = connection_complete.GetStatus();
    auto address = connection_complete.GetPeerAddress();
    auto peer_address_type = connection_complete.GetPeerAddressType();
    // TODO: find out which address and type was used to initiate the connection
    AddressWithType remote_address(address, peer_address_type);
    AddressWithType local_address = le_address_manager_->GetCurrentAddress();
    on_common_le_connection_complete(remote_address);
    if (status == ErrorCode::UNKNOWN_CONNECTION &&
        canceled_connections_.find(remote_address) != canceled_connections_.end()) {
      // connection canceled by LeAddressManager.OnPause(), will auto reconnect by LeAddressManager.OnResume()
      return;
    } else {
      canceled_connections_.erase(remote_address);
      ready_to_unregister = true;
      remove_device_from_connect_list(remote_address);
    }

    if (status != ErrorCode::SUCCESS) {
      le_client_handler_->Post(common::BindOnce(&LeConnectionCallbacks::OnLeConnectFail,
                                                common::Unretained(le_client_callbacks_), remote_address, status));
      return;
    }

    uint16_t conn_interval = connection_complete.GetConnInterval();
    uint16_t conn_latency = connection_complete.GetConnLatency();
    uint16_t supervision_timeout = connection_complete.GetSupervisionTimeout();
    if (!check_connection_parameters(conn_interval, conn_interval, conn_latency, supervision_timeout)) {
      LOG_ERROR("Receive connection complete with invalid connection parameters");
      return;
    }

    auto role = connection_complete.GetRole();
    uint16_t handle = connection_complete.GetConnectionHandle();
    ASSERT(le_acl_connections_.count(handle) == 0);
    auto queue = std::make_shared<AclConnection::Queue>(10);
    le_acl_connections_.emplace(std::piecewise_construct, std::forward_as_tuple(handle),
                                std::forward_as_tuple(remote_address, queue->GetDownEnd(), handler_));
    auto& connection_proxy = check_and_get_le_connection(handle);
    round_robin_scheduler_->Register(RoundRobinScheduler::ConnectionType::LE, handle, queue);
    std::unique_ptr<LeAclConnection> connection(new LeAclConnection(
        std::move(queue), le_acl_connection_interface_, handle, local_address, remote_address, role));
    connection_proxy.le_connection_management_callbacks_ = connection->GetEventCallbacks();
    le_client_handler_->Post(common::BindOnce(&LeConnectionCallbacks::OnLeConnectSuccess,
                                              common::Unretained(le_client_callbacks_), remote_address,
                                              std::move(connection)));
  }

  void on_le_enhanced_connection_complete(LeMetaEventView packet) {
    LeEnhancedConnectionCompleteView connection_complete = LeEnhancedConnectionCompleteView::Create(packet);
    ASSERT(connection_complete.IsValid());
    auto status = connection_complete.GetStatus();
    auto address = connection_complete.GetPeerAddress();
    auto peer_address_type = connection_complete.GetPeerAddressType();
    auto peer_resolvable_address = connection_complete.GetPeerResolvablePrivateAddress();
    AddressWithType remote_address(address, peer_address_type);
    if (!peer_resolvable_address.IsEmpty()) {
      remote_address = AddressWithType(peer_resolvable_address, AddressType::RANDOM_DEVICE_ADDRESS);
    }
    on_common_le_connection_complete(remote_address);
    if (status == ErrorCode::UNKNOWN_CONNECTION &&
        canceled_connections_.find(remote_address) != canceled_connections_.end()) {
      // connection canceled by LeAddressManager.OnPause(), will auto reconnect by LeAddressManager.OnResume()
      return;
    } else {
      canceled_connections_.erase(remote_address);
      ready_to_unregister = true;
      remove_device_from_connect_list(remote_address);
    }

    if (status != ErrorCode::SUCCESS) {
      le_client_handler_->Post(common::BindOnce(&LeConnectionCallbacks::OnLeConnectFail,
                                                common::Unretained(le_client_callbacks_), remote_address, status));
      return;
    }

    auto role = connection_complete.GetRole();
    AddressWithType local_address;
    if (role == hci::Role::CENTRAL) {
      local_address = le_address_manager_->GetCurrentAddress();
    } else {
      // when accepting connection, we must obtain the address from the advertiser.
      // When we receive "set terminated event", we associate connection handle with advertiser address
      local_address = AddressWithType{};
    }

    uint16_t conn_interval = connection_complete.GetConnInterval();
    uint16_t conn_latency = connection_complete.GetConnLatency();
    uint16_t supervision_timeout = connection_complete.GetSupervisionTimeout();
    if (!check_connection_parameters(conn_interval, conn_interval, conn_latency, supervision_timeout)) {
      LOG_ERROR("Receive enhenced connection complete with invalid connection parameters");
      return;
    }
    uint16_t handle = connection_complete.GetConnectionHandle();
    ASSERT(le_acl_connections_.count(handle) == 0);
    auto queue = std::make_shared<AclConnection::Queue>(10);
    le_acl_connections_.emplace(std::piecewise_construct, std::forward_as_tuple(handle),
                                std::forward_as_tuple(remote_address, queue->GetDownEnd(), handler_));
    auto& connection_proxy = check_and_get_le_connection(handle);
    round_robin_scheduler_->Register(RoundRobinScheduler::ConnectionType::LE, handle, queue);
    std::unique_ptr<LeAclConnection> connection(new LeAclConnection(
        std::move(queue), le_acl_connection_interface_, handle, local_address, remote_address, role));
    connection_proxy.le_connection_management_callbacks_ = connection->GetEventCallbacks();
    le_client_handler_->Post(common::BindOnce(&LeConnectionCallbacks::OnLeConnectSuccess,
                                              common::Unretained(le_client_callbacks_), remote_address,
                                              std::move(connection)));
  }

  void on_le_connection_update_complete(LeMetaEventView view) {
    auto complete_view = LeConnectionUpdateCompleteView::Create(view);
    if (!complete_view.IsValid()) {
      LOG_ERROR("Received on_le_connection_update_complete with invalid packet");
      return;
    } else if (complete_view.GetStatus() != ErrorCode::SUCCESS) {
      auto status = complete_view.GetStatus();
      std::string error_code = ErrorCodeText(status);
      LOG_ERROR("Received on_le_connection_update_complete with error code %s", error_code.c_str());
      return;
    }
    auto handle = complete_view.GetConnectionHandle();
    if (le_acl_connections_.find(handle) == le_acl_connections_.end()) {
      LOG_WARN("Can't find connection %hd", handle);
      return;
    }
    auto& connection = le_acl_connections_.find(handle)->second;
    connection.le_connection_management_callbacks_->OnConnectionUpdate(
        complete_view.GetConnInterval(), complete_view.GetConnLatency(), complete_view.GetSupervisionTimeout());
  }

  void on_le_read_remote_version_information(
      uint16_t handle, uint8_t version, uint16_t manufacturer_name, uint16_t sub_version) {
    auto connection = le_acl_connections_.find(handle);
    if (connection != le_acl_connections_.end()) {
      connection->second.le_connection_management_callbacks_->OnReadRemoteVersionInformationComplete(
          version, manufacturer_name, sub_version);
    }
  }

  void enqueue_command(std::unique_ptr<CommandPacketBuilder> command_packet) {
    hci_layer_->EnqueueCommand(
        std::move(command_packet),
        handler_->BindOnce(&LeAddressManager::OnCommandComplete, common::Unretained(le_address_manager_)));
  }

  void on_data_length_change(LeMetaEventView view) {
    auto data_length_view = LeDataLengthChangeView::Create(view);
    if (!data_length_view.IsValid()) {
      LOG_ERROR("Invalid packet");
      return;
    }
    auto handle = data_length_view.GetConnectionHandle();
    auto connection_iterator = le_acl_connections_.find(handle);
    if (connection_iterator == le_acl_connections_.end()) {
      LOG_WARN("Can't find connection %hd", handle);
      return;
    }
    connection_iterator->second.le_connection_management_callbacks_->OnDataLengthChange(
        data_length_view.GetMaxTxOctets(),
        data_length_view.GetMaxTxTime(),
        data_length_view.GetMaxRxOctets(),
        data_length_view.GetMaxRxTime());
  }

  void on_remote_connection_parameter_request(LeMetaEventView view) {
    auto request_view = LeRemoteConnectionParameterRequestView::Create(view);
    if (!request_view.IsValid()) {
      LOG_ERROR("Invalid packet");
      return;
    }

    // TODO: this is blindly accepting any parameters, just so we don't hang connection
    // have proper parameter negotiation
    le_acl_connection_interface_->EnqueueCommand(
        LeRemoteConnectionParameterRequestReplyBuilder::Create(
            request_view.GetConnectionHandle(),
            request_view.GetIntervalMin(),
            request_view.GetIntervalMax(),
            request_view.GetLatency(),
            request_view.GetTimeout(),
            0,
            0),
        handler_->BindOnce([](CommandCompleteView status) {}));
  }

  void add_device_to_connect_list(AddressWithType address_with_type) {
    AddressType address_type = address_with_type.GetAddressType();
    if (!address_manager_registered) {
      le_address_manager_->Register(this);
      address_manager_registered = true;
    }
    pause_connection = true;
    switch (address_type) {
      case AddressType::PUBLIC_DEVICE_ADDRESS:
      case AddressType::PUBLIC_IDENTITY_ADDRESS: {
        le_address_manager_->AddDeviceToConnectList(ConnectListAddressType::PUBLIC, address_with_type.GetAddress());
      } break;
      case AddressType::RANDOM_DEVICE_ADDRESS:
      case AddressType::RANDOM_IDENTITY_ADDRESS: {
        le_address_manager_->AddDeviceToConnectList(ConnectListAddressType::RANDOM, address_with_type.GetAddress());
      }
    }
  }

  void add_device_to_resolving_list(
      AddressWithType address_with_type,
      const std::array<uint8_t, 16>& peer_irk,
      const std::array<uint8_t, 16>& local_irk) {
    AddressType address_type = address_with_type.GetAddressType();
    if (!address_manager_registered) {
      le_address_manager_->Register(this);
      address_manager_registered = true;
    }
    pause_connection = true;
    switch (address_type) {
      case AddressType::PUBLIC_DEVICE_ADDRESS:
      case AddressType::PUBLIC_IDENTITY_ADDRESS: {
        le_address_manager_->AddDeviceToResolvingList(
            PeerAddressType::PUBLIC_DEVICE_OR_IDENTITY_ADDRESS, address_with_type.GetAddress(), peer_irk, local_irk);
      } break;
      case AddressType::RANDOM_DEVICE_ADDRESS:
      case AddressType::RANDOM_IDENTITY_ADDRESS: {
        le_address_manager_->AddDeviceToResolvingList(
            PeerAddressType::RANDOM_DEVICE_OR_IDENTITY_ADDRESS, address_with_type.GetAddress(), peer_irk, local_irk);
      }
    }
  }

  void create_le_connection(AddressWithType address_with_type, bool add_to_connect_list) {
    // TODO: Configure default LE connection parameters?

    if (add_to_connect_list) {
      add_device_to_connect_list(address_with_type);
    }

    if (!address_manager_registered) {
      auto policy = le_address_manager_->Register(this);
      address_manager_registered = true;

      // Pause connection, wait for set random address complete
      if (policy == LeAddressManager::AddressPolicy::USE_RESOLVABLE_ADDRESS ||
          policy == LeAddressManager::AddressPolicy::USE_NON_RESOLVABLE_ADDRESS) {
        pause_connection = true;
      }
    }

    if (pause_connection) {
      canceled_connections_.insert(address_with_type);
      return;
    }

    uint16_t le_scan_interval = 0x0060;
    uint16_t le_scan_window = 0x0030;
    InitiatorFilterPolicy initiator_filter_policy = InitiatorFilterPolicy::USE_CONNECT_LIST;
    OwnAddressType own_address_type =
        static_cast<OwnAddressType>(le_address_manager_->GetCurrentAddress().GetAddressType());
    uint16_t conn_interval_min = 0x0018;
    uint16_t conn_interval_max = 0x0028;
    uint16_t conn_latency = 0x0000;
    uint16_t supervision_timeout = 0x001f4;
    ASSERT(le_client_callbacks_ != nullptr);
    ASSERT(check_connection_parameters(conn_interval_min, conn_interval_max, conn_latency, supervision_timeout));

    connecting_le_.insert(address_with_type);

    if (initiator_filter_policy == InitiatorFilterPolicy::USE_CONNECT_LIST) {
      address_with_type = AddressWithType();
    }

    if (controller_->IsSupported(OpCode::LE_EXTENDED_CREATE_CONNECTION)) {
      LeCreateConnPhyScanParameters tmp;
      tmp.scan_interval_ = le_scan_interval;
      tmp.scan_window_ = le_scan_window;
      tmp.conn_interval_min_ = conn_interval_min;
      tmp.conn_interval_max_ = conn_interval_max;
      tmp.conn_latency_ = conn_latency;
      tmp.supervision_timeout_ = supervision_timeout;
      tmp.min_ce_length_ = 0x00;
      tmp.max_ce_length_ = 0x00;

      le_acl_connection_interface_->EnqueueCommand(
          LeExtendedCreateConnectionBuilder::Create(initiator_filter_policy, own_address_type,
                                                    address_with_type.GetAddressType(), address_with_type.GetAddress(),
                                                    0x01 /* 1M PHY ONLY */, {tmp}),
          handler_->BindOnce([](CommandStatusView status) {
            ASSERT(status.IsValid());
            ASSERT(status.GetCommandOpCode() == OpCode::LE_EXTENDED_CREATE_CONNECTION);
          }));
    } else {
      le_acl_connection_interface_->EnqueueCommand(
          LeCreateConnectionBuilder::Create(le_scan_interval, le_scan_window, initiator_filter_policy,
                                            address_with_type.GetAddressType(), address_with_type.GetAddress(),
                                            own_address_type, conn_interval_min, conn_interval_max, conn_latency,
                                            supervision_timeout, kMinimumCeLength, kMaximumCeLength),
          handler_->BindOnce([](CommandStatusView status) {
            ASSERT(status.IsValid());
            ASSERT(status.GetCommandOpCode() == OpCode::LE_CREATE_CONNECTION);
          }));
    }
  }

  void cancel_connect(AddressWithType address_with_type) {
    // the connection will be canceled by LeAddressManager.OnPause()
    remove_device_from_connect_list(address_with_type);
  }

  void set_le_suggested_default_data_parameters(uint16_t length, uint16_t time) {
    auto packet = LeWriteSuggestedDefaultDataLengthBuilder::Create(length, time);
    le_acl_connection_interface_->EnqueueCommand(
        std::move(packet), handler_->BindOnce([](CommandCompleteView complete) {}));
  }

  void remove_device_from_connect_list(AddressWithType address_with_type) {
    AddressType address_type = address_with_type.GetAddressType();
    if (!address_manager_registered) {
      le_address_manager_->Register(this);
      address_manager_registered = true;
    }
    pause_connection = true;
    switch (address_type) {
      case AddressType::PUBLIC_DEVICE_ADDRESS:
      case AddressType::PUBLIC_IDENTITY_ADDRESS: {
        le_address_manager_->RemoveDeviceFromConnectList(
            ConnectListAddressType::PUBLIC, address_with_type.GetAddress());
      } break;
      case AddressType::RANDOM_DEVICE_ADDRESS:
      case AddressType::RANDOM_IDENTITY_ADDRESS: {
        le_address_manager_->RemoveDeviceFromConnectList(
            ConnectListAddressType::RANDOM, address_with_type.GetAddress());
      }
    }
  }

  void remove_device_from_resolving_list(AddressWithType address_with_type) {
    AddressType address_type = address_with_type.GetAddressType();
    if (!address_manager_registered) {
      le_address_manager_->Register(this);
      address_manager_registered = true;
    }
    pause_connection = true;
    switch (address_type) {
      case AddressType::PUBLIC_DEVICE_ADDRESS:
      case AddressType::PUBLIC_IDENTITY_ADDRESS: {
        le_address_manager_->RemoveDeviceFromResolvingList(
            PeerAddressType::PUBLIC_DEVICE_OR_IDENTITY_ADDRESS, address_with_type.GetAddress());
      } break;
      case AddressType::RANDOM_DEVICE_ADDRESS:
      case AddressType::RANDOM_IDENTITY_ADDRESS: {
        le_address_manager_->RemoveDeviceFromResolvingList(
            PeerAddressType::RANDOM_DEVICE_OR_IDENTITY_ADDRESS, address_with_type.GetAddress());
      }
    }
  }

  void set_privacy_policy_for_initiator_address(
      LeAddressManager::AddressPolicy address_policy,
      AddressWithType fixed_address,
      crypto_toolbox::Octet16 rotation_irk,
      std::chrono::milliseconds minimum_rotation_time,
      std::chrono::milliseconds maximum_rotation_time) {
    le_address_manager_->SetPrivacyPolicyForInitiatorAddress(
        address_policy, fixed_address, rotation_irk, minimum_rotation_time, maximum_rotation_time);
  }

  // TODO(jpawlowski): remove once we have config file abstraction in cert tests
  void set_privacy_policy_for_initiator_address_for_test(
      LeAddressManager::AddressPolicy address_policy,
      AddressWithType fixed_address,
      crypto_toolbox::Octet16 rotation_irk,
      std::chrono::milliseconds minimum_rotation_time,
      std::chrono::milliseconds maximum_rotation_time) {
    le_address_manager_->SetPrivacyPolicyForInitiatorAddressForTest(
        address_policy, fixed_address, rotation_irk, minimum_rotation_time, maximum_rotation_time);
  }

  void handle_register_le_callbacks(LeConnectionCallbacks* callbacks, os::Handler* handler) {
    ASSERT(le_client_callbacks_ == nullptr);
    ASSERT(le_client_handler_ == nullptr);
    le_client_callbacks_ = callbacks;
    le_client_handler_ = handler;
  }

  le_acl_connection& check_and_get_le_connection(uint16_t handle) {
    auto connection = le_acl_connections_.find(handle);
    ASSERT(connection != le_acl_connections_.end());
    return connection->second;
  }

  bool check_connection_parameters(
      uint16_t conn_interval_min, uint16_t conn_interval_max, uint16_t conn_latency, uint16_t supervision_timeout) {
    if (conn_interval_min < 0x0006 || conn_interval_min > 0x0C80 || conn_interval_max < 0x0006 ||
        conn_interval_max > 0x0C80 || conn_latency > 0x01F3 || supervision_timeout < 0x000A ||
        supervision_timeout > 0x0C80) {
      LOG_ERROR("Invalid parameter");
      return false;
    }

    // The Maximum interval in milliseconds will be conn_interval_max * 1.25 ms
    // The Timeout in milliseconds will be expected_supervision_timeout * 10 ms
    // The Timeout in milliseconds shall be larger than (1 + Latency) * Interval_Max * 2, where Interval_Max is given in
    // milliseconds.
    uint32_t supervision_timeout_min = (uint32_t)(1 + conn_latency) * conn_interval_max * 2 + 1;
    if (supervision_timeout * 8 < supervision_timeout_min || conn_interval_max < conn_interval_min) {
      LOG_ERROR("Invalid parameter");
      return false;
    }

    return true;
  }

  void OnPause() override {
    pause_connection = true;
    if (connecting_le_.empty()) {
      le_address_manager_->AckPause(this);
      return;
    }
    canceled_connections_ = connecting_le_;
    le_acl_connection_interface_->EnqueueCommand(
        LeCreateConnectionCancelBuilder::Create(),
        handler_->BindOnce(&le_impl::on_create_connection_cancel_complete, common::Unretained(this)));
  }

  void on_create_connection_cancel_complete(CommandCompleteView view) {
    auto complete_view = LeCreateConnectionCancelCompleteView::Create(view);
    ASSERT(complete_view.IsValid());
    if (complete_view.GetStatus() != ErrorCode::SUCCESS) {
      auto status = complete_view.GetStatus();
      std::string error_code = ErrorCodeText(status);
      LOG_WARN("Received on_create_connection_cancel_complete with error code %s", error_code.c_str());
    }
    le_address_manager_->AckPause(this);
  }

  void check_for_unregister() {
    if (le_acl_connections_.empty() && connecting_le_.empty() && canceled_connections_.empty() &&
        address_manager_registered && ready_to_unregister) {
      le_address_manager_->Unregister(this);
      address_manager_registered = false;
      pause_connection = false;
      ready_to_unregister = false;
    }
  }

  void OnResume() override {
    pause_connection = false;
    if (!canceled_connections_.empty()) {
      create_le_connection(*canceled_connections_.begin(), false);
    }
    canceled_connections_.clear();
    le_address_manager_->AckResume(this);
    check_for_unregister();
  }

  uint16_t HACK_get_handle(Address address) {
    for (auto it = le_acl_connections_.begin(); it != le_acl_connections_.end(); it++) {
      if (it->second.address_with_type_.GetAddress() == address) {
        return it->first;
      }
    }
    return 0xFFFF;
  }

  static constexpr uint16_t kMinimumCeLength = 0x0002;
  static constexpr uint16_t kMaximumCeLength = 0x0C00;
  HciLayer* hci_layer_ = nullptr;
  Controller* controller_ = nullptr;
  os::Handler* handler_ = nullptr;
  RoundRobinScheduler* round_robin_scheduler_ = nullptr;
  LeAddressManager* le_address_manager_ = nullptr;
  LeAclConnectionInterface* le_acl_connection_interface_ = nullptr;
  LeConnectionCallbacks* le_client_callbacks_ = nullptr;
  os::Handler* le_client_handler_ = nullptr;
  std::map<uint16_t, le_acl_connection> le_acl_connections_;
  std::set<AddressWithType> connecting_le_;
  std::set<AddressWithType> canceled_connections_;
  bool address_manager_registered = false;
  bool ready_to_unregister = false;
  bool pause_connection = false;
};

}  // namespace acl_manager
}  // namespace hci
}  // namespace bluetooth
