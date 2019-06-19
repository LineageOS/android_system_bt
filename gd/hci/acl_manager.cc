/*
 * Copyright 2019 The Android Open Source Project
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

#include "hci/acl_manager.h"

#include <future>
#include <set>
#include <utility>

#include "acl_manager.h"
#include "common/bidi_queue.h"
#include "hci/controller.h"
#include "hci/hci_layer.h"

namespace bluetooth {
namespace hci {

using common::Bind;
using common::BindOnce;

struct AclManager::acl_connection {
  friend AclConnection;
  std::unique_ptr<AclConnection::Queue> queue_ = std::make_unique<AclConnection::Queue>(10);
  bool is_disconnected_ = false;
  ErrorCode disconnect_reason_;
  os::Handler* disconnect_handler_ = nullptr;
  common::OnceCallback<void(ErrorCode)> on_disconnect_callback_;
  // Round-robin: Track if dequeue is registered for this connection
  bool is_registered_ = false;
  // Credits: Track the number of packets which have been sent to the controller
  uint16_t number_of_sent_packets_ = 0;
  void call_disconnect_callback() {
    disconnect_handler_->Post(BindOnce(std::move(on_disconnect_callback_), disconnect_reason_));
  }
};

struct AclManager::impl {
  impl(AclManager& acl_manager) : acl_manager_(acl_manager) {}

  void Start() {
    hci_layer_ = acl_manager_.GetDependency<HciLayer>();
    handler_ = acl_manager_.GetHandler();
    controller_ = acl_manager_.GetDependency<Controller>();
    max_acl_packet_credits_ = controller_->ReadControllerNumAclPacketBuffers();
    acl_packet_credits_ = max_acl_packet_credits_;
    acl_buffer_length_ = controller_->ReadControllerAclPacketLength();
    controller_->RegisterCompletedAclPacketsCallback(
        common::Bind(&impl::incoming_acl_credits, common::Unretained(this)), handler_);

    // TODO: determine when we should reject connection
    should_accept_connection_ = common::Bind([](common::Address, common::ClassOfDevice) { return true; });
    hci_queue_end_ = hci_layer_->GetAclQueueEnd();
    hci_queue_end_->RegisterDequeue(
        handler_, common::Bind(&impl::dequeue_and_route_acl_packet_to_connection, common::Unretained(this)));
    hci_layer_->RegisterEventHandler(EventCode::CONNECTION_COMPLETE,
                                     Bind(&impl::on_connection_complete, common::Unretained(this)), handler_);
    hci_layer_->RegisterEventHandler(EventCode::DISCONNECTION_COMPLETE,
                                     Bind(&impl::on_disconnection_complete, common::Unretained(this)), handler_);
    hci_layer_->RegisterEventHandler(EventCode::CONNECTION_REQUEST,
                                     Bind(&impl::on_incoming_connection, common::Unretained(this)), handler_);
  }

  void Stop() {
    hci_layer_->UnregisterEventHandler(EventCode::DISCONNECTION_COMPLETE);
    hci_layer_->UnregisterEventHandler(EventCode::CONNECTION_COMPLETE);
    hci_layer_->UnregisterEventHandler(EventCode::CONNECTION_REQUEST);
    hci_queue_end_->UnregisterDequeue();
    unregister_all_connections();
    acl_connections_.clear();
    hci_queue_end_ = nullptr;
    handler_ = nullptr;
    hci_layer_ = nullptr;
  }

  void incoming_acl_credits(uint16_t handle, uint16_t credits) {
    auto connection_pair = acl_connections_.find(handle);
    if (connection_pair == acl_connections_.end()) {
      LOG_INFO("Dropping %hx received credits to unknown connection 0x%0hx", credits, handle);
      return;
    }
    if (connection_pair->second.is_disconnected_) {
      LOG_INFO("Dropping %hx received credits to disconnected connection 0x%0hx", credits, handle);
      return;
    }
    connection_pair->second.number_of_sent_packets_ -= credits;
    acl_packet_credits_ += credits;
    ASSERT(acl_packet_credits_ <= max_acl_packet_credits_);
    start_round_robin();
  }

  // Round-robin scheduler
  void start_round_robin() {
    if (acl_packet_credits_ == 0) {
      return;
    }
    if (!fragments_to_send_.empty()) {
      send_next_fragment();
      return;
    }
    for (auto connection_pair = acl_connections_.begin(); connection_pair != acl_connections_.end();
         connection_pair = std::next(connection_pair)) {
      if (connection_pair->second.is_registered_) {
        continue;
      }
      connection_pair->second.is_registered_ = true;
      connection_pair->second.queue_->GetDownEnd()->RegisterDequeue(
          handler_, common::Bind(&impl::handle_dequeue_from_upper, common::Unretained(this), connection_pair));
    }
  }

  void handle_dequeue_from_upper(std::map<uint16_t, acl_connection>::iterator connection_pair) {
    current_connection_pair_ = connection_pair;
    buffer_packet();
  }

  void unregister_all_connections() {
    for (auto connection_pair = acl_connections_.begin(); connection_pair != acl_connections_.end();
         connection_pair = std::next(connection_pair)) {
      if (connection_pair->second.is_registered_) {
        connection_pair->second.is_registered_ = false;
        connection_pair->second.queue_->GetDownEnd()->UnregisterDequeue();
      }
    }
  }

  void buffer_packet() {
    unregister_all_connections();
    PacketBoundaryFlag packet_boundary_flag = PacketBoundaryFlag::COMPLETE_PDU;
    BroadcastFlag broadcast_flag = BroadcastFlag::POINT_TO_POINT;
    //   Wrap packet and enqueue it
    uint16_t handle = current_connection_pair_->first;
    packet_to_send_ = AclPacketBuilder::Create(handle, packet_boundary_flag, broadcast_flag,
                                               current_connection_pair_->second.queue_->GetDownEnd()->TryDequeue());
    ASSERT(packet_to_send_ != nullptr);
    fragment_and_send();
  }

  void fragment_and_send() {
    // TODO: Fragment the packet into a list of packets
    fragments_to_send_.push_back(std::move(packet_to_send_));
    packet_to_send_ = nullptr;
    current_connection_pair_->second.number_of_sent_packets_ += fragments_to_send_.size();
    send_next_fragment();
  }

  void send_next_fragment() {
    hci_queue_end_->RegisterEnqueue(handler_,
                                    common::Bind(&impl::handle_enqueue_next_fragment, common::Unretained(this)));
  }

  std::unique_ptr<AclPacketBuilder> handle_enqueue_next_fragment() {
    ASSERT(acl_packet_credits_ > 0);
    if (acl_packet_credits_ == 1 || fragments_to_send_.size() == 1) {
      hci_queue_end_->UnregisterEnqueue();
      if (fragments_to_send_.size() == 1) {
        handler_->Post(common::BindOnce(&impl::start_round_robin, common::Unretained(this)));
      }
    }
    ASSERT(fragments_to_send_.size() > 0);
    auto raw_pointer = fragments_to_send_.front().release();
    acl_packet_credits_ -= 1;
    fragments_to_send_.pop_front();
    return std::unique_ptr<AclPacketBuilder>(raw_pointer);
  }

  void dequeue_and_route_acl_packet_to_connection() {
    auto packet = hci_queue_end_->TryDequeue();
    ASSERT(packet != nullptr);
    if (!packet->IsValid()) {
      LOG_INFO("Dropping invalid packet of size %zu", packet->size());
      return;
    }
    uint16_t handle = packet->GetHandle();
    auto connection_pair = acl_connections_.find(handle);
    if (connection_pair == acl_connections_.end()) {
      LOG_INFO("Dropping packet of size %zu to unknown connection 0x%0hx", packet->size(), handle);
      return;
    }
    // TODO: What happens if the connection is stalled and fills up?
    // TODO hsz: define enqueue callback
    auto queue_end = connection_pair->second.queue_->GetDownEnd();
    PacketView<kLittleEndian> payload = packet->GetPayload();
    queue_end->RegisterEnqueue(handler_, common::Bind(
                                             [](decltype(queue_end) queue_end, PacketView<kLittleEndian> payload) {
                                               queue_end->UnregisterEnqueue();
                                               return std::make_unique<PacketView<kLittleEndian>>(payload);
                                             },
                                             queue_end, std::move(payload)));
  }

  void on_incoming_connection(EventPacketView packet) {
    ConnectionRequestView request = ConnectionRequestView::Create(packet);
    ASSERT(request.IsValid());
    common::Address address = request.GetBdAddr();
    if (client_callbacks_ == nullptr) {
      LOG_ERROR("No callbacks to call");
      auto reason = RejectConnectionReason::LIMITED_RESOURCES;
      this->reject_connection(RejectConnectionRequestBuilder::Create(address, reason));
      return;
    }
    connecting_.insert(address);
    if (should_accept_connection_.Run(address, request.GetClassOfDevice())) {
      this->accept_connection(address);
    } else {
      auto reason = RejectConnectionReason::LIMITED_RESOURCES;  // TODO: determine reason
      this->reject_connection(RejectConnectionRequestBuilder::Create(address, reason));
    }
  }

  void on_connection_complete(EventPacketView packet) {
    ConnectionCompleteView connection_complete = ConnectionCompleteView::Create(std::move(packet));
    ASSERT(connection_complete.IsValid());
    auto status = connection_complete.GetStatus();
    auto address = connection_complete.GetBdAddr();
    auto connecting_addr = connecting_.find(address);
    if (connecting_addr == connecting_.end()) {
      LOG_WARN("No prior connection request for %s", address.ToString().c_str());
    } else {
      connecting_.erase(connecting_addr);
    }
    if (status == ErrorCode::SUCCESS) {
      uint16_t handle = connection_complete.GetConnectionHandle();
      ASSERT(acl_connections_.count(handle) == 0);
      acl_connections_[handle] = {};
      if (acl_connections_.size() == 1 && packet_to_send_ == nullptr) {
        start_round_robin();
      }
      AclConnection connection_proxy{&acl_manager_, handle, address};
      client_handler_->Post(common::BindOnce(&ConnectionCallbacks::OnConnectSuccess,
                                             common::Unretained(client_callbacks_), std::move(connection_proxy)));
    } else {
      client_handler_->Post(common::BindOnce(&ConnectionCallbacks::OnConnectFail, common::Unretained(client_callbacks_),
                                             address, status));
    }
  }

  void on_disconnection_complete(EventPacketView packet) {
    DisconnectionCompleteView disconnection_complete = DisconnectionCompleteView::Create(std::move(packet));
    ASSERT(disconnection_complete.IsValid());
    uint16_t handle = disconnection_complete.GetConnectionHandle();
    auto status = disconnection_complete.GetStatus();
    if (status == ErrorCode::SUCCESS) {
      ASSERT(acl_connections_.count(handle) == 1);
      auto& acl_connection = acl_connections_.find(handle)->second;
      acl_connection.is_disconnected_ = true;
      acl_connection.disconnect_reason_ = disconnection_complete.GetReason();
      acl_connection.call_disconnect_callback();
      // Reclaim outstanding packets
      acl_packet_credits_ += acl_connection.number_of_sent_packets_;
      acl_connection.number_of_sent_packets_ = 0;
    } else {
      std::string error_code = ErrorCodeText(status);
      LOG_ERROR("Received disconnection complete with error code %s, handle 0x%02hx", error_code.c_str(), handle);
    }
  }

  void create_connection(common::Address address) {
    // TODO: Configure default connection parameters?
    uint16_t packet_type = 0x4408 /* DM 1,3,5 */ | 0x8810 /*DH 1,3,5 */;
    PageScanRepetitionMode page_scan_repetition_mode = PageScanRepetitionMode::R1;
    uint16_t clock_offset = 0;
    ClockOffsetValid clock_offset_valid = ClockOffsetValid::INVALID;
    CreateConnectionRoleSwitch allow_role_switch = CreateConnectionRoleSwitch::ALLOW_ROLE_SWITCH;
    ASSERT(client_callbacks_ != nullptr);

    connecting_.insert(address);
    std::unique_ptr<CreateConnectionBuilder> packet = CreateConnectionBuilder::Create(
        address, packet_type, page_scan_repetition_mode, clock_offset, clock_offset_valid, allow_role_switch);

    hci_layer_->EnqueueCommand(std::move(packet), common::BindOnce([](CommandStatusView status) {
                                 ASSERT(status.IsValid());
                                 ASSERT(status.GetCommandOpCode() == OpCode::CREATE_CONNECTION);
                               }),
                               handler_);
  }

  void cancel_connect(common::Address address) {
    auto connecting_addr = connecting_.find(address);
    if (connecting_addr == connecting_.end()) {
      LOG_INFO("Cannot cancel non-existent connection to %s", address.ToString().c_str());
      return;
    }
    connecting_.erase(connecting_addr);
    std::unique_ptr<CreateConnectionCancelBuilder> packet = CreateConnectionCancelBuilder::Create(address);
    hci_layer_->EnqueueCommand(std::move(packet), common::BindOnce([](CommandCompleteView complete) { /* TODO */ }),
                               handler_);
  }

  void accept_connection(common::Address address) {
    auto role = AcceptConnectionRequestRole::BECOME_MASTER;  // We prefer to be master
    hci_layer_->EnqueueCommand(AcceptConnectionRequestBuilder::Create(address, role),
                               common::BindOnce(&impl::on_accept_connection_status, common::Unretained(this), address),
                               handler_);
  }

  void handle_disconnect(uint16_t handle, DisconnectReason reason) {
    ASSERT(acl_connections_.count(handle) == 1);
    std::unique_ptr<DisconnectBuilder> packet = DisconnectBuilder::Create(handle, reason);
    hci_layer_->EnqueueCommand(std::move(packet), BindOnce([](CommandStatusView status) { /* TODO: check? */ }),
                               handler_);
  }

  void cleanup(uint16_t handle) {
    ASSERT(acl_connections_.count(handle) == 1);
    auto& acl_connection = acl_connections_.find(handle)->second;
    if (acl_connection.is_registered_) {
      acl_connection.is_registered_ = false;
      acl_connection.queue_->GetDownEnd()->UnregisterDequeue();
    }
    acl_connections_.erase(handle);
  }

  void on_accept_connection_status(common::Address address, CommandStatusView status) {
    auto accept_status = AcceptConnectionRequestStatusView::Create(status);
    ASSERT(accept_status.IsValid());
    if (status.GetStatus() != ErrorCode::SUCCESS) {
      cancel_connect(address);
    }
  }

  void reject_connection(std::unique_ptr<RejectConnectionRequestBuilder> builder) {
    hci_layer_->EnqueueCommand(std::move(builder), BindOnce([](CommandStatusView status) { /* TODO: check? */ }),
                               handler_);
  }

  void handle_register_callbacks(ConnectionCallbacks* callbacks, os::Handler* handler) {
    ASSERT(client_callbacks_ == nullptr);
    ASSERT(client_handler_ == nullptr);
    client_callbacks_ = callbacks;
    client_handler_ = handler;
  }

  acl_connection& check_and_get_connection(uint16_t handle) {
    auto connection = acl_connections_.find(handle);
    ASSERT(connection != acl_connections_.end());
    return connection->second;
  }

  AclConnection::QueueUpEnd* get_acl_queue_end(uint16_t handle) {
    auto& connection = check_and_get_connection(handle);
    ASSERT_LOG(connection.disconnect_handler_ != nullptr, "No disconnect handler registered.");
    return connection.queue_->GetUpEnd();
  }

  void RegisterDisconnectCallback(uint16_t handle, common::OnceCallback<void(ErrorCode)> on_disconnect,
                                  os::Handler* handler) {
    auto& connection = check_and_get_connection(handle);
    connection.on_disconnect_callback_ = std::move(on_disconnect);
    connection.disconnect_handler_ = handler;
    if (connection.is_disconnected_) {
      connection.call_disconnect_callback();
    }
  }

  bool Disconnect(uint16_t handle, DisconnectReason reason) {
    auto& connection = check_and_get_connection(handle);
    if (connection.is_disconnected_) {
      LOG_INFO("Already disconnected");
      return false;
    }
    handler_->Post(BindOnce(&impl::handle_disconnect, common::Unretained(this), handle, reason));
    return true;
  }

  void Finish(uint16_t handle) {
    auto& connection = check_and_get_connection(handle);
    ASSERT_LOG(connection.is_disconnected_, "Finish must be invoked after disconnection (handle 0x%04hx)", handle);
    handler_->Post(BindOnce(&impl::cleanup, common::Unretained(this), handle));
  }

  AclManager& acl_manager_;

  Controller* controller_ = nullptr;
  uint16_t max_acl_packet_credits_ = 0;
  uint16_t acl_packet_credits_ = 0;
  uint16_t acl_buffer_length_ = 0;

  std::unique_ptr<AclPacketBuilder> packet_to_send_;
  std::list<std::unique_ptr<AclPacketBuilder>> fragments_to_send_;
  std::map<uint16_t, acl_connection>::iterator current_connection_pair_;

  HciLayer* hci_layer_ = nullptr;
  os::Handler* handler_ = nullptr;
  ConnectionCallbacks* client_callbacks_ = nullptr;
  os::Handler* client_handler_ = nullptr;
  common::BidiQueueEnd<AclPacketBuilder, AclPacketView>* hci_queue_end_ = nullptr;
  std::map<uint16_t, AclManager::acl_connection> acl_connections_;
  std::set<common::Address> connecting_;
  common::Callback<bool(common::Address, common::ClassOfDevice)> should_accept_connection_;
};

AclConnection::QueueUpEnd* AclConnection::GetAclQueueEnd() const {
  return manager_->pimpl_->get_acl_queue_end(handle_);
}

void AclConnection::RegisterDisconnectCallback(common::OnceCallback<void(ErrorCode)> on_disconnect,
                                               os::Handler* handler) {
  return manager_->pimpl_->RegisterDisconnectCallback(handle_, std::move(on_disconnect), handler);
}

bool AclConnection::Disconnect(DisconnectReason reason) {
  return manager_->pimpl_->Disconnect(handle_, reason);
}

void AclConnection::Finish() {
  return manager_->pimpl_->Finish(handle_);
}

AclManager::AclManager() : pimpl_(std::make_unique<impl>(*this)) {}

bool AclManager::RegisterCallbacks(ConnectionCallbacks* callbacks, os::Handler* handler) {
  ASSERT(callbacks != nullptr && handler != nullptr);
  GetHandler()->Post(common::BindOnce(&impl::handle_register_callbacks, common::Unretained(pimpl_.get()),
                                      common::Unretained(callbacks), common::Unretained(handler)));
  return true;
}

void AclManager::CreateConnection(common::Address address) {
  GetHandler()->Post(common::BindOnce(&impl::create_connection, common::Unretained(pimpl_.get()), address));
}

void AclManager::CancelConnect(common::Address address) {
  GetHandler()->Post(BindOnce(&impl::cancel_connect, common::Unretained(pimpl_.get()), address));
}

void AclManager::ListDependencies(ModuleList* list) {
  list->add<HciLayer>();
  list->add<Controller>();
}

void AclManager::Start() {
  pimpl_->Start();
}

void AclManager::Stop() {
  pimpl_->Stop();
}

const ModuleFactory AclManager::Factory = ModuleFactory([]() { return new AclManager(); });

}  // namespace hci
}  // namespace bluetooth
