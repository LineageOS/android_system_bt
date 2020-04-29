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

#include <atomic>
#include <queue>
#include <set>
#include <utility>

#include "common/bidi_queue.h"
#include "crypto_toolbox/crypto_toolbox.h"
#include "hci/acl_fragmenter.h"
#include "hci/controller.h"
#include "hci/hci_layer.h"
#include "hci/round_robin_scheduler.h"
#include "os/alarm.h"
#include "os/rand.h"
#include "security/security_module.h"

using bluetooth::crypto_toolbox::Octet16;

namespace bluetooth {
namespace hci {

constexpr uint16_t kQualcommDebugHandle = 0xedc;
constexpr size_t kMaxQueuedPacketsPerConnection = 10;

using common::Bind;
using common::BindOnce;

namespace {
class PacketViewForRecombination : public packet::PacketView<kLittleEndian> {
 public:
  PacketViewForRecombination(const PacketView& packetView) : PacketView(packetView) {}
  void AppendPacketView(packet::PacketView<kLittleEndian> to_append) {
    Append(to_append);
  }
};

constexpr int kL2capBasicFrameHeaderSize = 4;

// Per spec 5.1 Vol 2 Part B 5.3, ACL link shall carry L2CAP data. Therefore, an ACL packet shall contain L2CAP PDU.
// This function returns the PDU size of the L2CAP data if it's a starting packet. Returns 0 if it's invalid.
uint16_t GetL2capPduSize(AclPacketView packet) {
  auto l2cap_payload = packet.GetPayload();
  if (l2cap_payload.size() < kL2capBasicFrameHeaderSize) {
    LOG_ERROR("Controller sent an invalid L2CAP starting packet!");
    return 0;
  }
  return (l2cap_payload.at(1) << 8) + l2cap_payload.at(0);
}

}  // namespace

template <class T>
void check_command_complete(CommandCompleteView view) {
  ASSERT(view.IsValid());
  auto status_view = T::Create(view);
  if (!status_view.IsValid()) {
    LOG_ERROR("Received command complete with invalid packet, opcode 0x%02hx", view.GetCommandOpCode());
    return;
  }
  ErrorCode status = status_view.GetStatus();
  OpCode op_code = status_view.GetCommandOpCode();
  if (status != ErrorCode::SUCCESS) {
    std::string error_code = ErrorCodeText(status);
    LOG_ERROR("Received command complete with error code %s, opcode 0x%02hx", error_code.c_str(), op_code);
    return;
  }
}

template <class T>
void check_command_status(CommandStatusView view) {
  ASSERT(view.IsValid());
  auto status_view = T::Create(view);
  if (!status_view.IsValid()) {
    LOG_ERROR("Received command status with invalid packet, opcode 0x%02hx", view.GetCommandOpCode());
    return;
  }
  ErrorCode status = status_view.GetStatus();
  OpCode op_code = status_view.GetCommandOpCode();
  if (status != ErrorCode::SUCCESS) {
    std::string error_code = ErrorCodeText(status);
    LOG_ERROR("Received command status with error code %s, opcode 0x%02hx", error_code.c_str(), op_code);
    return;
  }
}

struct assembler {
  assembler(AddressWithType address_with_type, AclConnection::QueueDownEnd* down_end, os::Handler* handler)
      : address_with_type_(address_with_type), down_end_(down_end), handler_(handler) {}
  AddressWithType address_with_type_;
  AclConnection::QueueDownEnd* down_end_;
  os::Handler* handler_;
  PacketViewForRecombination recombination_stage_{std::make_shared<std::vector<uint8_t>>()};
  int remaining_sdu_continuation_packet_size_ = 0;
  std::shared_ptr<std::atomic_bool> enqueue_registered_ = std::make_shared<std::atomic_bool>(false);
  std::queue<packet::PacketView<kLittleEndian>> incoming_queue_;

  ~assembler() {
    if (enqueue_registered_->exchange(false)) {
      down_end_->UnregisterEnqueue();
    }
  }

  // Invoked from some external Queue Reactable context
  std::unique_ptr<packet::PacketView<kLittleEndian>> on_le_incoming_data_ready() {
    auto packet = incoming_queue_.front();
    incoming_queue_.pop();
    if (incoming_queue_.empty() && enqueue_registered_->exchange(false)) {
      down_end_->UnregisterEnqueue();
    }
    return std::make_unique<PacketView<kLittleEndian>>(packet);
  }

  void on_incoming_packet(AclPacketView packet) {
    // TODO: What happens if the connection is stalled and fills up?
    PacketView<kLittleEndian> payload = packet.GetPayload();
    auto payload_size = payload.size();
    auto packet_boundary_flag = packet.GetPacketBoundaryFlag();
    if (packet_boundary_flag == PacketBoundaryFlag::FIRST_NON_AUTOMATICALLY_FLUSHABLE) {
      LOG_ERROR("Controller is not allowed to send FIRST_NON_AUTOMATICALLY_FLUSHABLE to host except loopback mode");
      return;
    }
    if (packet_boundary_flag == PacketBoundaryFlag::CONTINUING_FRAGMENT) {
      if (remaining_sdu_continuation_packet_size_ < payload_size) {
        LOG_WARN("Remote sent unexpected L2CAP PDU. Drop the entire L2CAP PDU");
        recombination_stage_ = PacketViewForRecombination(std::make_shared<std::vector<uint8_t>>());
        remaining_sdu_continuation_packet_size_ = 0;
        return;
      }
      remaining_sdu_continuation_packet_size_ -= payload_size;
      recombination_stage_.AppendPacketView(payload);
      if (remaining_sdu_continuation_packet_size_ != 0) {
        return;
      } else {
        payload = recombination_stage_;
        recombination_stage_ = PacketViewForRecombination(std::make_shared<std::vector<uint8_t>>());
      }
    } else if (packet_boundary_flag == PacketBoundaryFlag::FIRST_AUTOMATICALLY_FLUSHABLE) {
      if (recombination_stage_.size() > 0) {
        LOG_ERROR("Controller sent a starting packet without finishing previous packet. Drop previous one.");
      }
      auto l2cap_pdu_size = GetL2capPduSize(packet);
      remaining_sdu_continuation_packet_size_ = l2cap_pdu_size - (payload_size - kL2capBasicFrameHeaderSize);
      if (remaining_sdu_continuation_packet_size_ > 0) {
        recombination_stage_ = payload;
        return;
      }
    }
    if (incoming_queue_.size() > kMaxQueuedPacketsPerConnection) {
      LOG_ERROR("Dropping packet due to congestion from remote:%s", address_with_type_.ToString().c_str());
      return;
    }

    incoming_queue_.push(payload);
    if (!enqueue_registered_->exchange(true)) {
      down_end_->RegisterEnqueue(handler_,
                                 common::Bind(&assembler::on_le_incoming_data_ready, common::Unretained(this)));
    }
  }
};

struct AclManager::acl_connection {
  acl_connection(AddressWithType address_with_type, AclConnection::QueueDownEnd* queue_down_end, os::Handler* handler)
      : assembler_(address_with_type, queue_down_end, handler), address_with_type_(address_with_type) {}
  ~acl_connection() = default;
  struct assembler assembler_;
  AddressWithType address_with_type_;
  ConnectionManagementCallbacks* connection_management_callbacks_ = nullptr;
};

struct AclManager::le_acl_connection {
  le_acl_connection(AddressWithType address_with_type, AclConnection::QueueDownEnd* queue_down_end,
                    os::Handler* handler)
      : assembler_(address_with_type, queue_down_end, handler) {}
  ~le_acl_connection() = default;
  struct assembler assembler_;
  LeConnectionManagementCallbacks* le_connection_management_callbacks_ = nullptr;
};

class AclConnectionTracker : public ConnectionManagementCallbacks {
 public:
  AclConnectionTracker(AclConnectionInterface* acl_connection_interface)
      : acl_connection_interface_(acl_connection_interface) {}
  ~AclConnectionTracker() override {
    ASSERT(queued_callbacks_.empty());
  }
  void RegisterCallbacks(ConnectionManagementCallbacks* callbacks, os::Handler* handler) {
    while (!queued_callbacks_.empty()) {
      auto iter = queued_callbacks_.begin();
      handler->Post(std::move(*iter));
      queued_callbacks_.erase(iter);
    }
    client_handler_ = handler;
    client_callbacks_ = callbacks;
  }

#define SAVE_OR_CALL(f, ...)                                                                                        \
  if (client_handler_ == nullptr) {                                                                                 \
    queued_callbacks_.emplace_back(                                                                                 \
        common::BindOnce(&ConnectionManagementCallbacks::f, common::Unretained(this), ##__VA_ARGS__));              \
  } else {                                                                                                          \
    client_handler_->Post(                                                                                          \
        common::BindOnce(&ConnectionManagementCallbacks::f, common::Unretained(client_callbacks_), ##__VA_ARGS__)); \
  }

  void OnConnectionPacketTypeChanged(uint16_t packet_type) override {
    SAVE_OR_CALL(OnConnectionPacketTypeChanged, packet_type)
  }
  void OnAuthenticationComplete() override {
    SAVE_OR_CALL(OnAuthenticationComplete)
  }
  void OnEncryptionChange(EncryptionEnabled enabled) override {
    SAVE_OR_CALL(OnEncryptionChange, enabled)
  }
  void OnChangeConnectionLinkKeyComplete() override {
    SAVE_OR_CALL(OnChangeConnectionLinkKeyComplete)
  }
  void OnReadClockOffsetComplete(uint16_t clock_offset) override {
    SAVE_OR_CALL(OnReadClockOffsetComplete, clock_offset)
  }
  void OnModeChange(Mode current_mode, uint16_t interval) override {
    SAVE_OR_CALL(OnModeChange, current_mode, interval)
  }
  void OnQosSetupComplete(ServiceType service_type, uint32_t token_rate, uint32_t peak_bandwidth, uint32_t latency,
                          uint32_t delay_variation) override {
    SAVE_OR_CALL(OnQosSetupComplete, service_type, token_rate, peak_bandwidth, latency, delay_variation)
  }
  void OnFlowSpecificationComplete(FlowDirection flow_direction, ServiceType service_type, uint32_t token_rate,
                                   uint32_t token_bucket_size, uint32_t peak_bandwidth,
                                   uint32_t access_latency) override {
    SAVE_OR_CALL(OnFlowSpecificationComplete, flow_direction, service_type, token_rate, token_bucket_size,
                 peak_bandwidth, access_latency)
  }
  void OnFlushOccurred() override {
    SAVE_OR_CALL(OnFlushOccurred)
  }
  void OnRoleDiscoveryComplete(Role current_role) override {
    SAVE_OR_CALL(OnRoleDiscoveryComplete, current_role)
  }
  void OnReadLinkPolicySettingsComplete(uint16_t link_policy_settings) override {
    SAVE_OR_CALL(OnReadLinkPolicySettingsComplete, link_policy_settings)
  }
  void OnReadAutomaticFlushTimeoutComplete(uint16_t flush_timeout) override {
    SAVE_OR_CALL(OnReadAutomaticFlushTimeoutComplete, flush_timeout)
  }
  void OnReadTransmitPowerLevelComplete(uint8_t transmit_power_level) override {
    SAVE_OR_CALL(OnReadTransmitPowerLevelComplete, transmit_power_level)
  }
  void OnReadLinkSupervisionTimeoutComplete(uint16_t link_supervision_timeout) override {
    SAVE_OR_CALL(OnReadLinkSupervisionTimeoutComplete, link_supervision_timeout)
  }
  void OnReadFailedContactCounterComplete(uint16_t failed_contact_counter) override {
    SAVE_OR_CALL(OnReadFailedContactCounterComplete, failed_contact_counter)
  }
  void OnReadLinkQualityComplete(uint8_t link_quality) override {
    SAVE_OR_CALL(OnReadLinkQualityComplete, link_quality)
  }
  void OnReadAfhChannelMapComplete(AfhMode afh_mode, std::array<uint8_t, 10> afh_channel_map) override {
    SAVE_OR_CALL(OnReadAfhChannelMapComplete, afh_mode, afh_channel_map)
  }
  void OnReadRssiComplete(uint8_t rssi) override {
    SAVE_OR_CALL(OnReadRssiComplete, rssi)
  }
  void OnReadClockComplete(uint32_t clock, uint16_t accuracy) override {
    SAVE_OR_CALL(OnReadClockComplete, clock, accuracy)
  }
  void OnMasterLinkKeyComplete(KeyFlag key_flag) override {
    SAVE_OR_CALL(OnMasterLinkKeyComplete, key_flag)
  }
  void OnRoleChange(Role new_role) override {
    SAVE_OR_CALL(OnRoleChange, new_role)
  }
  void OnDisconnection(ErrorCode reason) {
    SAVE_OR_CALL(OnDisconnection, reason);
  }
#undef SAVE_OR_CALL

  void on_role_discovery_complete(CommandCompleteView view) {
    auto complete_view = RoleDiscoveryCompleteView::Create(view);
    if (!complete_view.IsValid()) {
      LOG_ERROR("Received on_role_discovery_complete with invalid packet");
      return;
    } else if (complete_view.GetStatus() != ErrorCode::SUCCESS) {
      auto status = complete_view.GetStatus();
      std::string error_code = ErrorCodeText(status);
      LOG_ERROR("Received on_role_discovery_complete with error code %s", error_code.c_str());
      return;
    }
    OnRoleDiscoveryComplete(complete_view.GetCurrentRole());
  }

  void on_read_link_policy_settings_complete(CommandCompleteView view) {
    auto complete_view = ReadLinkPolicySettingsCompleteView::Create(view);
    if (!complete_view.IsValid()) {
      LOG_ERROR("Received on_read_link_policy_settings_complete with invalid packet");
      return;
    } else if (complete_view.GetStatus() != ErrorCode::SUCCESS) {
      auto status = complete_view.GetStatus();
      std::string error_code = ErrorCodeText(status);
      LOG_ERROR("Received on_read_link_policy_settings_complete with error code %s", error_code.c_str());
      return;
    }
    OnReadLinkPolicySettingsComplete(complete_view.GetLinkPolicySettings());
  }

  void on_read_automatic_flush_timeout_complete(CommandCompleteView view) {
    auto complete_view = ReadAutomaticFlushTimeoutCompleteView::Create(view);
    if (!complete_view.IsValid()) {
      LOG_ERROR("Received on_read_automatic_flush_timeout_complete with invalid packet");
      return;
    } else if (complete_view.GetStatus() != ErrorCode::SUCCESS) {
      auto status = complete_view.GetStatus();
      std::string error_code = ErrorCodeText(status);
      LOG_ERROR("Received on_read_automatic_flush_timeout_complete with error code %s", error_code.c_str());
      return;
    }
    OnReadAutomaticFlushTimeoutComplete(complete_view.GetFlushTimeout());
  }

  void on_read_transmit_power_level_complete(CommandCompleteView view) {
    auto complete_view = ReadTransmitPowerLevelCompleteView::Create(view);
    if (!complete_view.IsValid()) {
      LOG_ERROR("Received on_read_transmit_power_level_complete with invalid packet");
      return;
    } else if (complete_view.GetStatus() != ErrorCode::SUCCESS) {
      auto status = complete_view.GetStatus();
      std::string error_code = ErrorCodeText(status);
      LOG_ERROR("Received on_read_transmit_power_level_complete with error code %s", error_code.c_str());
      return;
    }
    OnReadTransmitPowerLevelComplete(complete_view.GetTransmitPowerLevel());
  }

  void on_read_link_supervision_timeout_complete(CommandCompleteView view) {
    auto complete_view = ReadLinkSupervisionTimeoutCompleteView::Create(view);
    if (!complete_view.IsValid()) {
      LOG_ERROR("Received on_read_link_supervision_timeout_complete with invalid packet");
      return;
    } else if (complete_view.GetStatus() != ErrorCode::SUCCESS) {
      auto status = complete_view.GetStatus();
      std::string error_code = ErrorCodeText(status);
      LOG_ERROR("Received on_read_link_supervision_timeout_complete with error code %s", error_code.c_str());
      return;
    }
    OnReadLinkSupervisionTimeoutComplete(complete_view.GetLinkSupervisionTimeout());
  }

  void on_read_failed_contact_counter_complete(CommandCompleteView view) {
    auto complete_view = ReadFailedContactCounterCompleteView::Create(view);
    if (!complete_view.IsValid()) {
      LOG_ERROR("Received on_read_failed_contact_counter_complete with invalid packet");
      return;
    } else if (complete_view.GetStatus() != ErrorCode::SUCCESS) {
      auto status = complete_view.GetStatus();
      std::string error_code = ErrorCodeText(status);
      LOG_ERROR("Received on_read_failed_contact_counter_complete with error code %s", error_code.c_str());
      return;
    }
    OnReadFailedContactCounterComplete(complete_view.GetFailedContactCounter());
  }

  void on_read_link_quality_complete(CommandCompleteView view) {
    auto complete_view = ReadLinkQualityCompleteView::Create(view);
    if (!complete_view.IsValid()) {
      LOG_ERROR("Received on_read_link_quality_complete with invalid packet");
      return;
    } else if (complete_view.GetStatus() != ErrorCode::SUCCESS) {
      auto status = complete_view.GetStatus();
      std::string error_code = ErrorCodeText(status);
      LOG_ERROR("Received on_read_link_quality_complete with error code %s", error_code.c_str());
      return;
    }
    OnReadLinkQualityComplete(complete_view.GetLinkQuality());
  }

  void on_read_afh_channel_map_complete(CommandCompleteView view) {
    auto complete_view = ReadAfhChannelMapCompleteView::Create(view);
    if (!complete_view.IsValid()) {
      LOG_ERROR("Received on_read_afh_channel_map_complete with invalid packet");
      return;
    } else if (complete_view.GetStatus() != ErrorCode::SUCCESS) {
      auto status = complete_view.GetStatus();
      std::string error_code = ErrorCodeText(status);
      LOG_ERROR("Received on_read_afh_channel_map_complete with error code %s", error_code.c_str());
      return;
    }
    OnReadAfhChannelMapComplete(complete_view.GetAfhMode(), complete_view.GetAfhChannelMap());
  }

  void on_read_rssi_complete(CommandCompleteView view) {
    auto complete_view = ReadRssiCompleteView::Create(view);
    if (!complete_view.IsValid()) {
      LOG_ERROR("Received on_read_rssi_complete with invalid packet");
      return;
    } else if (complete_view.GetStatus() != ErrorCode::SUCCESS) {
      auto status = complete_view.GetStatus();
      std::string error_code = ErrorCodeText(status);
      LOG_ERROR("Received on_read_rssi_complete with error code %s", error_code.c_str());
      return;
    }
    OnReadRssiComplete(complete_view.GetRssi());
  }

  void on_read_remote_version_information_status(CommandStatusView view) {
    ASSERT_LOG(view.IsValid(), "Bad status packet!");
    LOG_INFO("UNIMPLEMENTED called: %s", hci::ErrorCodeText(view.GetStatus()).c_str());
  }

  void on_read_remote_supported_features_status(CommandStatusView view) {
    ASSERT_LOG(view.IsValid(), "Bad status packet!");
    LOG_INFO("UNIMPLEMENTED called: %s", hci::ErrorCodeText(view.GetStatus()).c_str());
  }

  void on_read_remote_extended_features_status(CommandStatusView view) {
    ASSERT_LOG(view.IsValid(), "Broken");
    LOG_INFO("UNIMPLEMENTED called: %s", hci::ErrorCodeText(view.GetStatus()).c_str());
  }
  void on_read_clock_complete(CommandCompleteView view) {
    auto complete_view = ReadClockCompleteView::Create(view);
    if (!complete_view.IsValid()) {
      LOG_ERROR("Received on_read_clock_complete with invalid packet");
      return;
    } else if (complete_view.GetStatus() != ErrorCode::SUCCESS) {
      auto status = complete_view.GetStatus();
      std::string error_code = ErrorCodeText(status);
      LOG_ERROR("Received on_read_clock_complete with error code %s", error_code.c_str());
      return;
    }
    uint32_t clock = complete_view.GetClock();
    uint16_t accuracy = complete_view.GetAccuracy();
    OnReadClockComplete(clock, accuracy);
  }

  AclConnectionInterface* acl_connection_interface_;
  os::Handler* client_handler_ = nullptr;
  ConnectionManagementCallbacks* client_callbacks_ = nullptr;
  std::list<common::OnceClosure> queued_callbacks_;
};

class LeAclConnectionTracker : public LeConnectionManagementCallbacks {
 public:
  LeAclConnectionTracker(LeAclConnectionInterface* le_acl_connection_interface,
                         common::OnceCallback<void(DisconnectReason reason)> disconnect)
      : le_acl_connection_interface_(le_acl_connection_interface), do_disconnect_(std::move(disconnect)) {}
  ~LeAclConnectionTracker() override {
    ASSERT(queued_callbacks_.empty());
  }
  void RegisterCallbacks(LeConnectionManagementCallbacks* callbacks, os::Handler* handler) {
    while (!queued_callbacks_.empty()) {
      auto iter = queued_callbacks_.begin();
      handler->Post(std::move(*iter));
      queued_callbacks_.erase(iter);
    }
    client_handler_ = handler;
    client_callbacks_ = callbacks;
  }

#define SAVE_OR_CALL(f, ...)                                                                                        \
  if (client_handler_ == nullptr) {                                                                                 \
    queued_callbacks_.emplace_back(                                                                                 \
        common::BindOnce(&LeConnectionManagementCallbacks::f, common::Unretained(this), __VA_ARGS__));              \
  } else {                                                                                                          \
    client_handler_->Post(                                                                                          \
        common::BindOnce(&LeConnectionManagementCallbacks::f, common::Unretained(client_callbacks_), __VA_ARGS__)); \
  }

  void OnConnectionUpdate(uint16_t conn_interval, uint16_t conn_latency, uint16_t supervision_timeout) override {
    SAVE_OR_CALL(OnConnectionUpdate, conn_interval, conn_latency, supervision_timeout)
  }

  void OnDisconnection(ErrorCode reason) override {
    SAVE_OR_CALL(OnDisconnection, reason);
  }
#undef SAVE_OR_CALL

  LeAclConnectionInterface* le_acl_connection_interface_;
  common::OnceCallback<void(DisconnectReason)> do_disconnect_;
  os::Handler* client_handler_ = nullptr;
  LeConnectionManagementCallbacks* client_callbacks_ = nullptr;
  std::list<common::OnceClosure> queued_callbacks_;
};

struct AclManager::impl : public security::ISecurityManagerListener {
  impl(const AclManager& acl_manager) : acl_manager_(acl_manager) {}

  void Start() {
    hci_layer_ = acl_manager_.GetDependency<HciLayer>();
    handler_ = acl_manager_.GetHandler();
    controller_ = acl_manager_.GetDependency<Controller>();
    round_robin_scheduler_ = new RoundRobinScheduler(handler_, controller_, hci_layer_->GetAclQueueEnd());

    // TODO: determine when we should reject connection
    should_accept_connection_ = common::Bind([](Address, ClassOfDevice) { return true; });
    hci_queue_end_ = hci_layer_->GetAclQueueEnd();
    hci_queue_end_->RegisterDequeue(
        handler_, common::Bind(&impl::dequeue_and_route_acl_packet_to_connection, common::Unretained(this)));
    acl_connection_interface_ = hci_layer_->GetAclConnectionInterface(
        handler_->BindOn(this, &impl::on_classic_event), handler_->BindOn(this, &impl::on_classic_disconnect));
    le_acl_connection_interface_ = hci_layer_->GetLeAclConnectionInterface(
        handler_->BindOn(this, &impl::on_le_event), handler_->BindOn(this, &impl::on_le_disconnect));
    le_initiator_address_ =
        AddressWithType(Address{{0x00, 0x11, 0xFF, 0xFF, 0x33, 0x22}}, AddressType::RANDOM_DEVICE_ADDRESS);

    if (le_initiator_address_.GetAddressType() == AddressType::RANDOM_DEVICE_ADDRESS) {
      address_rotation_alarm_ = std::make_unique<os::Alarm>(handler_);
      RotateRandomAddress();
    }
  }

  void Stop() {
    for (auto event_code : AclConnectionEvents) {
      hci_layer_->UnregisterEventHandler(event_code);
    }
    for (auto subevent_code : LeConnectionManagementEvents) {
      hci_layer_->UnregisterLeEventHandler(subevent_code);
    }
    hci_queue_end_->UnregisterDequeue();
    delete round_robin_scheduler_;
    if (enqueue_registered_.exchange(false)) {
      hci_queue_end_->UnregisterEnqueue();
    }
    acl_connections_.clear();
    le_acl_connections_.clear();
    hci_queue_end_ = nullptr;
    handler_ = nullptr;
    hci_layer_ = nullptr;
    security_manager_.reset();

    // Address might have been already canceled if public address was used
    if (address_rotation_alarm_) {
      address_rotation_alarm_->Cancel();
      address_rotation_alarm_.reset();
    }
  }

  void on_classic_event(EventPacketView event_packet) {
    EventCode event_code = event_packet.GetEventCode();
    switch (event_code) {
      case EventCode::CONNECTION_COMPLETE:
        on_connection_complete(event_packet);
        break;
      case EventCode::CONNECTION_REQUEST:
        on_incoming_connection(event_packet);
        break;
      case EventCode::CONNECTION_PACKET_TYPE_CHANGED:
        on_connection_packet_type_changed(event_packet);
        break;
      case EventCode::AUTHENTICATION_COMPLETE:
        on_authentication_complete(event_packet);
        break;
      case EventCode::READ_CLOCK_OFFSET_COMPLETE:
        on_read_clock_offset_complete(event_packet);
        break;
      case EventCode::MODE_CHANGE:
        on_mode_change(event_packet);
        break;
      case EventCode::QOS_SETUP_COMPLETE:
        on_qos_setup_complete(event_packet);
        break;
      case EventCode::ROLE_CHANGE:
        on_role_change(event_packet);
        break;
      case EventCode::FLOW_SPECIFICATION_COMPLETE:
        on_flow_specification_complete(event_packet);
        break;
      case EventCode::FLUSH_OCCURRED:
        on_flush_occurred(event_packet);
        break;
      case EventCode::READ_REMOTE_SUPPORTED_FEATURES_COMPLETE:
        on_read_remote_supported_features_complete(event_packet);
        break;
      case EventCode::READ_REMOTE_EXTENDED_FEATURES_COMPLETE:
        on_read_remote_extended_features_complete(event_packet);
        break;
      case EventCode::READ_REMOTE_VERSION_INFORMATION_COMPLETE:
        on_read_remote_version_information_complete(event_packet);
        break;
      case EventCode::LINK_SUPERVISION_TIMEOUT_CHANGED:
        on_link_supervision_timeout_changed(event_packet);
        break;
      default:
        LOG_ALWAYS_FATAL("Unhandled event code %s", EventCodeText(event_code).c_str());
    }
  }

  void on_classic_disconnect(uint16_t handle, ErrorCode reason) {
    if (acl_connections_.count(handle) == 1) {
      auto& connection = acl_connections_.find(handle)->second;
      hci_layer_->GetHciHandler()->Post(
          common::BindOnce(&RoundRobinScheduler::SetDisconnect, common::Unretained(round_robin_scheduler_), handle));
      hci_layer_->GetHciHandler()->Post(
          common::BindOnce(&RoundRobinScheduler::Unregister, common::Unretained(round_robin_scheduler_), handle));
      connection.connection_management_callbacks_->OnDisconnection(reason);
      cleanup(handle);
    }
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
      default:
        LOG_ALWAYS_FATAL("Unhandled event code %s", SubeventCodeText(code).c_str());
    }
  }

  void on_le_disconnect(uint16_t handle, ErrorCode reason) {
    if (le_acl_connections_.count(handle) == 1) {
      auto& connection = le_acl_connections_.find(handle)->second;
      hci_layer_->GetHciHandler()->Post(
          common::BindOnce(&RoundRobinScheduler::SetDisconnect, common::Unretained(round_robin_scheduler_), handle));
      hci_layer_->GetHciHandler()->Post(
          common::BindOnce(&RoundRobinScheduler::Unregister, common::Unretained(round_robin_scheduler_), handle));
      connection.le_connection_management_callbacks_->OnDisconnection(reason);
      cleanup(handle);
    }
  }

  void handle_disconnect(uint16_t handle, DisconnectReason reason) {
    acl_connection_interface_->EnqueueCommand(hci::DisconnectBuilder::Create(handle, reason),
                                              handler_->BindOnce(&check_command_status<DisconnectStatusView>));
  }

  // Invoked from some external Queue Reactable context 2
  void dequeue_and_route_acl_packet_to_connection() {
    auto packet = hci_queue_end_->TryDequeue();
    ASSERT(packet != nullptr);
    if (!packet->IsValid()) {
      LOG_INFO("Dropping invalid packet of size %zu", packet->size());
      return;
    }
    uint16_t handle = packet->GetHandle();
    if (handle == kQualcommDebugHandle) {
      return;
    }
    auto connection_pair = acl_connections_.find(handle);
    if (connection_pair != acl_connections_.end()) {
      connection_pair->second.assembler_.on_incoming_packet(*packet);
    } else {
      auto le_connection_pair = le_acl_connections_.find(handle);
      if (le_connection_pair == le_acl_connections_.end()) {
        LOG_INFO("Dropping packet of size %zu to unknown connection 0x%0hx", packet->size(), handle);
        return;
      }
      le_connection_pair->second.assembler_.on_incoming_packet(*packet);
    }
  }

  void on_incoming_connection(EventPacketView packet) {
    ConnectionRequestView request = ConnectionRequestView::Create(packet);
    ASSERT(request.IsValid());
    Address address = request.GetBdAddr();
    if (client_callbacks_ == nullptr) {
      LOG_ERROR("No callbacks to call");
      auto reason = RejectConnectionReason::LIMITED_RESOURCES;
      this->reject_connection(RejectConnectionRequestBuilder::Create(address, reason));
      return;
    }
    connecting_.insert(address);
    if (is_classic_link_already_connected(address)) {
      auto reason = RejectConnectionReason::UNACCEPTABLE_BD_ADDR;
      this->reject_connection(RejectConnectionRequestBuilder::Create(address, reason));
    } else if (should_accept_connection_.Run(address, request.GetClassOfDevice())) {
      this->accept_connection(address);
    } else {
      auto reason = RejectConnectionReason::LIMITED_RESOURCES;  // TODO: determine reason
      this->reject_connection(RejectConnectionRequestBuilder::Create(address, reason));
    }
  }

  void on_classic_connection_complete(Address address) {
    auto connecting_addr = connecting_.find(address);
    if (connecting_addr == connecting_.end()) {
      LOG_WARN("No prior connection request for %s", address.ToString().c_str());
    } else {
      connecting_.erase(connecting_addr);
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
    AddressWithType local_address = le_initiator_address_;
    on_common_le_connection_complete(remote_address);
    if (status != ErrorCode::SUCCESS) {
      le_client_handler_->Post(common::BindOnce(&LeConnectionCallbacks::OnLeConnectFail,
                                                common::Unretained(le_client_callbacks_), remote_address, status));
      return;
    }
    // TODO: Check and save other connection parameters
    auto role = connection_complete.GetRole();
    uint16_t handle = connection_complete.GetConnectionHandle();
    ASSERT(le_acl_connections_.count(handle) == 0);
    auto queue = std::make_shared<AclConnection::Queue>(10);
    le_acl_connections_.emplace(std::piecewise_construct, std::forward_as_tuple(handle),
                                std::forward_as_tuple(remote_address, queue->GetDownEnd(), handler_));
    auto& connection_proxy = check_and_get_le_connection(handle);
    auto do_disconnect = common::BindOnce(&impl::handle_disconnect, common::Unretained(this), handle);
    hci_layer_->GetHciHandler()->Post(common::BindOnce(&RoundRobinScheduler::Register,
                                                       common::Unretained(round_robin_scheduler_),
                                                       RoundRobinScheduler::ConnectionType::LE, handle, queue));
    std::unique_ptr<LeAclConnection> connection(new LeAclConnection(std::move(queue), le_acl_connection_interface_,
                                                                    std::move(do_disconnect), handle, local_address,
                                                                    remote_address, role));
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
    AddressWithType local_address = le_initiator_address_;
    if (!peer_resolvable_address.IsEmpty()) {
      remote_address = AddressWithType(peer_resolvable_address, AddressType::RANDOM_DEVICE_ADDRESS);
    }
    on_common_le_connection_complete(remote_address);
    if (status != ErrorCode::SUCCESS) {
      le_client_handler_->Post(common::BindOnce(&LeConnectionCallbacks::OnLeConnectFail,
                                                common::Unretained(le_client_callbacks_), remote_address, status));
      return;
    }
    // TODO: Check and save other connection parameters
    uint16_t handle = connection_complete.GetConnectionHandle();
    ASSERT(acl_connections_.count(handle) == 0);
    auto queue = std::make_shared<AclConnection::Queue>(10);
    le_acl_connections_.emplace(std::piecewise_construct, std::forward_as_tuple(handle),
                                std::forward_as_tuple(remote_address, queue->GetDownEnd(), handler_));
    auto& connection_proxy = check_and_get_le_connection(handle);
    hci_layer_->GetHciHandler()->Post(common::BindOnce(&RoundRobinScheduler::Register,
                                                       common::Unretained(round_robin_scheduler_),
                                                       RoundRobinScheduler::ConnectionType::LE, handle, queue));
    auto role = connection_complete.GetRole();
    auto do_disconnect = common::BindOnce(&impl::handle_disconnect, common::Unretained(this), handle);
    std::unique_ptr<LeAclConnection> connection(new LeAclConnection(std::move(queue), le_acl_connection_interface_,
                                                                    std::move(do_disconnect), handle, local_address,
                                                                    remote_address, role));
    connection_proxy.le_connection_management_callbacks_ = connection->GetEventCallbacks();
    le_client_handler_->Post(common::BindOnce(&LeConnectionCallbacks::OnLeConnectSuccess,
                                              common::Unretained(le_client_callbacks_), remote_address,
                                              std::move(connection)));
  }

  void on_connection_complete(EventPacketView packet) {
    ConnectionCompleteView connection_complete = ConnectionCompleteView::Create(packet);
    ASSERT(connection_complete.IsValid());
    auto status = connection_complete.GetStatus();
    auto address = connection_complete.GetBdAddr();
    on_classic_connection_complete(address);
    if (status != ErrorCode::SUCCESS) {
      client_handler_->Post(common::BindOnce(&ConnectionCallbacks::OnConnectFail, common::Unretained(client_callbacks_),
                                             address, status));
      return;
    }
    uint16_t handle = connection_complete.GetConnectionHandle();
    ASSERT(acl_connections_.count(handle) == 0);
    auto queue = std::make_shared<AclConnection::Queue>(10);
    acl_connections_.emplace(std::piecewise_construct, std::forward_as_tuple(handle),
                             std::forward_as_tuple(AddressWithType{address, AddressType::PUBLIC_DEVICE_ADDRESS},
                                                   queue->GetDownEnd(), handler_));
    hci_layer_->GetHciHandler()->Post(common::BindOnce(&RoundRobinScheduler::Register,
                                                       common::Unretained(round_robin_scheduler_),
                                                       RoundRobinScheduler::ConnectionType::CLASSIC, handle, queue));
    std::unique_ptr<ClassicAclConnection> connection(new ClassicAclConnection(
        std::move(queue), acl_connection_interface_, handle, address, Role::MASTER /* TODO: Did we connect? */));
    auto& connection_proxy = check_and_get_connection(handle);
    connection_proxy.connection_management_callbacks_ = connection->GetEventCallbacks();
    client_handler_->Post(common::BindOnce(&ConnectionCallbacks::OnConnectSuccess,
                                           common::Unretained(client_callbacks_), std::move(connection)));
    while (!pending_outgoing_connections_.empty()) {
      auto create_connection_packet_and_address = std::move(pending_outgoing_connections_.front());
      pending_outgoing_connections_.pop();
      if (!is_classic_link_already_connected(create_connection_packet_and_address.first)) {
        connecting_.insert(create_connection_packet_and_address.first);
        acl_connection_interface_->EnqueueCommand(std::move(create_connection_packet_and_address.second),
                                                  handler_->BindOnce([](CommandStatusView status) {
                                                    ASSERT(status.IsValid());
                                                    ASSERT(status.GetCommandOpCode() == OpCode::CREATE_CONNECTION);
                                                  }));
        break;
      }
    }
  }

  void on_connection_packet_type_changed(EventPacketView packet) {
    ConnectionPacketTypeChangedView packet_type_changed = ConnectionPacketTypeChangedView::Create(packet);
    if (!packet_type_changed.IsValid()) {
      LOG_ERROR("Received on_connection_packet_type_changed with invalid packet");
      return;
    } else if (packet_type_changed.GetStatus() != ErrorCode::SUCCESS) {
      auto status = packet_type_changed.GetStatus();
      std::string error_code = ErrorCodeText(status);
      LOG_ERROR("Received on_connection_packet_type_changed with error code %s", error_code.c_str());
      return;
    }
    uint16_t handle = packet_type_changed.GetConnectionHandle();
    auto& acl_connection = acl_connections_.find(handle)->second;
    uint16_t packet_type = packet_type_changed.GetPacketType();
    acl_connection.connection_management_callbacks_->OnConnectionPacketTypeChanged(packet_type);
  }

  void on_master_link_key_complete(EventPacketView packet) {
    MasterLinkKeyCompleteView complete_view = MasterLinkKeyCompleteView::Create(packet);
    if (!complete_view.IsValid()) {
      LOG_ERROR("Received on_master_link_key_complete with invalid packet");
      return;
    } else if (complete_view.GetStatus() != ErrorCode::SUCCESS) {
      auto status = complete_view.GetStatus();
      std::string error_code = ErrorCodeText(status);
      LOG_ERROR("Received on_master_link_key_complete with error code %s", error_code.c_str());
      return;
    }
    uint16_t handle = complete_view.GetConnectionHandle();
    auto& acl_connection = acl_connections_.find(handle)->second;
    KeyFlag key_flag = complete_view.GetKeyFlag();
    acl_connection.connection_management_callbacks_->OnMasterLinkKeyComplete(key_flag);
  }

  void on_authentication_complete(EventPacketView packet) {
    AuthenticationCompleteView authentication_complete = AuthenticationCompleteView::Create(packet);
    if (!authentication_complete.IsValid()) {
      LOG_ERROR("Received on_authentication_complete with invalid packet");
      return;
    } else if (authentication_complete.GetStatus() != ErrorCode::SUCCESS) {
      auto status = authentication_complete.GetStatus();
      std::string error_code = ErrorCodeText(status);
      LOG_ERROR("Received on_authentication_complete with error code %s", error_code.c_str());
      return;
    }
    uint16_t handle = authentication_complete.GetConnectionHandle();
    auto& acl_connection = acl_connections_.find(handle)->second;
    acl_connection.connection_management_callbacks_->OnAuthenticationComplete();
  }

  void OnDeviceBonded(bluetooth::hci::AddressWithType device) override {}
  void OnDeviceUnbonded(bluetooth::hci::AddressWithType device) override {}
  void OnDeviceBondFailed(bluetooth::hci::AddressWithType device) override {}

  void OnEncryptionStateChanged(EncryptionChangeView encryption_change_view) override {
    if (!encryption_change_view.IsValid()) {
      LOG_ERROR("Received on_encryption_change with invalid packet");
      return;
    } else if (encryption_change_view.GetStatus() != ErrorCode::SUCCESS) {
      auto status = encryption_change_view.GetStatus();
      std::string error_code = ErrorCodeText(status);
      LOG_ERROR("Received on_change_connection_link_key_complete with error code %s", error_code.c_str());
      return;
    }
    uint16_t handle = encryption_change_view.GetConnectionHandle();
    auto& acl_connection = acl_connections_.find(handle)->second;
    EncryptionEnabled enabled = encryption_change_view.GetEncryptionEnabled();
    acl_connection.connection_management_callbacks_->OnEncryptionChange(enabled);
  }

  void on_change_connection_link_key_complete(EventPacketView packet) {
    ChangeConnectionLinkKeyCompleteView complete_view = ChangeConnectionLinkKeyCompleteView::Create(packet);
    if (!complete_view.IsValid()) {
      LOG_ERROR("Received on_change_connection_link_key_complete with invalid packet");
      return;
    } else if (complete_view.GetStatus() != ErrorCode::SUCCESS) {
      auto status = complete_view.GetStatus();
      std::string error_code = ErrorCodeText(status);
      LOG_ERROR("Received on_change_connection_link_key_complete with error code %s", error_code.c_str());
      return;
    }
    uint16_t handle = complete_view.GetConnectionHandle();
    auto& acl_connection = acl_connections_.find(handle)->second;
    acl_connection.connection_management_callbacks_->OnChangeConnectionLinkKeyComplete();
  }

  void on_read_clock_offset_complete(EventPacketView packet) {
    ReadClockOffsetCompleteView complete_view = ReadClockOffsetCompleteView::Create(packet);
    if (!complete_view.IsValid()) {
      LOG_ERROR("Received on_read_clock_offset_complete with invalid packet");
      return;
    } else if (complete_view.GetStatus() != ErrorCode::SUCCESS) {
      auto status = complete_view.GetStatus();
      std::string error_code = ErrorCodeText(status);
      LOG_ERROR("Received on_read_clock_offset_complete with error code %s", error_code.c_str());
      return;
    }
    uint16_t handle = complete_view.GetConnectionHandle();
    auto& acl_connection = acl_connections_.find(handle)->second;
    uint16_t clock_offset = complete_view.GetClockOffset();
    acl_connection.connection_management_callbacks_->OnReadClockOffsetComplete(clock_offset);
  }

  void on_mode_change(EventPacketView packet) {
    ModeChangeView mode_change_view = ModeChangeView::Create(packet);
    if (!mode_change_view.IsValid()) {
      LOG_ERROR("Received on_mode_change with invalid packet");
      return;
    } else if (mode_change_view.GetStatus() != ErrorCode::SUCCESS) {
      auto status = mode_change_view.GetStatus();
      std::string error_code = ErrorCodeText(status);
      LOG_ERROR("Received on_mode_change with error code %s", error_code.c_str());
      return;
    }
    uint16_t handle = mode_change_view.GetConnectionHandle();
    auto& acl_connection = acl_connections_.find(handle)->second;
    Mode current_mode = mode_change_view.GetCurrentMode();
    uint16_t interval = mode_change_view.GetInterval();
    acl_connection.connection_management_callbacks_->OnModeChange(current_mode, interval);
  }

  void on_qos_setup_complete(EventPacketView packet) {
    QosSetupCompleteView complete_view = QosSetupCompleteView::Create(packet);
    if (!complete_view.IsValid()) {
      LOG_ERROR("Received on_qos_setup_complete with invalid packet");
      return;
    } else if (complete_view.GetStatus() != ErrorCode::SUCCESS) {
      auto status = complete_view.GetStatus();
      std::string error_code = ErrorCodeText(status);
      LOG_ERROR("Received on_qos_setup_complete with error code %s", error_code.c_str());
      return;
    }
    uint16_t handle = complete_view.GetConnectionHandle();
    auto& acl_connection = acl_connections_.find(handle)->second;
    ServiceType service_type = complete_view.GetServiceType();
    uint32_t token_rate = complete_view.GetTokenRate();
    uint32_t peak_bandwidth = complete_view.GetPeakBandwidth();
    uint32_t latency = complete_view.GetLatency();
    uint32_t delay_variation = complete_view.GetDelayVariation();
    acl_connection.connection_management_callbacks_->OnQosSetupComplete(service_type, token_rate, peak_bandwidth,
                                                                        latency, delay_variation);
  }

  void on_role_change(EventPacketView packet) {
    RoleChangeView role_change_view = RoleChangeView::Create(packet);
    if (!role_change_view.IsValid()) {
      LOG_ERROR("Received on_role_change with invalid packet");
      return;
    } else if (role_change_view.GetStatus() != ErrorCode::SUCCESS) {
      auto status = role_change_view.GetStatus();
      std::string error_code = ErrorCodeText(status);
      LOG_ERROR("Received on_role_change with error code %s", error_code.c_str());
      return;
    }
    Address bd_addr = role_change_view.GetBdAddr();
    Role new_role = role_change_view.GetNewRole();
    for (auto& connection_pair : acl_connections_) {
      if (connection_pair.second.address_with_type_.GetAddress() == bd_addr) {
        connection_pair.second.connection_management_callbacks_->OnRoleChange(new_role);
      }
    }
  }

  void on_flow_specification_complete(EventPacketView packet) {
    FlowSpecificationCompleteView complete_view = FlowSpecificationCompleteView::Create(packet);
    if (!complete_view.IsValid()) {
      LOG_ERROR("Received on_flow_specification_complete with invalid packet");
      return;
    } else if (complete_view.GetStatus() != ErrorCode::SUCCESS) {
      auto status = complete_view.GetStatus();
      std::string error_code = ErrorCodeText(status);
      LOG_ERROR("Received on_flow_specification_complete with error code %s", error_code.c_str());
      return;
    }
    uint16_t handle = complete_view.GetConnectionHandle();
    auto& acl_connection = acl_connections_.find(handle)->second;
    FlowDirection flow_direction = complete_view.GetFlowDirection();
    ServiceType service_type = complete_view.GetServiceType();
    uint32_t token_rate = complete_view.GetTokenRate();
    uint32_t token_bucket_size = complete_view.GetTokenBucketSize();
    uint32_t peak_bandwidth = complete_view.GetPeakBandwidth();
    uint32_t access_latency = complete_view.GetAccessLatency();
    acl_connection.connection_management_callbacks_->OnFlowSpecificationComplete(
        flow_direction, service_type, token_rate, token_bucket_size, peak_bandwidth, access_latency);
  }

  void on_flush_occurred(EventPacketView packet) {
    FlushOccurredView flush_occurred_view = FlushOccurredView::Create(packet);
    if (!flush_occurred_view.IsValid()) {
      LOG_ERROR("Received on_flush_occurred with invalid packet");
      return;
    }
    uint16_t handle = flush_occurred_view.GetConnectionHandle();
    auto& acl_connection = acl_connections_.find(handle)->second;
    acl_connection.connection_management_callbacks_->OnFlushOccurred();
  }

  void on_read_remote_version_information_complete(EventPacketView packet) {
    auto view = ReadRemoteVersionInformationCompleteView::Create(packet);
    ASSERT_LOG(view.IsValid(), "Read remote version information packet invalid");
    LOG_INFO("UNIMPLEMENTED called");
  }

  void on_read_remote_supported_features_complete(EventPacketView packet) {
    auto view = ReadRemoteSupportedFeaturesCompleteView::Create(packet);
    ASSERT_LOG(view.IsValid(), "Read remote supported features packet invalid");
    LOG_INFO("UNIMPLEMENTED called");
  }

  void on_read_remote_extended_features_complete(EventPacketView packet) {
    auto view = ReadRemoteExtendedFeaturesCompleteView::Create(packet);
    ASSERT_LOG(view.IsValid(), "Read remote extended features packet invalid");
    LOG_INFO("UNIMPLEMENTED called");
  }

  void on_link_supervision_timeout_changed(EventPacketView packet) {
    auto view = LinkSupervisionTimeoutChangedView::Create(packet);
    ASSERT_LOG(view.IsValid(), "Link supervision timeout changed packet invalid");
    LOG_INFO("UNIMPLEMENTED called");
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

  bool is_classic_link_already_connected(Address address) {
    for (const auto& connection : acl_connections_) {
      if (connection.second.address_with_type_.GetAddress() == address) {
        return true;
      }
    }
    return false;
  }

  void create_connection(Address address) {
    // TODO: Configure default connection parameters?
    uint16_t packet_type = 0x4408 /* DM 1,3,5 */ | 0x8810 /*DH 1,3,5 */;
    PageScanRepetitionMode page_scan_repetition_mode = PageScanRepetitionMode::R1;
    uint16_t clock_offset = 0;
    ClockOffsetValid clock_offset_valid = ClockOffsetValid::INVALID;
    CreateConnectionRoleSwitch allow_role_switch = CreateConnectionRoleSwitch::ALLOW_ROLE_SWITCH;
    ASSERT(client_callbacks_ != nullptr);
    std::unique_ptr<CreateConnectionBuilder> packet = CreateConnectionBuilder::Create(
        address, packet_type, page_scan_repetition_mode, clock_offset, clock_offset_valid, allow_role_switch);

    if (connecting_.empty()) {
      if (is_classic_link_already_connected(address)) {
        LOG_WARN("already connected: %s", address.ToString().c_str());
        return;
      }
      connecting_.insert(address);
      acl_connection_interface_->EnqueueCommand(std::move(packet), handler_->BindOnce([](CommandStatusView status) {
        ASSERT(status.IsValid());
        ASSERT(status.GetCommandOpCode() == OpCode::CREATE_CONNECTION);
      }));
    } else {
      pending_outgoing_connections_.emplace(address, std::move(packet));
    }
  }

  std::chrono::milliseconds GetNextPrivateAddrressIntervalMs() {
    /* 7 minutes minimum, 15 minutes maximum for random address refreshing */
    const uint64_t interval_min_ms = (7 * 60 * 1000);
    const uint64_t interval_random_part_max_ms = (8 * 60 * 1000);

    return std::chrono::milliseconds(interval_min_ms + os::GenerateRandom() % interval_random_part_max_ms);
  }

  /* This function generates Resolvable Private Address (RPA) from Identity
   * Resolving Key |irk| and |prand|*/
  hci::Address GenerateRpa(const Octet16& irk, std::array<uint8_t, 8> prand) {
    /* most significant bit, bit7, bit6 is 01 to be resolvable random */
    constexpr uint8_t BLE_RESOLVE_ADDR_MSB = 0x40;
    constexpr uint8_t BLE_RESOLVE_ADDR_MASK = 0xc0;
    prand[2] &= (~BLE_RESOLVE_ADDR_MASK);
    prand[2] |= BLE_RESOLVE_ADDR_MSB;

    hci::Address address;
    address.address[3] = prand[0];
    address.address[4] = prand[1];
    address.address[5] = prand[2];

    /* encrypt with IRK */
    Octet16 p = crypto_toolbox::aes_128(irk, prand.data(), 3);

    /* set hash to be LSB of rpAddress */
    address.address[0] = p[0];
    address.address[1] = p[1];
    address.address[2] = p[2];
    return address;
  }

  void RotateRandomAddress() {
    // TODO: we must stop advertising, conection initiation, and scanning before calling SetRandomAddress.
    // TODO: ensure this is called before first connection initiation.
    // TODO: obtain proper IRK
    Octet16 irk = {} /* TODO: = BTM_GetDeviceIDRoot() */;
    std::array<uint8_t, 8> random = os::GenerateRandom<8>();
    hci::Address address = GenerateRpa(irk, random);

    hci_layer_->EnqueueCommand(hci::LeSetRandomAddressBuilder::Create(address),
                               handler_->BindOnce(check_command_complete<LeSetRandomAddressCompleteView>));

    le_initiator_address_ = AddressWithType(address, AddressType::RANDOM_DEVICE_ADDRESS);
    address_rotation_alarm_->Schedule(BindOnce(&impl::RotateRandomAddress, common::Unretained(this)),
                                      GetNextPrivateAddrressIntervalMs());
  }

  void create_le_connection(AddressWithType address_with_type) {
    // TODO: Add white list handling.
    // TODO: Configure default LE connection parameters?
    uint16_t le_scan_interval = 0x0060;
    uint16_t le_scan_window = 0x0030;
    InitiatorFilterPolicy initiator_filter_policy = InitiatorFilterPolicy::USE_PEER_ADDRESS;
    OwnAddressType own_address_type = static_cast<OwnAddressType>(le_initiator_address_.GetAddressType());
    uint16_t conn_interval_min = 0x0018;
    uint16_t conn_interval_max = 0x0028;
    uint16_t conn_latency = 0x0000;
    uint16_t supervision_timeout = 0x001f4;
    ASSERT(le_client_callbacks_ != nullptr);

    connecting_le_.insert(address_with_type);

    // TODO: make features check nicer, like HCI_LE_EXTENDED_ADVERTISING_SUPPORTED
    if (controller_->GetControllerLeLocalSupportedFeatures() & 0x0010) {
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

  void set_le_initiator_address(AddressWithType le_initiator_address) {
    le_initiator_address_ = le_initiator_address;

    if (le_initiator_address_.GetAddressType() != AddressType::RANDOM_DEVICE_ADDRESS) {
      // Usually controllers provide vendor-specific way to override public address. Implement it if it's ever needed.
      LOG_ALWAYS_FATAL("Don't know how to use this type of address");
    }

    if (address_rotation_alarm_) {
      address_rotation_alarm_->Cancel();
      address_rotation_alarm_.reset();
    }

    // TODO: we must stop advertising, conection initiation, and scanning before calling SetRandomAddress.
    hci_layer_->EnqueueCommand(hci::LeSetRandomAddressBuilder::Create(le_initiator_address_.GetAddress()),
                               handler_->BindOnce([](CommandCompleteView status) {}));
  }

  void cancel_connect(Address address) {
    auto connecting_addr = connecting_.find(address);
    if (connecting_addr == connecting_.end()) {
      LOG_INFO("Cannot cancel non-existent connection to %s", address.ToString().c_str());
      return;
    }
    std::unique_ptr<CreateConnectionCancelBuilder> packet = CreateConnectionCancelBuilder::Create(address);
    acl_connection_interface_->EnqueueCommand(std::move(packet),
                                              handler_->BindOnce([](CommandCompleteView complete) { /* TODO */ }));
  }

  void master_link_key(KeyFlag key_flag) {
    std::unique_ptr<MasterLinkKeyBuilder> packet = MasterLinkKeyBuilder::Create(key_flag);
    acl_connection_interface_->EnqueueCommand(std::move(packet),
                                              handler_->BindOnce(&check_command_status<MasterLinkKeyStatusView>));
  }

  void switch_role(Address address, Role role) {
    std::unique_ptr<SwitchRoleBuilder> packet = SwitchRoleBuilder::Create(address, role);
    acl_connection_interface_->EnqueueCommand(std::move(packet),
                                              handler_->BindOnce(&check_command_status<SwitchRoleStatusView>));
  }

  void write_default_link_policy_settings(uint16_t default_link_policy_settings) {
    std::unique_ptr<WriteDefaultLinkPolicySettingsBuilder> packet =
        WriteDefaultLinkPolicySettingsBuilder::Create(default_link_policy_settings);
    acl_connection_interface_->EnqueueCommand(
        std::move(packet), handler_->BindOnce(&check_command_complete<WriteDefaultLinkPolicySettingsCompleteView>));
  }

  void set_security_module(security::SecurityModule* security_module) {
    security_manager_ = security_module->GetSecurityManager();
    security_manager_->RegisterCallbackListener(this, handler_);
  }

  void accept_connection(Address address) {
    auto role = AcceptConnectionRequestRole::BECOME_MASTER;  // We prefer to be master
    acl_connection_interface_->EnqueueCommand(AcceptConnectionRequestBuilder::Create(address, role),
                                              handler_->BindOnceOn(this, &impl::on_accept_connection_status, address));
  }

  void cleanup(uint16_t handle) {
    if (acl_connections_.count(handle) == 1) {
      acl_connections_.erase(handle);
    } else {
      ASSERT(le_acl_connections_.count(handle) == 1);
      le_acl_connections_.erase(handle);
    }
  }

  void on_accept_connection_status(Address address, CommandStatusView status) {
    auto accept_status = AcceptConnectionRequestStatusView::Create(status);
    ASSERT(accept_status.IsValid());
    if (status.GetStatus() != ErrorCode::SUCCESS) {
      cancel_connect(address);
    }
  }

  void reject_connection(std::unique_ptr<RejectConnectionRequestBuilder> builder) {
    acl_connection_interface_->EnqueueCommand(std::move(builder),
                                              handler_->BindOnce([](CommandStatusView status) { /* TODO: check? */ }));
  }

  void handle_register_callbacks(ConnectionCallbacks* callbacks, os::Handler* handler) {
    ASSERT(client_callbacks_ == nullptr);
    ASSERT(client_handler_ == nullptr);
    client_callbacks_ = callbacks;
    client_handler_ = handler;
  }

  void handle_register_le_callbacks(LeConnectionCallbacks* callbacks, os::Handler* handler) {
    ASSERT(le_client_callbacks_ == nullptr);
    ASSERT(le_client_handler_ == nullptr);
    le_client_callbacks_ = callbacks;
    le_client_handler_ = handler;
  }

  acl_connection& check_and_get_connection(uint16_t handle) {
    auto connection = acl_connections_.find(handle);
    ASSERT(connection != acl_connections_.end());
    return connection->second;
  }

  le_acl_connection& check_and_get_le_connection(uint16_t handle) {
    auto connection = le_acl_connections_.find(handle);
    ASSERT(connection != le_acl_connections_.end());
    return connection->second;
  }

  const AclManager& acl_manager_;

  static constexpr uint16_t kMinimumCeLength = 0x0002;
  static constexpr uint16_t kMaximumCeLength = 0x0C00;

  Controller* controller_ = nullptr;

  HciLayer* hci_layer_ = nullptr;
  RoundRobinScheduler* round_robin_scheduler_ = nullptr;
  AclConnectionInterface* acl_connection_interface_ = nullptr;
  LeAclConnectionInterface* le_acl_connection_interface_ = nullptr;
  std::unique_ptr<security::SecurityManager> security_manager_;
  os::Handler* handler_ = nullptr;
  ConnectionCallbacks* client_callbacks_ = nullptr;
  os::Handler* client_handler_ = nullptr;
  LeConnectionCallbacks* le_client_callbacks_ = nullptr;
  os::Handler* le_client_handler_ = nullptr;
  common::BidiQueueEnd<AclPacketBuilder, AclPacketView>* hci_queue_end_ = nullptr;
  std::atomic_bool enqueue_registered_ = false;
  std::map<uint16_t, AclManager::acl_connection> acl_connections_;
  std::map<uint16_t, AclManager::le_acl_connection> le_acl_connections_;
  std::set<Address> connecting_;
  std::set<AddressWithType> connecting_le_;
  common::Callback<bool(Address, ClassOfDevice)> should_accept_connection_;
  std::queue<std::pair<Address, std::unique_ptr<CreateConnectionBuilder>>> pending_outgoing_connections_;
  uint16_t default_link_policy_settings_ = 0xffff;
  AddressWithType le_initiator_address_{Address{}, AddressType::RANDOM_DEVICE_ADDRESS};
  std::unique_ptr<os::Alarm> address_rotation_alarm_;
};

AclConnection::QueueUpEnd* AclConnection::GetAclQueueEnd() const {
  return queue_up_end_;
}

struct ClassicAclConnection::impl {
  impl(AclConnectionInterface* acl_connection_interface, std::shared_ptr<Queue> queue)
      : tracker(acl_connection_interface), queue_(std::move(queue)) {}
  ConnectionManagementCallbacks* GetEventCallbacks() {
    ASSERT(!callbacks_given_);
    callbacks_given_ = true;
    return &tracker;
  }

  bool callbacks_given_{false};
  AclConnectionTracker tracker;
  std::shared_ptr<Queue> queue_;
};

ClassicAclConnection::ClassicAclConnection()
    : AclConnection(), acl_connection_interface_(nullptr), address_(Address::kEmpty) {}

ClassicAclConnection::ClassicAclConnection(std::shared_ptr<Queue> queue,
                                           AclConnectionInterface* acl_connection_interface, uint16_t handle,
                                           Address address, Role role)
    : AclConnection(queue->GetUpEnd(), handle, Role::MASTER), acl_connection_interface_(acl_connection_interface),
      address_(address) {
  pimpl_ = new ClassicAclConnection::impl(acl_connection_interface, std::move(queue));
}

ClassicAclConnection::~ClassicAclConnection() {
  delete pimpl_;
}

ConnectionManagementCallbacks* ClassicAclConnection::GetEventCallbacks() {
  return pimpl_->GetEventCallbacks();
}

void ClassicAclConnection::RegisterCallbacks(ConnectionManagementCallbacks* callbacks, os::Handler* handler) {
  return pimpl_->tracker.RegisterCallbacks(callbacks, handler);
}

bool ClassicAclConnection::Disconnect(DisconnectReason reason) {
  acl_connection_interface_->EnqueueCommand(
      DisconnectBuilder::Create(handle_, reason),
      pimpl_->tracker.client_handler_->BindOnce([](CommandStatusView status) { /* TODO: check? */ }));
  return true;
}

bool ClassicAclConnection::ChangeConnectionPacketType(uint16_t packet_type) {
  acl_connection_interface_->EnqueueCommand(
      ChangeConnectionPacketTypeBuilder::Create(handle_, packet_type),
      pimpl_->tracker.client_handler_->BindOnce(&check_command_status<ChangeConnectionPacketTypeStatusView>));
  return true;
}

bool ClassicAclConnection::AuthenticationRequested() {
  acl_connection_interface_->EnqueueCommand(
      AuthenticationRequestedBuilder::Create(handle_),
      pimpl_->tracker.client_handler_->BindOnce(&check_command_status<AuthenticationRequestedStatusView>));
  return true;
}

bool ClassicAclConnection::SetConnectionEncryption(Enable enable) {
  acl_connection_interface_->EnqueueCommand(
      SetConnectionEncryptionBuilder::Create(handle_, enable),
      pimpl_->tracker.client_handler_->BindOnce(&check_command_status<SetConnectionEncryptionStatusView>));
  return true;
}

bool ClassicAclConnection::ChangeConnectionLinkKey() {
  acl_connection_interface_->EnqueueCommand(
      ChangeConnectionLinkKeyBuilder::Create(handle_),
      pimpl_->tracker.client_handler_->BindOnce(&check_command_status<ChangeConnectionLinkKeyStatusView>));
  return true;
}

bool ClassicAclConnection::ReadClockOffset() {
  acl_connection_interface_->EnqueueCommand(
      ReadClockOffsetBuilder::Create(handle_),
      pimpl_->tracker.client_handler_->BindOnce(&check_command_status<ReadClockOffsetStatusView>));
  return true;
}

bool ClassicAclConnection::HoldMode(uint16_t max_interval, uint16_t min_interval) {
  acl_connection_interface_->EnqueueCommand(
      HoldModeBuilder::Create(handle_, max_interval, min_interval),
      pimpl_->tracker.client_handler_->BindOnce(&check_command_status<HoldModeStatusView>));
  return true;
}

bool ClassicAclConnection::SniffMode(uint16_t max_interval, uint16_t min_interval, uint16_t attempt, uint16_t timeout) {
  acl_connection_interface_->EnqueueCommand(
      SniffModeBuilder::Create(handle_, max_interval, min_interval, attempt, timeout),
      pimpl_->tracker.client_handler_->BindOnce(&check_command_status<SniffModeStatusView>));
  return true;
}

bool ClassicAclConnection::ExitSniffMode() {
  acl_connection_interface_->EnqueueCommand(
      ExitSniffModeBuilder::Create(handle_),
      pimpl_->tracker.client_handler_->BindOnce(&check_command_status<ExitSniffModeStatusView>));
  return true;
}

bool ClassicAclConnection::QosSetup(ServiceType service_type, uint32_t token_rate, uint32_t peak_bandwidth,
                                    uint32_t latency, uint32_t delay_variation) {
  acl_connection_interface_->EnqueueCommand(
      QosSetupBuilder::Create(handle_, service_type, token_rate, peak_bandwidth, latency, delay_variation),
      pimpl_->tracker.client_handler_->BindOnce(&check_command_status<QosSetupStatusView>));
  return true;
}

bool ClassicAclConnection::RoleDiscovery() {
  acl_connection_interface_->EnqueueCommand(
      RoleDiscoveryBuilder::Create(handle_),
      pimpl_->tracker.client_handler_->BindOnceOn(&pimpl_->tracker, &AclConnectionTracker::on_role_discovery_complete));
  return true;
}

bool ClassicAclConnection::ReadLinkPolicySettings() {
  acl_connection_interface_->EnqueueCommand(
      ReadLinkPolicySettingsBuilder::Create(handle_),
      pimpl_->tracker.client_handler_->BindOnceOn(&pimpl_->tracker,
                                                  &AclConnectionTracker::on_read_link_policy_settings_complete));
  return true;
}

bool ClassicAclConnection::WriteLinkPolicySettings(uint16_t link_policy_settings) {
  acl_connection_interface_->EnqueueCommand(
      WriteLinkPolicySettingsBuilder::Create(handle_, link_policy_settings),
      pimpl_->tracker.client_handler_->BindOnce(&check_command_complete<WriteLinkPolicySettingsCompleteView>));
  return true;
}

bool ClassicAclConnection::FlowSpecification(FlowDirection flow_direction, ServiceType service_type,
                                             uint32_t token_rate, uint32_t token_bucket_size, uint32_t peak_bandwidth,
                                             uint32_t access_latency) {
  acl_connection_interface_->EnqueueCommand(
      FlowSpecificationBuilder::Create(handle_, flow_direction, service_type, token_rate, token_bucket_size,
                                       peak_bandwidth, access_latency),
      pimpl_->tracker.client_handler_->BindOnce(&check_command_status<FlowSpecificationStatusView>));
  return true;
}

bool ClassicAclConnection::SniffSubrating(uint16_t maximum_latency, uint16_t minimum_remote_timeout,
                                          uint16_t minimum_local_timeout) {
  acl_connection_interface_->EnqueueCommand(
      SniffSubratingBuilder::Create(handle_, maximum_latency, minimum_remote_timeout, minimum_local_timeout),
      pimpl_->tracker.client_handler_->BindOnce(&check_command_complete<SniffSubratingCompleteView>));
  return true;
}

bool ClassicAclConnection::Flush() {
  acl_connection_interface_->EnqueueCommand(
      FlushBuilder::Create(handle_),
      pimpl_->tracker.client_handler_->BindOnce(&check_command_complete<FlushCompleteView>));
  return true;
}

bool ClassicAclConnection::ReadAutomaticFlushTimeout() {
  acl_connection_interface_->EnqueueCommand(
      ReadAutomaticFlushTimeoutBuilder::Create(handle_),
      pimpl_->tracker.client_handler_->BindOnceOn(&pimpl_->tracker,
                                                  &AclConnectionTracker::on_read_automatic_flush_timeout_complete));
  return true;
}

bool ClassicAclConnection::WriteAutomaticFlushTimeout(uint16_t flush_timeout) {
  acl_connection_interface_->EnqueueCommand(
      WriteAutomaticFlushTimeoutBuilder::Create(handle_, flush_timeout),
      pimpl_->tracker.client_handler_->BindOnce(&check_command_complete<WriteAutomaticFlushTimeoutCompleteView>));
  return true;
}

bool ClassicAclConnection::ReadTransmitPowerLevel(TransmitPowerLevelType type) {
  acl_connection_interface_->EnqueueCommand(
      ReadTransmitPowerLevelBuilder::Create(handle_, type),
      pimpl_->tracker.client_handler_->BindOnceOn(&pimpl_->tracker,
                                                  &AclConnectionTracker::on_read_transmit_power_level_complete));
  return true;
}

bool ClassicAclConnection::ReadLinkSupervisionTimeout() {
  acl_connection_interface_->EnqueueCommand(
      ReadLinkSupervisionTimeoutBuilder::Create(handle_),
      pimpl_->tracker.client_handler_->BindOnceOn(&pimpl_->tracker,
                                                  &AclConnectionTracker::on_read_link_supervision_timeout_complete));
  return true;
}

bool ClassicAclConnection::WriteLinkSupervisionTimeout(uint16_t link_supervision_timeout) {
  acl_connection_interface_->EnqueueCommand(
      WriteLinkSupervisionTimeoutBuilder::Create(handle_, link_supervision_timeout),
      pimpl_->tracker.client_handler_->BindOnce(&check_command_complete<WriteLinkSupervisionTimeoutCompleteView>));
  return true;
}

bool ClassicAclConnection::ReadFailedContactCounter() {
  acl_connection_interface_->EnqueueCommand(
      ReadFailedContactCounterBuilder::Create(handle_),
      pimpl_->tracker.client_handler_->BindOnceOn(&pimpl_->tracker,
                                                  &AclConnectionTracker::on_read_failed_contact_counter_complete));
  return true;
}

bool ClassicAclConnection::ResetFailedContactCounter() {
  acl_connection_interface_->EnqueueCommand(
      ResetFailedContactCounterBuilder::Create(handle_),
      pimpl_->tracker.client_handler_->BindOnce([](CommandCompleteView view) { /* TODO: check? */ }));
  return true;
}

bool ClassicAclConnection::ReadLinkQuality() {
  acl_connection_interface_->EnqueueCommand(
      ReadLinkQualityBuilder::Create(handle_),
      pimpl_->tracker.client_handler_->BindOnceOn(&pimpl_->tracker,
                                                  &AclConnectionTracker::on_read_link_quality_complete));
  return true;
}

bool ClassicAclConnection::ReadAfhChannelMap() {
  acl_connection_interface_->EnqueueCommand(
      ReadAfhChannelMapBuilder::Create(handle_),
      pimpl_->tracker.client_handler_->BindOnceOn(&pimpl_->tracker,
                                                  &AclConnectionTracker::on_read_afh_channel_map_complete));
  return true;
}

bool ClassicAclConnection::ReadRssi() {
  acl_connection_interface_->EnqueueCommand(
      ReadRssiBuilder::Create(handle_),
      pimpl_->tracker.client_handler_->BindOnceOn(&pimpl_->tracker, &AclConnectionTracker::on_read_rssi_complete));
  return true;
}

bool ClassicAclConnection::ReadRemoteVersionInformation() {
  acl_connection_interface_->EnqueueCommand(
      ReadRemoteVersionInformationBuilder::Create(handle_),
      pimpl_->tracker.client_handler_->BindOnceOn(&pimpl_->tracker,
                                                  &AclConnectionTracker::on_read_remote_version_information_status));
  return true;
}

bool ClassicAclConnection::ReadRemoteSupportedFeatures() {
  acl_connection_interface_->EnqueueCommand(
      ReadRemoteSupportedFeaturesBuilder::Create(handle_),
      pimpl_->tracker.client_handler_->BindOnceOn(&pimpl_->tracker,
                                                  &AclConnectionTracker::on_read_remote_supported_features_status));
  return true;
}

bool ClassicAclConnection::ReadRemoteExtendedFeatures() {
  acl_connection_interface_->EnqueueCommand(
      ReadRemoteExtendedFeaturesBuilder::Create(handle_, 1),
      pimpl_->tracker.client_handler_->BindOnceOn(&pimpl_->tracker,
                                                  &AclConnectionTracker::on_read_remote_extended_features_status));
  return true;
}

bool ClassicAclConnection::ReadClock(WhichClock which_clock) {
  pimpl_->tracker.acl_connection_interface_->EnqueueCommand(
      ReadClockBuilder::Create(handle_, which_clock),
      pimpl_->tracker.client_handler_->BindOnceOn(&pimpl_->tracker, &AclConnectionTracker::on_read_clock_complete));
  return true;
}

struct LeAclConnection::impl {
  impl(LeAclConnectionInterface* le_acl_connection_interface, std::shared_ptr<Queue> queue,
       common::OnceCallback<void(DisconnectReason)> disconnect)
      : queue_(std::move(queue)), tracker(le_acl_connection_interface, std::move(disconnect)) {}
  LeConnectionManagementCallbacks* GetEventCallbacks() {
    ASSERT(!callbacks_given_);
    callbacks_given_ = true;
    return &tracker;
  }

  bool callbacks_given_{false};
  std::shared_ptr<Queue> queue_;
  LeAclConnectionTracker tracker;
};

LeAclConnection::LeAclConnection()
    : AclConnection(), local_address_(Address::kEmpty, AddressType::PUBLIC_DEVICE_ADDRESS),
      remote_address_(Address::kEmpty, AddressType::PUBLIC_DEVICE_ADDRESS) {}

LeAclConnection::LeAclConnection(std::shared_ptr<Queue> queue, LeAclConnectionInterface* le_acl_connection_interface,
                                 common::OnceCallback<void(DisconnectReason)> disconnect, uint16_t handle,
                                 AddressWithType local_address, AddressWithType remote_address, Role role)
    : AclConnection(queue->GetUpEnd(), handle, role), local_address_(local_address), remote_address_(remote_address) {
  pimpl_ = new LeAclConnection::impl(le_acl_connection_interface, std::move(queue), std::move(disconnect));
}

LeAclConnection::~LeAclConnection() {
  delete pimpl_;
  AclConnection::~AclConnection();
}

void LeAclConnection::RegisterCallbacks(LeConnectionManagementCallbacks* callbacks, os::Handler* handler) {
  return pimpl_->tracker.RegisterCallbacks(callbacks, handler);
}

void LeAclConnection::Disconnect(DisconnectReason reason) {
  common::BindOnce(std::move(pimpl_->tracker.do_disconnect_), reason).Run();
}

LeConnectionManagementCallbacks* LeAclConnection::GetEventCallbacks() {
  return pimpl_->GetEventCallbacks();
}

bool LeAclConnection::LeConnectionUpdate(uint16_t conn_interval_min, uint16_t conn_interval_max, uint16_t conn_latency,
                                         uint16_t supervision_timeout, uint16_t min_ce_length, uint16_t max_ce_length) {
  if (conn_interval_min < 0x0006 || conn_interval_min > 0x0C80 || conn_interval_max < 0x0006 ||
      conn_interval_max > 0x0C80 || conn_latency > 0x01F3 || supervision_timeout < 0x000A ||
      supervision_timeout > 0x0C80) {
    LOG_ERROR("Invalid parameter");
    return false;
  }
  pimpl_->tracker.le_acl_connection_interface_->EnqueueCommand(
      LeConnectionUpdateBuilder::Create(handle_, conn_interval_min, conn_interval_max, conn_latency,
                                        supervision_timeout, min_ce_length, max_ce_length),
      pimpl_->tracker.client_handler_->BindOnce([](CommandStatusView status) {
        ASSERT(status.IsValid());
        ASSERT(status.GetCommandOpCode() == OpCode::LE_CONNECTION_UPDATE);
      }));
  return true;
}

AclManager::AclManager() : pimpl_(std::make_unique<impl>(*this)) {}

void AclManager::RegisterCallbacks(ConnectionCallbacks* callbacks, os::Handler* handler) {
  ASSERT(callbacks != nullptr && handler != nullptr);
  GetHandler()->Post(common::BindOnce(&impl::handle_register_callbacks, common::Unretained(pimpl_.get()),
                                      common::Unretained(callbacks), common::Unretained(handler)));
}

void AclManager::RegisterLeCallbacks(LeConnectionCallbacks* callbacks, os::Handler* handler) {
  ASSERT(callbacks != nullptr && handler != nullptr);
  GetHandler()->Post(common::BindOnce(&impl::handle_register_le_callbacks, common::Unretained(pimpl_.get()),
                                      common::Unretained(callbacks), common::Unretained(handler)));
}

void AclManager::CreateConnection(Address address) {
  GetHandler()->Post(common::BindOnce(&impl::create_connection, common::Unretained(pimpl_.get()), address));
}

void AclManager::CreateLeConnection(AddressWithType address_with_type) {
  GetHandler()->Post(
      common::BindOnce(&impl::create_le_connection, common::Unretained(pimpl_.get()), address_with_type));
}

void AclManager::SetLeInitiatorAddress(AddressWithType initiator_address) {
  GetHandler()->Post(
      common::BindOnce(&impl::set_le_initiator_address, common::Unretained(pimpl_.get()), initiator_address));
}

void AclManager::CancelConnect(Address address) {
  GetHandler()->Post(BindOnce(&impl::cancel_connect, common::Unretained(pimpl_.get()), address));
}

void AclManager::MasterLinkKey(KeyFlag key_flag) {
  GetHandler()->Post(BindOnce(&impl::master_link_key, common::Unretained(pimpl_.get()), key_flag));
}

void AclManager::SwitchRole(Address address, Role role) {
  GetHandler()->Post(BindOnce(&impl::switch_role, common::Unretained(pimpl_.get()), address, role));
}

uint16_t AclManager::ReadDefaultLinkPolicySettings() {
  ASSERT_LOG(pimpl_->default_link_policy_settings_ != 0xffff, "Settings were never written");
  return pimpl_->default_link_policy_settings_;
}

void AclManager::WriteDefaultLinkPolicySettings(uint16_t default_link_policy_settings) {
  pimpl_->default_link_policy_settings_ = default_link_policy_settings;
  GetHandler()->Post(BindOnce(&impl::write_default_link_policy_settings, common::Unretained(pimpl_.get()),
                              default_link_policy_settings));
}

void AclManager::SetSecurityModule(security::SecurityModule* security_module) {
  GetHandler()->Post(BindOnce(&impl::set_security_module, common::Unretained(pimpl_.get()), security_module));
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

std::string AclManager::ToString() const {
  return "Acl Manager";
}

const ModuleFactory AclManager::Factory = ModuleFactory([]() { return new AclManager(); });

AclManager::~AclManager() = default;

}  // namespace hci
}  // namespace bluetooth
