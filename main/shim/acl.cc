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

#include "main/shim/acl.h"

#include <base/location.h>

#include <chrono>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>

#include "gd/common/bidi_queue.h"
#include "gd/common/bind.h"
#include "gd/hci/acl_manager.h"
#include "gd/hci/acl_manager/acl_connection.h"
#include "gd/hci/acl_manager/classic_acl_connection.h"
#include "gd/hci/acl_manager/connection_management_callbacks.h"
#include "gd/hci/acl_manager/le_acl_connection.h"
#include "gd/hci/acl_manager/le_connection_management_callbacks.h"
#include "gd/hci/controller.h"
#include "gd/os/handler.h"
#include "gd/os/queue.h"
#include "main/shim/entry.h"
#include "main/shim/helpers.h"
#include "stack/include/acl_hci_link_interface.h"
#include "stack/include/ble_acl_interface.h"
#include "stack/include/btm_status.h"
#include "stack/include/sec_hci_link_interface.h"

bt_status_t do_in_main_thread(const base::Location& from_here,
                              base::OnceClosure task);

using namespace bluetooth;

namespace {

using HciHandle = uint16_t;
using PageNumber = uint8_t;

constexpr PageNumber kRemoteExtendedFeaturesPageZero = 0;

using SendDataUpwards = void (*const)(BT_HDR*);
using OnDisconnect = std::function<void(HciHandle, hci::ErrorCode reason)>;

inline uint8_t LowByte(uint16_t val) { return val & 0xff; }
inline uint8_t HighByte(uint16_t val) { return val >> 8; }

void ValidateAclInterface(
    const bluetooth::shim::legacy::acl_interface_t& acl_interface) {
  ASSERT_LOG(acl_interface.on_send_data_upwards != nullptr,
             "Must provide to receive data on acl links");
  ASSERT_LOG(acl_interface.on_packets_completed != nullptr,
             "Must provide to receive completed packet indication");

  ASSERT_LOG(acl_interface.connection.classic.on_connected != nullptr,
             "Must provide to respond to successful classic connections");
  ASSERT_LOG(acl_interface.connection.classic.on_failed != nullptr,
             "Must provide to respond when classic connection attempts fail");
  ASSERT_LOG(
      acl_interface.connection.classic.on_disconnected != nullptr,
      "Must provide to respond when active classic connection disconnects");

  ASSERT_LOG(acl_interface.connection.le.on_connected != nullptr,
             "Must provide to respond to successful le connections");
  ASSERT_LOG(acl_interface.connection.le.on_failed != nullptr,
             "Must provide to respond when le connection attempts fail");
  ASSERT_LOG(acl_interface.connection.le.on_disconnected != nullptr,
             "Must provide to respond when active le connection disconnects");
}

}  // namespace

#define TRY_POSTING_ON_MAIN(cb, ...)                             \
  if (cb == nullptr) {                                           \
    LOG_WARN("Dropping ACL event with no callback");             \
  } else {                                                       \
    do_in_main_thread(FROM_HERE, base::Bind(cb, ##__VA_ARGS__)); \
  }

constexpr HciHandle kInvalidHciHandle = 0xffff;

class ShimAclConnection {
 public:
  ShimAclConnection(const HciHandle handle, SendDataUpwards send_data_upwards,
                    os::Handler* handler,
                    hci::acl_manager::AclConnection::QueueUpEnd* queue_up_end)
      : handle_(handle),
        handler_(handler),
        send_data_upwards_(send_data_upwards),
        queue_up_end_(queue_up_end) {
    queue_up_end_->RegisterDequeue(
        handler_, common::Bind(&ShimAclConnection::data_ready_callback,
                               common::Unretained(this)));
  }

  virtual ~ShimAclConnection() {
    ASSERT_LOG(queue_.empty(), "Shim ACL queue still has outgoing packets");
    ASSERT_LOG(is_disconnected_, "Shim Acl was not properly disconnected");
  }

  void EnqueuePacket(std::unique_ptr<bluetooth::packet::RawBuilder> packet) {
    // TODO Handle queue size exceeds some threshold
    queue_.push(std::move(packet));
    RegisterEnqueue();
  }

  std::unique_ptr<bluetooth::packet::BasePacketBuilder> handle_enqueue() {
    auto packet = std::move(queue_.front());
    queue_.pop();
    if (queue_.empty()) {
      UnregisterEnqueue();
    }
    return packet;
  }

  void data_ready_callback() {
    auto packet = queue_up_end_->TryDequeue();
    uint16_t length = packet->size();
    std::vector<uint8_t> preamble;
    preamble.push_back(LowByte(handle_));
    preamble.push_back(HighByte(handle_));
    preamble.push_back(LowByte(length));
    preamble.push_back(HighByte(length));
    BT_HDR* p_buf = MakeLegacyBtHdrPacket(std::move(packet), preamble);
    ASSERT_LOG(p_buf != nullptr, "Unable to allocate BT_HDR legacy packet");
    TRY_POSTING_ON_MAIN(send_data_upwards_, p_buf);
  }

 protected:
  const uint16_t handle_{kInvalidHciHandle};
  os::Handler* handler_;

  void UnregisterEnqueue() {
    if (!is_enqueue_registered_) return;
    is_enqueue_registered_ = false;
    queue_up_end_->UnregisterEnqueue();
  }

  void Disconnect() {
    ASSERT_LOG(!is_disconnected_, "Cannot disconnect multiple times");
    is_disconnected_ = true;
    UnregisterEnqueue();
    queue_up_end_->UnregisterDequeue();
  }

  virtual void ReadRemoteControllerInformation() = 0;

 private:
  SendDataUpwards send_data_upwards_;
  hci::acl_manager::AclConnection::QueueUpEnd* queue_up_end_;

  std::queue<std::unique_ptr<bluetooth::packet::RawBuilder>> queue_;
  bool is_enqueue_registered_{false};
  bool is_disconnected_{false};

  void RegisterEnqueue() {
    ASSERT_LOG(!is_disconnected_,
               "Unable to send data over disconnected channel");
    if (is_enqueue_registered_) return;
    is_enqueue_registered_ = true;
    queue_up_end_->RegisterEnqueue(
        handler_, common::Bind(&ShimAclConnection::handle_enqueue,
                               common::Unretained(this)));
  }

  virtual void RegisterCallbacks() = 0;
};

class ClassicShimAclConnection
    : public ShimAclConnection,
      public hci::acl_manager::ConnectionManagementCallbacks {
 public:
  ClassicShimAclConnection(
      SendDataUpwards send_data_upwards, OnDisconnect on_disconnect,
      const shim::legacy::acl_classic_link_interface_t& interface,
      os::Handler* handler,
      std::unique_ptr<hci::acl_manager::ClassicAclConnection> connection)
      : ShimAclConnection(connection->GetHandle(), send_data_upwards, handler,
                          connection->GetAclQueueEnd()),
        on_disconnect_(on_disconnect),
        interface_(interface),
        connection_(std::move(connection)) {}

  void RegisterCallbacks() override {
    connection_->RegisterCallbacks(this, handler_);
  }

  void ReadRemoteControllerInformation() override {
    connection_->ReadRemoteVersionInformation();
    connection_->ReadRemoteExtendedFeatures(kRemoteExtendedFeaturesPageZero);
  }

  void OnConnectionPacketTypeChanged(uint16_t packet_type) override {
    TRY_POSTING_ON_MAIN(interface_.on_packet_type_changed, packet_type);
  }

  void OnAuthenticationComplete() override {
    TRY_POSTING_ON_MAIN(interface_.on_authentication_complete, handle_,
                        ToLegacyHciErrorCode(hci::ErrorCode::SUCCESS));
  }

  void OnEncryptionChange(hci::EncryptionEnabled enabled) override {
    bool is_enabled = (enabled == hci::EncryptionEnabled::ON ||
                       enabled == hci::EncryptionEnabled::BR_EDR_AES_CCM);
    TRY_POSTING_ON_MAIN(interface_.on_encryption_change, is_enabled);
  }

  void OnChangeConnectionLinkKeyComplete() override {
    TRY_POSTING_ON_MAIN(interface_.on_change_connection_link_key_complete);
  }

  void OnReadClockOffsetComplete(uint16_t clock_offset) override {
    LOG_INFO("UNIMPLEMENTED");
  }

  void OnModeChange(hci::Mode current_mode, uint16_t interval) override {
    LOG_INFO("UNIMPLEMENTED");
  }

  void OnQosSetupComplete(hci::ServiceType service_type, uint32_t token_rate,
                          uint32_t peak_bandwidth, uint32_t latency,
                          uint32_t delay_variation) override {
    LOG_INFO("UNIMPLEMENTED");
  }

  void OnFlowSpecificationComplete(hci::FlowDirection flow_direction,
                                   hci::ServiceType service_type,
                                   uint32_t token_rate,
                                   uint32_t token_bucket_size,
                                   uint32_t peak_bandwidth,
                                   uint32_t access_latency) override {
    LOG_INFO("UNIMPLEMENTED");
  }

  void OnFlushOccurred() override { LOG_INFO("UNIMPLEMENTED"); }

  void OnRoleDiscoveryComplete(hci::Role current_role) override {
    LOG_INFO("UNIMPLEMENTED");
  }

  void OnReadLinkPolicySettingsComplete(
      uint16_t link_policy_settings) override {
    LOG_INFO("UNIMPLEMENTED");
  }

  void OnReadAutomaticFlushTimeoutComplete(uint16_t flush_timeout) override {
    LOG_INFO("UNIMPLEMENTED");
  }

  void OnReadTransmitPowerLevelComplete(uint8_t transmit_power_level) override {
    LOG_INFO("UNIMPLEMENTED");
  }

  void OnReadLinkSupervisionTimeoutComplete(
      uint16_t link_supervision_timeout) override {
    LOG_INFO("UNIMPLEMENTED");
  }

  void OnReadFailedContactCounterComplete(
      uint16_t failed_contact_counter) override {
    LOG_INFO("UNIMPLEMENTED");
  }

  void OnReadLinkQualityComplete(uint8_t link_quality) override {
    LOG_INFO("UNIMPLEMENTED");
  }

  void OnReadAfhChannelMapComplete(
      hci::AfhMode afh_mode, std::array<uint8_t, 10> afh_channel_map) override {
    LOG_INFO("UNIMPLEMENTED");
  }

  void OnReadRssiComplete(uint8_t rssi) override { LOG_INFO("UNIMPLEMENTED"); }

  void OnReadClockComplete(uint32_t clock, uint16_t accuracy) override {
    LOG_INFO("UNIMPLEMENTED");
  }

  void OnCentralLinkKeyComplete(hci::KeyFlag key_flag) override {
    LOG_INFO("%s UNIMPLEMENTED", __func__);
  }

  void OnRoleChange(hci::Role new_role) override {
    TRY_POSTING_ON_MAIN(interface_.on_role_change,
                        ToLegacyHciErrorCode(hci::ErrorCode::SUCCESS),
                        ToRawAddress(connection_->GetAddress()),
                        ToLegacyRole(new_role));
  }

  void OnDisconnection(hci::ErrorCode reason) override {
    Disconnect();
    on_disconnect_(handle_, reason);
  }

  void OnReadRemoteVersionInformationComplete(uint8_t lmp_version,
                                              uint16_t manufacturer_name,
                                              uint16_t sub_version) override {
    TRY_POSTING_ON_MAIN(interface_.on_read_remote_version_information_complete,
                        ToLegacyHciErrorCode(hci::ErrorCode::SUCCESS), handle_,
                        lmp_version, manufacturer_name, sub_version);
  }

  void OnReadRemoteExtendedFeaturesComplete(uint8_t page_number,
                                            uint8_t max_page_number,
                                            uint64_t features) override {
    TRY_POSTING_ON_MAIN(interface_.on_read_remote_extended_features_complete,
                        handle_, page_number, max_page_number, features);
    if (page_number != max_page_number)
      connection_->ReadRemoteExtendedFeatures(page_number + 1);
  }

 private:
  OnDisconnect on_disconnect_;
  const shim::legacy::acl_classic_link_interface_t interface_;
  std::unique_ptr<hci::acl_manager::ClassicAclConnection> connection_;
};

class LeShimAclConnection
    : public ShimAclConnection,
      public hci::acl_manager::LeConnectionManagementCallbacks {
 public:
  LeShimAclConnection(
      SendDataUpwards send_data_upwards, OnDisconnect on_disconnect,
      const shim::legacy::acl_le_link_interface_t& interface,
      os::Handler* handler,
      std::unique_ptr<hci::acl_manager::LeAclConnection> connection)
      : ShimAclConnection(connection->GetHandle(), send_data_upwards, handler,
                          connection->GetAclQueueEnd()),
        on_disconnect_(on_disconnect),
        interface_(interface),
        connection_(std::move(connection)) {}

  void RegisterCallbacks() override {
    connection_->RegisterCallbacks(this, handler_);
  }

  void ReadRemoteControllerInformation() override {
    // TODO Issue LeReadRemoteFeatures Command
  }

  void OnConnectionUpdate(uint16_t connection_interval,
                          uint16_t connection_latency,
                          uint16_t supervision_timeout) {
    TRY_POSTING_ON_MAIN(interface_.on_connection_update, connection_interval,
                        connection_latency, supervision_timeout);
  }
  void OnDataLengthChange(uint16_t tx_octets, uint16_t tx_time,
                          uint16_t rx_octets, uint16_t rx_time) {
    TRY_POSTING_ON_MAIN(interface_.on_data_length_change, tx_octets, tx_time,
                        rx_octets, rx_time);
  }

  void OnDisconnection(hci::ErrorCode reason) {
    Disconnect();
    on_disconnect_(handle_, reason);
  }

 private:
  OnDisconnect on_disconnect_;
  const shim::legacy::acl_le_link_interface_t interface_;
  std::unique_ptr<hci::acl_manager::LeAclConnection> connection_;
};

struct bluetooth::shim::legacy::Acl::impl {
  std::map<HciHandle, std::unique_ptr<ClassicShimAclConnection>>
      handle_to_classic_connection_map_;
  std::map<HciHandle, std::unique_ptr<LeShimAclConnection>>
      handle_to_le_connection_map_;

  bool IsClassicAcl(HciHandle handle) {
    return handle_to_classic_connection_map_.find(handle) !=
           handle_to_classic_connection_map_.end();
  }

  void EnqueueClassicPacket(
      HciHandle handle, std::unique_ptr<bluetooth::packet::RawBuilder> packet) {
    handle_to_classic_connection_map_[handle]->EnqueuePacket(std::move(packet));
  }

  bool IsLeAcl(HciHandle handle) {
    return handle_to_le_connection_map_.find(handle) !=
           handle_to_le_connection_map_.end();
  }

  void EnqueueLePacket(HciHandle handle,
                       std::unique_ptr<bluetooth::packet::RawBuilder> packet) {
    handle_to_le_connection_map_[handle]->EnqueuePacket(std::move(packet));
  }
};

bluetooth::shim::legacy::Acl::Acl(os::Handler* handler,
                                  const acl_interface_t& acl_interface)
    : handler_(handler), acl_interface_(acl_interface) {
  ValidateAclInterface(acl_interface_);
  pimpl_ = std::make_unique<Acl::impl>();
  GetAclManager()->RegisterCallbacks(this, handler_);
  GetAclManager()->RegisterLeCallbacks(this, handler_);
  GetController()->RegisterCompletedMonitorAclPacketsCallback(
      handler->BindOn(this, &Acl::on_incoming_acl_credits));

  // TODO(b/161543441): read the privacy policy from device-specific
  // configuration, and IRK from config file.
  hci::LeAddressManager::AddressPolicy address_policy =
      hci::LeAddressManager::AddressPolicy::USE_RESOLVABLE_ADDRESS;
  hci::AddressWithType empty_address_with_type(
      hci::Address{}, hci::AddressType::RANDOM_DEVICE_ADDRESS);
  crypto_toolbox::Octet16 rotation_irk = {0x44, 0xfb, 0x4b, 0x8d, 0x6c, 0x58,
                                          0x21, 0x0c, 0xf9, 0x3d, 0xda, 0xf1,
                                          0x64, 0xa3, 0xbb, 0x7f};
  /* 7 minutes minimum, 15 minutes maximum for random address refreshing */
  auto minimum_rotation_time = std::chrono::minutes(7);
  auto maximum_rotation_time = std::chrono::minutes(15);

  GetAclManager()->SetPrivacyPolicyForInitiatorAddress(
      address_policy, empty_address_with_type, rotation_irk,
      minimum_rotation_time, maximum_rotation_time);
}

bluetooth::shim::legacy::Acl::~Acl() {
  GetController()->UnregisterCompletedMonitorAclPacketsCallback();
}

void bluetooth::shim::legacy::Acl::on_incoming_acl_credits(uint16_t handle,
                                                           uint16_t credits) {
  TRY_POSTING_ON_MAIN(acl_interface_.on_packets_completed, handle, credits);
}

void bluetooth::shim::legacy::Acl::write_data_sync(
    HciHandle handle, std::unique_ptr<bluetooth::packet::RawBuilder> packet) {
  if (pimpl_->IsClassicAcl(handle)) {
    pimpl_->EnqueueClassicPacket(handle, std::move(packet));
  } else if (pimpl_->IsLeAcl(handle)) {
    pimpl_->EnqueueLePacket(handle, std::move(packet));
  } else {
    LOG_ERROR("Unable to find destination to write data\n");
  }
}

void bluetooth::shim::legacy::Acl::WriteData(
    HciHandle handle, std::unique_ptr<bluetooth::packet::RawBuilder> packet) {
  handler_->Post(common::BindOnce(&Acl::write_data_sync,
                                  common::Unretained(this), handle,
                                  std::move(packet)));
}

void bluetooth::shim::legacy::Acl::CreateClassicConnection(
    const bluetooth::hci::Address& address) {
  LOG_DEBUG("Initiate the creation of a classic connection %s",
            address.ToString().c_str());
  GetAclManager()->CreateConnection(address);
}

void bluetooth::shim::legacy::Acl::CreateLeConnection(
    const bluetooth::hci::AddressWithType& address_with_type) {
  GetAclManager()->AddDeviceToConnectList(address_with_type);
  GetAclManager()->CreateLeConnection(address_with_type);
  LOG_DEBUG("Started Le device to connection %s",
            address_with_type.ToString().c_str());
}

void bluetooth::shim::legacy::Acl::CancelLeConnection(
    const bluetooth::hci::AddressWithType& address_with_type) {
  LOG_DEBUG("Terminate and cancel a le connection %s",
            address_with_type.ToString().c_str());
  GetAclManager()->CancelLeConnect(address_with_type);
}

void bluetooth::shim::legacy::Acl::OnClassicLinkDisconnected(
    HciHandle handle, hci::ErrorCode reason) {
  tHCI_STATUS legacy_reason = ToLegacyHciErrorCode(reason);
  LOG_DEBUG("Classic link disconnected handle:%hu reason:%s", handle,
            hci_error_code_text(legacy_reason).c_str());
  TRY_POSTING_ON_MAIN(acl_interface_.connection.classic.on_disconnected,
                      ToLegacyHciErrorCode(hci::ErrorCode::SUCCESS), handle,
                      legacy_reason);
  pimpl_->handle_to_classic_connection_map_.erase(handle);
}

void bluetooth::shim::legacy::Acl::OnLeLinkDisconnected(HciHandle handle,
                                                        hci::ErrorCode reason) {
  tHCI_STATUS legacy_reason = ToLegacyHciErrorCode(reason);
  LOG_DEBUG("Le link disconnected handle:%hu reason:%s", handle,
            hci_error_code_text(legacy_reason).c_str());
  TRY_POSTING_ON_MAIN(acl_interface_.connection.le.on_disconnected,
                      ToLegacyHciErrorCode(hci::ErrorCode::SUCCESS), handle,
                      legacy_reason);
  pimpl_->handle_to_le_connection_map_.erase(handle);
}

void bluetooth::shim::legacy::Acl::OnConnectSuccess(
    std::unique_ptr<hci::acl_manager::ClassicAclConnection> connection) {
  ASSERT(connection != nullptr);
  auto handle = connection->GetHandle();
  const RawAddress bd_addr = ToRawAddress(connection->GetAddress());

  pimpl_->handle_to_classic_connection_map_.emplace(
      handle,
      std::make_unique<ClassicShimAclConnection>(
          acl_interface_.on_send_data_upwards,
          std::bind(&shim::legacy::Acl::OnClassicLinkDisconnected, this,
                    std::placeholders::_1, std::placeholders::_2),
          acl_interface_.link.classic, handler_, std::move(connection)));
  pimpl_->handle_to_classic_connection_map_[handle]->RegisterCallbacks();
  pimpl_->handle_to_classic_connection_map_[handle]
      ->ReadRemoteControllerInformation();

  TRY_POSTING_ON_MAIN(acl_interface_.connection.classic.on_connected, bd_addr,
                      handle, HCI_SUCCESS, false);
}

void bluetooth::shim::legacy::Acl::OnConnectFail(hci::Address address,
                                                 hci::ErrorCode reason) {
  const RawAddress bd_addr = ToRawAddress(address);
  LOG_WARN("Classic ACL connection failed peer:%s reason:%s",
           address.ToString().c_str(), hci::ErrorCodeText(reason).c_str());
  TRY_POSTING_ON_MAIN(acl_interface_.connection.classic.on_failed, bd_addr,
                      kInvalidHciHandle, HCI_SUCCESS, false);
}

void bluetooth::shim::legacy::Acl::OnLeConnectSuccess(
    hci::AddressWithType address_with_type,
    std::unique_ptr<hci::acl_manager::LeAclConnection> connection) {
  ASSERT(connection != nullptr);
  auto handle = connection->GetHandle();

  bluetooth::hci::Role connection_role = connection->GetRole();

  pimpl_->handle_to_le_connection_map_.emplace(
      handle, std::make_unique<LeShimAclConnection>(
                  acl_interface_.on_send_data_upwards,
                  std::bind(&shim::legacy::Acl::OnLeLinkDisconnected, this,
                            std::placeholders::_1, std::placeholders::_2),
                  acl_interface_.link.le, handler_, std::move(connection)));
  pimpl_->handle_to_le_connection_map_[handle]->RegisterCallbacks();

  pimpl_->handle_to_le_connection_map_[handle]
      ->ReadRemoteControllerInformation();

  tBLE_BD_ADDR legacy_address_with_type =
      ToLegacyAddressWithType(address_with_type);

  uint16_t conn_interval = 36; /* TODO Default to 45 msec*/
  uint16_t conn_latency = 0;   /* TODO Default to zero events */
  uint16_t conn_timeout = 500; /* TODO Default to 5s */

  RawAddress local_rpa = RawAddress::kEmpty;           /* TODO enhanced */
  RawAddress peer_rpa = RawAddress::kEmpty;            /* TODO enhanced */
  uint8_t peer_addr_type = 0;                          /* TODO public */

  TRY_POSTING_ON_MAIN(
      acl_interface_.connection.le.on_connected, legacy_address_with_type,
      handle, static_cast<uint8_t>(connection_role), conn_interval,
      conn_latency, conn_timeout, local_rpa, peer_rpa, peer_addr_type);
}

void bluetooth::shim::legacy::Acl::OnLeConnectFail(
    hci::AddressWithType address_with_type, hci::ErrorCode reason) {
  LOG_WARN("Le ACL failed peer:%s", address_with_type.ToString().c_str());

  tBLE_BD_ADDR legacy_address_with_type =
      ToLegacyAddressWithType(address_with_type);

  uint16_t handle = 0;  /* TODO Unneeded */
  bool enhanced = true; /* TODO logging metrics only */
  tHCI_STATUS status = ToLegacyHciErrorCode(reason);

  TRY_POSTING_ON_MAIN(acl_interface_.connection.le.on_failed,
                      legacy_address_with_type, handle, enhanced, status);
}
