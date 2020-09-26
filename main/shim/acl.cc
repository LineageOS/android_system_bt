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

#include <chrono>
#include <cstdint>
#include <map>
#include <memory>

#include "gd/hci/acl_manager.h"
#include "gd/hci/acl_manager/acl_connection.h"
#include "gd/hci/acl_manager/classic_acl_connection.h"
#include "gd/hci/acl_manager/connection_management_callbacks.h"
#include "gd/hci/acl_manager/le_acl_connection.h"
#include "gd/hci/acl_manager/le_connection_management_callbacks.h"

#include "gd/os/handler.h"
#include "gd/os/queue.h"
#include "main/shim/acl.h"
#include "main/shim/entry.h"
#include "main/shim/helpers.h"
#include "stack/include/acl_hci_link_interface.h"
#include "stack/include/ble_acl_interface.h"
#include "stack/include/btm_status.h"
#include "stack/include/sec_hci_link_interface.h"

using namespace bluetooth;

using HciHandle = uint16_t;
constexpr HciHandle kInvalidHciHandle = 0xffff;

class ShimAclConnection {
 public:
  ShimAclConnection(os::Handler* handler,
                    hci::acl_manager::AclConnection::QueueUpEnd* queue_up_end)
      : handler_(handler), queue_up_end_(queue_up_end) {}

  virtual ~ShimAclConnection() {
    ASSERT(queue_.empty());
    UnregisterEnqueue();
  }

  void EnqueuePacket(std::unique_ptr<bluetooth::packet::RawBuilder> packet) {
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

 protected:
  os::Handler* handler_;

 private:
  hci::acl_manager::AclConnection::QueueUpEnd* queue_up_end_;
  std::queue<std::unique_ptr<bluetooth::packet::RawBuilder>> queue_;
  bool is_enqueue_registered_{false};

  void RegisterEnqueue() {
    if (is_enqueue_registered_) return;
    is_enqueue_registered_ = true;
    queue_up_end_->RegisterEnqueue(
        handler_, common::Bind(&ShimAclConnection::handle_enqueue,
                               common::Unretained(this)));
  }

  void UnregisterEnqueue() {
    if (!is_enqueue_registered_) return;
    is_enqueue_registered_ = false;
    queue_up_end_->UnregisterEnqueue();
  }

  virtual void RegisterCallbacks() = 0;
};

class ClassicShimAclConnection
    : public ShimAclConnection,
      public hci::acl_manager::ConnectionManagementCallbacks {
 public:
  ClassicShimAclConnection(
      os::Handler* handler,
      std::unique_ptr<hci::acl_manager::ClassicAclConnection> connection)
      : ShimAclConnection(handler, connection->GetAclQueueEnd()),
        connection_(std::move(connection)) {}

  void RegisterCallbacks() override {
    connection_->RegisterCallbacks(this, handler_);
  }

  void OnConnectionPacketTypeChanged(uint16_t packet_type) override {
    LOG_INFO("%s UNIMPLEMENTED", __func__);
  }
  void OnAuthenticationComplete() override {
    LOG_INFO("%s UNIMPLEMENTED", __func__);
  }
  void OnEncryptionChange(hci::EncryptionEnabled enabled) override {
    LOG_INFO("%s UNIMPLEMENTED", __func__);
  }
  void OnChangeConnectionLinkKeyComplete() override {
    LOG_INFO("%s UNIMPLEMENTED", __func__);
  }
  void OnReadClockOffsetComplete(uint16_t clock_offset) override {
    LOG_INFO("%s UNIMPLEMENTED", __func__);
  }
  void OnModeChange(hci::Mode current_mode, uint16_t interval) override {
    LOG_INFO("%s UNIMPLEMENTED", __func__);
  }
  void OnQosSetupComplete(hci::ServiceType service_type, uint32_t token_rate,
                          uint32_t peak_bandwidth, uint32_t latency,
                          uint32_t delay_variation) override {
    LOG_INFO("%s UNIMPLEMENTED", __func__);
  }
  void OnFlowSpecificationComplete(hci::FlowDirection flow_direction,
                                   hci::ServiceType service_type,
                                   uint32_t token_rate,
                                   uint32_t token_bucket_size,
                                   uint32_t peak_bandwidth,
                                   uint32_t access_latency) override {
    LOG_INFO("%s UNIMPLEMENTED", __func__);
  }
  void OnFlushOccurred() override { LOG_INFO("%s UNIMPLEMENTED", __func__); }
  void OnRoleDiscoveryComplete(hci::Role current_role) override {
    LOG_INFO("%s UNIMPLEMENTED", __func__);
  }
  void OnReadLinkPolicySettingsComplete(
      uint16_t link_policy_settings) override {
    LOG_INFO("%s UNIMPLEMENTED", __func__);
  }
  void OnReadAutomaticFlushTimeoutComplete(uint16_t flush_timeout) override {
    LOG_INFO("%s UNIMPLEMENTED", __func__);
  }
  void OnReadTransmitPowerLevelComplete(uint8_t transmit_power_level) override {
    LOG_INFO("%s UNIMPLEMENTED", __func__);
  }
  void OnReadLinkSupervisionTimeoutComplete(
      uint16_t link_supervision_timeout) override {
    LOG_INFO("%s UNIMPLEMENTED", __func__);
  }
  void OnReadFailedContactCounterComplete(
      uint16_t failed_contact_counter) override {
    LOG_INFO("%s UNIMPLEMENTED", __func__);
  }
  void OnReadLinkQualityComplete(uint8_t link_quality) override {
    LOG_INFO("%s UNIMPLEMENTED", __func__);
  }
  void OnReadAfhChannelMapComplete(
      hci::AfhMode afh_mode, std::array<uint8_t, 10> afh_channel_map) override {
    LOG_INFO("%s UNIMPLEMENTED", __func__);
  }
  void OnReadRssiComplete(uint8_t rssi) override {
    LOG_INFO("%s UNIMPLEMENTED", __func__);
  }
  void OnReadClockComplete(uint32_t clock, uint16_t accuracy) override {
    LOG_INFO("%s UNIMPLEMENTED", __func__);
  }
  void OnMasterLinkKeyComplete(hci::KeyFlag key_flag) override {
    LOG_INFO("%s UNIMPLEMENTED", __func__);
  }
  void OnRoleChange(hci::Role new_role) override {
    LOG_INFO("%s UNIMPLEMENTED", __func__);
  }

  void OnDisconnection(hci::ErrorCode reason) override {
    btm_sec_disconnected(connection_->GetHandle(),
                         static_cast<uint8_t>(reason));
  }

  void OnReadRemoteVersionInformationComplete(uint8_t lmp_version,
                                              uint16_t manufacturer_name,
                                              uint16_t sub_version) override {
    LOG_DEBUG(
        "UNIMPLEMENTED lmp_version:%hhu manufacturer_name:%hu sub_version:%hu",
        lmp_version, manufacturer_name, sub_version);
  }

 private:
  std::unique_ptr<hci::acl_manager::ClassicAclConnection> connection_;
};

class LeShimAclConnection
    : public ShimAclConnection,
      public hci::acl_manager::LeConnectionManagementCallbacks {
 public:
  LeShimAclConnection(
      os::Handler* handler,
      std::unique_ptr<hci::acl_manager::LeAclConnection> connection)
      : ShimAclConnection(handler, connection->GetAclQueueEnd()),
        connection_(std::move(connection)) {}

  void RegisterCallbacks() override {
    connection_->RegisterCallbacks(this, handler_);
  }

  void OnConnectionUpdate(uint16_t connection_interval,
                          uint16_t connection_latency,
                          uint16_t supervision_timeout) {
    LOG_INFO("%s UNIMPLEMENTED", __func__);
  }
  void OnDataLengthChange(uint16_t tx_octets, uint16_t tx_time,
                          uint16_t rx_octets, uint16_t rx_time) {
    LOG_INFO("%s UNIMPLEMENTED", __func__);
  }
  void OnDisconnection(hci::ErrorCode reason) {
    LOG_INFO("%s UNIMPLEMENTED", __func__);
  }

 private:
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

bluetooth::shim::legacy::Acl::Acl(os::Handler* handler) : handler_(handler) {
  pimpl_ = std::make_unique<Acl::impl>();
  GetAclManager()->RegisterCallbacks(this, handler_);
  GetAclManager()->RegisterLeCallbacks(this, handler_);
}

bluetooth::shim::legacy::Acl::~Acl() {}

void bluetooth::shim::legacy::Acl::WriteData(
    HciHandle handle, std::unique_ptr<bluetooth::packet::RawBuilder> packet) {
  if (pimpl_->IsClassicAcl(handle)) {
    pimpl_->EnqueueClassicPacket(handle, std::move(packet));
  } else if (pimpl_->IsLeAcl(handle)) {
    pimpl_->EnqueueLePacket(handle, std::move(packet));
  } else {
    LOG_ERROR("%s Unable to find destination to write data\n", __func__);
  }
}

void bluetooth::shim::legacy::Acl::CreateClassicConnection(
    const bluetooth::hci::Address& address) {
  LOG_DEBUG("%s Initiate the creation of a classic connection %s", __func__,
            address.ToString().c_str());
  GetAclManager()->CreateConnection(address);
}

void bluetooth::shim::legacy::Acl::CreateLeConnection(
    const bluetooth::hci::AddressWithType& address_with_type) {
  LOG_DEBUG("%s Initiate the creation of a le connection %s", __func__,
            address_with_type.ToString().c_str());
  GetAclManager()->CreateLeConnection(address_with_type);
}

void bluetooth::shim::legacy::Acl::OnConnectSuccess(
    std::unique_ptr<hci::acl_manager::ClassicAclConnection> connection) {
  ASSERT(connection != nullptr);
  auto handle = connection->GetHandle();
  const RawAddress bd_addr = ToRawAddress(connection->GetAddress());

  pimpl_->handle_to_classic_connection_map_.emplace(
      handle, std::make_unique<ClassicShimAclConnection>(
                  handler_, std::move(connection)));
  pimpl_->handle_to_classic_connection_map_[handle]->RegisterCallbacks();

  LOG_DEBUG("%s Classic ACL created successfully peer:%s", __func__,
            bd_addr.ToString().c_str());
  btm_acl_connected(bd_addr, handle, HCI_SUCCESS, false);
}

void bluetooth::shim::legacy::Acl::OnConnectFail(hci::Address address,
                                                 hci::ErrorCode reason) {
  const RawAddress bd_addr = ToRawAddress(address);
  LOG_WARN("%s Unable to create classic ACL peer:%s", __func__,
           address.ToString().c_str());
  btm_acl_connected(bd_addr, kInvalidHciHandle, ToLegacyHciErrorCode(reason),
                    false);
}

void bluetooth::shim::legacy::Acl::OnLeConnectSuccess(
    hci::AddressWithType address_with_type,
    std::unique_ptr<hci::acl_manager::LeAclConnection> connection) {
  ASSERT(connection != nullptr);
  auto handle = connection->GetHandle();

  pimpl_->handle_to_le_connection_map_.emplace(
      handle,
      std::make_unique<LeShimAclConnection>(handler_, std::move(connection)));
  pimpl_->handle_to_le_connection_map_[handle]->RegisterCallbacks();

  LOG_DEBUG("%s Le ACL created successfully peer:%s", __func__,
            address_with_type.ToString().c_str());

  tBLE_BD_ADDR legacy_address_with_type =
      ToLegacyAddressWithType(address_with_type);

  uint8_t role = 0;   /* TODO Master */
  bool match = false; /* TODO Was address resolved with known record ? */

  uint16_t conn_interval{0}; /* TODO */
  uint16_t conn_latency{0};  /* TODO */
  uint16_t conn_timeout{0};  /* TODO */

  RawAddress local_rpa = legacy_address_with_type.bda; /* TODO enhanced */
  RawAddress peer_rpa = legacy_address_with_type.bda;  /* TODO enhanced */
  uint8_t peer_addr_type = 0;                          /* TODO public */

  acl_ble_enhanced_connection_complete(
      legacy_address_with_type, handle, role, match, conn_interval,
      conn_latency, conn_timeout, local_rpa, peer_rpa, peer_addr_type);
}

void bluetooth::shim::legacy::Acl::OnLeConnectFail(
    hci::AddressWithType address_with_type, hci::ErrorCode reason) {
  tBLE_BD_ADDR legacy_address_with_type =
      ToLegacyAddressWithType(address_with_type);

  uint16_t handle{0};  /* TODO Unneeded */
  bool enhanced{true}; /* TODO logging metrics only */
  uint8_t status = ToLegacyHciErrorCode(reason);

  acl_ble_connection_fail(legacy_address_with_type, handle, enhanced, status);
}
