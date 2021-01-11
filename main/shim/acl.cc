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
#include <base/strings/stringprintf.h>

#include <time.h>
#include <chrono>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <string>

#include "gd/common/bidi_queue.h"
#include "gd/common/bind.h"
#include "gd/common/strings.h"
#include "gd/hci/acl_manager.h"
#include "gd/hci/acl_manager/acl_connection.h"
#include "gd/hci/acl_manager/classic_acl_connection.h"
#include "gd/hci/acl_manager/connection_management_callbacks.h"
#include "gd/hci/acl_manager/le_acl_connection.h"
#include "gd/hci/acl_manager/le_connection_management_callbacks.h"
#include "gd/hci/controller.h"
#include "gd/os/handler.h"
#include "gd/os/queue.h"
#include "main/shim/dumpsys.h"
#include "main/shim/entry.h"
#include "main/shim/helpers.h"
#include "stack/acl/acl.h"
#include "stack/btm/btm_int_types.h"
#include "stack/include/acl_hci_link_interface.h"
#include "stack/include/ble_acl_interface.h"
#include "stack/include/btm_status.h"
#include "stack/include/sec_hci_link_interface.h"
#include "stack/l2cap/l2c_int.h"

extern tBTM_CB btm_cb;

bt_status_t do_in_main_thread(const base::Location& from_here,
                              base::OnceClosure task);

using namespace bluetooth;

namespace {

using HciHandle = uint16_t;
using PageNumber = uint8_t;

constexpr PageNumber kRemoteExtendedFeaturesPageZero = 0;
constexpr char kBtmLogTag[] = "ACL";

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
    ASSERT_LOG(is_disconnected_,
               "Shim Acl was not properly disconnected handle:0x%04x", handle_);
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

  virtual void InitiateDisconnect(hci::DisconnectReason reason) = 0;

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
    TRY_POSTING_ON_MAIN(interface_.on_mode_change,
                        ToLegacyHciErrorCode(hci::ErrorCode::SUCCESS), handle_,
                        ToLegacyHciMode(current_mode), interval);
  }

  void OnSniffSubrating(uint16_t maximum_transmit_latency,
                        uint16_t maximum_receive_latency,
                        uint16_t minimum_remote_timeout,
                        uint16_t minimum_local_timeout) {
    TRY_POSTING_ON_MAIN(interface_.on_sniff_subrating,
                        ToLegacyHciErrorCode(hci::ErrorCode::SUCCESS), handle_,
                        maximum_transmit_latency, maximum_receive_latency,
                        minimum_remote_timeout, minimum_local_timeout);
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
    BTM_LogHistory(kBtmLogTag, ToRawAddress(connection_->GetAddress()),
                   "Role change",
                   base::StringPrintf("classic new_role:%s",
                                      hci::RoleText(new_role).c_str()));
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

  hci::Address GetRemoteAddress() const { return connection_->GetAddress(); }

  void InitiateDisconnect(hci::DisconnectReason reason) override {
    connection_->Disconnect(reason);
  }

  void HoldMode(uint16_t max_interval, uint16_t min_interval) {
    ASSERT(connection_->HoldMode(max_interval, min_interval));
  }

  void SniffMode(uint16_t max_interval, uint16_t min_interval, uint16_t attempt,
                 uint16_t timeout) {
    ASSERT(
        connection_->SniffMode(max_interval, min_interval, attempt, timeout));
  }

  void ExitSniffMode() { ASSERT(connection_->ExitSniffMode()); }

  void SniffSubrating(uint16_t maximum_latency, uint16_t minimum_remote_timeout,
                      uint16_t minimum_local_timeout) {
    ASSERT(connection_->SniffSubrating(maximum_latency, minimum_remote_timeout,
                                       minimum_local_timeout));
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
    TRY_POSTING_ON_MAIN(interface_.on_connection_update,
                        ToLegacyHciErrorCode(hci::ErrorCode::SUCCESS), handle_,
                        connection_interval, connection_latency,
                        supervision_timeout);
  }
  void OnDataLengthChange(uint16_t tx_octets, uint16_t tx_time,
                          uint16_t rx_octets, uint16_t rx_time) {
    TRY_POSTING_ON_MAIN(interface_.on_data_length_change, tx_octets, tx_time,
                        rx_octets, rx_time);
  }

  void OnReadRemoteVersionInformationComplete(uint8_t lmp_version,
                                              uint16_t manufacturer_name,
                                              uint16_t sub_version) override {
    TRY_POSTING_ON_MAIN(interface_.on_read_remote_version_information_complete,
                        ToLegacyHciErrorCode(hci::ErrorCode::SUCCESS), handle_,
                        lmp_version, manufacturer_name, sub_version);
  }

  void OnDisconnection(hci::ErrorCode reason) {
    Disconnect();
    on_disconnect_(handle_, reason);
  }

  hci::AddressWithType GetRemoteAddressWithType() const {
    return connection_->GetRemoteAddress();
  }

  void InitiateDisconnect(hci::DisconnectReason reason) override {
    connection_->Disconnect(reason);
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

  bool ClassicConnectionExists(HciHandle handle) {
    return handle_to_classic_connection_map_.find(handle) !=
           handle_to_classic_connection_map_.end();
  }

  void EnqueueLePacket(HciHandle handle,
                       std::unique_ptr<bluetooth::packet::RawBuilder> packet) {
    if (ClassicConnectionExists(handle))
      handle_to_le_connection_map_[handle]->EnqueuePacket(std::move(packet));
  }

  void HoldMode(HciHandle handle, uint16_t max_interval,
                uint16_t min_interval) {
    if (ClassicConnectionExists(handle))
      handle_to_classic_connection_map_[handle]->HoldMode(max_interval,
                                                          min_interval);
  }

  void ExitSniffMode(HciHandle handle) {
    if (ClassicConnectionExists(handle))
      handle_to_classic_connection_map_[handle]->ExitSniffMode();
  }

  void SniffMode(HciHandle handle, uint16_t max_interval, uint16_t min_interval,
                 uint16_t attempt, uint16_t timeout) {
    if (ClassicConnectionExists(handle))
      handle_to_classic_connection_map_[handle]->SniffMode(
          max_interval, min_interval, attempt, timeout);
  }

  void SniffSubrating(HciHandle handle, uint16_t maximum_latency,
                      uint16_t minimum_remote_timeout,
                      uint16_t minimum_local_timeout) {
    if (ClassicConnectionExists(handle))
      handle_to_classic_connection_map_[handle]->SniffSubrating(
          maximum_latency, minimum_remote_timeout, minimum_local_timeout);
  }
};

#define DUMPSYS_TAG "shim::legacy::l2cap"
extern tL2C_CB l2cb;
void DumpsysL2cap(int fd) {
  LOG_DUMPSYS_TITLE(fd, DUMPSYS_TAG);
  for (int i = 0; i < MAX_L2CAP_LINKS; i++) {
    const tL2C_LCB& lcb = l2cb.lcb_pool[i];
    if (!lcb.in_use) continue;
    LOG_DUMPSYS(fd, "link_state:%s", link_state_text(lcb.link_state).c_str());
    LOG_DUMPSYS(fd, "handle:0x%04x", lcb.Handle());

    const tL2C_CCB* ccb = lcb.ccb_queue.p_first_ccb;
    while (ccb != nullptr) {
      LOG_DUMPSYS(
          fd, "  active channel lcid:0x%04x rcid:0x%04x is_ecoc:%s in_use:%s",
          ccb->local_cid, ccb->remote_cid, common::ToString(ccb->ecoc).c_str(),
          common::ToString(ccb->in_use).c_str());
      ccb = ccb->p_next_ccb;
    }
  }
}

#undef DUMPSYS_TAG
#define DUMPSYS_TAG "shim::legacy::acl"
void DumpsysAcl(int fd) {
  const tACL_CB& acl_cb = btm_cb.acl_cb_;

  LOG_DUMPSYS_TITLE(fd, DUMPSYS_TAG);

  for (int i = 0; i < MAX_L2CAP_LINKS; i++) {
    const tACL_CONN& acl_conn = acl_cb.acl_db[i];
    const tBTM_PM_MCB& btm_pm_mcb = acl_cb.pm_mode_db[i];
    if (!acl_conn.in_use) continue;

    LOG_DUMPSYS(fd, "    peer_le_features valid:%s data:%s",
                common::ToString(acl_conn.peer_le_features_valid).c_str(),
                bd_features_text(acl_conn.peer_le_features).c_str());
    for (int j = 0; j < HCI_EXT_FEATURES_PAGE_MAX + 1; j++) {
      LOG_DUMPSYS(fd, "    peer_lmp_features[%d] valid:%s data:%s", j,
                  common::ToString(acl_conn.peer_lmp_feature_valid[j]).c_str(),
                  bd_features_text(acl_conn.peer_lmp_feature_pages[j]).c_str());
    }
    LOG_DUMPSYS(fd, "      sniff_subrating:%s",
                common::ToString(HCI_SNIFF_SUB_RATE_SUPPORTED(
                                     acl_conn.peer_lmp_feature_pages[0]))
                    .c_str());

    LOG_DUMPSYS(fd, "remote_addr:%s", acl_conn.remote_addr.ToString().c_str());
    LOG_DUMPSYS(fd, "    handle:0x%04x", acl_conn.hci_handle);
    LOG_DUMPSYS(fd, "    [le] active_remote_addr:%s",
                acl_conn.active_remote_addr.ToString().c_str());
    LOG_DUMPSYS(fd, "    [le] conn_addr:%s",
                acl_conn.conn_addr.ToString().c_str());
    LOG_DUMPSYS(fd, "    link_up_issued:%s",
                (acl_conn.link_up_issued) ? "true" : "false");
    LOG_DUMPSYS(fd, "    transport:%s",
                BtTransportText(acl_conn.transport).c_str());
    LOG_DUMPSYS(fd, "    flush_timeout:0x%04x",
                acl_conn.flush_timeout_in_ticks);
    LOG_DUMPSYS(
        fd, "    [classic] link_policy:%s",
        link_policy_text(static_cast<tLINK_POLICY>(acl_conn.link_policy))
            .c_str());
    LOG_DUMPSYS(fd, "    link_supervision_timeout:%.3f sec",
                ticks_to_seconds(acl_conn.link_super_tout));
    LOG_DUMPSYS(fd, "    pkt_types_mask:0x%04x", acl_conn.pkt_types_mask);
    LOG_DUMPSYS(fd, "    disconnect_reason:0x%02x", acl_conn.disconnect_reason);
    LOG_DUMPSYS(fd, "    chg_ind:%s", (btm_pm_mcb.chg_ind) ? "true" : "false");
    LOG_DUMPSYS(fd, "    role:%s", RoleText(acl_conn.link_role).c_str());
    LOG_DUMPSYS(fd, "    power_mode_state:%s",
                power_mode_state_text(btm_pm_mcb.State()).c_str());
  }
}
#undef DUMPSYS_TAG

using Record = bluetooth::common::TimestampedEntry<std::string>;
const std::string kTimeFormat("%Y-%m-%d %H:%M:%S");

#define DUMPSYS_TAG "shim::legacy::btm"
void DumpsysBtm(int fd) {
  LOG_DUMPSYS_TITLE(fd, DUMPSYS_TAG);
  if (btm_cb.history_ != nullptr) {
    std::vector<Record> history = btm_cb.history_->Pull();
    for (auto& record : history) {
      time_t then = record.timestamp / 1000;
      struct tm tm;
      localtime_r(&then, &tm);
      auto s2 = common::StringFormatTime(kTimeFormat, tm);
      LOG_DUMPSYS(fd, " %s.%03u %s", s2.c_str(),
                  static_cast<unsigned int>(record.timestamp % 1000),
                  record.entry.c_str());
    }
  }
}
#undef DUMPSYS_TAG

#define DUMPSYS_TAG "shim::legacy::record"
void DumpsysRecord(int fd) {
  LOG_DUMPSYS_TITLE(fd, DUMPSYS_TAG);

  if (btm_cb.sec_dev_rec == nullptr) {
    LOG_DUMPSYS(fd, "Record is empty - no devices");
    return;
  }

  unsigned cnt = 0;
  list_node_t* end = list_end(btm_cb.sec_dev_rec);
  for (list_node_t* node = list_begin(btm_cb.sec_dev_rec); node != end;
       node = list_next(node)) {
    tBTM_SEC_DEV_REC* p_dev_rec =
        static_cast<tBTM_SEC_DEV_REC*>(list_node(node));

    LOG_DUMPSYS(fd, "%03u %s", ++cnt, p_dev_rec->ToString().c_str());
  }
}
#undef DUMPSYS_TAG

void bluetooth::shim::legacy::Acl::Dump(int fd) const {
  DumpsysRecord(fd);
  DumpsysAcl(fd);
  DumpsysL2cap(fd);
  DumpsysBtm(fd);
}

bluetooth::shim::legacy::Acl::Acl(os::Handler* handler,
                                  const acl_interface_t& acl_interface)
    : handler_(handler), acl_interface_(acl_interface) {
  ValidateAclInterface(acl_interface_);
  pimpl_ = std::make_unique<Acl::impl>();
  GetAclManager()->RegisterCallbacks(this, handler_);
  GetAclManager()->RegisterLeCallbacks(this, handler_);
  GetController()->RegisterCompletedMonitorAclPacketsCallback(
      handler->BindOn(this, &Acl::on_incoming_acl_credits));
  bluetooth::shim::RegisterDumpsysFunction(static_cast<void*>(this),
                                           [this](int fd) { Dump(fd); });
}

bluetooth::shim::legacy::Acl::~Acl() {
  bluetooth::shim::UnregisterDumpsysFunction(static_cast<void*>(this));
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
  GetAclManager()->CreateConnection(address);
  LOG_DEBUG("Connection initiated for classic to remote:%s",
            PRIVATE_ADDRESS(address));
  BTM_LogHistory(kBtmLogTag, ToRawAddress(address), "Initiated connection",
                 "classic");
}

void bluetooth::shim::legacy::Acl::CreateLeConnection(
    const bluetooth::hci::AddressWithType& address_with_type) {
  GetAclManager()->CreateLeConnection(address_with_type);
  LOG_DEBUG("Connection initiated for le connection to remote:%s",
            PRIVATE_ADDRESS(address_with_type));
  BTM_LogHistory(kBtmLogTag, ToLegacyAddressWithType(address_with_type),
                 "Initiated connection", "le");
}

void bluetooth::shim::legacy::Acl::CancelLeConnection(
    const bluetooth::hci::AddressWithType& address_with_type) {
  GetAclManager()->CancelLeConnect(address_with_type);
  LOG_DEBUG("Cancelled le connection to remote:%s",
            PRIVATE_ADDRESS(address_with_type));
  BTM_LogHistory(kBtmLogTag, ToLegacyAddressWithType(address_with_type),
                 "Cancelled connection", "le");
}

void bluetooth::shim::legacy::Acl::OnClassicLinkDisconnected(
    HciHandle handle, hci::ErrorCode reason) {
  bluetooth::hci::Address remote_address =
      pimpl_->handle_to_classic_connection_map_[handle]->GetRemoteAddress();
  pimpl_->handle_to_classic_connection_map_.erase(handle);
  TRY_POSTING_ON_MAIN(acl_interface_.connection.classic.on_disconnected,
                      ToLegacyHciErrorCode(hci::ErrorCode::SUCCESS), handle,
                      ToLegacyHciErrorCode(reason));
  LOG_DEBUG("Disconnected classic link remote:%s handle:%hu reason:%s",
            PRIVATE_ADDRESS(remote_address), handle,
            ErrorCodeText(reason).c_str());
  BTM_LogHistory(
      kBtmLogTag, ToRawAddress(remote_address), "Disconnected",
      base::StringPrintf("classic reason:%s", ErrorCodeText(reason).c_str()));
}

void bluetooth::shim::legacy::Acl::OnLeLinkDisconnected(HciHandle handle,
                                                        hci::ErrorCode reason) {
  hci::AddressWithType remote_address_with_type =
      pimpl_->handle_to_le_connection_map_[handle]->GetRemoteAddressWithType();
  pimpl_->handle_to_le_connection_map_.erase(handle);
  TRY_POSTING_ON_MAIN(acl_interface_.connection.le.on_disconnected,
                      ToLegacyHciErrorCode(hci::ErrorCode::SUCCESS), handle,
                      ToLegacyHciErrorCode(reason));
  LOG_DEBUG("Disconnected le link remote:%s handle:%hu reason:%s",
            PRIVATE_ADDRESS(remote_address_with_type), handle,
            ErrorCodeText(reason).c_str());
  BTM_LogHistory(
      kBtmLogTag, ToLegacyAddressWithType(remote_address_with_type),
      "Disconnected",
      base::StringPrintf("le reason:%s", ErrorCodeText(reason).c_str()));
}

void bluetooth::shim::legacy::Acl::OnConnectSuccess(
    std::unique_ptr<hci::acl_manager::ClassicAclConnection> connection) {
  ASSERT(connection != nullptr);
  auto handle = connection->GetHandle();
  bool locally_initiated = connection->locally_initiated_;
  const hci::Address remote_address = connection->GetAddress();
  const RawAddress bd_addr = ToRawAddress(remote_address);

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
  LOG_DEBUG("Connection successful classic remote:%s handle:%hu initiator:%s",
            PRIVATE_ADDRESS(remote_address), handle,
            (locally_initiated) ? "local" : "remote");
  BTM_LogHistory(kBtmLogTag, ToRawAddress(remote_address),
                 "Connection successful",
                 (locally_initiated) ? "Local initiated" : "Remote initiated");
}

void bluetooth::shim::legacy::Acl::OnConnectFail(hci::Address address,
                                                 hci::ErrorCode reason) {
  const RawAddress bd_addr = ToRawAddress(address);
  TRY_POSTING_ON_MAIN(acl_interface_.connection.classic.on_failed, bd_addr,
                      kInvalidHciHandle, ToLegacyHciErrorCode(reason), false);
  LOG_WARN("Connection failed classic remote:%s reason:%s",
           PRIVATE_ADDRESS(address), hci::ErrorCodeText(reason).c_str());
  BTM_LogHistory(kBtmLogTag, ToRawAddress(address), "Connection failed",
                 base::StringPrintf("classic reason:%s",
                                    hci::ErrorCodeText(reason).c_str()));
}

void bluetooth::shim::legacy::Acl::OnLeConnectSuccess(
    hci::AddressWithType address_with_type,
    std::unique_ptr<hci::acl_manager::LeAclConnection> connection) {
  ASSERT(connection != nullptr);
  auto handle = connection->GetHandle();

  bluetooth::hci::Role connection_role = connection->GetRole();
  bool locally_initiated = connection->locally_initiated_;

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

  LOG_DEBUG("Connection successful le remote:%s handle:%hu initiator:%s",
            PRIVATE_ADDRESS(address_with_type), handle,
            (locally_initiated) ? "local" : "remote");
  BTM_LogHistory(kBtmLogTag, ToLegacyAddressWithType(address_with_type),
                 "Connection successful", "le");
}

void bluetooth::shim::legacy::Acl::OnLeConnectFail(
    hci::AddressWithType address_with_type, hci::ErrorCode reason) {
  tBLE_BD_ADDR legacy_address_with_type =
      ToLegacyAddressWithType(address_with_type);

  uint16_t handle = 0;  /* TODO Unneeded */
  bool enhanced = true; /* TODO logging metrics only */
  tHCI_STATUS status = ToLegacyHciErrorCode(reason);

  TRY_POSTING_ON_MAIN(acl_interface_.connection.le.on_failed,
                      legacy_address_with_type, handle, enhanced, status);
  LOG_WARN("Connection failed le remote:%s",
           PRIVATE_ADDRESS(address_with_type));
  BTM_LogHistory(
      kBtmLogTag, ToLegacyAddressWithType(address_with_type),
      "Connection failed",
      base::StringPrintf("le reason:%s", hci::ErrorCodeText(reason).c_str()));
}

void bluetooth::shim::legacy::Acl::ConfigureLePrivacy(
    bool is_le_privacy_enabled) {
  LOG_INFO("Configuring Le privacy:%s",
           (is_le_privacy_enabled) ? "true" : "false");
  ASSERT_LOG(is_le_privacy_enabled,
             "Gd shim does not support unsecure le privacy");

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

void bluetooth::shim::legacy::Acl::DisconnectClassic(uint16_t handle,
                                                     tHCI_STATUS reason) {
  auto connection = pimpl_->handle_to_classic_connection_map_.find(handle);
  if (connection != pimpl_->handle_to_classic_connection_map_.end()) {
    auto remote_address = connection->second->GetRemoteAddress();
    connection->second->InitiateDisconnect(
        ToDisconnectReasonFromLegacy(reason));
    LOG_DEBUG("Disconnection initiated classic remote:%s handle:%hu",
              PRIVATE_ADDRESS(remote_address), handle);
    BTM_LogHistory(kBtmLogTag, ToRawAddress(remote_address),
                   "Disconnection initiated", "classic");
  } else {
    LOG_WARN("Unable to disconnect unknown classic connection handle:0x%04x",
             handle);
  }
}

void bluetooth::shim::legacy::Acl::DisconnectLe(uint16_t handle,
                                                tHCI_STATUS reason) {
  auto connection = pimpl_->handle_to_le_connection_map_.find(handle);
  if (connection != pimpl_->handle_to_le_connection_map_.end()) {
    auto remote_address_with_type =
        connection->second->GetRemoteAddressWithType();
    connection->second->InitiateDisconnect(
        ToDisconnectReasonFromLegacy(reason));
    LOG_DEBUG("Disconnection initiated le remote:%s handle:%hu",
              PRIVATE_ADDRESS(remote_address_with_type), handle);
    BTM_LogHistory(kBtmLogTag,
                   ToLegacyAddressWithType(remote_address_with_type),
                   "Disconnection initiated", "le");
  } else {
    LOG_WARN("Unable to disconnect unknown le connection handle:0x%04x",
             handle);
  }
}
bool bluetooth::shim::legacy::Acl::HoldMode(uint16_t hci_handle,
                                            uint16_t max_interval,
                                            uint16_t min_interval) {
  handler_->CallOn(pimpl_.get(), &Acl::impl::HoldMode, hci_handle, max_interval,
                   min_interval);
  return false;  // TODO void
}

bool bluetooth::shim::legacy::Acl::SniffMode(uint16_t hci_handle,
                                             uint16_t max_interval,
                                             uint16_t min_interval,
                                             uint16_t attempt,
                                             uint16_t timeout) {
  handler_->CallOn(pimpl_.get(), &Acl::impl::SniffMode, hci_handle,
                   max_interval, min_interval, attempt, timeout);
  return false;
}

bool bluetooth::shim::legacy::Acl::ExitSniffMode(uint16_t hci_handle) {
  handler_->CallOn(pimpl_.get(), &Acl::impl::ExitSniffMode, hci_handle);
  return false;
}

bool bluetooth::shim::legacy::Acl::SniffSubrating(
    uint16_t hci_handle, uint16_t maximum_latency,
    uint16_t minimum_remote_timeout, uint16_t minimum_local_timeout) {
  handler_->CallOn(pimpl_.get(), &Acl::impl::SniffSubrating, hci_handle,
                   maximum_latency, minimum_remote_timeout,
                   minimum_local_timeout);
  return false;
}
