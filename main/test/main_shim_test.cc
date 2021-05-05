/*
 *  Copyright 2021 The Android Open Source Project
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at:
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <condition_variable>
#include <future>
#include <map>
#include <thread>

#include "btif/include/btif_hh.h"
#include "device/include/controller.h"
#include "gd/btaa/activity_attribution.h"
#include "gd/hal/hci_hal.h"
#include "gd/hci/acl_manager_mock.h"
#include "gd/hci/controller_mock.h"
#include "gd/module.h"
#include "gd/os/mock_queue.h"
#include "gd/os/queue.h"
#include "gd/packet/packet_view.h"
#include "hci/acl_manager.h"
#include "hci/acl_manager/classic_acl_connection.h"
#include "hci/acl_manager/connection_callbacks.h"
#include "hci/acl_manager/connection_management_callbacks.h"
#include "hci/acl_manager/le_acl_connection.h"
#include "hci/acl_manager/le_connection_callbacks.h"
#include "hci/acl_manager/le_connection_management_callbacks.h"
#include "hci/include/hci_layer.h"
#include "hci/include/hci_packet_factory.h"
#include "hci/include/hci_packet_parser.h"
#include "hci/include/packet_fragmenter.h"
#include "include/hardware/bt_activity_attribution.h"
#include "main/shim/acl.h"
#include "main/shim/acl_legacy_interface.h"
#include "main/shim/helpers.h"
#include "os/handler.h"
#include "os/thread.h"
#include "stack/btm/btm_int_types.h"
#include "stack/include/btu.h"
#include "stack/l2cap/l2c_int.h"
#include "test/common/main_handler.h"
#include "test/mock/mock_main_shim_entry.h"

using namespace bluetooth;
using namespace testing;

namespace test = bluetooth::hci::testing;

const uint8_t kMaxLeAcceptlistSize = 16;
std::map<std::string, int> mock_function_count_map;
tL2C_CB l2cb;
tBTM_CB btm_cb;
btif_hh_cb_t btif_hh_cb;

namespace {
std::map<std::string, std::promise<uint16_t>> mock_function_handle_promise_map;
}

uint8_t mock_get_ble_acceptlist_size() { return 123; }

struct controller_t mock_controller {
  .get_ble_acceptlist_size = mock_get_ble_acceptlist_size,
};

const controller_t* controller_get_interface() { return &mock_controller; }

void mock_on_send_data_upwards(BT_HDR*) { mock_function_count_map[__func__]++; }

void mock_on_packets_completed(uint16_t handle, uint16_t num_packets) {
  mock_function_count_map[__func__]++;
}

void mock_connection_classic_on_connected(const RawAddress& bda,
                                          uint16_t handle, uint8_t enc_mode) {
  mock_function_count_map[__func__]++;
}

void mock_connection_classic_on_failed(const RawAddress& bda,
                                       tHCI_STATUS status) {
  mock_function_count_map[__func__]++;
}

void mock_connection_classic_on_disconnected(tHCI_STATUS status,
                                             uint16_t handle,
                                             tHCI_STATUS reason) {
  mock_function_count_map[__func__]++;
  ASSERT_TRUE(mock_function_handle_promise_map.find(__func__) !=
              mock_function_handle_promise_map.end());
  mock_function_handle_promise_map[__func__].set_value(handle);
}
void mock_connection_le_on_connected(
    const tBLE_BD_ADDR& address_with_type, uint16_t handle, tHCI_ROLE role,
    uint16_t conn_interval, uint16_t conn_latency, uint16_t conn_timeout,
    const RawAddress& local_rpa, const RawAddress& peer_rpa,
    uint8_t peer_addr_type) {
  mock_function_count_map[__func__]++;
}
void mock_connection_le_on_failed(const tBLE_BD_ADDR& address_with_type,
                                  uint16_t handle, bool enhanced,
                                  tHCI_STATUS status) {
  mock_function_count_map[__func__]++;
}
void mock_connection_le_on_disconnected(tHCI_STATUS status, uint16_t handle,
                                        tHCI_STATUS reason) {
  mock_function_count_map[__func__]++;
}

const shim::legacy::acl_interface_t GetMockAclInterface() {
  shim::legacy::acl_interface_t acl_interface{
      .on_send_data_upwards = mock_on_send_data_upwards,
      .on_packets_completed = mock_on_packets_completed,

      .connection.classic.on_connected = mock_connection_classic_on_connected,
      .connection.classic.on_failed = mock_connection_classic_on_failed,
      .connection.classic.on_disconnected =
          mock_connection_classic_on_disconnected,

      .connection.le.on_connected = mock_connection_le_on_connected,
      .connection.le.on_failed = mock_connection_le_on_failed,
      .connection.le.on_disconnected = mock_connection_le_on_disconnected,

      .connection.sco.on_esco_connect_request = nullptr,
      .connection.sco.on_sco_connect_request = nullptr,
      .connection.sco.on_disconnected = nullptr,

      .link.classic.on_authentication_complete = nullptr,
      .link.classic.on_central_link_key_complete = nullptr,
      .link.classic.on_change_connection_link_key_complete = nullptr,
      .link.classic.on_encryption_change = nullptr,
      .link.classic.on_flow_specification_complete = nullptr,
      .link.classic.on_flush_occurred = nullptr,
      .link.classic.on_mode_change = nullptr,
      .link.classic.on_packet_type_changed = nullptr,
      .link.classic.on_qos_setup_complete = nullptr,
      .link.classic.on_read_afh_channel_map_complete = nullptr,
      .link.classic.on_read_automatic_flush_timeout_complete = nullptr,
      .link.classic.on_sniff_subrating = nullptr,
      .link.classic.on_read_clock_complete = nullptr,
      .link.classic.on_read_clock_offset_complete = nullptr,
      .link.classic.on_read_failed_contact_counter_complete = nullptr,
      .link.classic.on_read_link_policy_settings_complete = nullptr,
      .link.classic.on_read_link_quality_complete = nullptr,
      .link.classic.on_read_link_supervision_timeout_complete = nullptr,
      .link.classic.on_read_remote_version_information_complete = nullptr,
      .link.classic.on_read_remote_extended_features_complete = nullptr,
      .link.classic.on_read_rssi_complete = nullptr,
      .link.classic.on_read_transmit_power_level_complete = nullptr,
      .link.classic.on_role_change = nullptr,
      .link.classic.on_role_discovery_complete = nullptr,

      .link.le.on_connection_update = nullptr,
      .link.le.on_data_length_change = nullptr,
      .link.le.on_read_remote_version_information_complete = nullptr,
  };
  return acl_interface;
}

const hci_packet_factory_t* hci_packet_factory_get_interface() {
  return nullptr;
}
const hci_packet_parser_t* hci_packet_parser_get_interface() { return nullptr; }
const hci_t* hci_layer_get_interface() { return nullptr; }
const packet_fragmenter_t* packet_fragmenter_get_interface() { return nullptr; }
void LogMsg(uint32_t trace_set_mask, const char* fmt_str, ...) {}

template <typename T>
class MockEnQueue : public os::IQueueEnqueue<T> {
  using EnqueueCallback = base::Callback<std::unique_ptr<T>()>;

  void RegisterEnqueue(os::Handler* handler,
                       EnqueueCallback callback) override {}
  void UnregisterEnqueue() override {}
};

template <typename T>
class MockDeQueue : public os::IQueueDequeue<T> {
  using DequeueCallback = base::Callback<void()>;

  void RegisterDequeue(os::Handler* handler,
                       DequeueCallback callback) override {}
  void UnregisterDequeue() override {}
  std::unique_ptr<T> TryDequeue() override { return nullptr; }
};

class MockClassicAclConnection
    : public bluetooth::hci::acl_manager::ClassicAclConnection {
 public:
  MockClassicAclConnection(const hci::Address& address, uint16_t handle) {
    address_ = address;  // ClassicAclConnection
    handle_ = handle;    // AclConnection
  }

  void RegisterCallbacks(
      hci::acl_manager::ConnectionManagementCallbacks* callbacks,
      os::Handler* handler) override {
    callbacks_ = callbacks;
    handler_ = handler;
  }

  // Returns the bidi queue for this mock connection
  AclConnection::QueueUpEnd* GetAclQueueEnd() const override {
    return &mock_acl_queue_;
  }

  mutable common::BidiQueueEnd<hci::BasePacketBuilder,
                               packet::PacketView<hci::kLittleEndian>>
      mock_acl_queue_{&tx_, &rx_};

  MockEnQueue<hci::BasePacketBuilder> tx_;
  MockDeQueue<packet::PacketView<hci::kLittleEndian>> rx_;

  bool ReadRemoteVersionInformation() override { return true; }
  bool ReadRemoteSupportedFeatures() override { return true; }

  bool Disconnect(hci::DisconnectReason reason) override {
    disconnect_cnt_++;
    disconnect_promise_.set_value(handle_);
    return true;
  }

  std::promise<uint16_t> disconnect_promise_;

  hci::acl_manager::ConnectionManagementCallbacks* callbacks_{nullptr};
  os::Handler* handler_{nullptr};

  int disconnect_cnt_{0};
};

namespace bluetooth {
namespace shim {
void init_activity_attribution() {}

namespace testing {
extern os::Handler* mock_handler_;

}  // namespace testing
}  // namespace shim

namespace activity_attribution {
ActivityAttributionInterface* get_activity_attribution_instance() {
  return nullptr;
}

const ModuleFactory ActivityAttribution::Factory =
    ModuleFactory([]() { return nullptr; });
}  // namespace activity_attribution

namespace hal {
const ModuleFactory HciHal::Factory = ModuleFactory([]() { return nullptr; });
}  // namespace hal

}  // namespace bluetooth

class MainShimTest : public testing::Test {
 public:
 protected:
  void SetUp() override {
    main_thread_start_up();

    thread_ = new os::Thread("acl_thread", os::Thread::Priority::NORMAL);
    handler_ = new os::Handler(thread_);

    /* extern */ test::mock_controller_ =
        new bluetooth::hci::testing::MockController();
    /* extern */ test::mock_acl_manager_ =
        new bluetooth::hci::testing::MockAclManager();
  }
  void TearDown() override {
    delete test::mock_controller_;
    test::mock_controller_ = nullptr;
    delete test::mock_acl_manager_;
    test::mock_acl_manager_ = nullptr;

    handler_->Clear();
    delete handler_;
    delete thread_;

    main_thread_shut_down();
  }
  os::Thread* thread_{nullptr};
  os::Handler* handler_{nullptr};

  // Convenience method to create ACL objects
  std::unique_ptr<shim::legacy::Acl> MakeAcl() {
    EXPECT_CALL(*test::mock_acl_manager_, RegisterCallbacks(_, _)).Times(1);
    EXPECT_CALL(*test::mock_acl_manager_, RegisterLeCallbacks(_, _)).Times(1);
    EXPECT_CALL(*test::mock_controller_,
                RegisterCompletedMonitorAclPacketsCallback(_))
        .Times(1);
    EXPECT_CALL(*test::mock_acl_manager_, HACK_SetScoDisconnectCallback(_))
        .Times(1);
    EXPECT_CALL(*test::mock_controller_,
                UnregisterCompletedMonitorAclPacketsCallback)
        .Times(1);
    return std::make_unique<shim::legacy::Acl>(handler_, GetMockAclInterface(),
                                               kMaxLeAcceptlistSize);
  }
};

TEST_F(MainShimTest, Nop) {}

TEST_F(MainShimTest, Acl_Lifecycle) {
  auto acl = MakeAcl();
  acl.reset();
  acl = MakeAcl();
}

TEST_F(MainShimTest, helpers) {
  uint8_t reason = 0;
  do {
    hci::ErrorCode gd_error_code = static_cast<hci::ErrorCode>(reason);
    tHCI_STATUS legacy_code = ToLegacyHciErrorCode(gd_error_code);
    ASSERT_EQ(reason,
              static_cast<uint8_t>(ToLegacyHciErrorCode(gd_error_code)));
    ASSERT_EQ(reason, static_cast<uint8_t>(legacy_code));
  } while (++reason != 0);
}

TEST_F(MainShimTest, connect_and_disconnect) {
  hci::Address address({0x11, 0x22, 0x33, 0x44, 0x55, 0x66});

  auto acl = MakeAcl();

  // Create connection
  EXPECT_CALL(*test::mock_acl_manager_, CreateConnection(_)).Times(1);
  acl->CreateClassicConnection(address);

  // Respond with a mock connection created
  auto connection = std::make_unique<MockClassicAclConnection>(address, 123);
  ASSERT_EQ(123, connection->GetHandle());
  ASSERT_EQ(hci::Address({0x11, 0x22, 0x33, 0x44, 0x55, 0x66}),
            connection->GetAddress());
  MockClassicAclConnection* raw_connection = connection.get();

  acl->OnConnectSuccess(std::move(connection));
  ASSERT_EQ(nullptr, connection);

  // Specify local disconnect request
  auto tx_disconnect_future = raw_connection->disconnect_promise_.get_future();
  acl->DisconnectClassic(123, HCI_SUCCESS);

  // Wait for disconnect to be received
  uint16_t result = tx_disconnect_future.get();
  ASSERT_EQ(123, result);

  // Now emulate the remote disconnect response
  auto handle_promise = std::promise<uint16_t>();
  auto rx_disconnect_future = handle_promise.get_future();
  mock_function_handle_promise_map["mock_connection_classic_on_disconnected"] =
      std::move(handle_promise);
  raw_connection->callbacks_->OnDisconnection(hci::ErrorCode::SUCCESS);

  result = rx_disconnect_future.get();
  ASSERT_EQ(123, result);

  // *Our* task completing indicates reactor is done
  std::promise<void> done;
  auto future = done.get_future();
  handler_->Call([](std::promise<void> done) { done.set_value(); },
                 std::move(done));
  future.wait();
}

TEST_F(MainShimTest, is_flushable) {
  {
    BT_HDR* bt_hdr =
        (BT_HDR*)calloc(1, sizeof(BT_HDR) + sizeof(HciDataPreamble));

    ASSERT_TRUE(!IsPacketFlushable(bt_hdr));
    HciDataPreamble* hci = ToPacketData<HciDataPreamble>(bt_hdr);
    hci->SetFlushable();
    ASSERT_TRUE(IsPacketFlushable(bt_hdr));

    free(bt_hdr);
  }

  {
    size_t offset = 1024;
    BT_HDR* bt_hdr =
        (BT_HDR*)calloc(1, sizeof(BT_HDR) + sizeof(HciDataPreamble) + offset);
    bt_hdr->offset = offset;

    ASSERT_TRUE(!IsPacketFlushable(bt_hdr));
    HciDataPreamble* hci = ToPacketData<HciDataPreamble>(bt_hdr);
    hci->SetFlushable();
    ASSERT_TRUE(IsPacketFlushable(bt_hdr));

    free(bt_hdr);
  }

  {
    size_t offset = 1024;
    BT_HDR* bt_hdr =
        (BT_HDR*)calloc(1, sizeof(BT_HDR) + sizeof(HciDataPreamble) + offset);

    uint8_t* p = ToPacketData<uint8_t>(bt_hdr, L2CAP_SEND_CMD_OFFSET);
    UINT16_TO_STREAM(
        p, 0x123 | (L2CAP_PKT_START_NON_FLUSHABLE << L2CAP_PKT_TYPE_SHIFT));
    ASSERT_TRUE(!IsPacketFlushable(bt_hdr));

    p = ToPacketData<uint8_t>(bt_hdr, L2CAP_SEND_CMD_OFFSET);
    UINT16_TO_STREAM(p, 0x123 | (L2CAP_PKT_START << L2CAP_PKT_TYPE_SHIFT));
    ASSERT_TRUE(IsPacketFlushable(bt_hdr));

    free(bt_hdr);
  }
}
