/*
 * Copyright 2021 The Android Open Source Project
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

#include "btif/include/btif_profile_queue.h"

#include <gtest/gtest.h>

#include <base/bind.h>
#include <base/callback.h>
#include <base/location.h>
#include "stack_manager.h"
#include "types/raw_address.h"

#include "bta/include/bta_ag_api.h"  // tBTA_AG_RES_DATA::kEmpty
#include "hci/include/hci_layer.h"   // hci_t

std::map<std::string, int> mock_function_count_map;

void set_hal_cbacks(bt_callbacks_t* callbacks);  // btif/src/bluetooth.cc

// tLEGACY_TRACE_LEVEL
uint8_t btu_trace_level = 6;
uint8_t appl_trace_level = 6;
uint8_t btif_trace_level = 6;

namespace {

void dump_mock_function_count_map() {
  LOG_INFO("Mock function count map size:%zu", mock_function_count_map.size());

  for (auto it : mock_function_count_map) {
    LOG_INFO("function:%s: call_count:%d", it.first.c_str(), it.second);
  }
}

namespace _adapter_state_changed {
bt_state_t state{BT_STATE_OFF};
}
void adapter_state_changed(bt_state_t state) {
  LOG_INFO("%u => %u", _adapter_state_changed::state, state);
}

void adapter_properties(bt_status_t status, int num_properties,
                        bt_property_t* properties) {
  LOG_INFO("Callback rx");
}

void remote_device_properties(bt_status_t status, RawAddress* bd_addr,
                              int num_properties, bt_property_t* properties) {
  LOG_INFO("Callback rx");
}

void device_found(int num_properties, bt_property_t* properties) {
  LOG_INFO("Callback rx");
}

void discovery_state_changed(bt_discovery_state_t state) {
  LOG_INFO("Callback rx");
}

/** Bluetooth Legacy PinKey Request callback */
void pin_request(RawAddress* remote_bd_addr, bt_bdname_t* bd_name, uint32_t cod,
                 bool min_16_digit) {
  LOG_INFO("Callback rx");
}

void ssp_request(RawAddress* remote_bd_addr, bt_bdname_t* bd_name, uint32_t cod,
                 bt_ssp_variant_t pairing_variant, uint32_t pass_key) {
  LOG_INFO("Callback rx");
}

/** Bluetooth Bond state changed callback */
/* Invoked in response to create_bond, cancel_bond or remove_bond */
void bond_state_changed(bt_status_t status, RawAddress* remote_bd_addr,
                        bt_bond_state_t state) {
  LOG_INFO("Callback rx");
}

/** Bluetooth ACL connection state changed callback */
void acl_state_changed(bt_status_t status, RawAddress* remote_bd_addr,
                       bt_acl_state_t state, bt_hci_error_code_t hci_reason) {
  LOG_INFO("status:%s device:%s state:%s", bt_status_text(status).c_str(),
           remote_bd_addr->ToString().c_str(),
           (state) ? "disconnected" : "connected");
}

/** Bluetooth Link Quality Report callback */
void link_quality_report(uint64_t timestamp, int report_id, int rssi, int snr,
                         int retransmission_count,
                         int packets_not_receive_count,
                         int negative_acknowledgement_count) {
  LOG_INFO("Callback rx");
}

void thread_event(bt_cb_thread_evt evt) { LOG_INFO("Callback rx"); }

void dut_mode_recv(uint16_t opcode, uint8_t* buf, uint8_t len) {
  LOG_INFO("Callback rx");
}

void le_test_mode(bt_status_t status, uint16_t num_packets) {
  LOG_INFO("Callback rx");
}

void energy_info(bt_activity_energy_info* energy_info,
                 bt_uid_traffic_t* uid_data) {
  LOG_INFO("Callback rx");
}

bt_callbacks_t bt_callbacks{
    /** set to sizeof(bt_callbacks_t) */
    .size = sizeof(bt_callbacks_t),
    .adapter_state_changed_cb = adapter_state_changed,
    .adapter_properties_cb = adapter_properties,
    .remote_device_properties_cb = remote_device_properties,
    .device_found_cb = device_found,
    .discovery_state_changed_cb = discovery_state_changed,
    .pin_request_cb = pin_request,
    .ssp_request_cb = ssp_request,
    .bond_state_changed_cb = bond_state_changed,
    .acl_state_changed_cb = acl_state_changed,
    .thread_evt_cb = thread_event,
    .dut_mode_recv_cb = dut_mode_recv,
    .le_test_mode_cb = le_test_mode,
    .energy_info_cb = energy_info,
    .link_quality_report_cb = link_quality_report,
};

void set_data_cb(
    base::Callback<void(const base::Location&, BT_HDR*)> send_data_cb) {
  mock_function_count_map[__func__]++;
}

void transmit_command(BT_HDR* command, command_complete_cb complete_callback,
                      command_status_cb status_cb, void* context) {
  mock_function_count_map[__func__]++;
}

future_t* transmit_command_futured(BT_HDR* command) {
  mock_function_count_map[__func__]++;
  return nullptr;
}

void transmit_downward(uint16_t type, void* data) {
  mock_function_count_map[__func__]++;
}

}  // namespace

hci_t mock_hci = {
    .set_data_cb = set_data_cb,
    .transmit_command = transmit_command,
    .transmit_command_futured = transmit_command_futured,
    .transmit_downward = transmit_downward,
};
const hci_t* hci_layer_get_interface() { return &mock_hci; }

bool is_bluetooth_uid() { return false; }
const tBTA_AG_RES_DATA tBTA_AG_RES_DATA::kEmpty = {};

namespace bluetooth {
namespace common {

class BluetoothMetricsLogger {};

}  // namespace common
}  // namespace bluetooth

class StackCycleTest : public ::testing::Test {
 protected:
  void SetUp() override { stack_manager_ = stack_manager_get_interface(); }

  void TearDown() override { stack_manager_ = nullptr; }
  const stack_manager_t* stack_manager_{nullptr};
};

TEST_F(StackCycleTest, stack_init) {
  // TODO load init flags
  // bluetooth::common::InitFlags::Load(init_flags);

  set_hal_cbacks(&bt_callbacks);

  stack_manager_get_interface()->init_stack();

  LOG_INFO("Initialized stack");

  ASSERT_EQ(1, mock_function_count_map["set_data_cb"]);

  dump_mock_function_count_map();
}
