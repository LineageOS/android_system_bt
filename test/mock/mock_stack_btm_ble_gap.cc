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

/*
 * Generated mock file from original source file
 *   Functions generated:47
 */

#include <map>
#include <string>

extern std::map<std::string, int> mock_function_count_map;

#include <base/bind.h>
#include <base/strings/string_number_conversions.h>
#include <cstdint>
#include <list>
#include <memory>
#include <vector>
#include "common/time_util.h"
#include "device/include/controller.h"
#include "main/shim/acl_api.h"
#include "main/shim/btm_api.h"
#include "main/shim/shim.h"
#include "osi/include/log.h"
#include "stack/btm/btm_ble_int.h"
#include "stack/btm/btm_ble_int_types.h"
#include "stack/btm/btm_dev.h"
#include "stack/btm/btm_int_types.h"
#include "stack/gatt/gatt_int.h"
#include "stack/include/acl_api.h"
#include "stack/include/advertise_data_parser.h"
#include "stack/include/bt_types.h"
#include "stack/include/btm_api_types.h"
#include "stack/include/gap_api.h"
#include "stack/include/hci_error_code.h"
#include "stack/include/hcimsgs.h"
#include "stack/include/inq_hci_link_interface.h"
#include "types/raw_address.h"

#ifndef UNUSED_ATTR
#define UNUSED_ATTR
#endif

bool BTM_BleConfigPrivacy(bool privacy_mode) {
  mock_function_count_map[__func__]++;
  return false;
}
bool BTM_BleLocalPrivacyEnabled(void) {
  mock_function_count_map[__func__]++;
  return false;
}
bool btm_ble_cancel_remote_name(const RawAddress& remote_bda) {
  mock_function_count_map[__func__]++;
  return false;
}
bool btm_ble_clear_topology_mask(tBTM_BLE_STATE_MASK request_state_mask) {
  mock_function_count_map[__func__]++;
  return false;
}
bool btm_ble_set_topology_mask(tBTM_BLE_STATE_MASK request_state_mask) {
  mock_function_count_map[__func__]++;
  return false;
}
bool btm_ble_topology_check(tBTM_BLE_STATE_MASK request_state_mask) {
  mock_function_count_map[__func__]++;
  return false;
}
tBTM_STATUS BTM_BleObserve(bool start, uint8_t duration,
                           tBTM_INQ_RESULTS_CB* p_results_cb,
                           tBTM_CMPL_CB* p_cmpl_cb) {
  mock_function_count_map[__func__]++;
  return BTM_SUCCESS;
}
tBTM_STATUS btm_ble_read_remote_name(const RawAddress& remote_bda,
                                     tBTM_CMPL_CB* p_cb) {
  mock_function_count_map[__func__]++;
  return BTM_SUCCESS;
}
tBTM_STATUS btm_ble_set_connectability(uint16_t combined_mode) {
  mock_function_count_map[__func__]++;
  return BTM_SUCCESS;
}
tBTM_STATUS btm_ble_set_discoverability(uint16_t combined_mode) {
  mock_function_count_map[__func__]++;
  return BTM_SUCCESS;
}
tBTM_STATUS btm_ble_start_adv(void) {
  mock_function_count_map[__func__]++;
  return BTM_SUCCESS;
}
tBTM_STATUS btm_ble_start_inquiry(uint8_t duration) {
  mock_function_count_map[__func__]++;
  return BTM_SUCCESS;
}
tBTM_STATUS btm_ble_stop_adv(void) {
  mock_function_count_map[__func__]++;
  return BTM_SUCCESS;
}
uint16_t BTM_BleReadConnectability() {
  mock_function_count_map[__func__]++;
  return 0;
}
uint16_t BTM_BleReadDiscoverability() {
  mock_function_count_map[__func__]++;
  return 0;
}
uint8_t BTM_BleMaxMultiAdvInstanceCount(void) {
  mock_function_count_map[__func__]++;
  return 0;
}
void BTM_BleGetDynamicAudioBuffer(
    tBTM_BT_DYNAMIC_AUDIO_BUFFER_CB p_dynamic_audio_buffer_cb[]) {
  mock_function_count_map[__func__]++;
}
void BTM_BleGetVendorCapabilities(tBTM_BLE_VSC_CB* p_cmn_vsc_cb) {
  mock_function_count_map[__func__]++;
}
void BTM_BleSetScanParams(uint32_t scan_interval, uint32_t scan_window,
                          tBLE_SCAN_MODE scan_mode,
                          base::Callback<void(uint8_t)> cb) {
  mock_function_count_map[__func__]++;
}
void btm_ble_decrement_link_topology_mask(uint8_t link_role) {
  mock_function_count_map[__func__]++;
}
void btm_ble_dir_adv_tout(void) { mock_function_count_map[__func__]++; }
void btm_ble_free() { mock_function_count_map[__func__]++; }
void btm_ble_increment_link_topology_mask(uint8_t link_role) {
  mock_function_count_map[__func__]++;
}
void btm_ble_init(void) { mock_function_count_map[__func__]++; }
void btm_ble_process_adv_addr(RawAddress& bda, uint8_t* addr_type) {
  mock_function_count_map[__func__]++;
}
void btm_ble_process_adv_pkt(uint8_t data_len, uint8_t* data) {
  mock_function_count_map[__func__]++;
}
void btm_ble_process_adv_pkt_cont(uint16_t evt_type, uint8_t addr_type,
                                  const RawAddress& bda, uint8_t primary_phy,
                                  uint8_t secondary_phy,
                                  uint8_t advertising_sid, int8_t tx_power,
                                  int8_t rssi, uint16_t periodic_adv_int,
                                  uint8_t data_len, uint8_t* data) {
  mock_function_count_map[__func__]++;
}
void btm_ble_process_adv_pkt_cont_for_inquiry(
    uint16_t evt_type, uint8_t addr_type, const RawAddress& bda,
    uint8_t primary_phy, uint8_t secondary_phy, uint8_t advertising_sid,
    int8_t tx_power, int8_t rssi, uint16_t periodic_adv_int,
    std::vector<uint8_t> advertising_data) {
  mock_function_count_map[__func__]++;
}
void btm_ble_process_ext_adv_pkt(uint8_t data_len, uint8_t* data) {
  mock_function_count_map[__func__]++;
}
void btm_ble_process_phy_update_pkt(uint8_t len, uint8_t* data) {
  mock_function_count_map[__func__]++;
}
void btm_ble_read_remote_features_complete(uint8_t* p) {
  mock_function_count_map[__func__]++;
}
void btm_ble_read_remote_name_cmpl(bool status, const RawAddress& bda,
                                   uint16_t length, char* p_name) {
  mock_function_count_map[__func__]++;
}
void btm_ble_set_adv_flag(uint16_t connect_mode, uint16_t disc_mode) {
  mock_function_count_map[__func__]++;
}
void btm_ble_start_scan() { mock_function_count_map[__func__]++; }
void btm_ble_stop_inquiry(void) { mock_function_count_map[__func__]++; }
void btm_ble_stop_scan(void) { mock_function_count_map[__func__]++; }
void btm_ble_update_dmt_flag_bits(uint8_t* adv_flag_value,
                                  const uint16_t connect_mode,
                                  const uint16_t disc_mode) {
  mock_function_count_map[__func__]++;
}
void btm_ble_update_inq_result(tINQ_DB_ENT* p_i, uint8_t addr_type,
                               const RawAddress& bda, uint16_t evt_type,
                               uint8_t primary_phy, uint8_t secondary_phy,
                               uint8_t advertising_sid, int8_t tx_power,
                               int8_t rssi, uint16_t periodic_adv_int,
                               std::vector<uint8_t> const& data) {
  mock_function_count_map[__func__]++;
}
void btm_ble_update_mode_operation(uint8_t link_role, const RawAddress* bd_addr,
                                   tHCI_STATUS status) {
  mock_function_count_map[__func__]++;
}
void btm_ble_write_adv_enable_complete(uint8_t* p) {
  mock_function_count_map[__func__]++;
}
void btm_clear_all_pending_le_entry(void) {
  mock_function_count_map[__func__]++;
}
void btm_send_hci_set_scan_params(uint8_t scan_type, uint16_t scan_int,
                                  uint16_t scan_win, uint8_t addr_type_own,
                                  uint8_t scan_filter_policy) {
  mock_function_count_map[__func__]++;
}
