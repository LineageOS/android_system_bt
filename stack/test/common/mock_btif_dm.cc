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

/*
 * Generated mock file from original source file
 *   Functions generated:51
 */

#include <map>
#include <string>

extern std::map<std::string, int> mock_function_count_map;

#include <cstdint>
#include "bta/include/bta_api.h"
#include "include/hardware/bluetooth.h"
#include "types/bt_transport.h"
#include "types/raw_address.h"

struct uid_set_t;

#ifndef UNUSED_ATTR
#define UNUSED_ATTR
#endif

bool btif_dm_pairing_is_busy() {
  mock_function_count_map[__func__]++;
  return false;
}
bool check_cod(const RawAddress* remote_bdaddr, uint32_t cod) {
  mock_function_count_map[__func__]++;
  return false;
}
bool check_cod_hid(const RawAddress* remote_bdaddr) {
  mock_function_count_map[__func__]++;
  return false;
}
bool check_sdp_bl(const RawAddress* remote_bdaddr) {
  mock_function_count_map[__func__]++;
  return false;
}
bt_status_t btif_dm_get_adapter_property(bt_property_t* prop) {
  mock_function_count_map[__func__]++;
  return BT_STATUS_SUCCESS;
}
bt_status_t btif_in_execute_service_request(tBTA_SERVICE_ID service_id,
                                            bool b_enable) {
  mock_function_count_map[__func__]++;
  return BT_STATUS_SUCCESS;
}
uint16_t btif_dm_get_connection_state(const RawAddress* bd_addr) {
  mock_function_count_map[__func__]++;
  return 0;
}
void BTIF_dm_disable() { mock_function_count_map[__func__]++; }
void BTIF_dm_enable() { mock_function_count_map[__func__]++; }
void BTIF_dm_on_hw_error() { mock_function_count_map[__func__]++; }
void BTIF_dm_report_inquiry_status_change(uint8_t status) {
  mock_function_count_map[__func__]++;
}
void bte_dm_evt(tBTA_DM_SEC_EVT event, tBTA_DM_SEC* p_data) {
  mock_function_count_map[__func__]++;
}
void btif_ble_receiver_test(uint8_t rx_freq) {
  mock_function_count_map[__func__]++;
}
void btif_ble_test_end() { mock_function_count_map[__func__]++; }
void btif_ble_transmitter_test(uint8_t tx_freq, uint8_t test_data_len,
                               uint8_t packet_payload) {
  mock_function_count_map[__func__]++;
}
void btif_debug_bond_event_dump(int fd) { mock_function_count_map[__func__]++; }
void btif_dm_ble_sec_req_evt(tBTA_DM_BLE_SEC_REQ* p_ble_req, bool is_consent) {
  mock_function_count_map[__func__]++;
}
void btif_dm_cancel_bond(const RawAddress bd_addr) {
  mock_function_count_map[__func__]++;
}
void btif_dm_cancel_discovery(void) { mock_function_count_map[__func__]++; }
void btif_dm_cleanup(void) { mock_function_count_map[__func__]++; }
void btif_dm_create_bond(const RawAddress bd_addr, int transport) {
  mock_function_count_map[__func__]++;
}
void btif_dm_create_bond_out_of_band(const RawAddress bd_addr, int transport,
                                     const bt_oob_data_t p192_data,
                                     const bt_oob_data_t p256_data) {
  mock_function_count_map[__func__]++;
}
void btif_dm_enable_service(tBTA_SERVICE_ID service_id, bool enable) {
  mock_function_count_map[__func__]++;
}
void btif_dm_get_ble_local_keys(tBTA_DM_BLE_LOCAL_KEY_MASK* p_key_mask,
                                Octet16* p_er,
                                tBTA_BLE_LOCAL_ID_KEYS* p_id_keys) {
  mock_function_count_map[__func__]++;
}
void btif_dm_get_remote_services(RawAddress remote_addr, const int transport) {
  mock_function_count_map[__func__]++;
}
void btif_dm_hh_open_failed(RawAddress* bdaddr) {
  mock_function_count_map[__func__]++;
}
void btif_dm_init(uid_set_t* set) { mock_function_count_map[__func__]++; }
void btif_dm_load_ble_local_keys(void) { mock_function_count_map[__func__]++; }
void btif_dm_on_disable() { mock_function_count_map[__func__]++; }
void btif_dm_pin_reply(const RawAddress bd_addr, uint8_t accept,
                       uint8_t pin_len, bt_pin_code_t pin_code) {
  mock_function_count_map[__func__]++;
}
void btif_dm_proc_io_req(tBTM_AUTH_REQ* p_auth_req, bool is_orig) {
  mock_function_count_map[__func__]++;
}
void btif_dm_proc_io_rsp(UNUSED_ATTR const RawAddress& bd_addr,
                         tBTM_IO_CAP io_cap, UNUSED_ATTR tBTM_OOB_DATA oob_data,
                         tBTM_AUTH_REQ auth_req) {
  mock_function_count_map[__func__]++;
}
void btif_dm_read_energy_info() { mock_function_count_map[__func__]++; }
void btif_dm_remove_ble_bonding_keys(void) {
  mock_function_count_map[__func__]++;
}
void btif_dm_remove_bond(const RawAddress bd_addr) {
  mock_function_count_map[__func__]++;
}
void btif_dm_save_ble_bonding_keys(RawAddress& bd_addr) {
  mock_function_count_map[__func__]++;
}
void btif_dm_set_oob_for_io_req(tBTM_OOB_DATA* p_has_oob_data) {
  mock_function_count_map[__func__]++;
}
void btif_dm_set_oob_for_le_io_req(const RawAddress& bd_addr,
                                   tBTM_OOB_DATA* p_has_oob_data,
                                   tBTM_LE_AUTH_REQ* p_auth_req) {
  mock_function_count_map[__func__]++;
}
void btif_dm_ssp_reply(const RawAddress bd_addr, bt_ssp_variant_t variant,
                       uint8_t accept) {
  mock_function_count_map[__func__]++;
}
void btif_dm_start_discovery(void) { mock_function_count_map[__func__]++; }
void btif_dm_update_ble_remote_properties(const RawAddress& bd_addr,
                                          BD_NAME bd_name,
                                          tBT_DEVICE_TYPE dev_type) {
  mock_function_count_map[__func__]++;
}

void btif_dm_proc_loc_oob(tBT_TRANSPORT transport, bool is_valid,
                          const Octet16& c, const Octet16& r) {
  mock_function_count_map[__func__]++;
}
