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
 *   Functions generated:22
 */

#include <cstdint>
#include <map>
#include <string>

extern std::map<std::string, int> mock_function_count_map;

#include "stack/l2cap/l2c_int.h"
#include "types/raw_address.h"

#ifndef UNUSED_ATTR
#define UNUSED_ATTR
#endif

bool L2CA_EnableUpdateBleConnParams(const RawAddress& rem_bda, bool enable) {
  mock_function_count_map[__func__]++;
  return false;
}
bool L2CA_UpdateBleConnParams(const RawAddress& rem_bda, uint16_t min_int,
                              uint16_t max_int, uint16_t latency,
                              uint16_t timeout, uint16_t min_ce_len,
                              uint16_t max_ce_len) {
  mock_function_count_map[__func__]++;
  return false;
}
bool l2cble_conn_comp(uint16_t handle, uint8_t role, const RawAddress& bda,
                      tBLE_ADDR_TYPE type, uint16_t conn_interval,
                      uint16_t conn_latency, uint16_t conn_timeout) {
  mock_function_count_map[__func__]++;
  return false;
}
bool l2cble_conn_comp_from_address_with_type(
    uint16_t handle, uint8_t role, const tBLE_BD_ADDR& address_with_type,
    uint16_t conn_interval, uint16_t conn_latency, uint16_t conn_timeout) {
  mock_function_count_map[__func__]++;
  return false;
}
bool l2cble_create_conn(tL2C_LCB* p_lcb) {
  mock_function_count_map[__func__]++;
  return false;
}
hci_role_t L2CA_GetBleConnRole(const RawAddress& bd_addr) {
  mock_function_count_map[__func__]++;
  return HCI_ROLE_CENTRAL;
}
tL2CAP_LE_RESULT_CODE l2ble_sec_access_req(const RawAddress& bd_addr,
                                           uint16_t psm, bool is_originator,
                                           tL2CAP_SEC_CBACK* p_callback,
                                           void* p_ref_data) {
  mock_function_count_map[__func__]++;
  return L2CAP_LE_RESULT_CONN_OK;
}
void L2CA_AdjustConnectionIntervals(uint16_t* min_interval,
                                    uint16_t* max_interval,
                                    uint16_t floor_interval) {
  mock_function_count_map[__func__]++;
}
void l2c_ble_link_adjust_allocation(void) {
  mock_function_count_map[__func__]++;
}
void l2c_link_processs_ble_num_bufs(uint16_t num_lm_ble_bufs) {
  mock_function_count_map[__func__]++;
}
void l2cble_credit_based_conn_req(tL2C_CCB* p_ccb) {
  mock_function_count_map[__func__]++;
}
void l2cble_credit_based_conn_res(tL2C_CCB* p_ccb, uint16_t result) {
  mock_function_count_map[__func__]++;
}
void l2cble_notify_le_connection(const RawAddress& bda) {
  mock_function_count_map[__func__]++;
}
void l2cble_process_conn_update_evt(uint16_t handle, uint8_t status,
                                    uint16_t interval, uint16_t latency,
                                    uint16_t timeout) {
  mock_function_count_map[__func__]++;
}
void l2cble_process_data_length_change_event(uint16_t handle,
                                             uint16_t tx_data_len,
                                             uint16_t rx_data_len) {
  mock_function_count_map[__func__]++;
}
void l2cble_process_rc_param_request_evt(uint16_t handle, uint16_t int_min,
                                         uint16_t int_max, uint16_t latency,
                                         uint16_t timeout) {
  mock_function_count_map[__func__]++;
}
void l2cble_process_sig_cmd(tL2C_LCB* p_lcb, uint8_t* p, uint16_t pkt_len) {
  mock_function_count_map[__func__]++;
}
void l2cble_sec_comp(const RawAddress* bda, tBT_TRANSPORT transport,
                     void* p_ref_data, uint8_t status) {
  mock_function_count_map[__func__]++;
}
void l2cble_send_flow_control_credit(tL2C_CCB* p_ccb, uint16_t credit_value) {
  mock_function_count_map[__func__]++;
}
void l2cble_send_peer_disc_req(tL2C_CCB* p_ccb) {
  mock_function_count_map[__func__]++;
}
void l2cble_update_data_length(tL2C_LCB* p_lcb) {
  mock_function_count_map[__func__]++;
}
void l2cble_use_preferred_conn_params(const RawAddress& bda) {
  mock_function_count_map[__func__]++;
}
