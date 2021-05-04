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
 *
 *  mockcify.pl ver 0.2
 */

#include <map>
#include <string>

extern std::map<std::string, int> mock_function_count_map;

// Original included files, if any
// NOTE: Since this is a mock file with mock definitions some number of
//       include files may not be required.  The include-what-you-use
//       still applies, but crafting proper inclusion is out of scope
//       for this effort.  This compilation unit may compile as-is, or
//       may need attention to prune the inclusion set.

// Mock include file to share data between tests and mock
#include "test/mock/mock_stack_l2cap_ble.h"

// Mocked compile conditionals, if any
#ifndef UNUSED_ATTR
#define UNUSED_ATTR
#endif

// Mocked internal structures, if any

namespace test {
namespace mock {
namespace stack_l2cap_ble {

// Function state capture and return values, if needed
struct L2CA_UpdateBleConnParams L2CA_UpdateBleConnParams;
struct L2CA_EnableUpdateBleConnParams L2CA_EnableUpdateBleConnParams;
struct L2CA_GetBleConnRole L2CA_GetBleConnRole;
struct l2cble_notify_le_connection l2cble_notify_le_connection;
struct l2cble_conn_comp l2cble_conn_comp;
struct l2cble_conn_comp_from_address_with_type
    l2cble_conn_comp_from_address_with_type;
struct l2cble_process_conn_update_evt l2cble_process_conn_update_evt;
struct l2cble_process_sig_cmd l2cble_process_sig_cmd;
struct l2cble_create_conn l2cble_create_conn;
struct l2c_link_processs_ble_num_bufs l2c_link_processs_ble_num_bufs;
struct l2c_ble_link_adjust_allocation l2c_ble_link_adjust_allocation;
struct l2cble_process_rc_param_request_evt l2cble_process_rc_param_request_evt;
struct l2cble_update_data_length l2cble_update_data_length;
struct l2cble_process_data_length_change_event
    l2cble_process_data_length_change_event;
struct l2cble_credit_based_conn_req l2cble_credit_based_conn_req;
struct l2cble_credit_based_conn_res l2cble_credit_based_conn_res;
struct l2cble_send_flow_control_credit l2cble_send_flow_control_credit;
struct l2cble_send_peer_disc_req l2cble_send_peer_disc_req;
struct l2cble_sec_comp l2cble_sec_comp;
struct l2ble_sec_access_req l2ble_sec_access_req;
struct L2CA_AdjustConnectionIntervals L2CA_AdjustConnectionIntervals;
struct l2cble_use_preferred_conn_params l2cble_use_preferred_conn_params;

}  // namespace stack_l2cap_ble
}  // namespace mock
}  // namespace test

// Mocked functions, if any
bool L2CA_UpdateBleConnParams(const RawAddress& rem_bda, uint16_t min_int,
                              uint16_t max_int, uint16_t latency,
                              uint16_t timeout, uint16_t min_ce_len,
                              uint16_t max_ce_len) {
  mock_function_count_map[__func__]++;
  return test::mock::stack_l2cap_ble::L2CA_UpdateBleConnParams(
      rem_bda, min_int, max_int, latency, timeout, min_ce_len, max_ce_len);
}
bool L2CA_EnableUpdateBleConnParams(const RawAddress& rem_bda, bool enable) {
  mock_function_count_map[__func__]++;
  return test::mock::stack_l2cap_ble::L2CA_EnableUpdateBleConnParams(rem_bda,
                                                                     enable);
}
hci_role_t L2CA_GetBleConnRole(const RawAddress& bd_addr) {
  mock_function_count_map[__func__]++;
  return test::mock::stack_l2cap_ble::L2CA_GetBleConnRole(bd_addr);
}
void l2cble_notify_le_connection(const RawAddress& bda) {
  mock_function_count_map[__func__]++;
  test::mock::stack_l2cap_ble::l2cble_notify_le_connection(bda);
}
bool l2cble_conn_comp(uint16_t handle, uint8_t role, const RawAddress& bda,
                      tBLE_ADDR_TYPE type, uint16_t conn_interval,
                      uint16_t conn_latency, uint16_t conn_timeout) {
  mock_function_count_map[__func__]++;
  return test::mock::stack_l2cap_ble::l2cble_conn_comp(
      handle, role, bda, type, conn_interval, conn_latency, conn_timeout);
}
bool l2cble_conn_comp_from_address_with_type(
    uint16_t handle, uint8_t role, const tBLE_BD_ADDR& address_with_type,
    uint16_t conn_interval, uint16_t conn_latency, uint16_t conn_timeout) {
  mock_function_count_map[__func__]++;
  return test::mock::stack_l2cap_ble::l2cble_conn_comp_from_address_with_type(
      handle, role, address_with_type, conn_interval, conn_latency,
      conn_timeout);
}
void l2cble_process_conn_update_evt(uint16_t handle, uint8_t status,
                                    uint16_t interval, uint16_t latency,
                                    uint16_t timeout) {
  mock_function_count_map[__func__]++;
  test::mock::stack_l2cap_ble::l2cble_process_conn_update_evt(
      handle, status, interval, latency, timeout);
}
void l2cble_process_sig_cmd(tL2C_LCB* p_lcb, uint8_t* p, uint16_t pkt_len) {
  mock_function_count_map[__func__]++;
  test::mock::stack_l2cap_ble::l2cble_process_sig_cmd(p_lcb, p, pkt_len);
}
bool l2cble_create_conn(tL2C_LCB* p_lcb) {
  mock_function_count_map[__func__]++;
  return test::mock::stack_l2cap_ble::l2cble_create_conn(p_lcb);
}
void l2c_link_processs_ble_num_bufs(uint16_t num_lm_ble_bufs) {
  mock_function_count_map[__func__]++;
  test::mock::stack_l2cap_ble::l2c_link_processs_ble_num_bufs(num_lm_ble_bufs);
}
void l2c_ble_link_adjust_allocation(void) {
  mock_function_count_map[__func__]++;
  test::mock::stack_l2cap_ble::l2c_ble_link_adjust_allocation();
}
void l2cble_process_rc_param_request_evt(uint16_t handle, uint16_t int_min,
                                         uint16_t int_max, uint16_t latency,
                                         uint16_t timeout) {
  mock_function_count_map[__func__]++;
  test::mock::stack_l2cap_ble::l2cble_process_rc_param_request_evt(
      handle, int_min, int_max, latency, timeout);
}
void l2cble_update_data_length(tL2C_LCB* p_lcb) {
  mock_function_count_map[__func__]++;
  test::mock::stack_l2cap_ble::l2cble_update_data_length(p_lcb);
}
void l2cble_process_data_length_change_event(uint16_t handle,
                                             uint16_t tx_data_len,
                                             uint16_t rx_data_len) {
  mock_function_count_map[__func__]++;
  test::mock::stack_l2cap_ble::l2cble_process_data_length_change_event(
      handle, tx_data_len, rx_data_len);
}
void l2cble_credit_based_conn_req(tL2C_CCB* p_ccb) {
  mock_function_count_map[__func__]++;
  test::mock::stack_l2cap_ble::l2cble_credit_based_conn_req(p_ccb);
}
void l2cble_credit_based_conn_res(tL2C_CCB* p_ccb, uint16_t result) {
  mock_function_count_map[__func__]++;
  test::mock::stack_l2cap_ble::l2cble_credit_based_conn_res(p_ccb, result);
}
void l2cble_send_flow_control_credit(tL2C_CCB* p_ccb, uint16_t credit_value) {
  mock_function_count_map[__func__]++;
  test::mock::stack_l2cap_ble::l2cble_send_flow_control_credit(p_ccb,
                                                               credit_value);
}
void l2cble_send_peer_disc_req(tL2C_CCB* p_ccb) {
  mock_function_count_map[__func__]++;
  test::mock::stack_l2cap_ble::l2cble_send_peer_disc_req(p_ccb);
}
void l2cble_sec_comp(const RawAddress* bda, tBT_TRANSPORT transport,
                     void* p_ref_data, tBTM_STATUS status) {
  mock_function_count_map[__func__]++;
  test::mock::stack_l2cap_ble::l2cble_sec_comp(bda, transport, p_ref_data,
                                               status);
}
tL2CAP_LE_RESULT_CODE l2ble_sec_access_req(const RawAddress& bd_addr,
                                           uint16_t psm, bool is_originator,
                                           tL2CAP_SEC_CBACK* p_callback,
                                           void* p_ref_data) {
  mock_function_count_map[__func__]++;
  return test::mock::stack_l2cap_ble::l2ble_sec_access_req(
      bd_addr, psm, is_originator, p_callback, p_ref_data);
}
void L2CA_AdjustConnectionIntervals(uint16_t* min_interval,
                                    uint16_t* max_interval,
                                    uint16_t floor_interval) {
  mock_function_count_map[__func__]++;
  test::mock::stack_l2cap_ble::L2CA_AdjustConnectionIntervals(
      min_interval, max_interval, floor_interval);
}
void l2cble_use_preferred_conn_params(const RawAddress& bda) {
  mock_function_count_map[__func__]++;
  test::mock::stack_l2cap_ble::l2cble_use_preferred_conn_params(bda);
}

// END mockcify generation
