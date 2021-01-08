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
 *   Functions generated:77
 */

#include <map>
#include <string>

extern std::map<std::string, int> mock_function_count_map;
#define UNUSED_ATTR

#include <stddef.h>
#include <string.h>
#include "bt_common.h"
#include "bt_target.h"
#include "btu.h"
#include "hcidefs.h"
#include "hcimsgs.h"
#include "stack/include/acl_hci_link_interface.h"
void btsnd_hcic_accept_conn(const RawAddress& dest, uint8_t role) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_accept_esco_conn(const RawAddress& bd_addr,
                                 uint32_t transmit_bandwidth,
                                 uint32_t receive_bandwidth,
                                 uint16_t max_latency, uint16_t content_fmt,
                                 uint8_t retrans_effort,
                                 uint16_t packet_types) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_add_SCO_conn(uint16_t handle, uint16_t packet_types) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_auth_request(uint16_t handle) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_change_conn_type(uint16_t handle, uint16_t packet_types) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_change_name(BD_NAME name) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_create_conn(const RawAddress& dest, uint16_t packet_types,
                            uint8_t page_scan_rep_mode, uint8_t page_scan_mode,
                            uint16_t clock_offset, uint8_t allow_switch) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_create_conn_cancel(const RawAddress& dest) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_delete_stored_key(const RawAddress& bd_addr,
                                  bool delete_all_flag) {
  mock_function_count_map[__func__]++;
}
static void btsnd_hcic_disconnect(uint16_t handle, uint8_t reason) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_enable_test_mode(void) { mock_function_count_map[__func__]++; }
void btsnd_hcic_enhanced_accept_synchronous_connection(
    const RawAddress& bd_addr, enh_esco_params_t* p_params) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_enhanced_flush(uint16_t handle, uint8_t packet_type) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_enhanced_set_up_synchronous_connection(
    uint16_t conn_handle, enh_esco_params_t* p_params) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_exit_park_mode(uint16_t handle) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_exit_per_inq(void) { mock_function_count_map[__func__]++; }
void btsnd_hcic_exit_sniff_mode(uint16_t handle) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_get_link_quality(uint16_t handle) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_hold_mode(uint16_t handle, uint16_t max_hold_period,
                          uint16_t min_hold_period) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_host_num_xmitted_pkts(uint8_t num_handles, uint16_t* handle,
                                      uint16_t* num_pkts) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_inq_cancel(void) { mock_function_count_map[__func__]++; }
void btsnd_hcic_inquiry(const LAP inq_lap, uint8_t duration,
                        uint8_t response_cnt) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_io_cap_req_neg_reply(const RawAddress& bd_addr,
                                     uint8_t err_code) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_io_cap_req_reply(const RawAddress& bd_addr, uint8_t capability,
                                 uint8_t oob_present, uint8_t auth_req) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_link_key_neg_reply(const RawAddress& bd_addr) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_link_key_req_reply(const RawAddress& bd_addr,
                                   const LinkKey& link_key) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_park_mode(uint16_t handle, uint16_t beacon_max_interval,
                          uint16_t beacon_min_interval) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_per_inq_mode(uint16_t max_period, uint16_t min_period,
                             const LAP inq_lap, uint8_t duration,
                             uint8_t response_cnt) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_pin_code_neg_reply(const RawAddress& bd_addr) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_pin_code_req_reply(const RawAddress& bd_addr,
                                   uint8_t pin_code_len, PIN_CODE pin_code) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_qos_setup(uint16_t handle, uint8_t flags, uint8_t service_type,
                          uint32_t token_rate, uint32_t peak, uint32_t latency,
                          uint32_t delay_var) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_read_automatic_flush_timeout(uint16_t handle) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_read_encryption_key_size(uint16_t handle, ReadEncKeySizeCb cb) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_read_failed_contact_counter(uint16_t handle) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_read_inq_tx_power(void) { mock_function_count_map[__func__]++; }
void btsnd_hcic_read_lmp_handle(uint16_t handle) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_read_local_oob_data(void) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_read_name(void) { mock_function_count_map[__func__]++; }
void btsnd_hcic_read_rmt_clk_offset(uint16_t handle) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_read_rssi(uint16_t handle) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_read_tx_power(uint16_t handle, uint8_t type) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_reject_conn(const RawAddress& dest, uint8_t reason) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_reject_esco_conn(const RawAddress& bd_addr, uint8_t reason) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_rem_oob_neg_reply(const RawAddress& bd_addr) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_rem_oob_reply(const RawAddress& bd_addr, const Octet16& c,
                              const Octet16& r) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_rmt_ext_features(uint16_t handle, uint8_t page_num) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_rmt_features_req(uint16_t handle) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_rmt_name_req(const RawAddress& bd_addr,
                             uint8_t page_scan_rep_mode, uint8_t page_scan_mode,
                             uint16_t clock_offset) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_rmt_name_req_cancel(const RawAddress& bd_addr) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_rmt_ver_req(uint16_t handle) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_send_keypress_notif(const RawAddress& bd_addr, uint8_t notif) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_set_conn_encrypt(uint16_t handle, bool enable) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_set_event_filter(uint8_t filt_type, uint8_t filt_cond_type,
                                 uint8_t* filt_cond, uint8_t filt_cond_len) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_setup_esco_conn(uint16_t handle, uint32_t transmit_bandwidth,
                                uint32_t receive_bandwidth,
                                uint16_t max_latency, uint16_t voice,
                                uint8_t retrans_effort, uint16_t packet_types) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_sniff_mode(uint16_t handle, uint16_t max_sniff_period,
                           uint16_t min_sniff_period, uint16_t sniff_attempt,
                           uint16_t sniff_timeout) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_sniff_sub_rate(uint16_t handle, uint16_t max_lat,
                               uint16_t min_remote_lat,
                               uint16_t min_local_lat) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_switch_role(const RawAddress& bd_addr, uint8_t role) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_user_conf_reply(const RawAddress& bd_addr, bool is_yes) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_user_passkey_neg_reply(const RawAddress& bd_addr) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_user_passkey_reply(const RawAddress& bd_addr, uint32_t value) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_vendor_spec_cmd(void* buffer, uint16_t opcode, uint8_t len,
                                uint8_t* p_data, void* p_cmd_cplt_cback) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_write_auth_enable(uint8_t flag) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_write_auto_flush_tout(uint16_t handle, uint16_t tout) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_write_cur_iac_lap(uint8_t num_cur_iac, LAP* const iac_lap) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_write_def_policy_set(uint16_t settings) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_write_dev_class(DEV_CLASS dev_class) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_write_ext_inquiry_response(void* buffer, uint8_t fec_req) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_write_inqscan_cfg(uint16_t interval, uint16_t window) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_write_inqscan_type(uint8_t type) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_write_inquiry_mode(uint8_t mode) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_write_link_super_tout(uint8_t local_controller_id,
                                      uint16_t handle, uint16_t timeout) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_write_page_tout(uint16_t timeout) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_write_pagescan_cfg(uint16_t interval, uint16_t window) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_write_pagescan_type(uint8_t type) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_write_pin_type(uint8_t type) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_write_policy_set(uint16_t handle, uint16_t settings) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_write_scan_enable(uint8_t flag) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_write_voice_settings(uint16_t flags) {
  mock_function_count_map[__func__]++;
}

bluetooth::legacy::hci::Interface interface_ = {
    .Disconnect = btsnd_hcic_disconnect,
    .StartRoleSwitch = btsnd_hcic_switch_role,
};

const bluetooth::legacy::hci::Interface&
bluetooth::legacy::hci::GetInterface() {
  return interface_;
}
