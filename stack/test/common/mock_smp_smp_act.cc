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
 *   Functions generated:73
 */

#include <map>
#include <string>

extern std::map<std::string, int> mock_function_count_map;

#include "stack/smp/smp_int.h"
#include "types/raw_address.h"

#ifndef UNUSED_ATTR
#define UNUSED_ATTR
#endif

bool smp_proc_ltk_request(const RawAddress& bda) {
  mock_function_count_map[__func__]++;
  return false;
}
void smp_both_have_public_keys(tSMP_CB* p_cb, tSMP_INT_DATA* p_data) {
  mock_function_count_map[__func__]++;
}
void smp_br_check_authorization_request(tSMP_CB* p_cb, tSMP_INT_DATA* p_data) {
  mock_function_count_map[__func__]++;
}
void smp_br_pairing_complete(tSMP_CB* p_cb, tSMP_INT_DATA* p_data) {
  mock_function_count_map[__func__]++;
}
void smp_br_process_link_key(tSMP_CB* p_cb, tSMP_INT_DATA* p_data) {
  mock_function_count_map[__func__]++;
}
void smp_br_process_pairing_command(tSMP_CB* p_cb, tSMP_INT_DATA* p_data) {
  mock_function_count_map[__func__]++;
}
void smp_br_process_peripheral_keys_response(tSMP_CB* p_cb,
                                             tSMP_INT_DATA* p_data) {
  mock_function_count_map[__func__]++;
}
void smp_br_process_security_grant(tSMP_CB* p_cb, tSMP_INT_DATA* p_data) {
  mock_function_count_map[__func__]++;
}
void smp_br_select_next_key(tSMP_CB* p_cb, tSMP_INT_DATA* p_data) {
  mock_function_count_map[__func__]++;
}
void smp_br_send_pair_response(tSMP_CB* p_cb, tSMP_INT_DATA* p_data) {
  mock_function_count_map[__func__]++;
}
void smp_cancel_start_encryption_attempt() {
  mock_function_count_map[__func__]++;
}
void smp_check_auth_req(tSMP_CB* p_cb, tSMP_INT_DATA* p_data) {
  mock_function_count_map[__func__]++;
}
void smp_decide_association_model(tSMP_CB* p_cb, tSMP_INT_DATA* p_data) {
  mock_function_count_map[__func__]++;
}
void smp_derive_link_key_from_long_term_key(tSMP_CB* p_cb,
                                            tSMP_INT_DATA* p_data) {
  mock_function_count_map[__func__]++;
}
void smp_enc_cmpl(tSMP_CB* p_cb, tSMP_INT_DATA* p_data) {
  mock_function_count_map[__func__]++;
}
void smp_idle_terminate(tSMP_CB* p_cb, tSMP_INT_DATA* p_data) {
  mock_function_count_map[__func__]++;
}
void smp_key_distribution(tSMP_CB* p_cb, tSMP_INT_DATA* p_data) {
  mock_function_count_map[__func__]++;
}
void smp_key_distribution_by_transport(tSMP_CB* p_cb, tSMP_INT_DATA* p_data) {
  mock_function_count_map[__func__]++;
}
void smp_key_pick_key(tSMP_CB* p_cb, tSMP_INT_DATA* p_data) {
  mock_function_count_map[__func__]++;
}
void smp_link_encrypted(const RawAddress& bda, uint8_t encr_enable) {
  mock_function_count_map[__func__]++;
}
void smp_match_dhkey_checks(tSMP_CB* p_cb, tSMP_INT_DATA* p_data) {
  mock_function_count_map[__func__]++;
}
void smp_move_to_secure_connections_phase2(tSMP_CB* p_cb,
                                           tSMP_INT_DATA* p_data) {
  mock_function_count_map[__func__]++;
}
void smp_pair_terminate(tSMP_CB* p_cb, tSMP_INT_DATA* p_data) {
  mock_function_count_map[__func__]++;
}
void smp_pairing_cmpl(tSMP_CB* p_cb, tSMP_INT_DATA* p_data) {
  mock_function_count_map[__func__]++;
}
void smp_phase_2_dhkey_checks_are_present(tSMP_CB* p_cb,
                                          tSMP_INT_DATA* p_data) {
  mock_function_count_map[__func__]++;
}
void smp_proc_central_id(tSMP_CB* p_cb, tSMP_INT_DATA* p_data) {
  mock_function_count_map[__func__]++;
}
void smp_proc_compare(tSMP_CB* p_cb, tSMP_INT_DATA* p_data) {
  mock_function_count_map[__func__]++;
}
void smp_proc_confirm(tSMP_CB* p_cb, tSMP_INT_DATA* p_data) {
  mock_function_count_map[__func__]++;
}
void smp_proc_discard(tSMP_CB* p_cb, tSMP_INT_DATA* p_data) {
  mock_function_count_map[__func__]++;
}
void smp_proc_enc_info(tSMP_CB* p_cb, tSMP_INT_DATA* p_data) {
  mock_function_count_map[__func__]++;
}
void smp_proc_id_addr(tSMP_CB* p_cb, tSMP_INT_DATA* p_data) {
  mock_function_count_map[__func__]++;
}
void smp_proc_id_info(tSMP_CB* p_cb, tSMP_INT_DATA* p_data) {
  mock_function_count_map[__func__]++;
}
void smp_proc_init(tSMP_CB* p_cb, tSMP_INT_DATA* p_data) {
  mock_function_count_map[__func__]++;
}
void smp_proc_pair_cmd(tSMP_CB* p_cb, tSMP_INT_DATA* p_data) {
  mock_function_count_map[__func__]++;
}
void smp_proc_pair_fail(tSMP_CB* p_cb, tSMP_INT_DATA* p_data) {
  mock_function_count_map[__func__]++;
}
void smp_proc_rand(tSMP_CB* p_cb, tSMP_INT_DATA* p_data) {
  mock_function_count_map[__func__]++;
}
void smp_proc_sec_grant(tSMP_CB* p_cb, tSMP_INT_DATA* p_data) {
  mock_function_count_map[__func__]++;
}
void smp_proc_sec_req(tSMP_CB* p_cb, tSMP_INT_DATA* p_data) {
  mock_function_count_map[__func__]++;
}
void smp_proc_sl_key(tSMP_CB* p_cb, tSMP_INT_DATA* p_data) {
  mock_function_count_map[__func__]++;
}
void smp_proc_srk_info(tSMP_CB* p_cb, tSMP_INT_DATA* p_data) {
  mock_function_count_map[__func__]++;
}
void smp_process_dhkey_check(tSMP_CB* p_cb, tSMP_INT_DATA* p_data) {
  mock_function_count_map[__func__]++;
}
void smp_process_io_response(tSMP_CB* p_cb, tSMP_INT_DATA* p_data) {
  mock_function_count_map[__func__]++;
}
void smp_process_keypress_notification(tSMP_CB* p_cb, tSMP_INT_DATA* p_data) {
  mock_function_count_map[__func__]++;
}
void smp_process_local_nonce(tSMP_CB* p_cb, tSMP_INT_DATA* p_data) {
  mock_function_count_map[__func__]++;
}
void smp_process_pairing_commitment(tSMP_CB* p_cb, tSMP_INT_DATA* p_data) {
  mock_function_count_map[__func__]++;
}
void smp_process_pairing_public_key(tSMP_CB* p_cb, tSMP_INT_DATA* p_data) {
  mock_function_count_map[__func__]++;
}
void smp_process_peer_nonce(tSMP_CB* p_cb, tSMP_INT_DATA* p_data) {
  mock_function_count_map[__func__]++;
}
void smp_process_secure_connection_long_term_key(void) {
  mock_function_count_map[__func__]++;
}
void smp_process_secure_connection_oob_data(tSMP_CB* p_cb,
                                            tSMP_INT_DATA* p_data) {
  mock_function_count_map[__func__]++;
}
void smp_send_app_cback(tSMP_CB* p_cb, tSMP_INT_DATA* p_data) {
  mock_function_count_map[__func__]++;
}
void smp_send_commitment(tSMP_CB* p_cb, tSMP_INT_DATA* p_data) {
  mock_function_count_map[__func__]++;
}
void smp_send_confirm(tSMP_CB* p_cb, tSMP_INT_DATA* p_data) {
  mock_function_count_map[__func__]++;
}
void smp_send_csrk_info(tSMP_CB* p_cb, tSMP_INT_DATA* p_data) {
  mock_function_count_map[__func__]++;
}
void smp_send_dhkey_check(tSMP_CB* p_cb, tSMP_INT_DATA* p_data) {
  mock_function_count_map[__func__]++;
}
void smp_send_enc_info(tSMP_CB* p_cb, tSMP_INT_DATA* p_data) {
  mock_function_count_map[__func__]++;
}
void smp_send_id_info(tSMP_CB* p_cb, tSMP_INT_DATA* p_data) {
  mock_function_count_map[__func__]++;
}
void smp_send_init(tSMP_CB* p_cb, tSMP_INT_DATA* p_data) {
  mock_function_count_map[__func__]++;
}
void smp_send_keypress_notification(tSMP_CB* p_cb, tSMP_INT_DATA* p_data) {
  mock_function_count_map[__func__]++;
}
void smp_send_ltk_reply(tSMP_CB* p_cb, tSMP_INT_DATA* p_data) {
  mock_function_count_map[__func__]++;
}
void smp_send_pair_fail(tSMP_CB* p_cb, tSMP_INT_DATA* p_data) {
  mock_function_count_map[__func__]++;
}
void smp_send_pair_public_key(tSMP_CB* p_cb, tSMP_INT_DATA* p_data) {
  mock_function_count_map[__func__]++;
}
void smp_send_pair_req(tSMP_CB* p_cb, tSMP_INT_DATA* p_data) {
  mock_function_count_map[__func__]++;
}
void smp_send_pair_rsp(tSMP_CB* p_cb, tSMP_INT_DATA* p_data) {
  mock_function_count_map[__func__]++;
}
void smp_send_rand(tSMP_CB* p_cb, tSMP_INT_DATA* p_data) {
  mock_function_count_map[__func__]++;
}
void smp_set_derive_link_key(tSMP_CB* p_cb, tSMP_INT_DATA* p_data) {
  mock_function_count_map[__func__]++;
}
void smp_set_local_oob_keys(tSMP_CB* p_cb, tSMP_INT_DATA* p_data) {
  mock_function_count_map[__func__]++;
}
void smp_set_local_oob_random_commitment(tSMP_CB* p_cb, tSMP_INT_DATA* p_data) {
  mock_function_count_map[__func__]++;
}
void smp_start_enc(tSMP_CB* p_cb, tSMP_INT_DATA* p_data) {
  mock_function_count_map[__func__]++;
}
void smp_start_passkey_verification(tSMP_CB* p_cb, tSMP_INT_DATA* p_data) {
  mock_function_count_map[__func__]++;
}
void smp_start_secure_connection_phase1(tSMP_CB* p_cb, tSMP_INT_DATA* p_data) {
  mock_function_count_map[__func__]++;
}
void smp_wait_for_both_public_keys(tSMP_CB* p_cb, tSMP_INT_DATA* p_data) {
  mock_function_count_map[__func__]++;
}
