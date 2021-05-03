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
 *   Functions generated:10
 */

#include <map>
#include <string>

extern std::map<std::string, int> mock_function_count_map;

#include <cstdint>
#include "stack/gatt/gatt_int.h"

#ifndef UNUSED_ATTR
#define UNUSED_ATTR
#endif

bool gatt_security_check_start(tGATT_CLCB* p_clcb) {
  mock_function_count_map[__func__]++;
  return false;
}
tGATT_SEC_ACTION gatt_determine_sec_act(tGATT_CLCB* p_clcb) {
  mock_function_count_map[__func__]++;
  return GATT_SEC_NONE;
}
tGATT_SEC_ACTION gatt_get_sec_act(tGATT_TCB* p_tcb) {
  mock_function_count_map[__func__]++;
  return GATT_SEC_NONE;
}
tGATT_STATUS gatt_get_link_encrypt_status(tGATT_TCB& tcb) {
  mock_function_count_map[__func__]++;
  return GATT_SUCCESS;
}
void gatt_enc_cmpl_cback(const RawAddress* bd_addr, tBT_TRANSPORT transport,
                         UNUSED_ATTR void* p_ref_data, tBTM_STATUS result) {
  mock_function_count_map[__func__]++;
}
void gatt_notify_enc_cmpl(const RawAddress& bd_addr) {
  mock_function_count_map[__func__]++;
}
void gatt_sec_check_complete(bool sec_check_ok, tGATT_CLCB* p_clcb,
                             uint8_t sec_act) {
  mock_function_count_map[__func__]++;
}
void gatt_set_sec_act(tGATT_TCB* p_tcb, tGATT_SEC_ACTION sec_act) {
  mock_function_count_map[__func__]++;
}
void gatt_verify_signature(tGATT_TCB& tcb, uint16_t cid, BT_HDR* p_buf) {
  mock_function_count_map[__func__]++;
}
