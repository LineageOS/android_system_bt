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
 *   Functions generated:11
 */

#include <map>
#include <string>

extern std::map<std::string, int> mock_function_count_map;

#include <base/logging.h>
#include <string.h>
#include "bnep_api.h"
#include "bt_common.h"
#include "bt_types.h"
#include "btm_api.h"
#include "hcidefs.h"
#include "l2c_api.h"
#include "pan_api.h"
#include "sdp_api.h"
#include "sdpdefs.h"
#include "stack/btm/btm_sec.h"
#include "stack/pan/pan_int.h"

#ifndef UNUSED_ATTR
#define UNUSED_ATTR
#endif

tBNEP_RESULT PAN_SetMulticastFilters(uint16_t handle,
                                     uint16_t num_mcast_filters,
                                     uint8_t* p_start_array,
                                     uint8_t* p_end_array) {
  mock_function_count_map[__func__]++;
  return 0;
}
tPAN_RESULT PAN_Connect(const RawAddress& rem_bda, uint8_t src_role,
                        uint8_t dst_role, uint16_t* handle) {
  mock_function_count_map[__func__]++;
  return 0;
}
tPAN_RESULT PAN_Disconnect(uint16_t handle) {
  mock_function_count_map[__func__]++;
  return 0;
}
tPAN_RESULT PAN_SetProtocolFilters(uint16_t handle, uint16_t num_filters,
                                   uint16_t* p_start_array,
                                   uint16_t* p_end_array) {
  mock_function_count_map[__func__]++;
  return 0;
}
tPAN_RESULT PAN_SetRole(uint8_t role, const char* p_user_name,
                        const char* p_nap_name) {
  mock_function_count_map[__func__]++;
  return 0;
}
tPAN_RESULT PAN_Write(uint16_t handle, const RawAddress& dst,
                      const RawAddress& src, uint16_t protocol, uint8_t* p_data,
                      uint16_t len, bool ext) {
  mock_function_count_map[__func__]++;
  return 0;
}
tPAN_RESULT PAN_WriteBuf(uint16_t handle, const RawAddress& dst,
                         const RawAddress& src, uint16_t protocol,
                         BT_HDR* p_buf, bool ext) {
  mock_function_count_map[__func__]++;
  return 0;
}
uint8_t PAN_SetTraceLevel(uint8_t new_level) {
  mock_function_count_map[__func__]++;
  return 0;
}
void PAN_Deregister(void) { mock_function_count_map[__func__]++; }
void PAN_Init(void) { mock_function_count_map[__func__]++; }
void PAN_Register(tPAN_REGISTER* p_register) {
  mock_function_count_map[__func__]++;
}
