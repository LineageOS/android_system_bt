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
 *   Functions generated:9
 */

#include <map>
#include <string>

extern std::map<std::string, int> mock_function_count_map;

#include <string.h>
#include "avct_api.h"
#include "bt_common.h"
#include "bt_target.h"
#include "bt_types.h"
#include "bt_utils.h"
#include "bta/include/bta_api.h"
#include "btm_api.h"
#include "l2c_api.h"
#include "l2cdefs.h"
#include "osi/include/osi.h"
#include "stack/avct/avct_int.h"
#include "stack/btm/btm_sec.h"

#ifndef UNUSED_ATTR
#define UNUSED_ATTR
#endif

uint16_t AVCT_CreateBrowse(uint8_t handle, uint8_t role) {
  mock_function_count_map[__func__]++;
  return 0;
}
uint16_t AVCT_CreateConn(uint8_t* p_handle, tAVCT_CC* p_cc,
                         const RawAddress& peer_addr) {
  mock_function_count_map[__func__]++;
  return 0;
}
uint16_t AVCT_GetBrowseMtu(uint8_t handle) {
  mock_function_count_map[__func__]++;
  return 0;
}
uint16_t AVCT_GetPeerMtu(uint8_t handle) {
  mock_function_count_map[__func__]++;
  return 0;
}
uint16_t AVCT_MsgReq(uint8_t handle, uint8_t label, uint8_t cr, BT_HDR* p_msg) {
  mock_function_count_map[__func__]++;
  return 0;
}
uint16_t AVCT_RemoveBrowse(uint8_t handle) {
  mock_function_count_map[__func__]++;
  return 0;
}
uint16_t AVCT_RemoveConn(uint8_t handle) {
  mock_function_count_map[__func__]++;
  return 0;
}
void AVCT_Deregister(void) { mock_function_count_map[__func__]++; }
void AVCT_Register() { mock_function_count_map[__func__]++; }
