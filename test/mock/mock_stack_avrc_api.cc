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
 *   Functions generated:14
 */

#include <map>
#include <string>

extern std::map<std::string, int> mock_function_count_map;

#include <base/logging.h>
#include <string.h>
#include "bt_common.h"
#include "osi/include/fixed_queue.h"
#include "osi/include/log.h"
#include "osi/include/osi.h"
#include "osi/include/properties.h"
#include "stack/avrc/avrc_int.h"
#include "stack/include/avrc_api.h"
#include "stack/include/btu.h"

#ifndef UNUSED_ATTR
#define UNUSED_ATTR
#endif

uint16_t AVRC_Close(uint8_t handle) {
  mock_function_count_map[__func__]++;
  return 0;
}
uint16_t AVRC_CloseBrowse(uint8_t handle) {
  mock_function_count_map[__func__]++;
  return 0;
}
uint16_t AVRC_GetProfileVersion() {
  mock_function_count_map[__func__]++;
  return 0;
}
uint16_t AVRC_MsgReq(uint8_t handle, uint8_t label, uint8_t ctype,
                     BT_HDR* p_pkt) {
  mock_function_count_map[__func__]++;
  return 0;
}
uint16_t AVRC_Open(uint8_t* p_handle, tAVRC_CONN_CB* p_ccb,
                   const RawAddress& peer_addr) {
  mock_function_count_map[__func__]++;
  return 0;
}
uint16_t AVRC_OpenBrowse(uint8_t handle, uint8_t conn_role) {
  mock_function_count_map[__func__]++;
  return 0;
}
uint16_t AVRC_PassCmd(uint8_t handle, uint8_t label, tAVRC_MSG_PASS* p_msg) {
  mock_function_count_map[__func__]++;
  return 0;
}
uint16_t AVRC_PassRsp(uint8_t handle, uint8_t label, tAVRC_MSG_PASS* p_msg) {
  mock_function_count_map[__func__]++;
  return 0;
}
void avrc_flush_cmd_q(uint8_t handle) { mock_function_count_map[__func__]++; }
void avrc_process_timeout(void* data) { mock_function_count_map[__func__]++; }
void avrc_send_next_vendor_cmd(uint8_t handle) {
  mock_function_count_map[__func__]++;
}
void avrc_start_cmd_timer(uint8_t handle, uint8_t label, uint8_t msg_mask) {
  mock_function_count_map[__func__]++;
}
