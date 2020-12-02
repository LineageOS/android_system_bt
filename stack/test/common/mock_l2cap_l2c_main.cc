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
 *   Functions generated:9
 */

#include <map>
#include <string>

extern std::map<std::string, int> mock_function_count_map;

#include <string.h>
#include "bt_common.h"
#include "bt_target.h"
#include "hci/include/btsnoop.h"
#include "hcimsgs.h"
#include "main/shim/shim.h"
#include "osi/include/log.h"
#include "osi/include/osi.h"
#include "stack/include/l2c_api.h"
#include "stack/include/l2cdefs.h"
#include "stack/l2cap/l2c_int.h"

#ifndef UNUSED_ATTR
#define UNUSED_ATTR
#endif

uint8_t l2c_data_write(uint16_t cid, BT_HDR* p_data, uint16_t flags) {
  mock_function_count_map[__func__]++;
  return 0;
}
void l2c_ccb_timer_timeout(void* data) { mock_function_count_map[__func__]++; }
void l2c_fcrb_ack_timer_timeout(void* data) {
  mock_function_count_map[__func__]++;
}
void l2c_free(void) { mock_function_count_map[__func__]++; }
void l2c_init(void) { mock_function_count_map[__func__]++; }
void l2c_lcb_timer_timeout(void* data) { mock_function_count_map[__func__]++; }
void l2c_process_held_packets(bool timed_out) {
  mock_function_count_map[__func__]++;
}
void l2c_rcv_acl_data(BT_HDR* p_msg) { mock_function_count_map[__func__]++; }
void l2c_receive_hold_timer_timeout(UNUSED_ATTR void* data) {
  mock_function_count_map[__func__]++;
}
