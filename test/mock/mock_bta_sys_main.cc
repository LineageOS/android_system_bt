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
 *   Functions generated:10
 */

#include <map>
#include <string>

extern std::map<std::string, int> mock_function_count_map;

#include <base/bind.h>
#include <cstring>
#include "bt_target.h"
#include "bta/sys/bta_sys.h"
#include "bta/sys/bta_sys_int.h"
#include "include/hardware/bluetooth.h"
#include "osi/include/alarm.h"
#include "osi/include/allocator.h"
#include "osi/include/log.h"
#include "stack/include/bt_types.h"
#include "stack/include/btu.h"

#ifndef UNUSED_ATTR
#define UNUSED_ATTR
#endif

bool bta_sys_is_register(uint8_t id) {
  mock_function_count_map[__func__]++;
  return false;
}
void BTA_sys_signal_hw_error() { mock_function_count_map[__func__]++; }
void bta_set_forward_hw_failures(bool value) {
  mock_function_count_map[__func__]++;
}
void bta_sys_deregister(uint8_t id) { mock_function_count_map[__func__]++; }
void bta_sys_disable() { mock_function_count_map[__func__]++; }
void bta_sys_init(void) { mock_function_count_map[__func__]++; }
void bta_sys_register(uint8_t id, const tBTA_SYS_REG* p_reg) {
  mock_function_count_map[__func__]++;
}
void bta_sys_sendmsg(void* p_msg) { mock_function_count_map[__func__]++; }
void bta_sys_sendmsg_delayed(void* p_msg, const base::TimeDelta& delay) {
  mock_function_count_map[__func__]++;
}
void bta_sys_start_timer(alarm_t* alarm, uint64_t interval_ms, uint16_t event,
                         uint16_t layer_specific) {
  mock_function_count_map[__func__]++;
}
