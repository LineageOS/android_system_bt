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

#include <cstdint>
#include "bt_target.h"

#ifndef UNUSED_ATTR
#define UNUSED_ATTR
#endif

#include "bta/pan/bta_pan_int.h"

void BTA_PanClose(uint16_t handle) { mock_function_count_map[__func__]++; }
void BTA_PanDisable(void) { mock_function_count_map[__func__]++; }
void BTA_PanEnable(tBTA_PAN_CBACK p_cback) {
  mock_function_count_map[__func__]++;
}
void BTA_PanOpen(const RawAddress& bd_addr, tBTA_PAN_ROLE local_role,
                 tBTA_PAN_ROLE peer_role) {
  mock_function_count_map[__func__]++;
}
void BTA_PanSetRole(tBTA_PAN_ROLE role, tBTA_PAN_ROLE_INFO* p_user_info,
                    tBTA_PAN_ROLE_INFO* p_nap_info) {
  mock_function_count_map[__func__]++;
}
