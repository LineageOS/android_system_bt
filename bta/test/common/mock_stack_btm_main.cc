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
 *   Functions generated:7
 */

#include <map>
#include <string>

extern std::map<std::string, int> mock_function_count_map;

#include <memory>
#include <string>
#include "bt_target.h"
#include "bt_types.h"
#include "main/shim/dumpsys.h"
#include "stack/btm/btm_int_types.h"
#include "stack/include/btm_client_interface.h"
#include "stack_config.h"

#ifndef UNUSED_ATTR
#define UNUSED_ATTR
#endif

void BTM_LogHistory(const std::string& tag, const RawAddress& bd_addr,
                    const std::string& msg) {
  mock_function_count_map[__func__]++;
}
void BTM_LogHistory(const std::string& tag, const RawAddress& bd_addr,
                    const std::string& msg, const std::string& extra) {
  mock_function_count_map[__func__]++;
}
void BTM_LogHistory(const std::string& tag, const tBLE_BD_ADDR& ble_bd_addr,
                    const std::string& msg) {
  mock_function_count_map[__func__]++;
}
void BTM_LogHistory(const std::string& tag, const tBLE_BD_ADDR& ble_bd_addr,
                    const std::string& msg, const std::string& extra) {
  mock_function_count_map[__func__]++;
}
void btm_free(void) { mock_function_count_map[__func__]++; }
void btm_init(void) { mock_function_count_map[__func__]++; }
