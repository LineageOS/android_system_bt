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
 *   Functions generated:4
 */

#include <map>
#include <string>

extern std::map<std::string, int> mock_function_count_map;

#include <base/bind.h>
#include <base/callback.h>
#include <base/location.h>
#include <base/logging.h>
#include <map>
#include <memory>
#include <set>
#include "internal_include/bt_trace.h"
#include "main/shim/shim.h"
#include "osi/include/alarm.h"
#include "osi/include/log.h"
#include "stack/btm/btm_ble_bgconn.h"
#include "stack/gatt/connection_manager.h"
#include "stack/include/l2c_api.h"

#ifndef UNUSED_ATTR
#define UNUSED_ATTR
#endif

bool connection_manager::direct_connect_add(uint8_t app_id,
                                            const RawAddress& address) {
  mock_function_count_map[__func__]++;
  return false;
}
bool connection_manager::direct_connect_remove(uint8_t app_id,
                                               const RawAddress& address) {
  mock_function_count_map[__func__]++;
  return false;
}
void connection_manager::on_connection_complete(const RawAddress& address) {
  mock_function_count_map[__func__]++;
}
void connection_manager::reset(bool) { mock_function_count_map[__func__]++; }
