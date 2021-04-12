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
 *   Functions generated:3
 */

#include <map>
#include <string>

extern std::map<std::string, int> mock_function_count_map;

#include "btif/include/btif_common.h"
#include "gd/common/init_flags.h"
#include "include/hardware/ble_advertiser.h"
#include "main/shim/le_advertising_manager.h"
#include "stack/include/ble_advertiser.h"

#include <vector>

#ifndef UNUSED_ATTR
#define UNUSED_ATTR
#endif

BleAdvertiserInterface* bluetooth::shim::get_ble_advertiser_instance() {
  mock_function_count_map[__func__]++;
  return nullptr;
}
void bluetooth::shim::init_advertising_manager() {
  mock_function_count_map[__func__]++;
}
