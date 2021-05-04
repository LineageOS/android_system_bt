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
 *   Functions generated:6
 */

#include <cstdint>
#include <map>
#include <string>

extern std::map<std::string, int> mock_function_count_map;

#include "stack/include/gap_api.h"
#include "types/raw_address.h"

#ifndef UNUSED_ATTR
#define UNUSED_ATTR
#endif

bool GAP_BleCancelReadPeerDevName(const RawAddress& peer_bda) {
  mock_function_count_map[__func__]++;
  return false;
}
bool GAP_BleReadPeerDevName(const RawAddress& peer_bda,
                            tGAP_BLE_CMPL_CBACK* p_cback) {
  mock_function_count_map[__func__]++;
  return false;
}
bool GAP_BleReadPeerPrefConnParams(const RawAddress& peer_bda) {
  mock_function_count_map[__func__]++;
  return false;
}
void GAP_BleAttrDBUpdate(uint16_t attr_uuid, tGAP_BLE_ATTR_VALUE* p_value) {
  mock_function_count_map[__func__]++;
}
void gap_attr_db_init(void) { mock_function_count_map[__func__]++; }
