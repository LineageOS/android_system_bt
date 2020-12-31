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
 *   Functions generated:14
 */

#include <cstdint>
#include <map>
#include <string>

extern std::map<std::string, int> mock_function_count_map;

#define LOG_TAG "bt_shim"

#include "main/shim/link_policy.h"
#include "stack/include/btm_api_types.h"
#include "types/raw_address.h"

#ifndef UNUSED_ATTR
#define UNUSED_ATTR
#endif

bool bluetooth::shim::UnregisterLinkPolicyClient(tBTM_PM_STATUS_CBACK* p_cb) {
  mock_function_count_map[__func__]++;
  return false;
}
bool bluetooth::shim::RegisterLinkPolicyClient(tBTM_PM_STATUS_CBACK* p_cb) {
  mock_function_count_map[__func__]++;
  return false;
}
