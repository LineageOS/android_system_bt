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

#include <cstddef>
#include <cstdint>
#include <map>
#include <string>

extern std::map<std::string, int> mock_function_count_map;

#include "device/include/interop.h"
#include "types/raw_address.h"

#ifndef UNUSED_ATTR
#define UNUSED_ATTR
#endif

bool interop_match_addr(const interop_feature_t feature,
                        const RawAddress* addr) {
  mock_function_count_map[__func__]++;
  return false;
}
bool interop_match_name(const interop_feature_t feature, const char* name) {
  mock_function_count_map[__func__]++;
  return false;
}
void interop_database_add(uint16_t feature, const RawAddress* addr,
                          size_t length) {
  mock_function_count_map[__func__]++;
}
void interop_database_clear() { mock_function_count_map[__func__]++; }
