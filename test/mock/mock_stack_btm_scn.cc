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

#include <cstdint>
#include "stack/btm/btm_int_types.h"
#include "stack/include/rfcdefs.h"

#ifndef UNUSED_ATTR
#define UNUSED_ATTR
#endif

bool BTM_FreeSCN(uint8_t scn) {
  mock_function_count_map[__func__]++;
  return false;
}
bool BTM_TryAllocateSCN(uint8_t scn) {
  mock_function_count_map[__func__]++;
  return false;
}
uint8_t BTM_AllocateSCN(void) {
  mock_function_count_map[__func__]++;
  return 0;
}
