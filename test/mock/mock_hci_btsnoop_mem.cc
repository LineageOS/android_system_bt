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

#include <base/logging.h>
#include "gd/common/init_flags.h"
#include "hci/include/btsnoop_mem.h"

#ifndef UNUSED_ATTR
#define UNUSED_ATTR
#endif

void activity_attribution_set_callback(activity_attribution_cb cb) {
  mock_function_count_map[__func__]++;
}
void btsnoop_mem_capture(const BT_HDR* packet, uint64_t timestamp_us) {
  mock_function_count_map[__func__]++;
}
void btsnoop_mem_set_callback(btsnoop_data_cb cb) {
  mock_function_count_map[__func__]++;
}
