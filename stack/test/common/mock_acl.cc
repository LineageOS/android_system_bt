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

#include <map>
#include <string>

extern std::map<std::string, int> mock_function_count_map;

#define LOG_TAG "bt_shim"
#include "gd/common/init_flags.h"
#include "main/shim/entry.h"
#include "main/shim/shim.h"
#include "types/raw_address.h"

#ifndef UNUSED_ATTR
#define UNUSED_ATTR
#endif

void acl_add_to_ignore_auto_connect_after_disconnect(
    const RawAddress& bd_addr) {
  mock_function_count_map[__func__]++;
}

bool acl_check_and_clear_ignore_auto_connect_after_disconnect(
    const RawAddress& bd_addr) {
  mock_function_count_map[__func__]++;
  return false;
}

void acl_clear_all_ignore_auto_connect_after_disconnect() {
  mock_function_count_map[__func__]++;
}
