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
 *   Functions generated:8
 */

#include <map>
#include <string>

extern std::map<std::string, int> mock_function_count_map;

#include <base/logging.h>
#include <dlfcn.h>
#include <string.h>
#include <mutex>
#include <unordered_map>
#include "btcore/include/module.h"
#include "common/message_loop_thread.h"
#include "osi/include/allocator.h"
#include "osi/include/log.h"
#include "osi/include/osi.h"

#ifndef UNUSED_ATTR
#define UNUSED_ATTR
#endif

bool module_init(const module_t* module) {
  mock_function_count_map[__func__]++;
  return false;
}
bool module_start_up(const module_t* module) {
  mock_function_count_map[__func__]++;
  return false;
}
const module_t* get_module(const char* name) {
  mock_function_count_map[__func__]++;
  return nullptr;
}
void module_management_start(void) { mock_function_count_map[__func__]++; }
void module_clean_up(const module_t* module) {
  mock_function_count_map[__func__]++;
}
void module_management_stop(void) { mock_function_count_map[__func__]++; }
void module_shut_down(const module_t* module) {
  mock_function_count_map[__func__]++;
}
