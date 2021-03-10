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

#ifndef UNUSED_ATTR
#define UNUSED_ATTR
#endif

extern bool MOCK_bluetooth_shim_is_gd_acl_enabled_;

bool bluetooth::shim::is_any_gd_enabled() {
  mock_function_count_map[__func__]++;
  return false;
}
bool bluetooth::shim::is_gd_acl_enabled() {
  mock_function_count_map[__func__]++;
  return MOCK_bluetooth_shim_is_gd_acl_enabled_;
}
bool bluetooth::shim::is_gd_advertising_enabled() {
  mock_function_count_map[__func__]++;
  return false;
}
bool bluetooth::shim::is_gd_scanning_enabled() {
  mock_function_count_map[__func__]++;
  return false;
}
bool bluetooth::shim::is_gd_controller_enabled() {
  mock_function_count_map[__func__]++;
  return false;
}
bool bluetooth::shim::is_gd_hci_enabled() {
  mock_function_count_map[__func__]++;
  return false;
}
bool bluetooth::shim::is_gd_l2cap_enabled() {
  mock_function_count_map[__func__]++;
  return false;
}
bool bluetooth::shim::is_gd_security_enabled() {
  mock_function_count_map[__func__]++;
  return false;
}
bool bluetooth::shim::is_gd_shim_enabled() {
  mock_function_count_map[__func__]++;
  return false;
}
bool bluetooth::shim::is_gd_stack_started_up() {
  mock_function_count_map[__func__]++;
  return false;
}
bool bluetooth::shim::is_gd_link_policy_enabled() {
  mock_function_count_map[__func__]++;
  return false;
}
future_t* GeneralShutDown() {
  mock_function_count_map[__func__]++;
  return nullptr;
}
future_t* IdleModuleStartUp() {
  mock_function_count_map[__func__]++;
  return nullptr;
}
future_t* ShimModuleStartUp() {
  mock_function_count_map[__func__]++;
  return nullptr;
}
