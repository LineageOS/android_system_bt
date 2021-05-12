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
 *   Functions generated:10
 *
 *  mockcify.pl ver 0.2
 */

#include <cstdint>
#include <functional>
#include <map>
#include <string>

extern std::map<std::string, int> mock_function_count_map;

// Mock include file to share data between tests and mock
#include "test/mock/mock_main_shim_link_policy.h"

// Mocked compile conditionals, if any
#ifndef UNUSED_ATTR
#define UNUSED_ATTR
#endif

// Mocked internal structures, if any

namespace test {
namespace mock {
namespace main_shim_link_policy {

// Function state capture and return values, if needed
struct set_active_mode set_active_mode;
struct set_hold_mode set_hold_mode;
struct set_sniff_mode set_sniff_mode;
struct controller_supports_link_policy_mode
    controller_supports_link_policy_mode;
struct RegisterLinkPolicyClient RegisterLinkPolicyClient;
struct UnregisterLinkPolicyClient UnregisterLinkPolicyClient;
struct BTM_SetPowerMode BTM_SetPowerMode;
struct btm_pm_on_mode_change btm_pm_on_mode_change;
struct BTM_SetSsrParams BTM_SetSsrParams;
struct btm_pm_on_sniff_subrating btm_pm_on_sniff_subrating;

}  // namespace main_shim_link_policy
}  // namespace mock
}  // namespace test

// Mocked functions, if any
tBTM_STATUS set_active_mode(tACL_CONN& p_acl) {
  mock_function_count_map[__func__]++;
  return test::mock::main_shim_link_policy::set_active_mode(p_acl);
}
tBTM_STATUS set_hold_mode(tACL_CONN& p_acl, uint16_t max, uint16_t min) {
  mock_function_count_map[__func__]++;
  return test::mock::main_shim_link_policy::set_hold_mode(p_acl, max, min);
}
tBTM_STATUS set_sniff_mode(tACL_CONN& p_acl, uint16_t max_interval,
                           uint16_t min_interval, uint16_t attempt,
                           uint16_t timeout) {
  mock_function_count_map[__func__]++;
  return test::mock::main_shim_link_policy::set_sniff_mode(
      p_acl, max_interval, min_interval, attempt, timeout);
}
bool controller_supports_link_policy_mode(const tBTM_PM_MODE& mode,
                                          bool interop_check) {
  mock_function_count_map[__func__]++;
  return test::mock::main_shim_link_policy::
      controller_supports_link_policy_mode(mode, interop_check);
}
bool bluetooth::shim::RegisterLinkPolicyClient(tBTM_PM_STATUS_CBACK* p_cb) {
  mock_function_count_map[__func__]++;
  return test::mock::main_shim_link_policy::RegisterLinkPolicyClient(p_cb);
}
bool bluetooth::shim::UnregisterLinkPolicyClient(tBTM_PM_STATUS_CBACK* p_cb) {
  mock_function_count_map[__func__]++;
  return test::mock::main_shim_link_policy::UnregisterLinkPolicyClient(p_cb);
}
tBTM_STATUS bluetooth::shim::BTM_SetPowerMode(uint16_t handle,
                                              const tBTM_PM_PWR_MD& new_mode) {
  mock_function_count_map[__func__]++;
  return test::mock::main_shim_link_policy::BTM_SetPowerMode(handle, new_mode);
}
void bluetooth::shim::btm_pm_on_mode_change(tHCI_STATUS status, uint16_t handle,
                                            tHCI_MODE hci_mode,
                                            uint16_t interval) {
  mock_function_count_map[__func__]++;
  test::mock::main_shim_link_policy::btm_pm_on_mode_change(status, handle,
                                                           hci_mode, interval);
}
tBTM_STATUS bluetooth::shim::BTM_SetSsrParams(uint16_t handle, uint16_t max_lat,
                                              uint16_t min_rmt_to,
                                              uint16_t min_loc_to) {
  mock_function_count_map[__func__]++;
  return test::mock::main_shim_link_policy::BTM_SetSsrParams(
      handle, max_lat, min_rmt_to, min_loc_to);
}
void bluetooth::shim::btm_pm_on_sniff_subrating(
    tHCI_STATUS status, uint16_t handle, uint16_t maximum_transmit_latency,
    UNUSED_ATTR uint16_t maximum_receive_latency,
    uint16_t minimum_remote_timeout, uint16_t minimum_local_timeout) {
  mock_function_count_map[__func__]++;
  test::mock::main_shim_link_policy::btm_pm_on_sniff_subrating(
      status, handle, maximum_transmit_latency, maximum_receive_latency,
      minimum_remote_timeout, minimum_local_timeout);
}

// END mockcify generation
