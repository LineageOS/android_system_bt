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

// Original included files, if any
// NOTE: Since this is a mock file with mock definitions some number of
//       include files may not be required.  The include-what-you-use
//       still applies, but crafting proper inclusion is out of scope
//       for this effort.  This compilation unit may compile as-is, or
//       may need attention to prune the inclusion set.
#include <base/bind.h>
#include <base/location.h>
#include <base/strings/stringprintf.h>
#include <cstdint>
#include <memory>
#include "device/include/interop.h"
#include "gd/module.h"
#include "hci/controller.h"
#include "main/shim/controller.h"
#include "main/shim/dumpsys.h"
#include "main/shim/link_policy.h"
#include "main/shim/stack.h"
#include "osi/include/log.h"
#include "stack/btm/btm_int_types.h"
#include "stack/include/btm_api.h"
#include "stack/include/btm_api_types.h"
#include "stack/include/btm_ble_api_types.h"
#include "stack/include/hci_error_code.h"
#include "stack/include/hcidefs.h"

// Mocked compile conditionals, if any
#ifndef UNUSED_ATTR
#define UNUSED_ATTR
#endif

namespace test {
namespace mock {
namespace main_shim_link_policy {

// Shared state between mocked functions and tests
// Name: set_active_mode
// Params: tACL_CONN& p_acl
// Returns: tBTM_STATUS
struct set_active_mode {
  std::function<tBTM_STATUS(tACL_CONN& p_acl)> body{
      [](tACL_CONN& p_acl) { return 0; }};
  tBTM_STATUS operator()(tACL_CONN& p_acl) { return body(p_acl); };
};
extern struct set_active_mode set_active_mode;
// Name: set_hold_mode
// Params: tACL_CONN& p_acl, uint16_t max, uint16_t min
// Returns: tBTM_STATUS
struct set_hold_mode {
  std::function<tBTM_STATUS(tACL_CONN& p_acl, uint16_t max, uint16_t min)> body{
      [](tACL_CONN& p_acl, uint16_t max, uint16_t min) { return 0; }};
  tBTM_STATUS operator()(tACL_CONN& p_acl, uint16_t max, uint16_t min) {
    return body(p_acl, max, min);
  };
};
extern struct set_hold_mode set_hold_mode;
// Name: set_sniff_mode
// Params: tACL_CONN& p_acl, uint16_t max_interval, uint16_t min_interval,
// uint16_t attempt, uint16_t timeout Returns: tBTM_STATUS
struct set_sniff_mode {
  std::function<tBTM_STATUS(tACL_CONN& p_acl, uint16_t max_interval,
                            uint16_t min_interval, uint16_t attempt,
                            uint16_t timeout)>
      body{[](tACL_CONN& p_acl, uint16_t max_interval, uint16_t min_interval,
              uint16_t attempt, uint16_t timeout) { return 0; }};
  tBTM_STATUS operator()(tACL_CONN& p_acl, uint16_t max_interval,
                         uint16_t min_interval, uint16_t attempt,
                         uint16_t timeout) {
    return body(p_acl, max_interval, min_interval, attempt, timeout);
  };
};
extern struct set_sniff_mode set_sniff_mode;
// Name: controller_supports_link_policy_mode
// Params: const tBTM_PM_MODE& mode, bool interop_check
// Returns: bool
struct controller_supports_link_policy_mode {
  std::function<bool(const tBTM_PM_MODE& mode, bool interop_check)> body{
      [](const tBTM_PM_MODE& mode, bool interop_check) { return false; }};
  bool operator()(const tBTM_PM_MODE& mode, bool interop_check) {
    return body(mode, interop_check);
  };
};
extern struct controller_supports_link_policy_mode
    controller_supports_link_policy_mode;
// Name: bluetooth::shim::RegisterLinkPolicyClient
// Params: tBTM_PM_STATUS_CBACK* p_cb
// Returns: bool
struct RegisterLinkPolicyClient {
  std::function<bool(tBTM_PM_STATUS_CBACK* p_cb)> body{
      [](tBTM_PM_STATUS_CBACK* p_cb) { return false; }};
  bool operator()(tBTM_PM_STATUS_CBACK* p_cb) { return body(p_cb); };
};
extern struct RegisterLinkPolicyClient RegisterLinkPolicyClient;
// Name: bluetooth::shim::UnregisterLinkPolicyClient
// Params: tBTM_PM_STATUS_CBACK* p_cb
// Returns: bool
struct UnregisterLinkPolicyClient {
  std::function<bool(tBTM_PM_STATUS_CBACK* p_cb)> body{
      [](tBTM_PM_STATUS_CBACK* p_cb) { return false; }};
  bool operator()(tBTM_PM_STATUS_CBACK* p_cb) { return body(p_cb); };
};
extern struct UnregisterLinkPolicyClient UnregisterLinkPolicyClient;
// Name: bluetooth::shim::BTM_SetPowerMode
// Params: uint16_t handle, const tBTM_PM_PWR_MD& new_mode
// Returns: tBTM_STATUS
struct BTM_SetPowerMode {
  std::function<tBTM_STATUS(uint16_t handle, const tBTM_PM_PWR_MD& new_mode)>
      body{[](uint16_t handle, const tBTM_PM_PWR_MD& new_mode) { return 0; }};
  tBTM_STATUS operator()(uint16_t handle, const tBTM_PM_PWR_MD& new_mode) {
    return body(handle, new_mode);
  };
};
extern struct BTM_SetPowerMode BTM_SetPowerMode;
// Name: bluetooth::shim::btm_pm_on_mode_change
// Params: tHCI_STATUS status, uint16_t handle, tHCI_MODE hci_mode, uint16_t
// interval Returns: void
struct btm_pm_on_mode_change {
  std::function<void(tHCI_STATUS status, uint16_t handle, tHCI_MODE hci_mode,
                     uint16_t interval)>
      body{[](tHCI_STATUS status, uint16_t handle, tHCI_MODE hci_mode,
              uint16_t interval) {}};
  void operator()(tHCI_STATUS status, uint16_t handle, tHCI_MODE hci_mode,
                  uint16_t interval) {
    body(status, handle, hci_mode, interval);
  };
};
extern struct btm_pm_on_mode_change btm_pm_on_mode_change;
// Name: bluetooth::shim::BTM_SetSsrParams
// Params: uint16_t handle, uint16_t max_lat, uint16_t min_rmt_to, uint16_t
// min_loc_to Returns: tBTM_STATUS
struct BTM_SetSsrParams {
  std::function<tBTM_STATUS(uint16_t handle, uint16_t max_lat,
                            uint16_t min_rmt_to, uint16_t min_loc_to)>
      body{[](uint16_t handle, uint16_t max_lat, uint16_t min_rmt_to,
              uint16_t min_loc_to) { return 0; }};
  tBTM_STATUS operator()(uint16_t handle, uint16_t max_lat, uint16_t min_rmt_to,
                         uint16_t min_loc_to) {
    return body(handle, max_lat, min_rmt_to, min_loc_to);
  };
};
extern struct BTM_SetSsrParams BTM_SetSsrParams;
// Name: bluetooth::shim::btm_pm_on_sniff_subrating
// Params:  tHCI_STATUS status, uint16_t handle, uint16_t
// maximum_transmit_latency, UNUSED_ATTR uint16_t maximum_receive_latency,
// uint16_t minimum_remote_timeout, uint16_t minimum_local_timeout Returns: void
struct btm_pm_on_sniff_subrating {
  std::function<void(
      tHCI_STATUS status, uint16_t handle, uint16_t maximum_transmit_latency,
      UNUSED_ATTR uint16_t maximum_receive_latency,
      uint16_t minimum_remote_timeout, uint16_t minimum_local_timeout)>
      body{[](tHCI_STATUS status, uint16_t handle,
              uint16_t maximum_transmit_latency,
              UNUSED_ATTR uint16_t maximum_receive_latency,
              uint16_t minimum_remote_timeout,
              uint16_t minimum_local_timeout) {}};
  void operator()(tHCI_STATUS status, uint16_t handle,
                  uint16_t maximum_transmit_latency,
                  UNUSED_ATTR uint16_t maximum_receive_latency,
                  uint16_t minimum_remote_timeout,
                  uint16_t minimum_local_timeout) {
    body(status, handle, maximum_transmit_latency, maximum_receive_latency,
         minimum_remote_timeout, minimum_local_timeout);
  };
};
extern struct btm_pm_on_sniff_subrating btm_pm_on_sniff_subrating;

}  // namespace main_shim_link_policy
}  // namespace mock
}  // namespace test

// END mockcify generation
