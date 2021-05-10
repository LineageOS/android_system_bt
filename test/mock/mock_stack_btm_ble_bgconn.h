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
 *   Functions generated:11
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
#include <cstdint>
#include <unordered_map>
#include "device/include/controller.h"
#include "main/shim/acl_api.h"
#include "main/shim/shim.h"
#include "stack/btm/btm_dev.h"
#include "stack/btm/btm_int_types.h"
#include "stack/btm/security_device_record.h"
#include "stack/include/bt_types.h"
#include "stack/include/hcimsgs.h"
#include "types/raw_address.h"

// Mocked compile conditionals, if any
#ifndef UNUSED_ATTR
#define UNUSED_ATTR
#endif

namespace test {
namespace mock {
namespace stack_btm_ble_bgconn {

// Shared state between mocked functions and tests
// Name: convert_to_address_with_type
// Params:  const RawAddress& bd_addr, const tBTM_SEC_DEV_REC* p_dev_rec
// Returns: const tBLE_BD_ADDR
struct convert_to_address_with_type {
  tBLE_BD_ADDR ble_bd_addr;
  std::function<const tBLE_BD_ADDR(const RawAddress& bd_addr,
                                   const tBTM_SEC_DEV_REC* p_dev_rec)>
      body{[this](const RawAddress& bd_addr,
                  const tBTM_SEC_DEV_REC* p_dev_rec) { return ble_bd_addr; }};
  const tBLE_BD_ADDR operator()(const RawAddress& bd_addr,
                                const tBTM_SEC_DEV_REC* p_dev_rec) {
    return body(bd_addr, p_dev_rec);
  };
};
extern struct convert_to_address_with_type convert_to_address_with_type;
// Name: btm_update_scanner_filter_policy
// Params: tBTM_BLE_SFP scan_policy
// Returns: void
struct btm_update_scanner_filter_policy {
  std::function<void(tBTM_BLE_SFP scan_policy)> body{
      [](tBTM_BLE_SFP scan_policy) {}};
  void operator()(tBTM_BLE_SFP scan_policy) { body(scan_policy); };
};
extern struct btm_update_scanner_filter_policy btm_update_scanner_filter_policy;
// Name: btm_ble_bgconn_cancel_if_disconnected
// Params: const RawAddress& bd_addr
// Returns: void
struct btm_ble_bgconn_cancel_if_disconnected {
  std::function<void(const RawAddress& bd_addr)> body{
      [](const RawAddress& bd_addr) {}};
  void operator()(const RawAddress& bd_addr) { body(bd_addr); };
};
extern struct btm_ble_bgconn_cancel_if_disconnected
    btm_ble_bgconn_cancel_if_disconnected;
// Name: btm_ble_suspend_bg_conn
// Params: void
// Returns: bool
struct btm_ble_suspend_bg_conn {
  std::function<bool(void)> body{[](void) { return false; }};
  bool operator()(void) { return body(); };
};
extern struct btm_ble_suspend_bg_conn btm_ble_suspend_bg_conn;
// Name: btm_ble_resume_bg_conn
// Params: void
// Returns: bool
struct btm_ble_resume_bg_conn {
  std::function<bool(void)> body{[](void) { return false; }};
  bool operator()(void) { return body(); };
};
extern struct btm_ble_resume_bg_conn btm_ble_resume_bg_conn;
// Name: BTM_BackgroundConnectAddressKnown
// Params: const RawAddress& address
// Returns: bool
struct BTM_BackgroundConnectAddressKnown {
  std::function<bool(const RawAddress& address)> body{
      [](const RawAddress& address) { return false; }};
  bool operator()(const RawAddress& address) { return body(address); };
};
extern struct BTM_BackgroundConnectAddressKnown
    BTM_BackgroundConnectAddressKnown;
// Name: BTM_SetLeConnectionModeToFast
// Params:
// Returns: bool
struct BTM_SetLeConnectionModeToFast {
  std::function<bool()> body{[]() { return false; }};
  bool operator()() { return body(); };
};
extern struct BTM_SetLeConnectionModeToFast BTM_SetLeConnectionModeToFast;
// Name: BTM_SetLeConnectionModeToSlow
// Params:
// Returns: void
struct BTM_SetLeConnectionModeToSlow {
  std::function<void()> body{[]() {}};
  void operator()() { body(); };
};
extern struct BTM_SetLeConnectionModeToSlow BTM_SetLeConnectionModeToSlow;
// Name: BTM_AcceptlistAdd
// Params: const RawAddress& address
// Returns: bool
struct BTM_AcceptlistAdd {
  std::function<bool(const RawAddress& address)> body{
      [](const RawAddress& address) { return false; }};
  bool operator()(const RawAddress& address) { return body(address); };
};
extern struct BTM_AcceptlistAdd BTM_AcceptlistAdd;
// Name: BTM_AcceptlistRemove
// Params: const RawAddress& address
// Returns: void
struct BTM_AcceptlistRemove {
  std::function<void(const RawAddress& address)> body{
      [](const RawAddress& address) {}};
  void operator()(const RawAddress& address) { body(address); };
};
extern struct BTM_AcceptlistRemove BTM_AcceptlistRemove;
// Name: BTM_AcceptlistClear
// Params:
// Returns: void
struct BTM_AcceptlistClear {
  std::function<void()> body{[]() {}};
  void operator()() { body(); };
};
extern struct BTM_AcceptlistClear BTM_AcceptlistClear;

}  // namespace stack_btm_ble_bgconn
}  // namespace mock
}  // namespace test

// END mockcify generation
