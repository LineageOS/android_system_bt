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
 *   Functions generated:5
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
#include "stack/btm/ble_advertiser_hci_interface.h"

// Mocked compile conditionals, if any
#ifndef UNUSED_ATTR
#define UNUSED_ATTR
#endif

namespace test {
namespace mock {
namespace stack_btm_ble_advertiser_hci_interface {

// Shared state between mocked functions and tests
// Name: btm_le_on_advertising_set_terminated
// Params: uint8_t* p, uint16_t length
// Returns: void
struct btm_le_on_advertising_set_terminated {
  std::function<void(uint8_t* p, uint16_t length)> body{
      [](uint8_t* p, uint16_t length) {}};
  void operator()(uint8_t* p, uint16_t length) { body(p, length); };
};
extern struct btm_le_on_advertising_set_terminated
    btm_le_on_advertising_set_terminated;
// Name: btm_ble_advertiser_notify_terminated_legacy
// Params: uint8_t status, uint16_t connection_handle
// Returns: void
struct btm_ble_advertiser_notify_terminated_legacy {
  std::function<void(uint8_t status, uint16_t connection_handle)> body{
      [](uint8_t status, uint16_t connection_handle) {}};
  void operator()(uint8_t status, uint16_t connection_handle) {
    body(status, connection_handle);
  };
};
extern struct btm_ble_advertiser_notify_terminated_legacy
    btm_ble_advertiser_notify_terminated_legacy;

}  // namespace stack_btm_ble_advertiser_hci_interface
}  // namespace mock
}  // namespace test

// END mockcify generation
