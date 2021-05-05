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
 *
 *  mockcify.pl ver 0.2
 */

#include <cstdint>
#include <map>
#include <string>

extern std::map<std::string, int> mock_function_count_map;

// Original included files, if any
// NOTE: Since this is a mock file with mock definitions some number of
//       include files may not be required.  The include-what-you-use
//       still applies, but crafting proper inclusion is out of scope
//       for this effort.  This compilation unit may compile as-is, or
//       may need attention to prune the inclusion set.

#include "stack/include/hci_error_code.h"
#include "types/ble_address_with_type.h"
#include "types/raw_address.h"

// Mocked compile conditionals, if any
#ifndef UNUSED_ATTR
#define UNUSED_ATTR
#endif

namespace test {
namespace mock {
namespace stack_acl_btm_ble_connection_establishment {

// Shared state between mocked functions and tests
// Name: btm_send_hci_create_connection
// Params: uint16_t scan_int, uint16_t scan_win, uint8_t init_filter_policy,
// uint8_t addr_type_peer, const RawAddress& bda_peer, uint8_t addr_type_own,
// uint16_t conn_int_min, uint16_t conn_int_max, uint16_t conn_latency, uint16_t
// conn_timeout, uint16_t min_ce_len, uint16_t max_ce_len, uint8_t
// initiating_phys Returns: void
struct btm_send_hci_create_connection {
  std::function<void(
      uint16_t scan_int, uint16_t scan_win, uint8_t init_filter_policy,
      uint8_t addr_type_peer, const RawAddress& bda_peer, uint8_t addr_type_own,
      uint16_t conn_int_min, uint16_t conn_int_max, uint16_t conn_latency,
      uint16_t conn_timeout, uint16_t min_ce_len, uint16_t max_ce_len,
      uint8_t initiating_phys)>
      body{[](uint16_t scan_int, uint16_t scan_win, uint8_t init_filter_policy,
              uint8_t addr_type_peer, const RawAddress& bda_peer,
              uint8_t addr_type_own, uint16_t conn_int_min,
              uint16_t conn_int_max, uint16_t conn_latency,
              uint16_t conn_timeout, uint16_t min_ce_len, uint16_t max_ce_len,
              uint8_t initiating_phys) {}};
  void operator()(uint16_t scan_int, uint16_t scan_win,
                  uint8_t init_filter_policy, uint8_t addr_type_peer,
                  const RawAddress& bda_peer, uint8_t addr_type_own,
                  uint16_t conn_int_min, uint16_t conn_int_max,
                  uint16_t conn_latency, uint16_t conn_timeout,
                  uint16_t min_ce_len, uint16_t max_ce_len,
                  uint8_t initiating_phys) {
    body(scan_int, scan_win, init_filter_policy, addr_type_peer, bda_peer,
         addr_type_own, conn_int_min, conn_int_max, conn_latency, conn_timeout,
         min_ce_len, max_ce_len, initiating_phys);
  };
};
extern struct btm_send_hci_create_connection btm_send_hci_create_connection;
// Name: btm_ble_create_ll_conn_complete
// Params: tHCI_STATUS status
// Returns: void
struct btm_ble_create_ll_conn_complete {
  std::function<void(tHCI_STATUS status)> body{[](tHCI_STATUS status) {}};
  void operator()(tHCI_STATUS status) { body(status); };
};
extern struct btm_ble_create_ll_conn_complete btm_ble_create_ll_conn_complete;
// Name: maybe_resolve_address
// Params: RawAddress* bda, tBLE_ADDR_TYPE* bda_type
// Returns: bool
struct maybe_resolve_address {
  std::function<bool(RawAddress* bda, tBLE_ADDR_TYPE* bda_type)> body{
      [](RawAddress* bda, tBLE_ADDR_TYPE* bda_type) { return false; }};
  bool operator()(RawAddress* bda, tBLE_ADDR_TYPE* bda_type) {
    return body(bda, bda_type);
  };
};
extern struct maybe_resolve_address maybe_resolve_address;
// Name: btm_ble_conn_complete
// Params: uint8_t* p, uint16_t evt_len, bool enhanced
// Returns: void
struct btm_ble_conn_complete {
  std::function<void(uint8_t* p, uint16_t evt_len, bool enhanced)> body{
      [](uint8_t* p, uint16_t evt_len, bool enhanced) {}};
  void operator()(uint8_t* p, uint16_t evt_len, bool enhanced) {
    body(p, evt_len, enhanced);
  };
};
extern struct btm_ble_conn_complete btm_ble_conn_complete;
// Name: btm_ble_create_conn_cancel
// Params:
// Returns: void
struct btm_ble_create_conn_cancel {
  std::function<void()> body{[]() {}};
  void operator()() { body(); };
};
extern struct btm_ble_create_conn_cancel btm_ble_create_conn_cancel;
// Name: btm_ble_create_conn_cancel_complete
// Params: uint8_t* p
// Returns: void
struct btm_ble_create_conn_cancel_complete {
  std::function<void(uint8_t* p)> body{[](uint8_t* p) {}};
  void operator()(uint8_t* p) { body(p); };
};
extern struct btm_ble_create_conn_cancel_complete
    btm_ble_create_conn_cancel_complete;

}  // namespace stack_acl_btm_ble_connection_establishment
}  // namespace mock
}  // namespace test

// END mockcify generation
