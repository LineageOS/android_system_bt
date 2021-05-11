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

// Mock include file to share data between tests and mock
#include "test/mock/mock_stack_btm_ble_bgconn.h"

// Mocked compile conditionals, if any
#ifndef UNUSED_ATTR
#define UNUSED_ATTR
#endif

// Mocked internal structures, if any
struct BackgroundConnection {};
struct BgConnHash {};

namespace test {
namespace mock {
namespace stack_btm_ble_bgconn {

// Function state capture and return values, if needed
struct convert_to_address_with_type convert_to_address_with_type;
struct btm_update_scanner_filter_policy btm_update_scanner_filter_policy;
struct btm_ble_bgconn_cancel_if_disconnected
    btm_ble_bgconn_cancel_if_disconnected;
struct btm_ble_suspend_bg_conn btm_ble_suspend_bg_conn;
struct btm_ble_resume_bg_conn btm_ble_resume_bg_conn;
struct BTM_BackgroundConnectAddressKnown BTM_BackgroundConnectAddressKnown;
struct BTM_SetLeConnectionModeToFast BTM_SetLeConnectionModeToFast;
struct BTM_SetLeConnectionModeToSlow BTM_SetLeConnectionModeToSlow;
struct BTM_AcceptlistAdd BTM_AcceptlistAdd;
struct BTM_AcceptlistRemove BTM_AcceptlistRemove;
struct BTM_AcceptlistClear BTM_AcceptlistClear;

}  // namespace stack_btm_ble_bgconn
}  // namespace mock
}  // namespace test

// Mocked functions, if any
const tBLE_BD_ADDR convert_to_address_with_type(
    const RawAddress& bd_addr, const tBTM_SEC_DEV_REC* p_dev_rec) {
  mock_function_count_map[__func__]++;
  return test::mock::stack_btm_ble_bgconn::convert_to_address_with_type(
      bd_addr, p_dev_rec);
}
void btm_update_scanner_filter_policy(tBTM_BLE_SFP scan_policy) {
  mock_function_count_map[__func__]++;
  test::mock::stack_btm_ble_bgconn::btm_update_scanner_filter_policy(
      scan_policy);
}
void btm_ble_bgconn_cancel_if_disconnected(const RawAddress& bd_addr) {
  mock_function_count_map[__func__]++;
  test::mock::stack_btm_ble_bgconn::btm_ble_bgconn_cancel_if_disconnected(
      bd_addr);
}
bool btm_ble_suspend_bg_conn(void) {
  mock_function_count_map[__func__]++;
  return test::mock::stack_btm_ble_bgconn::btm_ble_suspend_bg_conn();
}
bool btm_ble_resume_bg_conn(void) {
  mock_function_count_map[__func__]++;
  return test::mock::stack_btm_ble_bgconn::btm_ble_resume_bg_conn();
}
bool BTM_BackgroundConnectAddressKnown(const RawAddress& address) {
  mock_function_count_map[__func__]++;
  return test::mock::stack_btm_ble_bgconn::BTM_BackgroundConnectAddressKnown(
      address);
}
bool BTM_SetLeConnectionModeToFast() {
  mock_function_count_map[__func__]++;
  return test::mock::stack_btm_ble_bgconn::BTM_SetLeConnectionModeToFast();
}
void BTM_SetLeConnectionModeToSlow() {
  mock_function_count_map[__func__]++;
  test::mock::stack_btm_ble_bgconn::BTM_SetLeConnectionModeToSlow();
}
bool BTM_AcceptlistAdd(const RawAddress& address) {
  mock_function_count_map[__func__]++;
  return test::mock::stack_btm_ble_bgconn::BTM_AcceptlistAdd(address);
}
void BTM_AcceptlistRemove(const RawAddress& address) {
  mock_function_count_map[__func__]++;
  test::mock::stack_btm_ble_bgconn::BTM_AcceptlistRemove(address);
}
void BTM_AcceptlistClear() {
  mock_function_count_map[__func__]++;
  test::mock::stack_btm_ble_bgconn::BTM_AcceptlistClear();
}

// END mockcify generation
