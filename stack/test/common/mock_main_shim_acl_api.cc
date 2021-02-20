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
 *   Functions generated:5
 */

#include <map>
#include <string>

extern std::map<std::string, int> mock_function_count_map;

#include <cstddef>
#include <cstdint>
#include "main/shim/acl_api.h"
#include "types/ble_address_with_type.h"
#include "types/raw_address.h"

#ifndef UNUSED_ATTR
#define UNUSED_ATTR
#endif

void bluetooth::shim::ACL_CreateClassicConnection(
    const RawAddress& raw_address) {
  mock_function_count_map[__func__]++;
}
void bluetooth::shim::ACL_CancelClassicConnection(
    const RawAddress& raw_address) {
  mock_function_count_map[__func__]++;
}
bool bluetooth::shim::ACL_AcceptLeConnectionFrom(
    const tBLE_BD_ADDR& legacy_address_with_type) {
  mock_function_count_map[__func__]++;
  return true;
}
void bluetooth::shim::ACL_IgnoreLeConnectionFrom(
    const tBLE_BD_ADDR& legacy_address_with_type) {
  mock_function_count_map[__func__]++;
}
void bluetooth::shim::ACL_ConfigureLePrivacy(bool is_le_privacy_enabled) {
  mock_function_count_map[__func__]++;
}
void bluetooth::shim::ACL_WriteData(uint16_t handle, const BT_HDR* p_buf) {
  mock_function_count_map[__func__]++;
}
void bluetooth::shim::ACL_Disconnect(uint16_t handle, bool is_classic,
                                     tHCI_STATUS reason) {
  mock_function_count_map[__func__]++;
}
void bluetooth::shim::ACL_IgnoreAllLeConnections() {
  mock_function_count_map[__func__]++;
}
void bluetooth::shim::ACL_ReadConnectionAddress(const RawAddress& pseudo_addr,
                                                RawAddress& conn_addr,
                                                uint8_t* p_addr_type) {
  mock_function_count_map[__func__]++;
}