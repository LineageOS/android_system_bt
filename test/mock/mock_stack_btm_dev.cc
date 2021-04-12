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
 *   Functions generated:16
 */

#include <map>
#include <string>

extern std::map<std::string, int> mock_function_count_map;

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "bt_common.h"
#include "bt_types.h"
#include "btm_api.h"
#include "btu.h"
#include "device/include/controller.h"
#include "hcidefs.h"
#include "hcimsgs.h"
#include "l2c_api.h"
#include "main/shim/btm_api.h"
#include "main/shim/shim.h"
#include "stack/btm/btm_dev.h"
#include "stack/include/acl_api.h"

#ifndef UNUSED_ATTR
#define UNUSED_ATTR
#endif

bool BTM_SecAddDevice(const RawAddress& bd_addr, DEV_CLASS dev_class,
                      BD_NAME bd_name, uint8_t* features, LinkKey* p_link_key,
                      uint8_t key_type, uint8_t pin_length) {
  mock_function_count_map[__func__]++;
  return false;
}
bool BTM_SecDeleteDevice(const RawAddress& bd_addr) {
  mock_function_count_map[__func__]++;
  return false;
}
bool btm_dev_support_role_switch(const RawAddress& bd_addr) {
  mock_function_count_map[__func__]++;
  return false;
}
bool btm_set_bond_type_dev(const RawAddress& bd_addr,
                           tBTM_SEC_DEV_REC::tBTM_BOND_TYPE bond_type) {
  mock_function_count_map[__func__]++;
  return false;
}
bool is_address_equal(void* data, void* context) {
  mock_function_count_map[__func__]++;
  return false;
}
bool is_handle_equal(void* data, void* context) {
  mock_function_count_map[__func__]++;
  return false;
}
char* BTM_SecReadDevName(const RawAddress& bd_addr) {
  mock_function_count_map[__func__]++;
  return nullptr;
}
tBTM_SEC_DEV_REC* btm_find_dev(const RawAddress& bd_addr) {
  mock_function_count_map[__func__]++;
  return nullptr;
}
tBTM_SEC_DEV_REC* btm_find_dev_by_handle(uint16_t handle) {
  mock_function_count_map[__func__]++;
  return nullptr;
}
tBTM_SEC_DEV_REC* btm_find_or_alloc_dev(const RawAddress& bd_addr) {
  mock_function_count_map[__func__]++;
  return nullptr;
}
tBTM_SEC_DEV_REC* btm_sec_alloc_dev(const RawAddress& bd_addr) {
  mock_function_count_map[__func__]++;
  return nullptr;
}
tBTM_SEC_DEV_REC* btm_sec_allocate_dev_rec(void) {
  mock_function_count_map[__func__]++;
  return nullptr;
}
tBTM_SEC_DEV_REC::tBTM_BOND_TYPE btm_get_bond_type_dev(
    const RawAddress& bd_addr) {
  mock_function_count_map[__func__]++;
  return tBTM_SEC_DEV_REC::BOND_TYPE_UNKNOWN;
}
void BTM_SecClearSecurityFlags(const RawAddress& bd_addr) {
  mock_function_count_map[__func__]++;
}
void btm_consolidate_dev(tBTM_SEC_DEV_REC* p_target_rec) {
  mock_function_count_map[__func__]++;
}
void wipe_secrets_and_remove(tBTM_SEC_DEV_REC* p_dev_rec) {
  mock_function_count_map[__func__]++;
}
