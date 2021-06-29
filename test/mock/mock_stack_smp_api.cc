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
 */

#include <map>
#include <string>

extern std::map<std::string, int> mock_function_count_map;

#include <string.h>
#include "bt_target.h"
#include "hcimsgs.h"
#include "main/shim/shim.h"
#include "stack/btm/btm_dev.h"
#include "stack/include/l2c_api.h"
#include "stack/include/l2cdefs.h"
#include "stack/include/smp_api.h"
#include "stack/smp/smp_int.h"
#include "stack_config.h"
#include "utils/include/bt_utils.h"

#ifndef UNUSED_ATTR
#define UNUSED_ATTR
#endif

bool SMP_PairCancel(const RawAddress& bd_addr) {
  mock_function_count_map[__func__]++;
  return false;
}
bool SMP_Register(tSMP_CALLBACK* p_cback) {
  mock_function_count_map[__func__]++;
  return false;
}
tSMP_STATUS SMP_BR_PairWith(const RawAddress& bd_addr) {
  mock_function_count_map[__func__]++;
  return SMP_SUCCESS;
}
tSMP_STATUS SMP_Pair(const RawAddress& bd_addr) {
  mock_function_count_map[__func__]++;
  return SMP_SUCCESS;
}
uint8_t SMP_SetTraceLevel(uint8_t new_level) {
  mock_function_count_map[__func__]++;
  return 0;
}
void SMP_ConfirmReply(const RawAddress& bd_addr, uint8_t res) {
  mock_function_count_map[__func__]++;
}
void SMP_Init(void) { mock_function_count_map[__func__]++; }
void SMP_OobDataReply(const RawAddress& bd_addr, tSMP_STATUS res, uint8_t len,
                      uint8_t* p_data) {
  mock_function_count_map[__func__]++;
}
void SMP_PasskeyReply(const RawAddress& bd_addr, uint8_t res,
                      uint32_t passkey) {
  mock_function_count_map[__func__]++;
}
void SMP_SecureConnectionOobDataReply(uint8_t* p_data) {
  mock_function_count_map[__func__]++;
}
void SMP_SecurityGrant(const RawAddress& bd_addr, tSMP_STATUS res) {
  mock_function_count_map[__func__]++;
}

void SMP_CrLocScOobData() { mock_function_count_map[__func__]++; }

void SMP_ClearLocScOobData() { mock_function_count_map[__func__]++; }
