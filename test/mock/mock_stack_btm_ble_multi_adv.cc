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

#include <base/bind.h>
#include <base/bind_helpers.h>
#include <base/location.h>
#include <base/logging.h>
#include <base/memory/weak_ptr.h>
#include <base/strings/string_number_conversions.h>
#include <base/time/time.h>
#include <string.h>
#include <queue>
#include <vector>
#include "ble_advertiser.h"
#include "ble_advertiser_hci_interface.h"
#include "bt_target.h"
#include "btm_int_types.h"
#include "device/include/controller.h"
#include "osi/include/alarm.h"
#include "stack/btm/btm_ble_int.h"

#ifndef UNUSED_ATTR
#define UNUSED_ATTR
#endif

void BleAdvertisingManager::CleanUp() { mock_function_count_map[__func__]++; }
void btm_ble_adv_init() { mock_function_count_map[__func__]++; }
base::WeakPtr<BleAdvertisingManager> BleAdvertisingManager::Get() {
  mock_function_count_map[__func__]++;
  return nullptr;
}
bool BleAdvertisingManager::IsInitialized() {
  mock_function_count_map[__func__]++;
  return false;
}
void test_timeout_cb(uint8_t status) { mock_function_count_map[__func__]++; }
void BleAdvertisingManager::Initialize(BleAdvertiserHciInterface* interface) {
  mock_function_count_map[__func__]++;
}
void btm_ble_multi_adv_cleanup(void) { mock_function_count_map[__func__]++; }
void testRecomputeTimeout1() { mock_function_count_map[__func__]++; }
void testRecomputeTimeout2() { mock_function_count_map[__func__]++; }
void testRecomputeTimeout3() { mock_function_count_map[__func__]++; }
