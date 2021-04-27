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
 *   Functions generated:7
 */

#include <map>
#include <string>

extern std::map<std::string, int> mock_function_count_map;

#include <base/bind.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <vector>
#include "bt_target.h"
#include "bt_types.h"
#include "btm_ble_api.h"
#include "btu.h"
#include "device/include/controller.h"
#include "hcimsgs.h"
#include "stack/btm/btm_int_types.h"
#include "utils/include/bt_utils.h"

#ifndef UNUSED_ATTR
#define UNUSED_ATTR
#endif

void BTM_BleDisableBatchScan(base::Callback<void(uint8_t)> cb) {
  mock_function_count_map[__func__]++;
}
void BTM_BleEnableBatchScan(tBTM_BLE_BATCH_SCAN_MODE scan_mode,
                            uint32_t scan_interval, uint32_t scan_window,
                            tBLE_ADDR_TYPE addr_type,
                            tBTM_BLE_DISCARD_RULE discard_rule,
                            base::Callback<void(uint8_t)> cb) {
  mock_function_count_map[__func__]++;
}
void BTM_BleReadScanReports(tBTM_BLE_BATCH_SCAN_MODE scan_mode,
                            tBTM_BLE_SCAN_REP_CBACK cb) {
  mock_function_count_map[__func__]++;
}
void BTM_BleSetStorageConfig(uint8_t batch_scan_full_max,
                             uint8_t batch_scan_trunc_max,
                             uint8_t batch_scan_notify_threshold,
                             base::Callback<void(uint8_t)> cb,
                             tBTM_BLE_SCAN_THRESHOLD_CBACK* p_thres_cback,
                             tBTM_BLE_REF_VALUE ref_value) {
  mock_function_count_map[__func__]++;
}
void BTM_BleTrackAdvertiser(tBTM_BLE_TRACK_ADV_CBACK* p_track_cback,
                            tBTM_BLE_REF_VALUE ref_value) {
  mock_function_count_map[__func__]++;
}
void btm_ble_batchscan_init(void) { mock_function_count_map[__func__]++; }
