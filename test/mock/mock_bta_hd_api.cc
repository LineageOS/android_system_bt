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
 *   Functions generated:12
 */

#include <map>
#include <string>

extern std::map<std::string, int> mock_function_count_map;

#include "bt_target.h"
#include "bta/hd/bta_hd_int.h"
#include "osi/include/allocator.h"
#include "osi/include/compat.h"
#include "osi/include/log.h"

#ifndef UNUSED_ATTR
#define UNUSED_ATTR
#endif

void BTA_HdEnable(tBTA_HD_CBACK* p_cback) {
  mock_function_count_map[__func__]++;
}
void BTA_HdAddDevice(const RawAddress& addr) {
  mock_function_count_map[__func__]++;
}
void BTA_HdConnect(const RawAddress& addr) {
  mock_function_count_map[__func__]++;
}
void BTA_HdDisable(void) { mock_function_count_map[__func__]++; }
void BTA_HdDisconnect(void) { mock_function_count_map[__func__]++; }
void BTA_HdRegisterApp(tBTA_HD_APP_INFO* p_app_info, tBTA_HD_QOS_INFO* p_in_qos,
                       tBTA_HD_QOS_INFO* p_out_qos) {
  mock_function_count_map[__func__]++;
}
void BTA_HdRemoveDevice(const RawAddress& addr) {
  mock_function_count_map[__func__]++;
}
void BTA_HdReportError(uint8_t error) { mock_function_count_map[__func__]++; }
void BTA_HdSendReport(tBTA_HD_REPORT* p_report) {
  mock_function_count_map[__func__]++;
}
void BTA_HdUnregisterApp(void) { mock_function_count_map[__func__]++; }
void BTA_HdVirtualCableUnplug(void) { mock_function_count_map[__func__]++; }
