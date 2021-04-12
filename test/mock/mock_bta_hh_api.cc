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

#include <cstdint>
#include "bt_target.h"
#include "bta/hh/bta_hh_int.h"
#include "bta/sys/bta_sys.h"
#include "osi/include/allocator.h"
#include "osi/include/osi.h"
#include "types/raw_address.h"

#ifndef UNUSED_ATTR
#define UNUSED_ATTR
#endif

void BTA_HhEnable(tBTA_HH_CBACK* p_cback) {
  mock_function_count_map[__func__]++;
}
void BTA_HhAddDev(const RawAddress& bda, tBTA_HH_ATTR_MASK attr_mask,
                  uint8_t sub_class, uint8_t app_id,
                  tBTA_HH_DEV_DSCP_INFO dscp_info) {
  mock_function_count_map[__func__]++;
}
void BTA_HhClose(uint8_t dev_handle) { mock_function_count_map[__func__]++; }
void BTA_HhDisable(void) { mock_function_count_map[__func__]++; }
void BTA_HhGetDscpInfo(uint8_t dev_handle) {
  mock_function_count_map[__func__]++;
}
void BTA_HhGetIdle(uint8_t dev_handle) { mock_function_count_map[__func__]++; }
void BTA_HhGetProtoMode(uint8_t dev_handle) {
  mock_function_count_map[__func__]++;
}
void BTA_HhGetReport(uint8_t dev_handle, tBTA_HH_RPT_TYPE r_type,
                     uint8_t rpt_id, uint16_t buf_size) {
  mock_function_count_map[__func__]++;
}
void BTA_HhOpen(const RawAddress& dev_bda) {
  mock_function_count_map[__func__]++;
}
void BTA_HhRemoveDev(uint8_t dev_handle) {
  mock_function_count_map[__func__]++;
}
void BTA_HhSendCtrl(uint8_t dev_handle, tBTA_HH_TRANS_CTRL_TYPE c_type) {
  mock_function_count_map[__func__]++;
}
void BTA_HhSendData(uint8_t dev_handle, UNUSED_ATTR const RawAddress& dev_bda,
                    BT_HDR* p_data) {
  mock_function_count_map[__func__]++;
}
void BTA_HhSetIdle(uint8_t dev_handle, uint16_t idle_rate) {
  mock_function_count_map[__func__]++;
}
void BTA_HhSetProtoMode(uint8_t dev_handle, tBTA_HH_PROTO_MODE p_type) {
  mock_function_count_map[__func__]++;
}
void BTA_HhSetReport(uint8_t dev_handle, tBTA_HH_RPT_TYPE r_type,
                     BT_HDR* p_data) {
  mock_function_count_map[__func__]++;
}
