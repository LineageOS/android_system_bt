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
 *   Functions generated:8
 */

#include <map>
#include <string>

extern std::map<std::string, int> mock_function_count_map;

#include <cstdint>
#include "bta/ar/bta_ar_int.h"
#include "bta/sys/bta_sys.h"
#include "stack/include/avct_api.h"
#include "stack/include/avrc_api.h"

#ifndef UNUSED_ATTR
#define UNUSED_ATTR
#endif

void bta_ar_avdt_conn(tBTA_SYS_ID sys_id, const RawAddress& bd_addr,
                      uint8_t scb_index) {
  mock_function_count_map[__func__]++;
}
void bta_ar_dereg_avct() { mock_function_count_map[__func__]++; }
void bta_ar_dereg_avdt() { mock_function_count_map[__func__]++; }
void bta_ar_dereg_avrc(uint16_t service_uuid) {
  mock_function_count_map[__func__]++;
}
void bta_ar_init(void) { mock_function_count_map[__func__]++; }
void bta_ar_reg_avct() { mock_function_count_map[__func__]++; }
void bta_ar_reg_avdt(AvdtpRcb* p_reg, tAVDT_CTRL_CBACK* p_cback) {
  mock_function_count_map[__func__]++;
}
void bta_ar_reg_avrc(uint16_t service_uuid, const char* service_name,
                     const char* provider_name, uint16_t categories,
                     bool browse_supported, uint16_t profile_version) {
  mock_function_count_map[__func__]++;
}
