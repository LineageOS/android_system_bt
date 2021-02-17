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

#include <cstdint>
#include <map>
#include <string>

extern std::map<std::string, int> mock_function_count_map;

#include "bta/include/bta_hh_api.h"
#include "bta/include/bta_hh_co.h"
#include "btif/include/btif_hh.h"

#ifndef UNUSED_ATTR
#define UNUSED_ATTR
#endif

int bta_hh_co_write(int fd, uint8_t* rpt, uint16_t len) {
  mock_function_count_map[__func__]++;
  return 0;
}
tBTA_HH_RPT_CACHE_ENTRY* bta_hh_le_co_cache_load(const RawAddress& remote_bda,
                                                 uint8_t* p_num_rpt,
                                                 UNUSED_ATTR uint8_t app_id) {
  mock_function_count_map[__func__]++;
  return nullptr;
}
void bta_hh_co_close(uint8_t dev_handle, uint8_t app_id) {
  mock_function_count_map[__func__]++;
}
void bta_hh_co_data(uint8_t dev_handle, uint8_t* p_rpt, uint16_t len,
                    tBTA_HH_PROTO_MODE mode, uint8_t sub_class,
                    uint8_t ctry_code, UNUSED_ATTR const RawAddress& peer_addr,
                    uint8_t app_id) {
  mock_function_count_map[__func__]++;
}
void bta_hh_co_destroy(int fd) { mock_function_count_map[__func__]++; }
void bta_hh_co_get_rpt_rsp(uint8_t dev_handle, uint8_t status, uint8_t* p_rpt,
                           uint16_t len) {
  mock_function_count_map[__func__]++;
}
void bta_hh_co_open(uint8_t dev_handle, uint8_t sub_class,
                    tBTA_HH_ATTR_MASK attr_mask, uint8_t app_id) {
  mock_function_count_map[__func__]++;
}
void bta_hh_co_send_hid_info(btif_hh_device_t* p_dev, const char* dev_name,
                             uint16_t vendor_id, uint16_t product_id,
                             uint16_t version, uint8_t ctry_code, int dscp_len,
                             uint8_t* p_dscp) {
  mock_function_count_map[__func__]++;
}
void bta_hh_co_set_rpt_rsp(uint8_t dev_handle, uint8_t status) {
  mock_function_count_map[__func__]++;
}
void bta_hh_le_co_reset_rpt_cache(const RawAddress& remote_bda,
                                  UNUSED_ATTR uint8_t app_id) {
  mock_function_count_map[__func__]++;
}
void bta_hh_le_co_rpt_info(const RawAddress& remote_bda,
                           tBTA_HH_RPT_CACHE_ENTRY* p_entry,
                           UNUSED_ATTR uint8_t app_id) {
  mock_function_count_map[__func__]++;
}
void uhid_set_non_blocking(int fd) { mock_function_count_map[__func__]++; }
