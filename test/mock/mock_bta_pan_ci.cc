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

#include "bt_target.h"
#include "bta/pan/bta_pan_int.h"
#include "osi/include/allocator.h"
#include "types/raw_address.h"

#ifndef UNUSED_ATTR
#define UNUSED_ATTR
#endif

BT_HDR* bta_pan_ci_readbuf(uint16_t handle, RawAddress& src, RawAddress& dst,
                           uint16_t* p_protocol, bool* p_ext, bool* p_forward) {
  mock_function_count_map[__func__]++;
  return nullptr;
}
void bta_pan_ci_rx_ready(uint16_t handle) {
  mock_function_count_map[__func__]++;
}
void bta_pan_ci_rx_write(uint16_t handle, const RawAddress& dst,
                         const RawAddress& src, uint16_t protocol,
                         uint8_t* p_data, uint16_t len, bool ext) {
  mock_function_count_map[__func__]++;
}
void bta_pan_ci_rx_writebuf(uint16_t handle, const RawAddress& dst,
                            const RawAddress& src, uint16_t protocol,
                            BT_HDR* p_buf, bool ext) {
  mock_function_count_map[__func__]++;
}
void bta_pan_ci_set_mfilters(uint16_t handle, uint16_t num_mcast_filters,
                             uint8_t* p_start_array, uint8_t* p_end_array) {
  mock_function_count_map[__func__]++;
}
void bta_pan_ci_set_pfilters(uint16_t handle, uint16_t num_filters,
                             uint16_t* p_start_array, uint16_t* p_end_array) {
  mock_function_count_map[__func__]++;
}
void bta_pan_ci_tx_flow(uint16_t handle, bool enable) {
  mock_function_count_map[__func__]++;
}
void bta_pan_ci_tx_ready(uint16_t handle) {
  mock_function_count_map[__func__]++;
}
