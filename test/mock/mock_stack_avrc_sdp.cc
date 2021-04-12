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

#include <string.h>

#include "bt_common.h"
#include "stack/avrc/avrc_int.h"
#include "stack/include/avrc_api.h"

#ifndef UNUSED_ATTR
#define UNUSED_ATTR
#endif

uint16_t AVRC_AddRecord(uint16_t service_uuid, const char* p_service_name,
                        const char* p_provider_name, uint16_t categories,
                        uint32_t sdp_handle, bool browse_supported,
                        uint16_t profile_version, uint16_t cover_art_psm) {
  mock_function_count_map[__func__]++;
  return 0;
}
uint16_t AVRC_FindService(uint16_t service_uuid, const RawAddress& bd_addr,
                          tAVRC_SDP_DB_PARAMS* p_db,
                          const tAVRC_FIND_CBACK& find_cback) {
  mock_function_count_map[__func__]++;
  return 0;
}
uint16_t AVRC_RemoveRecord(uint32_t sdp_handle) {
  mock_function_count_map[__func__]++;
  return 0;
}
uint8_t AVRC_SetTraceLevel(uint8_t new_level) {
  mock_function_count_map[__func__]++;
  return 0;
}
void AVRC_Init(void) { mock_function_count_map[__func__]++; }
