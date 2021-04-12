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
 *   Functions generated:4
 */

#include <map>
#include <string>

extern std::map<std::string, int> mock_function_count_map;

#include <base/bind.h>
#include <base/location.h>
#include "bt_target.h"
#include "bta/include/bta_sdp_api.h"
#include "bta/sdp/bta_sdp_int.h"
#include "stack/include/btu.h"

#ifndef UNUSED_ATTR
#define UNUSED_ATTR
#endif

tBTA_SDP_STATUS BTA_SdpCreateRecordByUser(void* user_data) {
  mock_function_count_map[__func__]++;
  return BTA_SDP_SUCCESS;
}
tBTA_SDP_STATUS BTA_SdpEnable(tBTA_SDP_DM_CBACK* p_cback) {
  mock_function_count_map[__func__]++;
  return BTA_SDP_SUCCESS;
}
tBTA_SDP_STATUS BTA_SdpRemoveRecordByUser(void* user_data) {
  mock_function_count_map[__func__]++;
  return BTA_SDP_SUCCESS;
}
tBTA_SDP_STATUS BTA_SdpSearch(const RawAddress& bd_addr,
                              const bluetooth::Uuid& uuid) {
  mock_function_count_map[__func__]++;
  return BTA_SDP_SUCCESS;
}
