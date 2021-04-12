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
 *   Functions generated:5
 */

#include <map>
#include <string>

extern std::map<std::string, int> mock_function_count_map;

#include <string.h>
#include "bt_common.h"
#include "bt_target.h"
#include "hcidefs.h"
#include "l2c_api.h"
#include "l2cdefs.h"
#include "osi/include/osi.h"
#include "sdp_api.h"
#include "stack/btm/btm_sec.h"
#include "stack/sdp/sdpint.h"

#ifndef UNUSED_ATTR
#define UNUSED_ATTR
#endif

tCONN_CB* sdp_conn_originate(const RawAddress& p_bd_addr) {
  mock_function_count_map[__func__]++;
  return nullptr;
}
void sdp_conn_timer_timeout(void* data) { mock_function_count_map[__func__]++; }
void sdp_disconnect(tCONN_CB* p_ccb, uint16_t reason) {
  mock_function_count_map[__func__]++;
}
void sdp_free(void) { mock_function_count_map[__func__]++; }
void sdp_init(void) { mock_function_count_map[__func__]++; }
