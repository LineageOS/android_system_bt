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
 *   Functions generated:2
 */

#include <map>
#include <string>

extern std::map<std::string, int> mock_function_count_map;

#include "btif/include/btif_debug_conn.h"
#include "stack/include/gatt_api.h"
#include "types/raw_address.h"

#ifndef UNUSED_ATTR
#define UNUSED_ATTR
#endif

void btif_debug_conn_dump(int fd) { mock_function_count_map[__func__]++; }
void btif_debug_conn_state(const RawAddress& bda,
                           const btif_debug_conn_state_t state,
                           const tGATT_DISCONN_REASON disconnect_reason) {
  mock_function_count_map[__func__]++;
}
