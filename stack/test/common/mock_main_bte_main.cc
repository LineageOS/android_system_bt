/*
 * Copyright 2020 The Android Open Source Project
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
 *   Functions generated:3
 */

#include <map>
#include <string>

extern std::map<std::string, int> mock_function_count_map;

#include <base/logging.h>
#include <hardware/bluetooth.h>
#include "bt_common.h"
#include "btcore/include/module.h"
#include "bte.h"
#include "btif/include/btif_config.h"
#include "btu.h"
#include "device/include/interop.h"
#include "osi/include/log.h"
#include "osi/include/osi.h"

#ifndef UNUSED_ATTR
#define UNUSED_ATTR
#endif

void bte_main_hci_send(BT_HDR* p_msg, uint16_t event) {
  mock_function_count_map[__func__]++;
}
void bte_main_init(void) { mock_function_count_map[__func__]++; }
void post_to_main_message_loop(const base::Location& from_here, BT_HDR* p_msg) {
  mock_function_count_map[__func__]++;
}
