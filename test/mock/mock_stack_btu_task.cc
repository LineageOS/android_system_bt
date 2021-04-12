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

#include <base/bind.h>
#include <base/logging.h>
#include <base/run_loop.h>
#include <base/threading/thread.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "bta/sys/bta_sys.h"
#include "btcore/include/module.h"
#include "bte.h"
#include "btif/include/btif_common.h"
#include "btm_iso_api.h"
#include "common/message_loop_thread.h"
#include "osi/include/log.h"
#include "osi/include/osi.h"
#include "stack/include/acl_hci_link_interface.h"
#include "stack/include/btu.h"

#ifndef UNUSED_ATTR
#define UNUSED_ATTR
#endif

bluetooth::common::MessageLoopThread* get_main_thread() {
  mock_function_count_map[__func__]++;
  return nullptr;
}
bt_status_t do_in_main_thread(const base::Location& from_here,
                              base::OnceClosure task) {
  mock_function_count_map[__func__]++;
  return BT_STATUS_SUCCESS;
}
bt_status_t do_in_main_thread_delayed(const base::Location& from_here,
                                      base::OnceClosure task,
                                      const base::TimeDelta& delay) {
  mock_function_count_map[__func__]++;
  return BT_STATUS_SUCCESS;
}
void btu_hci_msg_process(BT_HDR* p_msg) { mock_function_count_map[__func__]++; }
void main_thread_shut_down() { mock_function_count_map[__func__]++; }
void main_thread_start_up() { mock_function_count_map[__func__]++; }
void post_on_bt_main(BtMainClosure closure) {
  mock_function_count_map[__func__]++;
}
