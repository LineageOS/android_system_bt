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

#include <map>
#include <string>

extern std::map<std::string, int> mock_function_count_map;

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/poll.h>
#include <sys/prctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>
#include <mutex>
#include <set>
#include "audio_a2dp_hw/include/audio_a2dp_hw.h"
#include "bt_common.h"
#include "bt_types.h"
#include "bt_utils.h"
#include "osi/include/osi.h"
#include "osi/include/socket_utils/sockets.h"
#include "uipc.h"

#ifndef UNUSED_ATTR
#define UNUSED_ATTR
#endif

bool UIPC_Open(tUIPC_STATE& uipc, tUIPC_CH_ID ch_id, tUIPC_RCV_CBACK* p_cback,
               const char* socket_path) {
  mock_function_count_map[__func__]++;
  return false;
}
bool UIPC_Send(tUIPC_STATE& uipc, tUIPC_CH_ID ch_id,
               UNUSED_ATTR uint16_t msg_evt, const uint8_t* p_buf,
               uint16_t msglen) {
  mock_function_count_map[__func__]++;
  return false;
}
int uipc_start_main_server_thread(tUIPC_STATE& uipc) {
  mock_function_count_map[__func__]++;
  return 0;
}
std::unique_ptr<tUIPC_STATE> UIPC_Init() {
  mock_function_count_map[__func__]++;
  return nullptr;
}
const char* dump_uipc_event(tUIPC_EVENT event) {
  mock_function_count_map[__func__]++;
  return nullptr;
}
uint32_t UIPC_Read(tUIPC_STATE& uipc, tUIPC_CH_ID ch_id,
                   UNUSED_ATTR uint16_t* p_msg_evt, uint8_t* p_buf,
                   uint32_t len) {
  mock_function_count_map[__func__]++;
  return 0;
}
bool UIPC_Ioctl(tUIPC_STATE& uipc, tUIPC_CH_ID ch_id, uint32_t request,
                void* param) {
  mock_function_count_map[__func__]++;
  return false;
}
void UIPC_Close(tUIPC_STATE& uipc, tUIPC_CH_ID ch_id) {
  mock_function_count_map[__func__]++;
}
void uipc_close_locked(tUIPC_STATE& uipc, tUIPC_CH_ID ch_id) {
  mock_function_count_map[__func__]++;
}
void uipc_main_cleanup(tUIPC_STATE& uipc) {
  mock_function_count_map[__func__]++;
}
void uipc_stop_main_server_thread(tUIPC_STATE& uipc) {
  mock_function_count_map[__func__]++;
}
