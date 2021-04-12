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
 *   Functions generated:21
 */

#include <map>
#include <string>

extern std::map<std::string, int> mock_function_count_map;

#include <cstdint>
#include "bt_target.h"
#include "bta/av/bta_av_int.h"
#include "bta/include/bta_ar_api.h"
#include "bta/include/utl.h"
#include "btif/avrcp/avrcp_service.h"
#include "btif/include/btif_av_co.h"
#include "btif/include/btif_config.h"
#include "main/shim/dumpsys.h"
#include "osi/include/log.h"
#include "osi/include/osi.h"
#include "osi/include/properties.h"
#include "stack/include/acl_api.h"
#include "types/hci_role.h"

#ifndef UNUSED_ATTR
#define UNUSED_ATTR
#endif

bool bta_av_chk_start(tBTA_AV_SCB* p_scb) {
  mock_function_count_map[__func__]++;
  return false;
}
bool bta_av_hdl_event(BT_HDR* p_msg) {
  mock_function_count_map[__func__]++;
  return false;
}
bool bta_av_link_role_ok(tBTA_AV_SCB* p_scb, uint8_t bits) {
  mock_function_count_map[__func__]++;
  return false;
}
bool bta_av_switch_if_needed(tBTA_AV_SCB* p_scb) {
  mock_function_count_map[__func__]++;
  return false;
}
const char* bta_av_evt_code(uint16_t evt_code) {
  mock_function_count_map[__func__]++;
  return nullptr;
}
int BTA_AvObtainPeerChannelIndex(const RawAddress& peer_address) {
  mock_function_count_map[__func__]++;
  return 0;
}
tBTA_AV_SCB* bta_av_addr_to_scb(const RawAddress& bd_addr) {
  mock_function_count_map[__func__]++;
  return nullptr;
}
tBTA_AV_SCB* bta_av_hndl_to_scb(uint16_t handle) {
  mock_function_count_map[__func__]++;
  return nullptr;
}
void bta_av_api_deregister(tBTA_AV_DATA* p_data) {
  mock_function_count_map[__func__]++;
}
void bta_av_conn_cback(UNUSED_ATTR uint8_t handle, const RawAddress& bd_addr,
                       uint8_t event, tAVDT_CTRL* p_data, uint8_t scb_index) {
  mock_function_count_map[__func__]++;
}
void bta_av_dup_audio_buf(tBTA_AV_SCB* p_scb, BT_HDR* p_buf) {
  mock_function_count_map[__func__]++;
}
void bta_av_free_scb(tBTA_AV_SCB* p_scb) {
  mock_function_count_map[__func__]++;
}
void bta_av_restore_switch(void) { mock_function_count_map[__func__]++; }
void bta_av_sm_execute(tBTA_AV_CB* p_cb, uint16_t event, tBTA_AV_DATA* p_data) {
  mock_function_count_map[__func__]++;
}
void bta_debug_av_dump(int fd) { mock_function_count_map[__func__]++; }
void tBTA_AV_SCB::OnConnected(const RawAddress& peer_address) {
  mock_function_count_map[__func__]++;
}
void tBTA_AV_SCB::OnDisconnected() { mock_function_count_map[__func__]++; }
void tBTA_AV_SCB::SetAvdtpVersion(uint16_t avdtp_version) {
  mock_function_count_map[__func__]++;
}
