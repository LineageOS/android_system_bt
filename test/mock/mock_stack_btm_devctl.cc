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

#include <base/logging.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "bt_types.h"
#include "bta/dm/bta_dm_int.h"
#include "bta/sys/bta_sys.h"
#include "btcore/include/module.h"
#include "btif/include/btif_bqr.h"
#include "btu.h"
#include "common/message_loop_thread.h"
#include "device/include/controller.h"
#include "hci/include/hci_layer.h"
#include "hcimsgs.h"
#include "main/shim/btm_api.h"
#include "main/shim/controller.h"
#include "main/shim/shim.h"
#include "osi/include/osi.h"
#include "stack/btm/btm_ble_int.h"
#include "stack/gatt/connection_manager.h"
#include "stack/include/acl_api.h"
#include "stack/include/l2cap_controller_interface.h"

#ifndef UNUSED_ATTR
#define UNUSED_ATTR
#endif

bool BTM_IsDeviceUp(void) {
  mock_function_count_map[__func__]++;
  return false;
}
tBTM_STATUS BTM_BT_Quality_Report_VSE_Register(
    bool is_register, tBTM_BT_QUALITY_REPORT_RECEIVER* p_bqr_report_receiver) {
  mock_function_count_map[__func__]++;
  return BTM_SUCCESS;
}
tBTM_STATUS BTM_DeleteStoredLinkKey(const RawAddress* bd_addr,
                                    tBTM_CMPL_CB* p_cb) {
  mock_function_count_map[__func__]++;
  return BTM_SUCCESS;
}
tBTM_STATUS BTM_EnableTestMode(void) {
  mock_function_count_map[__func__]++;
  return BTM_SUCCESS;
}
tBTM_STATUS BTM_ReadLocalDeviceName(char** p_name) {
  mock_function_count_map[__func__]++;
  return BTM_SUCCESS;
}
tBTM_STATUS BTM_ReadLocalDeviceNameFromController(
    tBTM_CMPL_CB* p_rln_cmpl_cback) {
  mock_function_count_map[__func__]++;
  return BTM_SUCCESS;
}
tBTM_STATUS BTM_RegisterForVSEvents(tBTM_VS_EVT_CB* p_cb, bool is_register) {
  mock_function_count_map[__func__]++;
  return BTM_SUCCESS;
}
tBTM_STATUS BTM_SetDeviceClass(DEV_CLASS dev_class) {
  mock_function_count_map[__func__]++;
  return BTM_SUCCESS;
}
tBTM_STATUS BTM_SetLocalDeviceName(char* p_name) {
  mock_function_count_map[__func__]++;
  return BTM_SUCCESS;
}
uint8_t* BTM_ReadDeviceClass(void) {
  mock_function_count_map[__func__]++;
  return nullptr;
}
void BTM_VendorSpecificCommand(uint16_t opcode, uint8_t param_len,
                               uint8_t* p_param_buf, tBTM_VSC_CMPL_CB* p_cb) {
  mock_function_count_map[__func__]++;
}
void BTM_WritePageTimeout(uint16_t timeout) {
  mock_function_count_map[__func__]++;
}
void BTM_WriteVoiceSettings(uint16_t settings) {
  mock_function_count_map[__func__]++;
}
void BTM_db_reset(void) { mock_function_count_map[__func__]++; }
void BTM_reset_complete() { mock_function_count_map[__func__]++; }
void btm_delete_stored_link_key_complete(uint8_t* p) {
  mock_function_count_map[__func__]++;
}
void btm_dev_free() { mock_function_count_map[__func__]++; }
void btm_dev_init() { mock_function_count_map[__func__]++; }
void btm_read_local_name_complete(uint8_t* p, UNUSED_ATTR uint16_t evt_len) {
  mock_function_count_map[__func__]++;
}
void btm_vendor_specific_evt(uint8_t* p, uint8_t evt_len) {
  mock_function_count_map[__func__]++;
}
void btm_vsc_complete(uint8_t* p, uint16_t opcode, uint16_t evt_len,
                      tBTM_VSC_CMPL_CB* p_vsc_cplt_cback) {
  mock_function_count_map[__func__]++;
}
