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
 */

#include "stack/include/btm_ble_api_types.h"
#include "stack/include/btm_client_interface.h"
#include "types/raw_address.h"

bool BTM_HasEirService(const uint32_t* p_eir_uuid, uint16_t uuid16) {
  return false;
}
tBTM_INQ_INFO* BTM_InqDbFirst(void) { return nullptr; }
tBTM_INQ_INFO* BTM_InqDbNext(tBTM_INQ_INFO* p_cur) { return nullptr; }
tBTM_INQ_INFO* BTM_InqDbRead(const RawAddress& p_bda) { return nullptr; }
tBTM_STATUS BTM_CancelRemoteDeviceName(void) { return BTM_SUCCESS; }
tBTM_STATUS BTM_ClearInqDb(const RawAddress* p_bda) { return BTM_SUCCESS; }
tBTM_STATUS BTM_ReadLocalDeviceNameFromController(
    tBTM_CMPL_CB* p_rln_cmpl_cback) {
  return BTM_SUCCESS;
}
tBTM_STATUS BTM_ReadRemoteDeviceName(const RawAddress& remote_bda,
                                     tBTM_CMPL_CB* p_cb,
                                     tBT_TRANSPORT transport) {
  return BTM_SUCCESS;
}
tBTM_STATUS BTM_SetConnectability(uint16_t page_mode) { return BTM_SUCCESS; }
tBTM_STATUS BTM_SetDeviceClass(DEV_CLASS dev_class) { return BTM_SUCCESS; }
tBTM_STATUS BTM_SetLocalDeviceName(char* p_name) { return BTM_SUCCESS; }
tBTM_STATUS BTM_StartInquiry(tBTM_INQ_RESULTS_CB* p_results_cb,
                             tBTM_CMPL_CB* p_cmpl_cb) {
  return BTM_SUCCESS;
}
tBTM_STATUS BTM_WriteEIR(BT_HDR* p_buff) { return BTM_SUCCESS; }
tBTM_STATUS BTM_SetDiscoverability(uint16_t inq_mode) { return BTM_SUCCESS; }
tBTM_STATUS BTM_BleGetEnergyInfo(tBTM_BLE_ENERGY_INFO_CBACK* p_ener_cback) {
  return BTM_SUCCESS;
}
tBTM_STATUS BTM_BleObserve(bool start, uint8_t duration,
                           tBTM_INQ_RESULTS_CB* p_results_cb,
                           tBTM_CMPL_CB* p_cmpl_cb) {
  return BTM_SUCCESS;
}
uint16_t BTM_IsInquiryActive(void) { return 0; }
uint8_t BTM_GetEirSupportedServices(uint32_t* p_eir_uuid, uint8_t** p,
                                    uint8_t max_num_uuid16,
                                    uint8_t* p_num_uuid16) {
  return 0;
}
void BTM_AddEirService(uint32_t* p_eir_uuid, uint16_t uuid16) {}
void BTM_BleReadControllerFeatures(tBTM_BLE_CTRL_FEATURES_CBACK* p_vsc_cback) {}
void BTM_CancelInquiry(void) {}
void BTM_RemoveEirService(uint32_t* p_eir_uuid, uint16_t uuid16) {}
void BTM_WritePageTimeout(uint16_t timeout) {}
bool BTM_BleConfigPrivacy(bool enable) { return false; }
bool BTM_IsDeviceUp() { return false; }
bool BTM_is_sniff_allowed_for(const RawAddress& peer_addr) { return false; }
void btm_ble_adv_init() {}
tBTM_STATUS BTM_ReadLocalDeviceName(char** p_name) { return BTM_SUCCESS; }
uint8_t BTM_GetAcceptlistSize() { return 0; }

struct btm_client_interface_s btm_client_interface = {};

struct btm_client_interface_s& get_btm_client_interface() {
  return btm_client_interface;
}
