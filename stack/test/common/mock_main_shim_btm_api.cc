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
 *   Functions generated:85
 */

#include <map>
#include <string>

extern std::map<std::string, int> mock_function_count_map;

#include <base/callback.h>
#include <mutex>
#include "common/metric_id_allocator.h"
#include "common/time_util.h"
#include "device/include/controller.h"
#include "main/shim/btm_api.h"
#include "main/shim/controller.h"
#include "main/shim/link_policy.h"
#include "main/shim/shim.h"
#include "stack/btm/btm_int_types.h"
#include "types/raw_address.h"

#ifndef UNUSED_ATTR
#define UNUSED_ATTR
#endif

Octet16 octet16;

bool bluetooth::shim::BTM_BleDataSignature(const RawAddress& bd_addr,
                                           uint8_t* p_text, uint16_t len,
                                           BLE_SIGNATURE signature) {
  mock_function_count_map[__func__]++;
  return false;
}
bool bluetooth::shim::BTM_BleLocalPrivacyEnabled(void) {
  mock_function_count_map[__func__]++;
  return false;
}
bool bluetooth::shim::BTM_BleSecurityProcedureIsRunning(
    const RawAddress& bd_addr) {
  mock_function_count_map[__func__]++;
  return false;
}
bool bluetooth::shim::BTM_BleVerifySignature(const RawAddress& bd_addr,
                                             uint8_t* p_orig, uint16_t len,
                                             uint32_t counter,
                                             uint8_t* p_comp) {
  mock_function_count_map[__func__]++;
  return false;
}
bool bluetooth::shim::BTM_GetLeSecurityState(const RawAddress& bd_addr,
                                             uint8_t* p_le_dev_sec_flags,
                                             uint8_t* p_le_key_size) {
  mock_function_count_map[__func__]++;
  return false;
}
bool bluetooth::shim::BTM_HasEirService(const uint32_t* p_eir_uuid,
                                        uint16_t uuid16) {
  mock_function_count_map[__func__]++;
  return false;
}
bool bluetooth::shim::BTM_ReadConnectedTransportAddress(
    RawAddress* remote_bda, tBT_TRANSPORT transport) {
  mock_function_count_map[__func__]++;
  return false;
}
bool bluetooth::shim::BTM_ReadRemoteConnectionAddr(
    const RawAddress& pseudo_addr, RawAddress& conn_addr,
    tBLE_ADDR_TYPE* p_addr_type) {
  mock_function_count_map[__func__]++;
  return false;
}
bool bluetooth::shim::BTM_SecAddDevice(const RawAddress& bd_addr,
                                       DEV_CLASS dev_class, BD_NAME bd_name,
                                       uint8_t* features, LinkKey* link_key,
                                       uint8_t key_type, uint8_t pin_length) {
  mock_function_count_map[__func__]++;
  return false;
}
bool bluetooth::shim::BTM_SecAddRmtNameNotifyCallback(
    tBTM_RMT_NAME_CALLBACK* p_callback) {
  mock_function_count_map[__func__]++;
  return false;
}
bool bluetooth::shim::BTM_SecDeleteDevice(const RawAddress& bd_addr) {
  mock_function_count_map[__func__]++;
  return false;
}
bool bluetooth::shim::BTM_SecDeleteRmtNameNotifyCallback(
    tBTM_RMT_NAME_CALLBACK* p_callback) {
  mock_function_count_map[__func__]++;
  return false;
}
bool bluetooth::shim::BTM_SecRegister(const tBTM_APPL_INFO* bta_callbacks) {
  mock_function_count_map[__func__]++;
  return false;
}
bool bluetooth::shim::BTM_UseLeLink(const RawAddress& raw_address) {
  mock_function_count_map[__func__]++;
  return false;
}
char* bluetooth::shim::BTM_SecReadDevName(const RawAddress& address) {
  mock_function_count_map[__func__]++;
  return nullptr;
}
const Octet16& bluetooth::shim::BTM_GetDeviceEncRoot() {
  mock_function_count_map[__func__]++;
  return octet16;
}
const Octet16& bluetooth::shim::BTM_GetDeviceDHK() {
  mock_function_count_map[__func__]++;
  return octet16;
}
const Octet16& bluetooth::shim::BTM_GetDeviceIDRoot() {
  mock_function_count_map[__func__]++;
  return octet16;
}
tBTM_EIR_SEARCH_RESULT bluetooth::shim::BTM_HasInquiryEirService(
    tBTM_INQ_RESULTS* p_results, uint16_t uuid16) {
  mock_function_count_map[__func__]++;
  return 0;
}
tBTM_INQ_INFO* bluetooth::shim::BTM_InqDbFirst(void) {
  mock_function_count_map[__func__]++;
  return nullptr;
}
tBTM_INQ_INFO* bluetooth::shim::BTM_InqDbNext(tBTM_INQ_INFO* p_cur) {
  mock_function_count_map[__func__]++;
  return nullptr;
}
tBTM_INQ_INFO* bluetooth::shim::BTM_InqDbRead(const RawAddress& p_bda) {
  mock_function_count_map[__func__]++;
  return nullptr;
}
tBTM_STATUS bluetooth::shim::BTM_BleObserve(bool start, uint8_t duration_sec,
                                            tBTM_INQ_RESULTS_CB* p_results_cb,
                                            tBTM_CMPL_CB* p_cmpl_cb) {
  mock_function_count_map[__func__]++;
  return BTM_SUCCESS;
}
tBTM_STATUS bluetooth::shim::BTM_CancelRemoteDeviceName(void) {
  mock_function_count_map[__func__]++;
  return BTM_SUCCESS;
}
tBTM_STATUS bluetooth::shim::BTM_ClearInqDb(const RawAddress* p_bda) {
  mock_function_count_map[__func__]++;
  return BTM_SUCCESS;
}
tBTM_STATUS bluetooth::shim::BTM_ReadRemoteDeviceName(
    const RawAddress& raw_address, tBTM_CMPL_CB* callback,
    tBT_TRANSPORT transport) {
  mock_function_count_map[__func__]++;
  return BTM_SUCCESS;
}
tBTM_STATUS bluetooth::shim::BTM_SecBond(const RawAddress& bd_addr,
                                         tBLE_ADDR_TYPE addr_type,
                                         tBT_TRANSPORT transport,
                                         int device_type) {
  mock_function_count_map[__func__]++;
  return BTM_SUCCESS;
}
tBTM_STATUS bluetooth::shim::BTM_SecBondCancel(const RawAddress& bd_addr) {
  mock_function_count_map[__func__]++;
  return BTM_SUCCESS;
}
tBTM_STATUS bluetooth::shim::BTM_SetConnectability(uint16_t page_mode,
                                                   uint16_t window,
                                                   uint16_t interval) {
  mock_function_count_map[__func__]++;
  return BTM_SUCCESS;
}
tBTM_STATUS bluetooth::shim::BTM_SetDeviceClass(DEV_CLASS dev_class) {
  mock_function_count_map[__func__]++;
  return BTM_SUCCESS;
}
tBTM_STATUS bluetooth::shim::BTM_SetDiscoverability(uint16_t discoverable_mode,
                                                    uint16_t window,
                                                    uint16_t interval) {
  mock_function_count_map[__func__]++;
  return BTM_SUCCESS;
}
tBTM_STATUS bluetooth::shim::BTM_SetEncryption(const RawAddress& bd_addr,
                                               tBT_TRANSPORT transport,
                                               tBTM_SEC_CALLBACK* p_callback,
                                               void* p_ref_data,
                                               tBTM_BLE_SEC_ACT sec_act) {
  mock_function_count_map[__func__]++;
  return BTM_SUCCESS;
}
tBTM_STATUS bluetooth::shim::BTM_SetInquiryMode(uint8_t inquiry_mode) {
  mock_function_count_map[__func__]++;
  return BTM_SUCCESS;
}
tBTM_STATUS bluetooth::shim::BTM_StartInquiry(tBTM_INQ_RESULTS_CB* p_results_cb,
                                              tBTM_CMPL_CB* p_cmpl_cb) {
  mock_function_count_map[__func__]++;
  return BTM_SUCCESS;
}
tBTM_STATUS bluetooth::shim::BTM_WriteEIR(BT_HDR* p_buff) {
  mock_function_count_map[__func__]++;
  return BTM_SUCCESS;
}
tBTM_STATUS bluetooth::shim::btm_sec_mx_access_request(
    const RawAddress& bd_addr, bool is_originator,
    uint16_t security_requirement, tBTM_SEC_CALLBACK* p_callback,
    void* p_ref_data) {
  mock_function_count_map[__func__]++;
  return BTM_SUCCESS;
}
uint16_t bluetooth::shim::BTM_GetHCIConnHandle(const RawAddress& remote_bda,
                                               tBT_TRANSPORT transport) {
  mock_function_count_map[__func__]++;
  return 0;
}
uint16_t bluetooth::shim::BTM_IsInquiryActive(void) {
  mock_function_count_map[__func__]++;
  return 0;
}
uint8_t bluetooth::shim::BTM_BleGetSupportedKeySize(const RawAddress& bd_addr) {
  mock_function_count_map[__func__]++;
  return 0;
}
uint8_t bluetooth::shim::BTM_BleMaxMultiAdvInstanceCount() {
  mock_function_count_map[__func__]++;
  return 0;
}
uint8_t bluetooth::shim::BTM_GetEirSupportedServices(uint32_t* p_eir_uuid,
                                                     uint8_t** p,
                                                     uint8_t max_num_uuid16,
                                                     uint8_t* p_num_uuid16) {
  mock_function_count_map[__func__]++;
  return 0;
}
uint8_t bluetooth::shim::BTM_GetEirUuidList(uint8_t* p_eir, size_t eir_len,
                                            uint8_t uuid_size,
                                            uint8_t* p_num_uuid,
                                            uint8_t* p_uuid_list,
                                            uint8_t max_num_uuid) {
  mock_function_count_map[__func__]++;
  return 0;
}
void bluetooth::shim::BTM_AddEirService(uint32_t* p_eir_uuid, uint16_t uuid16) {
  mock_function_count_map[__func__]++;
}
void bluetooth::shim::BTM_BleAdvFilterParamSetup(
    int action, tBTM_BLE_PF_FILT_INDEX filt_index,
    std::unique_ptr<btgatt_filt_param_setup_t> p_filt_params,
    tBTM_BLE_PF_PARAM_CB cb) {
  mock_function_count_map[__func__]++;
}
void bluetooth::shim::BTM_BleEnableDisableFilterFeature(
    uint8_t enable, tBTM_BLE_PF_STATUS_CBACK p_stat_cback) {
  mock_function_count_map[__func__]++;
}
void bluetooth::shim::BTM_BleLoadLocalKeys(uint8_t key_type,
                                           tBTM_BLE_LOCAL_KEYS* p_key) {
  mock_function_count_map[__func__]++;
}
void bluetooth::shim::BTM_BleOobDataReply(const RawAddress& bd_addr,
                                          uint8_t res, uint8_t len,
                                          uint8_t* p_data) {
  mock_function_count_map[__func__]++;
}
void bluetooth::shim::BTM_BleReadPhy(
    const RawAddress& bd_addr,
    base::Callback<void(uint8_t tx_phy, uint8_t rx_phy, uint8_t status)> cb) {
  mock_function_count_map[__func__]++;
}
void bluetooth::shim::BTM_BleReceiverTest(uint8_t rx_freq,
                                          tBTM_CMPL_CB* p_cmd_cmpl_cback) {
  mock_function_count_map[__func__]++;
}
void bluetooth::shim::BTM_BleSecureConnectionOobDataReply(
    const RawAddress& bd_addr, uint8_t* p_c, uint8_t* p_r) {
  mock_function_count_map[__func__]++;
}
void bluetooth::shim::BTM_BleSetConnScanParams(uint32_t scan_interval,
                                               uint32_t scan_window) {
  mock_function_count_map[__func__]++;
}
void bluetooth::shim::BTM_BleSetPhy(const RawAddress& bd_addr, uint8_t tx_phys,
                                    uint8_t rx_phys, uint16_t phy_options) {
  mock_function_count_map[__func__]++;
}
void bluetooth::shim::BTM_BleSetPrefConnParams(const RawAddress& bd_addr,
                                               uint16_t min_conn_int,
                                               uint16_t max_conn_int,
                                               uint16_t peripheral_latency,
                                               uint16_t supervision_tout) {
  mock_function_count_map[__func__]++;
}
void bluetooth::shim::BTM_BleTestEnd(tBTM_CMPL_CB* p_cmd_cmpl_cback) {
  mock_function_count_map[__func__]++;
}
void bluetooth::shim::BTM_BleTransmitterTest(uint8_t tx_freq,
                                             uint8_t test_data_len,
                                             uint8_t packet_payload,
                                             tBTM_CMPL_CB* p_cmd_cmpl_cback) {
  mock_function_count_map[__func__]++;
}
void bluetooth::shim::BTM_BleUpdateAdvFilterPolicy(tBTM_BLE_AFP adv_policy) {
  mock_function_count_map[__func__]++;
}
void bluetooth::shim::BTM_CancelInquiry(void) {
  mock_function_count_map[__func__]++;
}
void bluetooth::shim::BTM_ConfirmReqReply(tBTM_STATUS res,
                                          const RawAddress& bd_addr) {
  mock_function_count_map[__func__]++;
}
void bluetooth::shim::BTM_EnableInterlacedInquiryScan() {
  mock_function_count_map[__func__]++;
}
void bluetooth::shim::BTM_EnableInterlacedPageScan() {
  mock_function_count_map[__func__]++;
}
void bluetooth::shim::BTM_LE_PF_addr_filter(tBTM_BLE_SCAN_COND_OP action,
                                            tBTM_BLE_PF_FILT_INDEX filt_index,
                                            tBLE_BD_ADDR addr,
                                            tBTM_BLE_PF_CFG_CBACK cb) {
  mock_function_count_map[__func__]++;
}
void bluetooth::shim::BTM_LE_PF_clear(tBTM_BLE_PF_FILT_INDEX filt_index,
                                      tBTM_BLE_PF_CFG_CBACK cb) {
  mock_function_count_map[__func__]++;
}
void bluetooth::shim::BTM_LE_PF_local_name(tBTM_BLE_SCAN_COND_OP action,
                                           tBTM_BLE_PF_FILT_INDEX filt_index,
                                           std::vector<uint8_t> name,
                                           tBTM_BLE_PF_CFG_CBACK cb) {
  mock_function_count_map[__func__]++;
}
void bluetooth::shim::BTM_LE_PF_manu_data(
    tBTM_BLE_SCAN_COND_OP action, tBTM_BLE_PF_FILT_INDEX filt_index,
    uint16_t company_id, uint16_t company_id_mask, std::vector<uint8_t> data,
    std::vector<uint8_t> data_mask, tBTM_BLE_PF_CFG_CBACK cb) {
  mock_function_count_map[__func__]++;
}
void bluetooth::shim::BTM_LE_PF_set(tBTM_BLE_PF_FILT_INDEX filt_index,
                                    std::vector<ApcfCommand> commands,
                                    tBTM_BLE_PF_CFG_CBACK cb) {
  mock_function_count_map[__func__]++;
}
void bluetooth::shim::BTM_LE_PF_srvc_data(tBTM_BLE_SCAN_COND_OP action,
                                          tBTM_BLE_PF_FILT_INDEX filt_index) {
  mock_function_count_map[__func__]++;
}
void bluetooth::shim::BTM_LE_PF_srvc_data_pattern(
    tBTM_BLE_SCAN_COND_OP action, tBTM_BLE_PF_FILT_INDEX filt_index,
    std::vector<uint8_t> data, std::vector<uint8_t> data_mask,
    tBTM_BLE_PF_CFG_CBACK cb) {
  mock_function_count_map[__func__]++;
}
void bluetooth::shim::BTM_LE_PF_uuid_filter(tBTM_BLE_SCAN_COND_OP action,
                                            tBTM_BLE_PF_FILT_INDEX filt_index,
                                            tBTM_BLE_PF_COND_TYPE filter_type,
                                            const bluetooth::Uuid& uuid,
                                            tBTM_BLE_PF_LOGIC_TYPE cond_logic,
                                            const bluetooth::Uuid& uuid_mask,
                                            tBTM_BLE_PF_CFG_CBACK cb) {
  mock_function_count_map[__func__]++;
}
void bluetooth::shim::BTM_PINCodeReply(const RawAddress& bd_addr, uint8_t res,
                                       uint8_t pin_len, uint8_t* p_pin) {
  mock_function_count_map[__func__]++;
}
void bluetooth::shim::BTM_ReadConnectionAddr(const RawAddress& remote_bda,
                                             RawAddress& local_conn_addr,
                                             tBLE_ADDR_TYPE* p_addr_type) {
  mock_function_count_map[__func__]++;
}
void bluetooth::shim::BTM_ReadDevInfo(const RawAddress& remote_bda,
                                      tBT_DEVICE_TYPE* p_dev_type,
                                      tBLE_ADDR_TYPE* p_addr_type) {
  mock_function_count_map[__func__]++;
}
void bluetooth::shim::BTM_RemoteOobDataReply(tBTM_STATUS res,
                                             const RawAddress& bd_addr,
                                             const Octet16& c,
                                             const Octet16& r) {
  mock_function_count_map[__func__]++;
}
void bluetooth::shim::BTM_RemoveEirService(uint32_t* p_eir_uuid,
                                           uint16_t uuid16) {
  mock_function_count_map[__func__]++;
}
void bluetooth::shim::BTM_SecAddBleDevice(const RawAddress& bd_addr,
                                          tBT_DEVICE_TYPE dev_type,
                                          tBLE_ADDR_TYPE addr_type) {
  mock_function_count_map[__func__]++;
}
void bluetooth::shim::BTM_SecAddBleKey(const RawAddress& bd_addr,
                                       tBTM_LE_KEY_VALUE* p_le_key,
                                       tBTM_LE_KEY_TYPE key_type) {
  mock_function_count_map[__func__]++;
}
void bluetooth::shim::BTM_SecClearSecurityFlags(const RawAddress& bd_addr) {
  mock_function_count_map[__func__]++;
}
void bluetooth::shim::BTM_SecurityGrant(const RawAddress& bd_addr,
                                        uint8_t res) {
  mock_function_count_map[__func__]++;
}
void bluetooth::shim::SendRemoteNameRequest(const RawAddress& raw_address) {
  mock_function_count_map[__func__]++;
}
void btm_api_process_extended_inquiry_result(RawAddress raw_address,
                                             uint8_t page_scan_rep_mode,
                                             DEV_CLASS device_class,
                                             uint16_t clock_offset, int8_t rssi,
                                             const uint8_t* eir_data,
                                             size_t eir_len) {
  mock_function_count_map[__func__]++;
}
void btm_api_process_inquiry_result(const RawAddress& raw_address,
                                    uint8_t page_scan_rep_mode,
                                    DEV_CLASS device_class,
                                    uint16_t clock_offset) {
  mock_function_count_map[__func__]++;
}
void btm_api_process_inquiry_result_with_rssi(RawAddress raw_address,
                                              uint8_t page_scan_rep_mode,
                                              DEV_CLASS device_class,
                                              uint16_t clock_offset,
                                              int8_t rssi) {
  mock_function_count_map[__func__]++;
}
tBTM_STATUS bluetooth::shim::BTM_SetPowerMode(uint16_t, tBTM_PM_PWR_MD const&) {
  mock_function_count_map[__func__]++;
  return BTM_SUCCESS;
}
void bluetooth::shim::btm_pm_on_mode_change(tHCI_STATUS status, uint16_t handle,
                                            tHCI_MODE current_mode,
                                            uint16_t interval) {
  mock_function_count_map[__func__]++;
}
tBTM_STATUS bluetooth::shim::BTM_SetSsrParams(uint16_t, uint16_t max_lat,
                                              uint16_t min_rmt_to,
                                              uint16_t min_loc_to) {
  mock_function_count_map[__func__]++;
  return BTM_SUCCESS;
}
void bluetooth::shim::btm_pm_on_sniff_subrating(
    tHCI_STATUS status, uint16_t handle, uint16_t maximum_transmit_latency,
    uint16_t maximum_receive_latency,
    UNUSED_ATTR uint16_t minimum_remote_timeout,
    UNUSED_ATTR uint16_t minimum_local_timeout) {
  mock_function_count_map[__func__]++;
}
