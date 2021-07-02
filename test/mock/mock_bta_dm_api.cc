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
 *   Functions generated:33
 */

#include <map>
#include <string>

extern std::map<std::string, int> mock_function_count_map;

#include <base/bind.h>
#include <vector>
#include "bt_target.h"
#include "bta/dm/bta_dm_int.h"
#include "osi/include/allocator.h"
#include "stack/btm/btm_sec.h"
#include "stack/include/btm_api.h"
#include "stack/include/btu.h"
#include "types/bluetooth/uuid.h"
#include "types/raw_address.h"

#ifndef UNUSED_ATTR
#define UNUSED_ATTR
#endif

void BTA_dm_init() { mock_function_count_map[__func__]++; }
bool BTA_DmGetConnectionState(const RawAddress& bd_addr) {
  mock_function_count_map[__func__]++;
  return false;
}
tBTA_STATUS BTA_DmRemoveDevice(const RawAddress& bd_addr) {
  mock_function_count_map[__func__]++;
  return BTA_SUCCESS;
}
tBTA_STATUS BTA_DmSetLocalDiRecord(tSDP_DI_RECORD* p_device_info,
                                   uint32_t* p_handle) {
  mock_function_count_map[__func__]++;
  return BTA_SUCCESS;
}
void BTA_AddEirUuid(uint16_t uuid16) { mock_function_count_map[__func__]++; }
void BTA_DmAddBleDevice(const RawAddress& bd_addr, tBLE_ADDR_TYPE addr_type,
                        tBT_DEVICE_TYPE dev_type) {
  mock_function_count_map[__func__]++;
}
void BTA_DmAddBleKey(const RawAddress& bd_addr, tBTA_LE_KEY_VALUE* p_le_key,
                     tBTM_LE_KEY_TYPE key_type) {
  mock_function_count_map[__func__]++;
}
void BTA_DmAddDevice(const RawAddress& bd_addr, DEV_CLASS dev_class,
                     const LinkKey& link_key, uint8_t key_type,
                     uint8_t pin_length) {
  mock_function_count_map[__func__]++;
}
void BTA_DmBleConfigLocalPrivacy(bool privacy_enable) {
  mock_function_count_map[__func__]++;
}
void BTA_DmBleConfirmReply(const RawAddress& bd_addr, bool accept) {
  mock_function_count_map[__func__]++;
}
void BTA_DmBleGetEnergyInfo(tBTA_BLE_ENERGY_INFO_CBACK* p_cmpl_cback) {
  mock_function_count_map[__func__]++;
}
void BTA_DmBlePasskeyReply(const RawAddress& bd_addr, bool accept,
                           uint32_t passkey) {
  mock_function_count_map[__func__]++;
}
void BTA_DmBleRequestMaxTxDataLength(const RawAddress& remote_device) {
  mock_function_count_map[__func__]++;
}
void BTA_DmBleSecurityGrant(const RawAddress& bd_addr,
                            tBTA_DM_BLE_SEC_GRANT res) {
  mock_function_count_map[__func__]++;
}
void BTA_DmBleUpdateConnectionParams(const RawAddress& bd_addr,
                                     uint16_t min_int, uint16_t max_int,
                                     uint16_t latency, uint16_t timeout,
                                     uint16_t min_ce_len, uint16_t max_ce_len) {
  mock_function_count_map[__func__]++;
}
void BTA_DmBond(const RawAddress& bd_addr, tBLE_ADDR_TYPE addr_type,
                tBT_TRANSPORT transport, int device_type) {
  mock_function_count_map[__func__]++;
}
void BTA_DmBondCancel(const RawAddress& bd_addr) {
  mock_function_count_map[__func__]++;
}
void BTA_DmCloseACL(const RawAddress& bd_addr, bool remove_dev,
                    tBT_TRANSPORT transport) {
  mock_function_count_map[__func__]++;
}
void BTA_DmConfirm(const RawAddress& bd_addr, bool accept) {
  mock_function_count_map[__func__]++;
}
void BTA_DmDiscover(const RawAddress& bd_addr, tBTA_DM_SEARCH_CBACK* p_cback,
                    tBT_TRANSPORT transport, bool is_bonding_or_sd) {
  mock_function_count_map[__func__]++;
}
void BTA_DmLocalOob(void) { mock_function_count_map[__func__]++; }
void BTA_DmPinReply(const RawAddress& bd_addr, bool accept, uint8_t pin_len,
                    uint8_t* p_pin) {
  mock_function_count_map[__func__]++;
}
void BTA_DmSearch(tBTA_DM_SEARCH_CBACK* p_cback, bool is_bonding_or_sdp) {
  mock_function_count_map[__func__]++;
}
void BTA_DmSearchCancel(void) { mock_function_count_map[__func__]++; }
void BTA_DmSetBlePrefConnParams(const RawAddress& bd_addr,
                                uint16_t min_conn_int, uint16_t max_conn_int,
                                uint16_t peripheral_latency,
                                uint16_t supervision_tout) {
  mock_function_count_map[__func__]++;
}
void BTA_DmSetDeviceName(char* p_name) { mock_function_count_map[__func__]++; }
void BTA_DmSetEncryption(const RawAddress& bd_addr, tBT_TRANSPORT transport,
                         tBTA_DM_ENCRYPT_CBACK* p_callback,
                         tBTM_BLE_SEC_ACT sec_act) {
  mock_function_count_map[__func__]++;
}
void BTA_EnableTestMode(void) { mock_function_count_map[__func__]++; }
void BTA_GetEirService(uint8_t* p_eir, size_t eir_len,
                       tBTA_SERVICE_MASK* p_services) {
  mock_function_count_map[__func__]++;
}
void BTA_RemoveEirUuid(uint16_t uuid16) { mock_function_count_map[__func__]++; }
void BTA_DmBleObserve(bool start, uint8_t duration,
                      tBTA_DM_SEARCH_CBACK* p_results_cb) {
  mock_function_count_map[__func__]++;
}
void BTA_VendorInit(void) { mock_function_count_map[__func__]++; }
