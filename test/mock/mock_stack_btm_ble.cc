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
 *   Functions generated:50
 */

#include <map>
#include <string>

extern std::map<std::string, int> mock_function_count_map;

#include <cstdint>
#include "device/include/controller.h"
#include "main/shim/btm_api.h"
#include "main/shim/l2c_api.h"
#include "main/shim/shim.h"
#include "stack/btm/btm_dev.h"
#include "stack/btm/btm_int_types.h"
#include "stack/btm/security_device_record.h"
#include "stack/crypto_toolbox/crypto_toolbox.h"
#include "stack/include/acl_api.h"
#include "stack/include/bt_types.h"
#include "stack/include/btm_api.h"
#include "stack/include/btu.h"
#include "stack/include/gatt_api.h"
#include "stack/include/l2cap_security_interface.h"
#include "stack/include/l2cdefs.h"
#include "stack/include/smp_api.h"
#include "types/raw_address.h"

#ifndef UNUSED_ATTR
#define UNUSED_ATTR
#endif

bool BTM_BleDataSignature(const RawAddress& bd_addr, uint8_t* p_text,
                          uint16_t len, BLE_SIGNATURE signature) {
  mock_function_count_map[__func__]++;
  return false;
}
bool BTM_BleVerifySignature(const RawAddress& bd_addr, uint8_t* p_orig,
                            uint16_t len, uint32_t counter, uint8_t* p_comp) {
  mock_function_count_map[__func__]++;
  return false;
}
bool BTM_ReadConnectedTransportAddress(RawAddress* remote_bda,
                                       tBT_TRANSPORT transport) {
  mock_function_count_map[__func__]++;
  return false;
}
bool BTM_UseLeLink(const RawAddress& bd_addr) {
  mock_function_count_map[__func__]++;
  return false;
}
bool btm_ble_get_acl_remote_addr(uint16_t hci_handle, RawAddress& conn_addr,
                                 tBLE_ADDR_TYPE* p_addr_type) {
  mock_function_count_map[__func__]++;
  return false;
}
bool btm_ble_get_enc_key_type(const RawAddress& bd_addr, uint8_t* p_key_types) {
  mock_function_count_map[__func__]++;
  return false;
}
bool btm_get_local_div(const RawAddress& bd_addr, uint16_t* p_div) {
  mock_function_count_map[__func__]++;
  return false;
}
static Octet16 octet16;

const Octet16& BTM_GetDeviceDHK() {
  mock_function_count_map[__func__]++;
  return octet16;
}
const Octet16& BTM_GetDeviceEncRoot() {
  mock_function_count_map[__func__]++;
  return octet16;
}
const Octet16& BTM_GetDeviceIDRoot() {
  mock_function_count_map[__func__]++;
  return octet16;
}
tBTM_SEC_ACTION btm_ble_determine_security_act(bool is_originator,
                                               const RawAddress& bdaddr,
                                               uint16_t security_required) {
  mock_function_count_map[__func__]++;
  return 0;
}
tBTM_STATUS BTM_SetBleDataLength(const RawAddress& bd_addr,
                                 uint16_t tx_pdu_length) {
  mock_function_count_map[__func__]++;
  return 0;
}
tBTM_STATUS btm_ble_set_encryption(const RawAddress& bd_addr,
                                   tBTM_BLE_SEC_ACT sec_act,
                                   uint8_t link_role) {
  mock_function_count_map[__func__]++;
  return 0;
}
tBTM_STATUS btm_ble_start_encrypt(const RawAddress& bda, bool use_stk,
                                  Octet16* p_stk) {
  mock_function_count_map[__func__]++;
  return 0;
}
tBTM_STATUS btm_proc_smp_cback(tSMP_EVT event, const RawAddress& bd_addr,
                               tSMP_EVT_DATA* p_data) {
  mock_function_count_map[__func__]++;
  return 0;
}
tL2CAP_LE_RESULT_CODE btm_ble_start_sec_check(const RawAddress& bd_addr,
                                              uint16_t psm, bool is_originator,
                                              tBTM_SEC_CALLBACK* p_callback,
                                              void* p_ref_data) {
  mock_function_count_map[__func__]++;
  return L2CAP_LE_RESULT_CONN_OK;
}
uint8_t btm_ble_br_keys_req(tBTM_SEC_DEV_REC* p_dev_rec,
                            tBTM_LE_IO_REQ* p_data) {
  mock_function_count_map[__func__]++;
  return 0;
}
uint8_t btm_ble_io_capabilities_req(tBTM_SEC_DEV_REC* p_dev_rec,
                                    tBTM_LE_IO_REQ* p_data) {
  mock_function_count_map[__func__]++;
  return 0;
}
uint8_t btm_ble_read_sec_key_size(const RawAddress& bd_addr) {
  mock_function_count_map[__func__]++;
  return 0;
}
void BTM_BleConfirmReply(const RawAddress& bd_addr, uint8_t res) {
  mock_function_count_map[__func__]++;
}
void BTM_BleLoadLocalKeys(uint8_t key_type, tBTM_BLE_LOCAL_KEYS* p_key) {
  mock_function_count_map[__func__]++;
}
void BTM_BleOobDataReply(const RawAddress& bd_addr, uint8_t res, uint8_t len,
                         uint8_t* p_data) {
  mock_function_count_map[__func__]++;
}
void BTM_BlePasskeyReply(const RawAddress& bd_addr, uint8_t res,
                         uint32_t passkey) {
  mock_function_count_map[__func__]++;
}
void BTM_BleReadPhy(
    const RawAddress& bd_addr,
    base::Callback<void(uint8_t tx_phy, uint8_t rx_phy, uint8_t status)> cb) {
  mock_function_count_map[__func__]++;
}
void BTM_BleReceiverTest(uint8_t rx_freq, tBTM_CMPL_CB* p_cmd_cmpl_cback) {
  mock_function_count_map[__func__]++;
}
void BTM_BleSecureConnectionOobDataReply(const RawAddress& bd_addr,
                                         uint8_t* p_c, uint8_t* p_r) {
  mock_function_count_map[__func__]++;
}
void BTM_BleSetPhy(const RawAddress& bd_addr, uint8_t tx_phys, uint8_t rx_phys,
                   uint16_t phy_options) {
  mock_function_count_map[__func__]++;
}
void BTM_BleSetPrefConnParams(const RawAddress& bd_addr, uint16_t min_conn_int,
                              uint16_t max_conn_int,
                              uint16_t peripheral_latency,
                              uint16_t supervision_tout) {
  mock_function_count_map[__func__]++;
}
void BTM_BleTestEnd(tBTM_CMPL_CB* p_cmd_cmpl_cback) {
  mock_function_count_map[__func__]++;
}
void BTM_BleTransmitterTest(uint8_t tx_freq, uint8_t test_data_len,
                            uint8_t packet_payload,
                            tBTM_CMPL_CB* p_cmd_cmpl_cback) {
  mock_function_count_map[__func__]++;
}
void BTM_ReadDevInfo(const RawAddress& remote_bda, tBT_DEVICE_TYPE* p_dev_type,
                     tBLE_ADDR_TYPE* p_addr_type) {
  mock_function_count_map[__func__]++;
}
void BTM_SecAddBleDevice(const RawAddress& bd_addr, tBT_DEVICE_TYPE dev_type,
                         tBLE_ADDR_TYPE addr_type) {
  mock_function_count_map[__func__]++;
}
void BTM_SecAddBleKey(const RawAddress& bd_addr, tBTM_LE_KEY_VALUE* p_le_key,
                      tBTM_LE_KEY_TYPE key_type) {
  mock_function_count_map[__func__]++;
}
void BTM_SecurityGrant(const RawAddress& bd_addr, uint8_t res) {
  mock_function_count_map[__func__]++;
}
void btm_ble_connected(const RawAddress& bda, uint16_t handle, uint8_t enc_mode,
                       uint8_t role, tBLE_ADDR_TYPE addr_type,
                       bool addr_matched) {
  mock_function_count_map[__func__]++;
}
void btm_ble_connected_from_address_with_type(
    const tBLE_BD_ADDR& address_with_type, uint16_t handle, uint8_t enc_mode,
    uint8_t role, bool addr_matched) {
  mock_function_count_map[__func__]++;
}
void btm_ble_increment_sign_ctr(const RawAddress& bd_addr, bool is_local) {
  mock_function_count_map[__func__]++;
}
void btm_ble_link_encrypted(const RawAddress& bd_addr, uint8_t encr_enable) {
  mock_function_count_map[__func__]++;
}
void btm_ble_link_sec_check(const RawAddress& bd_addr,
                            tBTM_LE_AUTH_REQ auth_req,
                            tBTM_BLE_SEC_REQ_ACT* p_sec_req_act) {
  mock_function_count_map[__func__]++;
}
void btm_ble_ltk_request(uint16_t handle, uint8_t rand[8], uint16_t ediv) {
  mock_function_count_map[__func__]++;
}
void btm_ble_ltk_request_reply(const RawAddress& bda, bool use_stk,
                               const Octet16& stk) {
  mock_function_count_map[__func__]++;
}
void btm_ble_rand_enc_complete(uint8_t* p, uint16_t op_code,
                               tBTM_RAND_ENC_CB* p_enc_cplt_cback) {
  mock_function_count_map[__func__]++;
}
void btm_ble_set_random_address(const RawAddress& random_bda) {
  mock_function_count_map[__func__]++;
}
void btm_ble_test_command_complete(uint8_t* p) {
  mock_function_count_map[__func__]++;
}
void btm_ble_update_sec_key_size(const RawAddress& bd_addr,
                                 uint8_t enc_key_size) {
  mock_function_count_map[__func__]++;
}
void btm_sec_save_le_key(const RawAddress& bd_addr, tBTM_LE_KEY_TYPE key_type,
                         tBTM_LE_KEY_VALUE* p_keys, bool pass_to_application) {
  mock_function_count_map[__func__]++;
}
void doNothing(uint8_t* data, uint16_t len) {
  mock_function_count_map[__func__]++;
}
void read_phy_cb(
    base::Callback<void(uint8_t tx_phy, uint8_t rx_phy, uint8_t status)> cb,
    uint8_t* data, uint16_t len) {
  mock_function_count_map[__func__]++;
}
void btm_ble_reset_id(void) {
  mock_function_count_map[__func__]++;
}
