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
 *   Functions generated:66
 */

#include <map>
#include <string>

extern std::map<std::string, int> mock_function_count_map;

#include <base/strings/stringprintf.h>
#include <frameworks/proto_logging/stats/enums/bluetooth/enums.pb.h>
#include <frameworks/proto_logging/stats/enums/bluetooth/hci/enums.pb.h>
#include <string.h>
#include "bt_types.h"
#include "btif/include/btif_storage.h"
#include "common/metrics.h"
#include "common/time_util.h"
#include "device/include/controller.h"
#include "hcimsgs.h"
#include "l2c_api.h"
#include "main/shim/btm_api.h"
#include "main/shim/dumpsys.h"
#include "main/shim/shim.h"
#include "osi/include/log.h"
#include "osi/include/osi.h"
#include "stack/btm/btm_dev.h"
#include "stack/btm/btm_sec.h"
#include "stack/include/acl_api.h"
#include "stack/include/acl_hci_link_interface.h"
#include "stack/include/btm_status.h"
#include "stack/include/l2cap_security_interface.h"
#include "stack/smp/smp_int.h"

#ifndef UNUSED_ATTR
#define UNUSED_ATTR
#endif

bool BTM_BothEndsSupportSecureConnections(const RawAddress& bd_addr) {
  mock_function_count_map[__func__]++;
  return false;
}
bool BTM_GetSecurityFlags(const RawAddress& bd_addr, uint8_t* p_sec_flags) {
  mock_function_count_map[__func__]++;
  return false;
}
bool BTM_GetSecurityFlagsByTransport(const RawAddress& bd_addr,
                                     uint8_t* p_sec_flags,
                                     tBT_TRANSPORT transport) {
  mock_function_count_map[__func__]++;
  return false;
}
bool BTM_IsAuthenticated(const RawAddress& bd_addr, tBT_TRANSPORT transport) {
  mock_function_count_map[__func__]++;
  return false;
}
bool BTM_IsEncrypted(const RawAddress& bd_addr, tBT_TRANSPORT transport) {
  mock_function_count_map[__func__]++;
  return false;
}
bool BTM_IsLinkKeyAuthed(const RawAddress& bd_addr, tBT_TRANSPORT transport) {
  mock_function_count_map[__func__]++;
  return false;
}
bool BTM_IsLinkKeyKnown(const RawAddress& bd_addr, tBT_TRANSPORT transport) {
  mock_function_count_map[__func__]++;
  return false;
}
bool BTM_PeerSupportsSecureConnections(const RawAddress& bd_addr) {
  mock_function_count_map[__func__]++;
  return false;
}
bool BTM_SecAddRmtNameNotifyCallback(tBTM_RMT_NAME_CALLBACK* p_callback) {
  mock_function_count_map[__func__]++;
  return false;
}
bool BTM_SecDeleteRmtNameNotifyCallback(tBTM_RMT_NAME_CALLBACK* p_callback) {
  mock_function_count_map[__func__]++;
  return false;
}
bool BTM_SecIsSecurityPending(const RawAddress& bd_addr) {
  mock_function_count_map[__func__]++;
  return false;
}
bool BTM_SecRegister(const tBTM_APPL_INFO* p_cb_info) {
  mock_function_count_map[__func__]++;
  return false;
}
bool BTM_SetSecurityLevel(bool is_originator, const char* p_name,
                          uint8_t service_id, uint16_t sec_level, uint16_t psm,
                          uint32_t mx_proto_id, uint32_t mx_chan_id) {
  mock_function_count_map[__func__]++;
  return false;
}
bool btm_sec_is_a_bonded_dev(const RawAddress& bda) {
  mock_function_count_map[__func__]++;
  return false;
}
bool is_sec_state_equal(void* data, void* context) {
  mock_function_count_map[__func__]++;
  return false;
}
bool is_state_getting_name(void* data, void* context) {
  mock_function_count_map[__func__]++;
  return false;
}
const uint8_t* btm_get_dev_class(const RawAddress& bda) {
  mock_function_count_map[__func__]++;
  return nullptr;
}
tBTM_LINK_KEY_TYPE BTM_SecGetDeviceLinkKeyType(const RawAddress& bd_addr) {
  mock_function_count_map[__func__]++;
  return 0;
}
tBTM_SEC_DEV_REC* btm_sec_find_dev_by_sec_state(uint8_t state) {
  mock_function_count_map[__func__]++;
  return nullptr;
}
tBTM_SEC_SERV_REC* btm_sec_find_first_serv(bool is_originator, uint16_t psm) {
  mock_function_count_map[__func__]++;
  return nullptr;
}
tBTM_STATUS BTM_SecBond(const RawAddress& bd_addr, tBLE_ADDR_TYPE addr_type,
                        tBT_TRANSPORT transport, int device_type,
                        uint8_t pin_len, uint8_t* p_pin) {
  mock_function_count_map[__func__]++;
  return BTM_SUCCESS;
}
tBTM_STATUS BTM_SecBondCancel(const RawAddress& bd_addr) {
  mock_function_count_map[__func__]++;
  return BTM_SUCCESS;
}
tBTM_STATUS BTM_SetEncryption(const RawAddress& bd_addr,
                              tBT_TRANSPORT transport,
                              tBTM_SEC_CALLBACK* p_callback, void* p_ref_data,
                              tBTM_BLE_SEC_ACT sec_act) {
  mock_function_count_map[__func__]++;
  return BTM_SUCCESS;
}
tBTM_STATUS btm_sec_bond_by_transport(const RawAddress& bd_addr,
                                      tBT_TRANSPORT transport, uint8_t pin_len,
                                      uint8_t* p_pin) {
  mock_function_count_map[__func__]++;
  return BTM_SUCCESS;
}
tBTM_STATUS btm_sec_disconnect(uint16_t handle, tHCI_STATUS reason) {
  mock_function_count_map[__func__]++;
  return BTM_SUCCESS;
}
tBTM_STATUS btm_sec_execute_procedure(tBTM_SEC_DEV_REC* p_dev_rec) {
  mock_function_count_map[__func__]++;
  return BTM_SUCCESS;
}
tBTM_STATUS btm_sec_l2cap_access_req(const RawAddress& bd_addr, uint16_t psm,
                                     bool is_originator,
                                     tBTM_SEC_CALLBACK* p_callback,
                                     void* p_ref_data) {
  mock_function_count_map[__func__]++;
  return BTM_SUCCESS;
}
tBTM_STATUS btm_sec_l2cap_access_req_by_requirement(
    const RawAddress& bd_addr, uint16_t security_required, bool is_originator,
    tBTM_SEC_CALLBACK* p_callback, void* p_ref_data) {
  mock_function_count_map[__func__]++;
  return BTM_SUCCESS;
}
tBTM_STATUS btm_sec_mx_access_request(const RawAddress& bd_addr,
                                      bool is_originator,
                                      uint16_t security_required,
                                      tBTM_SEC_CALLBACK* p_callback,
                                      void* p_ref_data) {
  mock_function_count_map[__func__]++;
  return BTM_SUCCESS;
}
uint16_t BTM_GetClockOffset(const RawAddress& remote_bda) {
  mock_function_count_map[__func__]++;
  return 0;
}
uint8_t BTM_SecClrService(uint8_t service_id) {
  mock_function_count_map[__func__]++;
  return 0;
}
uint8_t BTM_SecClrServiceByPsm(uint16_t psm) {
  mock_function_count_map[__func__]++;
  return 0;
}
void BTM_ConfirmReqReply(tBTM_STATUS res, const RawAddress& bd_addr) {
  mock_function_count_map[__func__]++;
}
void BTM_PINCodeReply(const RawAddress& bd_addr, uint8_t res, uint8_t pin_len,
                      uint8_t* p_pin) {
  mock_function_count_map[__func__]++;
}
void BTM_PasskeyReqReply(tBTM_STATUS res, const RawAddress& bd_addr,
                         uint32_t passkey) {
  mock_function_count_map[__func__]++;
}
void BTM_ReadLocalOobData(void) { mock_function_count_map[__func__]++; }
void BTM_RemoteOobDataReply(tBTM_STATUS res, const RawAddress& bd_addr,
                            const Octet16& c, const Octet16& r) {
  mock_function_count_map[__func__]++;
}
void BTM_SetPinType(uint8_t pin_type, PIN_CODE pin_code, uint8_t pin_code_len) {
  mock_function_count_map[__func__]++;
}
void NotifyBondingCanceled(tBTM_STATUS btm_status) {
  mock_function_count_map[__func__]++;
}
void btm_create_conn_cancel_complete(uint8_t* p) {
  mock_function_count_map[__func__]++;
}
void btm_io_capabilities_req(const RawAddress& p) {
  mock_function_count_map[__func__]++;
}
void btm_io_capabilities_rsp(uint8_t* p) {
  mock_function_count_map[__func__]++;
}
void btm_proc_sp_req_evt(tBTM_SP_EVT event, uint8_t* p) {
  mock_function_count_map[__func__]++;
}
void btm_read_local_oob_complete(uint8_t* p) {
  mock_function_count_map[__func__]++;
}
void btm_rem_oob_req(uint8_t* p) { mock_function_count_map[__func__]++; }
void btm_sec_abort_access_req(const RawAddress& bd_addr) {
  mock_function_count_map[__func__]++;
}
void btm_sec_auth_complete(uint16_t handle, tHCI_STATUS status) {
  mock_function_count_map[__func__]++;
}
void btm_sec_check_pending_reqs(void) { mock_function_count_map[__func__]++; }
void btm_sec_clear_ble_keys(tBTM_SEC_DEV_REC* p_dev_rec) {
  mock_function_count_map[__func__]++;
}
void btm_sec_conn_req(const RawAddress& bda, uint8_t* dc) {
  mock_function_count_map[__func__]++;
}
void btm_sec_connected(const RawAddress& bda, uint16_t handle,
                       tHCI_STATUS status, uint8_t enc_mode,
                       tHCI_ROLE assigned_role) {
  mock_function_count_map[__func__]++;
}
void btm_sec_dev_rec_cback_event(tBTM_SEC_DEV_REC* p_dev_rec,
                                 tBTM_STATUS btm_status, bool is_le_transport) {
  mock_function_count_map[__func__]++;
}
void btm_sec_dev_reset(void) { mock_function_count_map[__func__]++; }
void btm_sec_disconnected(uint16_t handle, tHCI_REASON reason) {
  mock_function_count_map[__func__]++;
}
void btm_sec_encrypt_change(uint16_t handle, tHCI_STATUS status,
                            uint8_t encr_enable) {
  mock_function_count_map[__func__]++;
}
void btm_sec_link_key_notification(const RawAddress& p_bda,
                                   const Octet16& link_key, uint8_t key_type) {
  mock_function_count_map[__func__]++;
}
void btm_sec_link_key_request(uint8_t* p_event) {
  mock_function_count_map[__func__]++;
}
void btm_sec_pin_code_request(uint8_t* p_event) {
  mock_function_count_map[__func__]++;
}
void btm_sec_rmt_host_support_feat_evt(uint8_t* p) {
  mock_function_count_map[__func__]++;
}
void btm_sec_rmt_name_request_complete(const RawAddress* p_bd_addr,
                                       uint8_t* p_bd_name, tHCI_STATUS status) {
  mock_function_count_map[__func__]++;
}
void btm_sec_set_peer_sec_caps(uint16_t hci_handle, bool ssp_supported,
                               bool sc_supported,
                               bool hci_role_switch_supported) {
  mock_function_count_map[__func__]++;
}
void btm_sec_update_clock_offset(uint16_t handle, uint16_t clock_offset) {
  mock_function_count_map[__func__]++;
}
void btm_simple_pair_complete(uint8_t* p) {
  mock_function_count_map[__func__]++;
}
