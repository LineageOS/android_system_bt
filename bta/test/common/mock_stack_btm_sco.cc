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
 *   Functions generated:23
 */

#include <cstdint>
#include <map>
#include <string>

extern std::map<std::string, int> mock_function_count_map;

#include "stack/include/btm_api_types.h"
#include "stack/include/btm_status.h"
#include "stack/include/hci_error_code.h"
#include "types/raw_address.h"

#ifndef UNUSED_ATTR
#define UNUSED_ATTR
#endif

bool BTM_IsScoActiveByBdaddr(const RawAddress& remote_bda) {
  mock_function_count_map[__func__]++;
  return false;
}
bool btm_is_sco_active(uint16_t handle) {
  mock_function_count_map[__func__]++;
  return false;
}
bool btm_sco_removed(uint16_t hci_handle, tHCI_REASON reason) {
  mock_function_count_map[__func__]++;
  return false;
}
const RawAddress* BTM_ReadScoBdAddr(uint16_t sco_inx) {
  mock_function_count_map[__func__]++;
  return nullptr;
}
tBTM_STATUS BTM_ChangeEScoLinkParms(uint16_t sco_inx,
                                    tBTM_CHG_ESCO_PARAMS* p_parms) {
  mock_function_count_map[__func__]++;
  return 0;
}
tBTM_STATUS BTM_CreateSco(const RawAddress* remote_bda, bool is_orig,
                          uint16_t pkt_types, uint16_t* p_sco_inx,
                          tBTM_SCO_CB* p_conn_cb, tBTM_SCO_CB* p_disc_cb) {
  mock_function_count_map[__func__]++;
  return 0;
}
tBTM_STATUS BTM_RegForEScoEvts(uint16_t sco_inx,
                               tBTM_ESCO_CBACK* p_esco_cback) {
  mock_function_count_map[__func__]++;
  return 0;
}
tBTM_STATUS BTM_RemoveSco(uint16_t sco_inx) {
  mock_function_count_map[__func__]++;
  return 0;
}
tBTM_STATUS BTM_SetEScoMode(enh_esco_params_t* p_parms) {
  mock_function_count_map[__func__]++;
  return 0;
}
uint8_t BTM_GetNumScoLinks(void) {
  mock_function_count_map[__func__]++;
  return 0;
}
void BTM_EScoConnRsp(uint16_t sco_inx, uint8_t hci_status,
                     enh_esco_params_t* p_parms) {
  mock_function_count_map[__func__]++;
}
void BTM_RemoveSco(const RawAddress& bda) {
  mock_function_count_map[__func__]++;
}
void btm_esco_proc_conn_chg(uint8_t status, uint16_t handle,
                            uint8_t tx_interval, uint8_t retrans_window,
                            uint16_t rx_pkt_len, uint16_t tx_pkt_len) {
  mock_function_count_map[__func__]++;
}
void btm_route_sco_data(BT_HDR* p_msg) { mock_function_count_map[__func__]++; }
void btm_sco_acl_removed(const RawAddress* bda) {
  mock_function_count_map[__func__]++;
}
void btm_sco_chk_pend_rolechange(uint16_t hci_handle) {
  mock_function_count_map[__func__]++;
}
void btm_sco_chk_pend_unpark(tHCI_STATUS hci_status, uint16_t hci_handle) {
  mock_function_count_map[__func__]++;
}
void btm_sco_conn_req(const RawAddress& bda, DEV_CLASS dev_class,
                      uint8_t link_type) {
  mock_function_count_map[__func__]++;
}
void btm_sco_connected(tHCI_STATUS hci_status, const RawAddress& bda,
                       uint16_t hci_handle, tBTM_ESCO_DATA* p_esco_data) {
  mock_function_count_map[__func__]++;
}
void btm_sco_disc_chk_pend_for_modechange(uint16_t hci_handle) {
  mock_function_count_map[__func__]++;
}
void btm_sco_on_disconnected(uint16_t hci_handle, tHCI_REASON reason) {
  mock_function_count_map[__func__]++;
}
