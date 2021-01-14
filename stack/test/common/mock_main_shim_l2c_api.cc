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
 *   Functions generated:54
 */

#include <map>
#include <string>

extern std::map<std::string, int> mock_function_count_map;

#include "main/shim/l2c_api.h"

#ifndef UNUSED_ATTR
#define UNUSED_ATTR
#endif

bool bluetooth::shim::L2CA_RegisterFixedChannel(uint16_t cid,
                                                tL2CAP_FIXED_CHNL_REG* p_freg) {
  mock_function_count_map[__func__]++;
  return false;
}
bool bluetooth::shim::L2CA_ConnectCreditBasedRsp(
    const RawAddress& bd_addr, uint8_t id,
    std::vector<uint16_t>& accepted_lcids, uint16_t result,
    tL2CAP_LE_CFG_INFO* p_cfg) {
  mock_function_count_map[__func__]++;
  return false;
}
bool bluetooth::shim::L2CA_ConnectFixedChnl(uint16_t cid,
                                            const RawAddress& rem_bda) {
  mock_function_count_map[__func__]++;
  return false;
}

bool bluetooth::shim::L2CA_DisconnectLECocReq(uint16_t cid) {
  mock_function_count_map[__func__]++;
  return false;
}
bool bluetooth::shim::L2CA_DisconnectReq(uint16_t cid) {
  mock_function_count_map[__func__]++;
  return false;
}
bool bluetooth::shim::L2CA_GetPeerFeatures(const RawAddress& bd_addr,
                                           uint32_t* p_ext_feat,
                                           uint8_t* p_chnl_mask) {
  mock_function_count_map[__func__]++;
  return false;
}
bool bluetooth::shim::L2CA_GetPeerLECocConfig(uint16_t cid,
                                              tL2CAP_LE_CFG_INFO* peer_cfg) {
  mock_function_count_map[__func__]++;
  return false;
}
bool bluetooth::shim::L2CA_GetRemoteCid(uint16_t lcid, uint16_t* rcid) {
  mock_function_count_map[__func__]++;
  return false;
}
bool bluetooth::shim::L2CA_IsLinkEstablished(const RawAddress& bd_addr,
                                             tBT_TRANSPORT transport) {
  mock_function_count_map[__func__]++;
  return false;
}
uint16_t bluetooth::shim::L2CA_GetLeHandle(uint16_t cid,
                                           const RawAddress& bd_addr) {
  mock_function_count_map[__func__]++;
  return 0;
}
bool bluetooth::shim::L2CA_IsLeLink(uint16_t) {
  mock_function_count_map[__func__]++;
  return false;
}
bool bluetooth::shim::L2CA_ReconfigCreditBasedConnsReq(
    const RawAddress& bd_addr, std::vector<uint16_t>& lcids,
    tL2CAP_LE_CFG_INFO* p_cfg) {
  mock_function_count_map[__func__]++;
  return false;
}
bool bluetooth::shim::L2CA_RemoveFixedChnl(uint16_t cid,
                                           const RawAddress& rem_bda) {
  mock_function_count_map[__func__]++;
  return false;
}
bool bluetooth::shim::L2CA_SetAclPriority(const RawAddress& bd_addr,
                                          tL2CAP_PRIORITY priority) {
  mock_function_count_map[__func__]++;
  return false;
}
bool bluetooth::shim::L2CA_SetChnlFlushability(uint16_t cid,
                                               bool is_flushable) {
  mock_function_count_map[__func__]++;
  return false;
}
bool bluetooth::shim::L2CA_SetLeGattTimeout(const RawAddress& rem_bda,
                                            uint16_t idle_tout) {
  mock_function_count_map[__func__]++;
  return false;
}
bool bluetooth::shim::L2CA_SetIdleTimeoutByBdAddr(const RawAddress& bd_addr,
                                                  uint16_t timeout,
                                                  tBT_TRANSPORT transport) {
  mock_function_count_map[__func__]++;
  return false;
}
bool bluetooth::shim::L2CA_SetTxPriority(uint16_t cid,
                                         tL2CAP_CHNL_PRIORITY priority) {
  mock_function_count_map[__func__]++;
  return false;
}
uint16_t bluetooth::shim::L2CA_AllocateLePSM(void) {
  mock_function_count_map[__func__]++;
  return 0;
}
uint16_t bluetooth::shim::L2CA_ConnectLECocReq(uint16_t psm,
                                               const RawAddress& p_bd_addr,
                                               tL2CAP_LE_CFG_INFO* p_cfg) {
  mock_function_count_map[__func__]++;
  return 0;
}
uint16_t bluetooth::shim::L2CA_ConnectReq(uint16_t psm,
                                          const RawAddress& raw_address) {
  mock_function_count_map[__func__]++;
  return 0;
}
uint16_t bluetooth::shim::L2CA_FlushChannel(uint16_t lcid,
                                            uint16_t num_to_flush) {
  mock_function_count_map[__func__]++;
  return 0;
}
uint16_t bluetooth::shim::L2CA_Register(
    uint16_t client_psm, const tL2CAP_APPL_INFO& callbacks, bool enable_snoop,
    tL2CAP_ERTM_INFO* p_ertm_info, uint16_t my_mtu,
    uint16_t required_remote_mtu, uint16_t sec_level) {
  mock_function_count_map[__func__]++;
  return 0;
}
uint16_t bluetooth::shim::L2CA_SendFixedChnlData(uint16_t cid,
                                                 const RawAddress& rem_bda,
                                                 BT_HDR* p_buf) {
  mock_function_count_map[__func__]++;
  return 0;
}
uint16_t find_classic_cid_token_by_psm_address(uint16_t psm,
                                               RawAddress remote) {
  mock_function_count_map[__func__]++;
  return 0;
}
uint16_t find_le_cid_token_by_psm_address(uint16_t psm, RawAddress remote) {
  mock_function_count_map[__func__]++;
  return 0;
}
uint8_t bluetooth::shim::L2CA_DataWrite(uint16_t cid, BT_HDR* p_data) {
  mock_function_count_map[__func__]++;
  return 0;
}
uint8_t bluetooth::shim::L2CA_LECocDataWrite(uint16_t cid, BT_HDR* p_data) {
  mock_function_count_map[__func__]++;
  return 0;
}
void bluetooth::shim::L2CA_ConnectForSecurity(const RawAddress& bd_addr) {
  mock_function_count_map[__func__]++;
}
void bluetooth::shim::L2CA_Deregister(uint16_t client_psm) {
  mock_function_count_map[__func__]++;
}
void bluetooth::shim::L2CA_DeregisterLECoc(uint16_t psm) {
  mock_function_count_map[__func__]++;
}
void bluetooth::shim::L2CA_FreeLePSM(uint16_t psm) {
  mock_function_count_map[__func__]++;
}
void bluetooth::shim::L2CA_SetBondingState(const RawAddress& bd_addr,
                                           bool is_bonding) {
  mock_function_count_map[__func__]++;
}
void bluetooth::shim::L2CA_SwitchRoleToCentral(const RawAddress& addr) {
  mock_function_count_map[__func__]++;
}
void bluetooth::shim::L2CA_UseLegacySecurityModule() {
  mock_function_count_map[__func__]++;
}
void remove_classic_cid_token_entry(uint16_t cid_token) {
  mock_function_count_map[__func__]++;
}
void remove_le_cid_token_entry(uint16_t cid_token) {
  mock_function_count_map[__func__]++;
}
bool bluetooth::shim::L2CA_ReadRemoteVersion(const RawAddress& addr,
                                             uint8_t* lmp_version,
                                             uint16_t* manufacturer,
                                             uint16_t* lmp_sub_version) {
  mock_function_count_map[__func__]++;
  return false;
}
void bluetooth::shim::L2CA_DisconnectLink(const RawAddress& remote) {
  mock_function_count_map[__func__]++;
}
uint16_t bluetooth::shim::L2CA_GetNumLinks() {
  mock_function_count_map[__func__]++;
  return 0;
}
