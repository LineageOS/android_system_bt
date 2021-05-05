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
 *   Functions generated:45
 *
 *  mockcify.pl ver 0.2
 */

#include <cstdint>
#include <functional>
#include <map>
#include <string>

extern std::map<std::string, int> mock_function_count_map;

// Mock include file to share data between tests and mock
#include "test/mock/mock_main_shim_l2cap_api.h"

// Mocked compile conditionals, if any
#ifndef UNUSED_ATTR
#define UNUSED_ATTR
#endif

// Mocked internal structures, if any

namespace test {
namespace mock {
namespace main_shim_l2cap_api {

// Function state capture and return values, if needed
struct L2CA_ReadRemoteVersion L2CA_ReadRemoteVersion;
struct L2CA_ReadRemoteFeatures L2CA_ReadRemoteFeatures;
struct L2CA_UseLegacySecurityModule L2CA_UseLegacySecurityModule;
struct L2CA_Register L2CA_Register;
struct L2CA_Deregister L2CA_Deregister;
struct L2CA_ConnectReq L2CA_ConnectReq;
struct L2CA_DisconnectReq L2CA_DisconnectReq;
struct L2CA_DataWrite L2CA_DataWrite;
struct L2CA_ReconfigCreditBasedConnsReq L2CA_ReconfigCreditBasedConnsReq;
struct L2CA_ConnectCreditBasedReq L2CA_ConnectCreditBasedReq;
struct L2CA_ConnectCreditBasedRsp L2CA_ConnectCreditBasedRsp;
struct L2CA_SetIdleTimeoutByBdAddr L2CA_SetIdleTimeoutByBdAddr;
struct L2CA_SetAclPriority L2CA_SetAclPriority;
struct L2CA_SetAclPriority2 L2CA_SetAclPriority2;
struct L2CA_GetPeerFeatures L2CA_GetPeerFeatures;
struct L2CA_RegisterFixedChannel L2CA_RegisterFixedChannel;
struct L2CA_ConnectFixedChnl L2CA_ConnectFixedChnl;
struct L2CA_SendFixedChnlData L2CA_SendFixedChnlData;
struct L2CA_RemoveFixedChnl L2CA_RemoveFixedChnl;
struct L2CA_GetLeHandle L2CA_GetLeHandle;
struct L2CA_LeConnectionUpdate L2CA_LeConnectionUpdate;
struct L2CA_EnableUpdateBleConnParams L2CA_EnableUpdateBleConnParams;
struct L2CA_GetRemoteCid L2CA_GetRemoteCid;
struct L2CA_SetTxPriority L2CA_SetTxPriority;
struct L2CA_SetLeGattTimeout L2CA_SetLeGattTimeout;
struct L2CA_SetChnlFlushability L2CA_SetChnlFlushability;
struct L2CA_FlushChannel L2CA_FlushChannel;
struct L2CA_IsLinkEstablished L2CA_IsLinkEstablished;
struct L2CA_IsLeLink L2CA_IsLeLink;
struct L2CA_ReadConnectionAddr L2CA_ReadConnectionAddr;
struct L2CA_ReadRemoteConnectionAddr L2CA_ReadRemoteConnectionAddr;
struct L2CA_GetBleConnRole L2CA_GetBleConnRole;
struct L2CA_ConnectForSecurity L2CA_ConnectForSecurity;
struct L2CA_SetBondingState L2CA_SetBondingState;
struct L2CA_DisconnectLink L2CA_DisconnectLink;
struct L2CA_GetNumLinks L2CA_GetNumLinks;
struct L2CA_AllocateLePSM L2CA_AllocateLePSM;
struct L2CA_FreeLePSM L2CA_FreeLePSM;
struct L2CA_RegisterLECoc L2CA_RegisterLECoc;
struct L2CA_DeregisterLECoc L2CA_DeregisterLECoc;
struct L2CA_ConnectLECocReq L2CA_ConnectLECocReq;
struct L2CA_GetPeerLECocConfig L2CA_GetPeerLECocConfig;
struct L2CA_DisconnectLECocReq L2CA_DisconnectLECocReq;
struct L2CA_LECocDataWrite L2CA_LECocDataWrite;
struct L2CA_SwitchRoleToCentral L2CA_SwitchRoleToCentral;

}  // namespace main_shim_l2cap_api
}  // namespace mock
}  // namespace test

// Mocked functions, if any
bool bluetooth::shim::L2CA_ReadRemoteVersion(const RawAddress& addr,
                                             uint8_t* lmp_version,
                                             uint16_t* manufacturer,
                                             uint16_t* lmp_sub_version) {
  mock_function_count_map[__func__]++;
  return test::mock::main_shim_l2cap_api::L2CA_ReadRemoteVersion(
      addr, lmp_version, manufacturer, lmp_sub_version);
}
uint8_t* bluetooth::shim::L2CA_ReadRemoteFeatures(const RawAddress& addr) {
  mock_function_count_map[__func__]++;
  return test::mock::main_shim_l2cap_api::L2CA_ReadRemoteFeatures(addr);
}
void bluetooth::shim::L2CA_UseLegacySecurityModule() {
  mock_function_count_map[__func__]++;
  test::mock::main_shim_l2cap_api::L2CA_UseLegacySecurityModule();
}
uint16_t bluetooth::shim::L2CA_Register(
    uint16_t client_psm, const tL2CAP_APPL_INFO& callbacks, bool enable_snoop,
    tL2CAP_ERTM_INFO* p_ertm_info, uint16_t my_mtu,
    uint16_t required_remote_mtu, uint16_t sec_level) {
  mock_function_count_map[__func__]++;
  return test::mock::main_shim_l2cap_api::L2CA_Register(
      client_psm, callbacks, enable_snoop, p_ertm_info, my_mtu,
      required_remote_mtu, sec_level);
}
void bluetooth::shim::L2CA_Deregister(uint16_t psm) {
  mock_function_count_map[__func__]++;
  test::mock::main_shim_l2cap_api::L2CA_Deregister(psm);
}
uint16_t bluetooth::shim::L2CA_ConnectReq(uint16_t psm,
                                          const RawAddress& raw_address) {
  mock_function_count_map[__func__]++;
  return test::mock::main_shim_l2cap_api::L2CA_ConnectReq(psm, raw_address);
}
bool bluetooth::shim::L2CA_DisconnectReq(uint16_t cid) {
  mock_function_count_map[__func__]++;
  return test::mock::main_shim_l2cap_api::L2CA_DisconnectReq(cid);
}
uint8_t bluetooth::shim::L2CA_DataWrite(uint16_t cid, BT_HDR* p_data) {
  mock_function_count_map[__func__]++;
  return test::mock::main_shim_l2cap_api::L2CA_DataWrite(cid, p_data);
}
bool bluetooth::shim::L2CA_ReconfigCreditBasedConnsReq(
    const RawAddress& bd_addr, std::vector<uint16_t>& lcids,
    tL2CAP_LE_CFG_INFO* p_cfg) {
  mock_function_count_map[__func__]++;
  return test::mock::main_shim_l2cap_api::L2CA_ReconfigCreditBasedConnsReq(
      bd_addr, lcids, p_cfg);
}
std::vector<uint16_t> bluetooth::shim::L2CA_ConnectCreditBasedReq(
    uint16_t psm, const RawAddress& p_bd_addr, tL2CAP_LE_CFG_INFO* p_cfg) {
  mock_function_count_map[__func__]++;
  return test::mock::main_shim_l2cap_api::L2CA_ConnectCreditBasedReq(
      psm, p_bd_addr, p_cfg);
}
bool bluetooth::shim::L2CA_ConnectCreditBasedRsp(
    const RawAddress& bd_addr, uint8_t id,
    std::vector<uint16_t>& accepted_lcids, uint16_t result,
    tL2CAP_LE_CFG_INFO* p_cfg) {
  mock_function_count_map[__func__]++;
  return test::mock::main_shim_l2cap_api::L2CA_ConnectCreditBasedRsp(
      bd_addr, id, accepted_lcids, result, p_cfg);
}
bool bluetooth::shim::L2CA_SetIdleTimeoutByBdAddr(const RawAddress& bd_addr,
                                                  uint16_t timeout,
                                                  tBT_TRANSPORT transport) {
  mock_function_count_map[__func__]++;
  return test::mock::main_shim_l2cap_api::L2CA_SetIdleTimeoutByBdAddr(
      bd_addr, timeout, transport);
}
bool bluetooth::shim::L2CA_SetAclPriority(uint16_t handle, bool high_priority) {
  mock_function_count_map[__func__]++;
  return test::mock::main_shim_l2cap_api::L2CA_SetAclPriority(handle,
                                                              high_priority);
}
bool bluetooth::shim::L2CA_SetAclPriority(const RawAddress& bd_addr,
                                          tL2CAP_PRIORITY priority) {
  mock_function_count_map[__func__]++;
  return test::mock::main_shim_l2cap_api::L2CA_SetAclPriority2(bd_addr,
                                                               priority);
}
bool bluetooth::shim::L2CA_GetPeerFeatures(const RawAddress& bd_addr,
                                           uint32_t* p_ext_feat,
                                           uint8_t* p_chnl_mask) {
  mock_function_count_map[__func__]++;
  return test::mock::main_shim_l2cap_api::L2CA_GetPeerFeatures(
      bd_addr, p_ext_feat, p_chnl_mask);
}
bool bluetooth::shim::L2CA_RegisterFixedChannel(uint16_t cid,
                                                tL2CAP_FIXED_CHNL_REG* p_freg) {
  mock_function_count_map[__func__]++;
  return test::mock::main_shim_l2cap_api::L2CA_RegisterFixedChannel(cid,
                                                                    p_freg);
}
bool bluetooth::shim::L2CA_ConnectFixedChnl(uint16_t cid,
                                            const RawAddress& rem_bda) {
  mock_function_count_map[__func__]++;
  return test::mock::main_shim_l2cap_api::L2CA_ConnectFixedChnl(cid, rem_bda);
}
uint16_t bluetooth::shim::L2CA_SendFixedChnlData(uint16_t cid,
                                                 const RawAddress& rem_bda,
                                                 BT_HDR* p_buf) {
  mock_function_count_map[__func__]++;
  return test::mock::main_shim_l2cap_api::L2CA_SendFixedChnlData(cid, rem_bda,
                                                                 p_buf);
}
bool bluetooth::shim::L2CA_RemoveFixedChnl(uint16_t cid,
                                           const RawAddress& rem_bda) {
  mock_function_count_map[__func__]++;
  return test::mock::main_shim_l2cap_api::L2CA_RemoveFixedChnl(cid, rem_bda);
}
uint16_t bluetooth::shim::L2CA_GetLeHandle(const RawAddress& rem_bda) {
  mock_function_count_map[__func__]++;
  return test::mock::main_shim_l2cap_api::L2CA_GetLeHandle(rem_bda);
}
void bluetooth::shim::L2CA_LeConnectionUpdate(
    const RawAddress& rem_bda, uint16_t min_int, uint16_t max_int,
    uint16_t latency, uint16_t timeout, uint16_t min_ce_len,
    uint16_t max_ce_len) {
  mock_function_count_map[__func__]++;
  test::mock::main_shim_l2cap_api::L2CA_LeConnectionUpdate(
      rem_bda, min_int, max_int, latency, timeout, min_ce_len, max_ce_len);
}
bool bluetooth::shim::L2CA_EnableUpdateBleConnParams(const RawAddress& rem_bda,
                                                     bool enable) {
  mock_function_count_map[__func__]++;
  return test::mock::main_shim_l2cap_api::L2CA_EnableUpdateBleConnParams(
      rem_bda, enable);
}
bool bluetooth::shim::L2CA_GetRemoteCid(uint16_t lcid, uint16_t* rcid) {
  mock_function_count_map[__func__]++;
  return test::mock::main_shim_l2cap_api::L2CA_GetRemoteCid(lcid, rcid);
}
bool bluetooth::shim::L2CA_SetTxPriority(uint16_t cid,
                                         tL2CAP_CHNL_PRIORITY priority) {
  mock_function_count_map[__func__]++;
  return test::mock::main_shim_l2cap_api::L2CA_SetTxPriority(cid, priority);
}
bool bluetooth::shim::L2CA_SetLeGattTimeout(const RawAddress& rem_bda,
                                            uint16_t idle_tout) {
  mock_function_count_map[__func__]++;
  return test::mock::main_shim_l2cap_api::L2CA_SetLeGattTimeout(rem_bda,
                                                                idle_tout);
}
bool bluetooth::shim::L2CA_SetChnlFlushability(uint16_t cid,
                                               bool is_flushable) {
  mock_function_count_map[__func__]++;
  return test::mock::main_shim_l2cap_api::L2CA_SetChnlFlushability(
      cid, is_flushable);
}
uint16_t bluetooth::shim::L2CA_FlushChannel(uint16_t lcid,
                                            uint16_t num_to_flush) {
  mock_function_count_map[__func__]++;
  return test::mock::main_shim_l2cap_api::L2CA_FlushChannel(lcid, num_to_flush);
}
bool bluetooth::shim::L2CA_IsLinkEstablished(const RawAddress& bd_addr,
                                             tBT_TRANSPORT transport) {
  mock_function_count_map[__func__]++;
  return test::mock::main_shim_l2cap_api::L2CA_IsLinkEstablished(bd_addr,
                                                                 transport);
}
bool bluetooth::shim::L2CA_IsLeLink(uint16_t acl_handle) {
  mock_function_count_map[__func__]++;
  return test::mock::main_shim_l2cap_api::L2CA_IsLeLink(acl_handle);
}
void bluetooth::shim::L2CA_ReadConnectionAddr(const RawAddress& pseudo_addr,
                                              RawAddress& conn_addr,
                                              uint8_t* p_addr_type) {
  mock_function_count_map[__func__]++;
  test::mock::main_shim_l2cap_api::L2CA_ReadConnectionAddr(
      pseudo_addr, conn_addr, p_addr_type);
}
bool bluetooth::shim::L2CA_ReadRemoteConnectionAddr(
    const RawAddress& pseudo_addr, RawAddress& conn_addr,
    uint8_t* p_addr_type) {
  mock_function_count_map[__func__]++;
  return test::mock::main_shim_l2cap_api::L2CA_ReadRemoteConnectionAddr(
      pseudo_addr, conn_addr, p_addr_type);
}
hci_role_t bluetooth::shim::L2CA_GetBleConnRole(const RawAddress& bd_addr) {
  mock_function_count_map[__func__]++;
  return test::mock::main_shim_l2cap_api::L2CA_GetBleConnRole(bd_addr);
}
void bluetooth::shim::L2CA_ConnectForSecurity(const RawAddress& bd_addr) {
  mock_function_count_map[__func__]++;
  test::mock::main_shim_l2cap_api::L2CA_ConnectForSecurity(bd_addr);
}
void bluetooth::shim::L2CA_SetBondingState(const RawAddress& bd_addr,
                                           bool is_bonding) {
  mock_function_count_map[__func__]++;
  test::mock::main_shim_l2cap_api::L2CA_SetBondingState(bd_addr, is_bonding);
}
void bluetooth::shim::L2CA_DisconnectLink(const RawAddress& remote) {
  mock_function_count_map[__func__]++;
  test::mock::main_shim_l2cap_api::L2CA_DisconnectLink(remote);
}
uint16_t bluetooth::shim::L2CA_GetNumLinks() {
  mock_function_count_map[__func__]++;
  return test::mock::main_shim_l2cap_api::L2CA_GetNumLinks();
}
uint16_t bluetooth::shim::L2CA_AllocateLePSM() {
  mock_function_count_map[__func__]++;
  return test::mock::main_shim_l2cap_api::L2CA_AllocateLePSM();
}
void bluetooth::shim::L2CA_FreeLePSM(uint16_t psm) {
  mock_function_count_map[__func__]++;
  test::mock::main_shim_l2cap_api::L2CA_FreeLePSM(psm);
}
uint16_t bluetooth::shim::L2CA_RegisterLECoc(uint16_t psm,
                                             const tL2CAP_APPL_INFO& callbacks,
                                             uint16_t sec_level,
                                             tL2CAP_LE_CFG_INFO cfg) {
  mock_function_count_map[__func__]++;
  return test::mock::main_shim_l2cap_api::L2CA_RegisterLECoc(psm, callbacks,
                                                             sec_level, cfg);
}
void bluetooth::shim::L2CA_DeregisterLECoc(uint16_t psm) {
  mock_function_count_map[__func__]++;
  test::mock::main_shim_l2cap_api::L2CA_DeregisterLECoc(psm);
}
uint16_t bluetooth::shim::L2CA_ConnectLECocReq(uint16_t psm,
                                               const RawAddress& p_bd_addr,
                                               tL2CAP_LE_CFG_INFO* p_cfg) {
  mock_function_count_map[__func__]++;
  return test::mock::main_shim_l2cap_api::L2CA_ConnectLECocReq(psm, p_bd_addr,
                                                               p_cfg);
}
bool bluetooth::shim::L2CA_GetPeerLECocConfig(uint16_t cid,
                                              tL2CAP_LE_CFG_INFO* peer_cfg) {
  mock_function_count_map[__func__]++;
  return test::mock::main_shim_l2cap_api::L2CA_GetPeerLECocConfig(cid,
                                                                  peer_cfg);
}
bool bluetooth::shim::L2CA_DisconnectLECocReq(uint16_t cid) {
  mock_function_count_map[__func__]++;
  return test::mock::main_shim_l2cap_api::L2CA_DisconnectLECocReq(cid);
}
uint8_t bluetooth::shim::L2CA_LECocDataWrite(uint16_t cid, BT_HDR* p_data) {
  mock_function_count_map[__func__]++;
  return test::mock::main_shim_l2cap_api::L2CA_LECocDataWrite(cid, p_data);
}
void bluetooth::shim::L2CA_SwitchRoleToCentral(const RawAddress& addr) {
  mock_function_count_map[__func__]++;
  test::mock::main_shim_l2cap_api::L2CA_SwitchRoleToCentral(addr);
}

// END mockcify generation
