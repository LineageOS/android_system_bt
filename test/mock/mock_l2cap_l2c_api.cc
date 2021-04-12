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

#include <cstdint>
#include "stack/include/l2c_api.h"
#include "types/raw_address.h"

#ifndef UNUSED_ATTR
#define UNUSED_ATTR
#endif

bool L2CA_ConnectCreditBasedRsp(const RawAddress& p_bd_addr, uint8_t id,
                                std::vector<uint16_t>& accepted_lcids,
                                uint16_t result, tL2CAP_LE_CFG_INFO* p_cfg) {
  mock_function_count_map[__func__]++;
  return false;
}
bool L2CA_ConnectFixedChnl(uint16_t fixed_cid, const RawAddress& rem_bda) {
  mock_function_count_map[__func__]++;
  return false;
}
bool L2CA_DisconnectLECocReq(uint16_t cid) {
  mock_function_count_map[__func__]++;
  return false;
}
bool L2CA_DisconnectReq(uint16_t cid) {
  mock_function_count_map[__func__]++;
  return false;
}
bool L2CA_GetPeerFeatures(const RawAddress& bd_addr, uint32_t* p_ext_feat,
                          uint8_t* p_chnl_mask) {
  mock_function_count_map[__func__]++;
  return false;
}
bool L2CA_GetPeerLECocConfig(uint16_t lcid, tL2CAP_LE_CFG_INFO* peer_cfg) {
  mock_function_count_map[__func__]++;
  return false;
}
bool L2CA_GetRemoteCid(uint16_t lcid, uint16_t* rcid) {
  mock_function_count_map[__func__]++;
  return false;
}
bool L2CA_IsLinkEstablished(const RawAddress& bd_addr,
                            tBT_TRANSPORT transport) {
  mock_function_count_map[__func__]++;
  return false;
}
bool L2CA_ReconfigCreditBasedConnsReq(const RawAddress& bda,
                                      std::vector<uint16_t>& lcids,
                                      tL2CAP_LE_CFG_INFO* p_cfg) {
  mock_function_count_map[__func__]++;
  return false;
}
bool L2CA_RegisterFixedChannel(uint16_t fixed_cid,
                               tL2CAP_FIXED_CHNL_REG* p_freg) {
  mock_function_count_map[__func__]++;
  return false;
}
bool L2CA_RemoveFixedChnl(uint16_t fixed_cid, const RawAddress& rem_bda) {
  mock_function_count_map[__func__]++;
  return false;
}
bool L2CA_SetAclPriority(const RawAddress& bd_addr, tL2CAP_PRIORITY priority) {
  mock_function_count_map[__func__]++;
  return false;
}
bool L2CA_SetChnlFlushability(uint16_t cid, bool is_flushable) {
  mock_function_count_map[__func__]++;
  return false;
}
bool L2CA_SetLeGattTimeout(const RawAddress& rem_bda, uint16_t idle_tout) {
  mock_function_count_map[__func__]++;
  return false;
}
bool L2CA_SetIdleTimeoutByBdAddr(const RawAddress& bd_addr, uint16_t timeout,
                                 tBT_TRANSPORT transport) {
  mock_function_count_map[__func__]++;
  return false;
}
bool L2CA_SetTxPriority(uint16_t cid, tL2CAP_CHNL_PRIORITY priority) {
  mock_function_count_map[__func__]++;
  return false;
}
std::vector<uint16_t> L2CA_ConnectCreditBasedReq(uint16_t psm,
                                                 const RawAddress& p_bd_addr,
                                                 tL2CAP_LE_CFG_INFO* p_cfg) {
  mock_function_count_map[__func__]++;
  std::vector<uint16_t> v;
  return v;
}
tBT_TRANSPORT l2c_get_transport_from_fixed_cid(uint16_t fixed_cid) {
  mock_function_count_map[__func__]++;
  return 0;
}
uint16_t L2CA_AllocateLePSM(void) {
  mock_function_count_map[__func__]++;
  return 0;
}
uint16_t L2CA_ConnectLECocReq(uint16_t psm, const RawAddress& p_bd_addr,
                              tL2CAP_LE_CFG_INFO* p_cfg, uint16_t sec_level) {
  mock_function_count_map[__func__]++;
  return 0;
}
uint16_t L2CA_ConnectReq(uint16_t psm, const RawAddress& p_bd_addr) {
  mock_function_count_map[__func__]++;
  return 0;
}
uint16_t L2CA_ConnectReq2(uint16_t psm, const RawAddress& p_bd_addr,
                          uint16_t sec_level) {
  mock_function_count_map[__func__]++;
  return 0;
}
uint16_t L2CA_FlushChannel(uint16_t lcid, uint16_t num_to_flush) {
  mock_function_count_map[__func__]++;
  return 0;
}
uint16_t L2CA_Register(uint16_t psm, const tL2CAP_APPL_INFO& p_cb_info,
                       bool enable_snoop, tL2CAP_ERTM_INFO* p_ertm_info,
                       uint16_t my_mtu, uint16_t required_remote_mtu) {
  mock_function_count_map[__func__]++;
  return 0;
}
uint16_t L2CA_Register2(uint16_t psm, const tL2CAP_APPL_INFO& p_cb_info,
                        bool enable_snoop, tL2CAP_ERTM_INFO* p_ertm_info,
                        uint16_t my_mtu, uint16_t required_remote_mtu,
                        uint16_t sec_level) {
  mock_function_count_map[__func__]++;
  return 0;
}
uint16_t L2CA_RegisterLECoc(uint16_t psm, const tL2CAP_APPL_INFO& p_cb_info,
                            uint16_t sec_level, tL2CAP_LE_CFG_INFO cfg) {
  mock_function_count_map[__func__]++;
  return 0;
}
uint16_t L2CA_SendFixedChnlData(uint16_t fixed_cid, const RawAddress& rem_bda,
                                BT_HDR* p_buf) {
  mock_function_count_map[__func__]++;
  return 0;
}
uint8_t L2CA_DataWrite(uint16_t cid, BT_HDR* p_data) {
  mock_function_count_map[__func__]++;
  return 0;
}
uint8_t L2CA_LECocDataWrite(uint16_t cid, BT_HDR* p_data) {
  mock_function_count_map[__func__]++;
  return 0;
}
uint8_t L2CA_SetTraceLevel(uint8_t new_level) {
  mock_function_count_map[__func__]++;
  return 0;
}
void L2CA_Deregister(uint16_t psm) { mock_function_count_map[__func__]++; }
void L2CA_DeregisterLECoc(uint16_t psm) { mock_function_count_map[__func__]++; }
void L2CA_FreeLePSM(uint16_t psm) { mock_function_count_map[__func__]++; }
