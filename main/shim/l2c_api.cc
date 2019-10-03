/*
 * Copyright 2019 The Android Open Source Project
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

#define LOG_TAG "bt_shim_l2cap"

#include "main/shim/l2c_api.h"
#include "main/shim/l2cap.h"
#include "main/shim/shim.h"
#include "osi/include/log.h"

static bluetooth::shim::L2cap shim_l2cap;

uint16_t bluetooth::shim::L2CA_Register(uint16_t client_psm,
                                        tL2CAP_APPL_INFO* p_cb_info,
                                        bool enable_snoop) {
  if (L2C_INVALID_PSM(client_psm)) {
    LOG_ERROR(LOG_TAG, "%s Invalid classic psm:0x%04x", __func__, client_psm);
    return 0;
  }

  if ((p_cb_info->pL2CA_ConfigCfm_Cb == nullptr) ||
      (p_cb_info->pL2CA_ConfigInd_Cb == nullptr) ||
      (p_cb_info->pL2CA_DataInd_Cb == nullptr) ||
      (p_cb_info->pL2CA_DisconnectInd_Cb == nullptr)) {
    LOG_ERROR(LOG_TAG, "%s Invalid classic callbacks psm:0x%04x", __func__,
              client_psm);
    return 0;
  }

  /**
   * Check if this is a registration for an outgoing-only connection.
   */
  bool is_outgoing_connection_only = p_cb_info->pL2CA_ConnectInd_Cb == nullptr;
  uint16_t psm = shim_l2cap.ConvertClientToRealPsm(client_psm,
                                                   is_outgoing_connection_only);

  if (shim_l2cap.Classic().IsPsmRegistered(psm)) {
    LOG_ERROR(LOG_TAG,
              "%s Already registered classic client_psm:0x%04x psm:0x%04x",
              __func__, client_psm, psm);
    return 0;
  }
  shim_l2cap.Classic().RegisterPsm(psm, p_cb_info);

  LOG_INFO(LOG_TAG, "%s classic client_psm:0x%04x psm:0x%04x", __func__,
           client_psm, psm);

  // TODO(cmanton) Register this service with GD
  // TODO(cmanton) Fake out a config negotiator
  return psm;
}

void bluetooth::shim::L2CA_Deregister(uint16_t client_psm) {
  if (L2C_INVALID_PSM(client_psm)) {
    LOG_ERROR(LOG_TAG, "%s Invalid classic psm:0x%04x", __func__, client_psm);
    return;
  }
  uint16_t psm = shim_l2cap.ConvertClientToRealPsm(client_psm);

  if (!shim_l2cap.Classic().IsPsmRegistered(psm)) {
    LOG_ERROR(
        LOG_TAG,
        "%s Not previously registered classic client_psm:0x%04x psm:0x%04x",
        __func__, client_psm, psm);
    return;
  }
  shim_l2cap.Classic().UnregisterPsm(psm);
  shim_l2cap.RemoveClientPsm(client_psm);
}

uint16_t bluetooth::shim::L2CA_AllocatePSM(void) {
  uint16_t psm = shim_l2cap.GetNextDynamicClassicPsm();
  shim_l2cap.Classic().AllocatePsm(psm);
  return psm;
}

uint16_t bluetooth::shim::L2CA_AllocateLePSM(void) {
  uint16_t psm = shim_l2cap.GetNextDynamicLePsm();
  shim_l2cap.Le().AllocatePsm(psm);
  return psm;
}

void bluetooth::shim::L2CA_FreeLePSM(uint16_t psm) {
  if (!shim_l2cap.Le().IsPsmAllocated(psm)) {
    LOG_ERROR(LOG_TAG, "%s Not previously allocated le psm:0x%04x", __func__,
              psm);
    return;
  }
  if (!shim_l2cap.Le().IsPsmRegistered(psm)) {
    LOG_ERROR(LOG_TAG, "%s Must deregister psm before deallocation psm:0x%04x",
              __func__, psm);
    return;
  }
  shim_l2cap.Le().DeallocatePsm(psm);
}

uint16_t bluetooth::shim::L2CA_ErtmConnectReq(uint16_t psm,
                                              const RawAddress& p_bd_addr,
                                              tL2CAP_ERTM_INFO* p_ertm_info) {
  LOG_INFO(LOG_TAG, "UNIMPLEMENTED %s psm:%hd addr:%s p_ertm_info:%p", __func__,
           psm, p_bd_addr.ToString().c_str(), p_ertm_info);
  return 0;
}

uint16_t bluetooth::shim::L2CA_ConnectReq(uint16_t psm,
                                          const RawAddress& p_bd_addr) {
  return bluetooth::shim::L2CA_ErtmConnectReq(psm, p_bd_addr, nullptr);
}

uint16_t bluetooth::shim::L2CA_RegisterLECoc(uint16_t psm,
                                             tL2CAP_APPL_INFO* p_cb_info) {
  LOG_INFO(LOG_TAG, "UNIMPLEMENTED %s psm:%hd p_cb_info:%p", __func__, psm,
           p_cb_info);
  return 0;
}

void bluetooth::shim::L2CA_DeregisterLECoc(uint16_t psm) {
  LOG_INFO(LOG_TAG, "UNIMPLEMENTED %s psm:%hd", __func__, psm);
}

uint16_t bluetooth::shim::L2CA_ConnectLECocReq(uint16_t psm,
                                               const RawAddress& p_bd_addr,
                                               tL2CAP_LE_CFG_INFO* p_cfg) {
  LOG_INFO(LOG_TAG, "UNIMPLEMENTED %s psm:%hd addr:%s p_cfg:%p", __func__, psm,
           p_bd_addr.ToString().c_str(), p_cfg);
  return 0;
}

bool bluetooth::shim::L2CA_ConnectLECocRsp(const RawAddress& p_bd_addr,
                                           uint8_t id, uint16_t lcid,
                                           uint16_t result, uint16_t status,
                                           tL2CAP_LE_CFG_INFO* p_cfg) {
  LOG_INFO(LOG_TAG,
           "UNIMPLEMENTED %s addr:%s id:%hhd lcid:%hd result:%hd status:%hd "
           "p_cfg:%p",
           __func__, p_bd_addr.ToString().c_str(), id, lcid, result, status,
           p_cfg);
  return false;
}

bool bluetooth::shim::L2CA_GetPeerLECocConfig(uint16_t lcid,
                                              tL2CAP_LE_CFG_INFO* peer_cfg) {
  LOG_INFO(LOG_TAG, "UNIMPLEMENTED %s lcid:%hd peer_cfg:%p", __func__, lcid,
           peer_cfg);
  return false;
}

bool bluetooth::shim::L2CA_SetConnectionCallbacks(
    uint16_t local_cid, const tL2CAP_APPL_INFO* callbacks) {
  LOG_INFO(LOG_TAG, "UNIMPLEMENTED %s lcid:%hd callbacks:%p", __func__,
           local_cid, callbacks);
  return false;
}

bool bluetooth::shim::L2CA_ErtmConnectRsp(const RawAddress& p_bd_addr,
                                          uint8_t id, uint16_t lcid,
                                          uint16_t result, uint16_t status,
                                          tL2CAP_ERTM_INFO* p_ertm_info) {
  LOG_INFO(LOG_TAG,
           "UNIMPLEMENTED %s addr:%s id:%hhd lcid:%hd result:%hd status:%hd "
           "p_ertm_info:%p",
           __func__, p_bd_addr.ToString().c_str(), id, lcid, result, status,
           p_ertm_info);
  return false;
}

bool bluetooth::shim::L2CA_ConnectRsp(const RawAddress& p_bd_addr, uint8_t id,
                                      uint16_t lcid, uint16_t result,
                                      uint16_t status) {
  return bluetooth::shim::L2CA_ErtmConnectRsp(p_bd_addr, id, lcid, result,
                                              status, NULL);
}

bool bluetooth::shim::L2CA_ConfigReq(uint16_t cid, tL2CAP_CFG_INFO* p_cfg) {
  LOG_INFO(LOG_TAG, "UNIMPLEMENTED %s cid:%hd p_cfg:%p", __func__, cid, p_cfg);
  return false;
}

bool bluetooth::shim::L2CA_ConfigRsp(uint16_t cid, tL2CAP_CFG_INFO* p_cfg) {
  LOG_INFO(LOG_TAG, "UNIMPLEMENTED %s cid:%hd p_cfg:%p", __func__, cid, p_cfg);
  return false;
}

bool bluetooth::shim::L2CA_DisconnectReq(uint16_t cid) {
  LOG_INFO(LOG_TAG, "UNIMPLEMENTED %s cid:%hd ", __func__, cid);
  return false;
}

bool bluetooth::shim::L2CA_DisconnectRsp(uint16_t cid) {
  LOG_INFO(LOG_TAG, "UNIMPLEMENTED %s cid:%hd ", __func__, cid);
  return false;
}

bool bluetooth::shim::L2CA_Ping(const RawAddress& p_bd_addr,
                                tL2CA_ECHO_RSP_CB* p_callback) {
  LOG_INFO(LOG_TAG, "UNIMPLEMENTED %s addr:%s p_callback:%p", __func__,
           p_bd_addr.ToString().c_str(), p_callback);
  return false;
}

bool bluetooth::shim::L2CA_Echo(const RawAddress& p_bd_addr, BT_HDR* p_data,
                                tL2CA_ECHO_DATA_CB* p_callback) {
  LOG_INFO(LOG_TAG, "UNIMPLEMENTED %s addr:%s p_callback:%p", __func__,
           p_bd_addr.ToString().c_str(), p_callback);
  return false;
}

bool bluetooth::shim::L2CA_GetIdentifiers(uint16_t lcid, uint16_t* rcid,
                                          uint16_t* handle) {
  LOG_INFO(LOG_TAG, "UNIMPLEMENTED %s", __func__);
  return false;
}

bool bluetooth::shim::L2CA_SetIdleTimeout(uint16_t cid, uint16_t timeout,
                                          bool is_global) {
  LOG_INFO(LOG_TAG, "UNIMPLEMENTED %s", __func__);
  return false;
}

bool bluetooth::shim::L2CA_SetIdleTimeoutByBdAddr(const RawAddress& bd_addr,
                                                  uint16_t timeout,
                                                  tBT_TRANSPORT transport) {
  LOG_INFO(LOG_TAG, "UNIMPLEMENTED %s", __func__);
  return false;
}

uint8_t bluetooth::shim::L2CA_SetDesireRole(uint8_t new_role) {
  LOG_INFO(LOG_TAG, "UNIMPLEMENTED %s", __func__);
  return 0;
}

uint16_t bluetooth::shim::L2CA_LocalLoopbackReq(uint16_t psm, uint16_t handle,
                                                const RawAddress& p_bd_addr) {
  LOG_INFO(LOG_TAG, "UNIMPLEMENTED %s", __func__);
  return 0;
}

bool bluetooth::shim::L2CA_SetAclPriority(const RawAddress& bd_addr,
                                          uint8_t priority) {
  LOG_INFO(LOG_TAG, "UNIMPLEMENTED %s", __func__);
  return false;
}

bool bluetooth::shim::L2CA_FlowControl(uint16_t cid, bool data_enabled) {
  LOG_INFO(LOG_TAG, "UNIMPLEMENTED %s", __func__);
  return false;
}

bool bluetooth::shim::L2CA_SendTestSFrame(uint16_t cid, uint8_t sup_type,
                                          uint8_t back_track) {
  LOG_INFO(LOG_TAG, "UNIMPLEMENTED %s", __func__);
  return false;
}

bool bluetooth::shim::L2CA_SetTxPriority(uint16_t cid,
                                         tL2CAP_CHNL_PRIORITY priority) {
  LOG_INFO(LOG_TAG, "UNIMPLEMENTED %s", __func__);
  return false;
}

bool bluetooth::shim::L2CA_SetChnlDataRate(uint16_t cid,
                                           tL2CAP_CHNL_DATA_RATE tx,
                                           tL2CAP_CHNL_DATA_RATE rx) {
  LOG_INFO(LOG_TAG, "UNIMPLEMENTED %s", __func__);
  return false;
}

bool bluetooth::shim::L2CA_SetFlushTimeout(const RawAddress& bd_addr,
                                           uint16_t flush_tout) {
  LOG_INFO(LOG_TAG, "UNIMPLEMENTED %s", __func__);
  return false;
}

bool bluetooth::shim::L2CA_GetPeerFeatures(const RawAddress& bd_addr,
                                           uint32_t* p_ext_feat,
                                           uint8_t* p_chnl_mask) {
  LOG_INFO(LOG_TAG, "UNIMPLEMENTED %s", __func__);
  return false;
}

bool bluetooth::shim::L2CA_GetBDAddrbyHandle(uint16_t handle,
                                             RawAddress& bd_addr) {
  LOG_INFO(LOG_TAG, "UNIMPLEMENTED %s", __func__);
  return false;
}

uint8_t bluetooth::shim::L2CA_GetChnlFcrMode(uint16_t lcid) {
  LOG_INFO(LOG_TAG, "UNIMPLEMENTED %s", __func__);
  return 0;
}

bool bluetooth::shim::L2CA_RegisterFixedChannel(uint16_t fixed_cid,
                                                tL2CAP_FIXED_CHNL_REG* p_freg) {
  LOG_INFO(LOG_TAG, "UNIMPLEMENTED %s", __func__);
  return false;
}

bool bluetooth::shim::L2CA_ConnectFixedChnl(uint16_t fixed_cid,
                                            const RawAddress& rem_bda) {
  LOG_INFO(LOG_TAG, "UNIMPLEMENTED %s", __func__);
  return false;
}

bool bluetooth::shim::L2CA_ConnectFixedChnl(uint16_t fixed_cid,
                                            const RawAddress& rem_bda,
                                            uint8_t initiating_phys) {
  LOG_INFO(LOG_TAG, "UNIMPLEMENTED %s", __func__);
  return false;
}

uint16_t bluetooth::shim::L2CA_SendFixedChnlData(uint16_t fixed_cid,
                                                 const RawAddress& rem_bda,
                                                 BT_HDR* p_buf) {
  LOG_INFO(LOG_TAG, "UNIMPLEMENTED %s", __func__);
  return 0;
}

bool bluetooth::shim::L2CA_RemoveFixedChnl(uint16_t fixed_cid,
                                           const RawAddress& rem_bda) {
  LOG_INFO(LOG_TAG, "UNIMPLEMENTED %s", __func__);
  return false;
}

bool bluetooth::shim::L2CA_SetFixedChannelTout(const RawAddress& rem_bda,
                                               uint16_t fixed_cid,
                                               uint16_t idle_tout) {
  LOG_INFO(LOG_TAG, "UNIMPLEMENTED %s", __func__);
  return false;
}

bool bluetooth::shim::L2CA_GetCurrentConfig(
    uint16_t lcid, tL2CAP_CFG_INFO** pp_our_cfg,
    tL2CAP_CH_CFG_BITS* p_our_cfg_bits, tL2CAP_CFG_INFO** pp_peer_cfg,
    tL2CAP_CH_CFG_BITS* p_peer_cfg_bits) {
  LOG_INFO(LOG_TAG, "UNIMPLEMENTED %s", __func__);
  return false;
}

bool bluetooth::shim::L2CA_GetConnectionConfig(uint16_t lcid, uint16_t* mtu,
                                               uint16_t* rcid,
                                               uint16_t* handle) {
  LOG_INFO(LOG_TAG, "UNIMPLEMENTED %s", __func__);
  return false;
}

bool bluetooth::shim::L2CA_RegForNoCPEvt(tL2CA_NOCP_CB* p_cb,
                                         const RawAddress& p_bda) {
  LOG_INFO(LOG_TAG, "UNIMPLEMENTED %s", __func__);
  return false;
}

uint8_t bluetooth::shim::L2CA_DataWrite(uint16_t cid, BT_HDR* p_data) {
  LOG_INFO(LOG_TAG, "UNIMPLEMENTED %s", __func__);
  return 0;
}

bool bluetooth::shim::L2CA_SetChnlFlushability(uint16_t cid,
                                               bool is_flushable) {
  LOG_INFO(LOG_TAG, "UNIMPLEMENTED %s", __func__);
  return false;
}

uint8_t bluetooth::shim::L2CA_DataWriteEx(uint16_t cid, BT_HDR* p_data,
                                          uint16_t flags) {
  LOG_INFO(LOG_TAG, "UNIMPLEMENTED %s", __func__);
  return false;
}

uint16_t bluetooth::shim::L2CA_FlushChannel(uint16_t lcid,
                                            uint16_t num_to_flush) {
  LOG_INFO(LOG_TAG, "UNIMPLEMENTED %s", __func__);
  return 0;
}
