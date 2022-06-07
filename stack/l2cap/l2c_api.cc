/******************************************************************************
 *
 *  Copyright 1999-2012 Broadcom Corporation
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at:
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 ******************************************************************************/

/******************************************************************************
 *
 *  This file contains the L2CAP API code
 *
 ******************************************************************************/

#define LOG_TAG "bt_l2cap"

#include <base/logging.h>
#include <base/strings/stringprintf.h>
#include <cstdint>
#include <string>

#include "btm_sec.h"
#include "device/include/controller.h"  // TODO Remove
#include "main/shim/l2c_api.h"
#include "main/shim/shim.h"
#include "osi/include/log.h"
#include "stack/include/l2c_api.h"
#include "stack/l2cap/l2c_int.h"

void btsnd_hcic_enhanced_flush(uint16_t handle,
                               uint8_t packet_type);  // TODO Remove

using base::StringPrintf;

tBT_TRANSPORT l2c_get_transport_from_fixed_cid(uint16_t fixed_cid) {
  if (fixed_cid >= L2CAP_ATT_CID && fixed_cid <= L2CAP_SMP_CID)
    return BT_TRANSPORT_LE;
  return BT_TRANSPORT_BR_EDR;
}

uint16_t L2CA_Register2(uint16_t psm, const tL2CAP_APPL_INFO& p_cb_info,
                        bool enable_snoop, tL2CAP_ERTM_INFO* p_ertm_info,
                        uint16_t my_mtu, uint16_t required_remote_mtu,
                        uint16_t sec_level) {
  auto ret = L2CA_Register(psm, p_cb_info, enable_snoop, p_ertm_info, my_mtu,
                           required_remote_mtu, sec_level);
  BTM_SetSecurityLevel(false, "", 0, sec_level, psm, 0, 0);
  return ret;
}

/*******************************************************************************
 *
 * Function         L2CA_Register
 *
 * Description      Other layers call this function to register for L2CAP
 *                  services.
 *
 * Returns          PSM to use or zero if error. Typically, the PSM returned
 *                  is the same as was passed in, but for an outgoing-only
 *                  connection to a dynamic PSM, a "virtual" PSM is returned
 *                  and should be used in the calls to L2CA_ConnectReq(),
 *                  L2CA_ErtmConnectReq() and L2CA_Deregister()
 *
 ******************************************************************************/
uint16_t L2CA_Register(uint16_t psm, const tL2CAP_APPL_INFO& p_cb_info,
                       bool enable_snoop, tL2CAP_ERTM_INFO* p_ertm_info,
                       uint16_t my_mtu, uint16_t required_remote_mtu,
                       uint16_t sec_level) {
  if (bluetooth::shim::is_gd_l2cap_enabled()) {
    return bluetooth::shim::L2CA_Register(psm, p_cb_info, enable_snoop,
                                          p_ertm_info, my_mtu,
                                          required_remote_mtu, sec_level);
  }

  const bool config_cfm_cb = (p_cb_info.pL2CA_ConfigCfm_Cb != nullptr);
  const bool config_ind_cb = (p_cb_info.pL2CA_ConfigInd_Cb != nullptr);
  const bool data_ind_cb = (p_cb_info.pL2CA_DataInd_Cb != nullptr);
  const bool disconnect_ind_cb = (p_cb_info.pL2CA_DisconnectInd_Cb != nullptr);

  tL2C_RCB* p_rcb;
  uint16_t vpsm = psm;

  /* Verify that the required callback info has been filled in
  **      Note:  Connection callbacks are required but not checked
  **             for here because it is possible to be only a client
  **             or only a server.
  */
  if (!config_cfm_cb || !data_ind_cb || !disconnect_ind_cb) {
    LOG_ERROR(
        "L2CAP - no cb registering PSM: 0x%04x cfg_cfm:%u cfg_ind:%u"
        " data_ind:%u discon_int:%u",
        psm, config_cfm_cb, config_ind_cb, data_ind_cb, disconnect_ind_cb);
    return (0);
  }

  /* Verify PSM is valid */
  if (L2C_INVALID_PSM(psm)) {
    LOG_ERROR("L2CAP - invalid PSM value, PSM: 0x%04x", psm);
    return (0);
  }

  /* Check if this is a registration for an outgoing-only connection to */
  /* a dynamic PSM. If so, allocate a "virtual" PSM for the app to use. */
  if ((psm >= 0x1001) && (p_cb_info.pL2CA_ConnectInd_Cb == NULL)) {
    for (vpsm = 0x1002; vpsm < 0x8000; vpsm += 2) {
      p_rcb = l2cu_find_rcb_by_psm(vpsm);
      if (p_rcb == NULL) break;
    }

    LOG_DEBUG("L2CAP - Real PSM: 0x%04x  Virtual PSM: 0x%04x", psm, vpsm);
  }

  /* If registration block already there, just overwrite it */
  p_rcb = l2cu_find_rcb_by_psm(vpsm);
  if (p_rcb == NULL) {
    p_rcb = l2cu_allocate_rcb(vpsm);
    if (p_rcb == NULL) {
      LOG_WARN("L2CAP - no RCB available, PSM: 0x%04x  vPSM: 0x%04x", psm,
               vpsm);
      return (0);
    }
  }

  LOG_INFO("L2CAP Registered service classic PSM: 0x%04x", psm);
  p_rcb->log_packets = enable_snoop;
  p_rcb->api = p_cb_info;
  p_rcb->real_psm = psm;
  p_rcb->ertm_info = p_ertm_info == nullptr
                         ? tL2CAP_ERTM_INFO{L2CAP_FCR_BASIC_MODE}
                         : *p_ertm_info;
  p_rcb->my_mtu = my_mtu;
  p_rcb->required_remote_mtu =
      std::max<uint16_t>(required_remote_mtu, L2CAP_MIN_MTU);

  return (vpsm);
}

/*******************************************************************************
 *
 * Function         L2CA_Deregister
 *
 * Description      Other layers call this function to de-register for L2CAP
 *                  services.
 *
 * Returns          void
 *
 ******************************************************************************/
void L2CA_Deregister(uint16_t psm) {
  if (bluetooth::shim::is_gd_l2cap_enabled()) {
    return bluetooth::shim::L2CA_Deregister(psm);
  }

  tL2C_RCB* p_rcb;
  tL2C_CCB* p_ccb;
  tL2C_LCB* p_lcb;
  int ii;

  L2CAP_TRACE_API("L2CAP - L2CA_Deregister() called for PSM: 0x%04x", psm);

  p_rcb = l2cu_find_rcb_by_psm(psm);
  if (p_rcb != NULL) {
    p_lcb = &l2cb.lcb_pool[0];
    for (ii = 0; ii < MAX_L2CAP_LINKS; ii++, p_lcb++) {
      if (p_lcb->in_use) {
        p_ccb = p_lcb->ccb_queue.p_first_ccb;
        if ((p_ccb == NULL) || (p_lcb->link_state == LST_DISCONNECTING)) {
          continue;
        }

        if ((p_ccb->in_use) &&
            ((p_ccb->chnl_state == CST_W4_L2CAP_DISCONNECT_RSP) ||
             (p_ccb->chnl_state == CST_W4_L2CA_DISCONNECT_RSP))) {
          continue;
        }

        if (p_ccb->p_rcb == p_rcb) {
          l2c_csm_execute(p_ccb, L2CEVT_L2CA_DISCONNECT_REQ, NULL);
        }
      }
    }
    l2cu_release_rcb(p_rcb);
  } else {
    L2CAP_TRACE_WARNING("L2CAP - PSM: 0x%04x not found for deregistration",
                        psm);
  }
}

/*******************************************************************************
 *
 * Function         L2CA_AllocateLePSM
 *
 * Description      To find an unused LE PSM for L2CAP services.
 *
 * Returns          LE_PSM to use if success. Otherwise returns 0.
 *
 ******************************************************************************/
uint16_t L2CA_AllocateLePSM(void) {
  if (bluetooth::shim::is_gd_l2cap_enabled()) {
    return bluetooth::shim::L2CA_AllocateLePSM();
  }

  bool done = false;
  uint16_t psm = l2cb.le_dyn_psm;
  uint16_t count = 0;

  L2CAP_TRACE_API("%s: last psm=%d", __func__, psm);
  while (!done) {
    count++;
    if (count > LE_DYNAMIC_PSM_RANGE) {
      L2CAP_TRACE_ERROR("%s: Out of free BLE PSM", __func__);
      return 0;
    }

    psm++;
    if (psm > LE_DYNAMIC_PSM_END) {
      psm = LE_DYNAMIC_PSM_START;
    }

    if (!l2cb.le_dyn_psm_assigned[psm - LE_DYNAMIC_PSM_START]) {
      /* make sure the newly allocated psm is not used right now */
      if (l2cu_find_ble_rcb_by_psm(psm)) {
        L2CAP_TRACE_WARNING("%s: supposedly-free PSM=%d have allocated rcb!",
                            __func__, psm);
        continue;
      }

      l2cb.le_dyn_psm_assigned[psm - LE_DYNAMIC_PSM_START] = true;
      L2CAP_TRACE_DEBUG("%s: assigned PSM=%d", __func__, psm);
      done = true;
      break;
    }
  }
  l2cb.le_dyn_psm = psm;

  return (psm);
}

/*******************************************************************************
 *
 * Function         L2CA_FreeLePSM
 *
 * Description      Free an assigned LE PSM.
 *
 * Returns          void
 *
 ******************************************************************************/
void L2CA_FreeLePSM(uint16_t psm) {
  if (bluetooth::shim::is_gd_l2cap_enabled()) {
    return bluetooth::shim::L2CA_FreeLePSM(psm);
  }

  L2CAP_TRACE_API("%s: to free psm=%d", __func__, psm);

  if ((psm < LE_DYNAMIC_PSM_START) || (psm > LE_DYNAMIC_PSM_END)) {
    L2CAP_TRACE_ERROR("%s: Invalid PSM=%d value!", __func__, psm);
    return;
  }

  if (!l2cb.le_dyn_psm_assigned[psm - LE_DYNAMIC_PSM_START]) {
    L2CAP_TRACE_WARNING("%s: PSM=%d was not allocated!", __func__, psm);
  }
  l2cb.le_dyn_psm_assigned[psm - LE_DYNAMIC_PSM_START] = false;
}

uint16_t L2CA_ConnectReq2(uint16_t psm, const RawAddress& p_bd_addr,
                          uint16_t sec_level) {
  BTM_SetSecurityLevel(true, "", 0, sec_level, psm, 0, 0);
  return L2CA_ConnectReq(psm, p_bd_addr);
}

/*******************************************************************************
 *
 * Function         L2CA_ConnectReq
 *
 * Description      Higher layers call this function to create an L2CAP
 *                  connection.
 *                  Note that the connection is not established at this time,
 *                  but connection establishment gets started. The callback
 *                  will be invoked when connection establishes or fails.
 *
 * Returns          the CID of the connection, or 0 if it failed to start
 *
 ******************************************************************************/
uint16_t L2CA_ConnectReq(uint16_t psm, const RawAddress& p_bd_addr) {
  if (bluetooth::shim::is_gd_l2cap_enabled()) {
    return bluetooth::shim::L2CA_ConnectReq(psm, p_bd_addr);
  }

  VLOG(1) << __func__ << "BDA " << p_bd_addr
          << StringPrintf(" PSM: 0x%04x", psm);

  /* Fail if we have not established communications with the controller */
  if (!BTM_IsDeviceUp()) {
    LOG(WARNING) << __func__ << ": BTU not ready";
    return 0;
  }
  /* Fail if the PSM is not registered */
  tL2C_RCB* p_rcb = l2cu_find_rcb_by_psm(psm);
  if (p_rcb == nullptr) {
    LOG(WARNING) << __func__ << ": no RCB, PSM=" << loghex(psm);
    return 0;
  }

  /* First, see if we already have a link to the remote */
  /* assume all ERTM l2cap connection is going over BR/EDR for now */
  tL2C_LCB* p_lcb = l2cu_find_lcb_by_bd_addr(p_bd_addr, BT_TRANSPORT_BR_EDR);
  if (p_lcb == nullptr) {
    /* No link. Get an LCB and start link establishment */
    p_lcb = l2cu_allocate_lcb(p_bd_addr, false, BT_TRANSPORT_BR_EDR);
    /* currently use BR/EDR for ERTM mode l2cap connection */
    if (p_lcb == nullptr) {
      LOG(WARNING) << __func__
                   << ": connection not started for PSM=" << loghex(psm)
                   << ", p_lcb=" << p_lcb;
      return 0;
    }
    l2cu_create_conn_br_edr(p_lcb);
  }

  /* Allocate a channel control block */
  tL2C_CCB* p_ccb = l2cu_allocate_ccb(p_lcb, 0);
  if (p_ccb == nullptr) {
    LOG(WARNING) << __func__ << ": no CCB, PSM=" << loghex(psm);
    return 0;
  }

  /* Save registration info */
  p_ccb->p_rcb = p_rcb;

  p_ccb->connection_initiator = L2CAP_INITIATOR_LOCAL;

  /* If link is up, start the L2CAP connection */
  if (p_lcb->link_state == LST_CONNECTED) {
    l2c_csm_execute(p_ccb, L2CEVT_L2CA_CONNECT_REQ, nullptr);
  } else if (p_lcb->link_state == LST_DISCONNECTING) {
    /* If link is disconnecting, save link info to retry after disconnect
     * Possible Race condition when a reconnect occurs
     * on the channel during a disconnect of link. This
     * ccb will be automatically retried after link disconnect
     * arrives
     */
    L2CAP_TRACE_DEBUG("L2CAP API - link disconnecting: RETRY LATER");

    /* Save ccb so it can be started after disconnect is finished */
    p_lcb->p_pending_ccb = p_ccb;
  }

  L2CAP_TRACE_API("L2CAP - L2CA_conn_req(psm: 0x%04x) returned CID: 0x%04x",
                  psm, p_ccb->local_cid);

  /* Return the local CID as our handle */
  return p_ccb->local_cid;
}

/*******************************************************************************
 *
 * Function         L2CA_RegisterLECoc
 *
 * Description      Other layers call this function to register for L2CAP
 *                  Connection Oriented Channel.
 *
 * Returns          PSM to use or zero if error. Typically, the PSM returned
 *                  is the same as was passed in, but for an outgoing-only
 *                  connection to a dynamic PSM, a "virtual" PSM is returned
 *                  and should be used in the calls to L2CA_ConnectLECocReq()
 *                  and L2CA_DeregisterLECoc()
 *
 ******************************************************************************/
uint16_t L2CA_RegisterLECoc(uint16_t psm, const tL2CAP_APPL_INFO& p_cb_info,
                            uint16_t sec_level, tL2CAP_LE_CFG_INFO cfg) {
  if (bluetooth::shim::is_gd_l2cap_enabled()) {
    return bluetooth::shim::L2CA_RegisterLECoc(psm, p_cb_info, sec_level, cfg);
  }

  if (p_cb_info.pL2CA_ConnectInd_Cb != nullptr || psm < LE_DYNAMIC_PSM_START) {
    //  If we register LE COC for outgoing connection only, don't register with
    //  BTM_Sec, because it's handled by L2CA_ConnectLECocReq.
    BTM_SetSecurityLevel(false, "", 0, sec_level, psm, 0, 0);
  }

  /* Verify that the required callback info has been filled in
  **      Note:  Connection callbacks are required but not checked
  **             for here because it is possible to be only a client
  **             or only a server.
  */
  if ((!p_cb_info.pL2CA_DataInd_Cb) || (!p_cb_info.pL2CA_DisconnectInd_Cb)) {
    LOG_ERROR("No cb registering BLE PSM: 0x%04x", psm);
    return 0;
  }

  /* Verify PSM is valid */
  if (!L2C_IS_VALID_LE_PSM(psm)) {
    LOG_ERROR("Invalid BLE PSM value, PSM: 0x%04x", psm);
    return 0;
  }

  tL2C_RCB* p_rcb;
  uint16_t vpsm = psm;

  /* Check if this is a registration for an outgoing-only connection to */
  /* a dynamic PSM. If so, allocate a "virtual" PSM for the app to use. */
  if ((psm >= LE_DYNAMIC_PSM_START) &&
      (p_cb_info.pL2CA_ConnectInd_Cb == NULL)) {
    vpsm = L2CA_AllocateLePSM();
    if (vpsm == 0) {
      LOG_ERROR("Out of free BLE PSM");
      return 0;
    }

    LOG_DEBUG("Real PSM: 0x%04x  Virtual PSM: 0x%04x", psm, vpsm);
  }

  /* If registration block already there, just overwrite it */
  p_rcb = l2cu_find_ble_rcb_by_psm(vpsm);
  if (p_rcb == NULL) {
    LOG_DEBUG("Allocate rcp for Virtual PSM: 0x%04x", vpsm);
    p_rcb = l2cu_allocate_ble_rcb(vpsm);
    if (p_rcb == NULL) {
      LOG_WARN("No BLE RCB available, PSM: 0x%04x  vPSM: 0x%04x", psm, vpsm);
      return 0;
    }
  }

  LOG_INFO("Registered service LE COC PSM: 0x%04x", psm);
  p_rcb->api = p_cb_info;
  p_rcb->real_psm = psm;
  p_rcb->coc_cfg = cfg;

  return vpsm;
}

/*******************************************************************************
 *
 * Function         L2CA_DeregisterLECoc
 *
 * Description      Other layers call this function to de-register for L2CAP
 *                  Connection Oriented Channel.
 *
 * Returns          void
 *
 ******************************************************************************/
void L2CA_DeregisterLECoc(uint16_t psm) {
  if (bluetooth::shim::is_gd_l2cap_enabled()) {
    return bluetooth::shim::L2CA_DeregisterLECoc(psm);
  }

  L2CAP_TRACE_API("%s called for PSM: 0x%04x", __func__, psm);

  tL2C_RCB* p_rcb = l2cu_find_ble_rcb_by_psm(psm);
  if (p_rcb == NULL) {
    L2CAP_TRACE_WARNING("%s PSM: 0x%04x not found for deregistration", __func__,
                        psm);
    return;
  }

  tL2C_LCB* p_lcb = &l2cb.lcb_pool[0];
  for (int i = 0; i < MAX_L2CAP_LINKS; i++, p_lcb++) {
    if (!p_lcb->in_use || p_lcb->transport != BT_TRANSPORT_LE) continue;

    tL2C_CCB* p_ccb = p_lcb->ccb_queue.p_first_ccb;
    if ((p_ccb == NULL) || (p_lcb->link_state == LST_DISCONNECTING)) continue;

    if (p_ccb->in_use && (p_ccb->chnl_state == CST_W4_L2CAP_DISCONNECT_RSP ||
                          p_ccb->chnl_state == CST_W4_L2CA_DISCONNECT_RSP))
      continue;

    if (p_ccb->p_rcb == p_rcb)
      l2c_csm_execute(p_ccb, L2CEVT_L2CA_DISCONNECT_REQ, NULL);
  }

  l2cu_release_ble_rcb(p_rcb);
}

/*******************************************************************************
 *
 * Function         L2CA_ConnectLECocReq
 *
 * Description      Higher layers call this function to create an L2CAP
 *                  connection. Note that the connection is not established at
 *                  this time, but connection establishment gets started. The
 *                  callback function will be invoked when connection
 *                  establishes or fails.
 *
 *  Parameters:     PSM: L2CAP PSM for the connection
 *                  BD address of the peer
 *                  Local Coc configurations

 * Returns          the CID of the connection, or 0 if it failed to start
 *
 ******************************************************************************/
uint16_t L2CA_ConnectLECocReq(uint16_t psm, const RawAddress& p_bd_addr,
                              tL2CAP_LE_CFG_INFO* p_cfg, uint16_t sec_level) {
  if (bluetooth::shim::is_gd_l2cap_enabled()) {
    return bluetooth::shim::L2CA_ConnectLECocReq(psm, p_bd_addr, p_cfg);
  }

  BTM_SetSecurityLevel(true, "", 0, sec_level, psm, 0, 0);

  VLOG(1) << __func__ << " BDA: " << p_bd_addr
          << StringPrintf(" PSM: 0x%04x", psm);

  /* Fail if we have not established communications with the controller */
  if (!BTM_IsDeviceUp()) {
    L2CAP_TRACE_WARNING("%s BTU not ready", __func__);
    return 0;
  }

  /* Fail if the PSM is not registered */
  tL2C_RCB* p_rcb = l2cu_find_ble_rcb_by_psm(psm);
  if (p_rcb == NULL) {
    L2CAP_TRACE_WARNING("%s No BLE RCB, PSM: 0x%04x", __func__, psm);
    return 0;
  }

  /* First, see if we already have a le link to the remote */
  tL2C_LCB* p_lcb = l2cu_find_lcb_by_bd_addr(p_bd_addr, BT_TRANSPORT_LE);
  if (p_lcb == NULL) {
    /* No link. Get an LCB and start link establishment */
    p_lcb = l2cu_allocate_lcb(p_bd_addr, false, BT_TRANSPORT_LE);
    if ((p_lcb == NULL)
        /* currently use BR/EDR for ERTM mode l2cap connection */
        || (!l2cu_create_conn_le(p_lcb))) {
      L2CAP_TRACE_WARNING("%s conn not started for PSM: 0x%04x  p_lcb: 0x%08x",
                          __func__, psm, p_lcb);
      return 0;
    }
  }

  /* Allocate a channel control block */
  tL2C_CCB* p_ccb = l2cu_allocate_ccb(p_lcb, 0);
  if (p_ccb == NULL) {
    L2CAP_TRACE_WARNING("%s no CCB, PSM: 0x%04x", __func__, psm);
    return 0;
  }

  /* Save registration info */
  p_ccb->p_rcb = p_rcb;

  p_ccb->connection_initiator = L2CAP_INITIATOR_LOCAL;

  /* Save the configuration */
  if (p_cfg) {
    p_ccb->local_conn_cfg = *p_cfg;
    p_ccb->remote_credit_count = p_cfg->credits;
  }

  /* If link is up, start the L2CAP connection */
  if (p_lcb->link_state == LST_CONNECTED) {
    if (p_ccb->p_lcb->transport == BT_TRANSPORT_LE) {
      L2CAP_TRACE_DEBUG("%s LE Link is up", __func__);
      l2c_csm_execute(p_ccb, L2CEVT_L2CA_CONNECT_REQ, NULL);
    }
  }

  /* If link is disconnecting, save link info to retry after disconnect
   * Possible Race condition when a reconnect occurs
   * on the channel during a disconnect of link. This
   * ccb will be automatically retried after link disconnect
   * arrives
   */
  else if (p_lcb->link_state == LST_DISCONNECTING) {
    L2CAP_TRACE_DEBUG("%s link disconnecting: RETRY LATER", __func__);

    /* Save ccb so it can be started after disconnect is finished */
    p_lcb->p_pending_ccb = p_ccb;
  }

  L2CAP_TRACE_API("%s(psm: 0x%04x) returned CID: 0x%04x", __func__, psm,
                  p_ccb->local_cid);

  /* Return the local CID as our handle */
  return p_ccb->local_cid;
}

/*******************************************************************************
 *
 *  Function         L2CA_GetPeerLECocConfig
 *
 *  Description      Get a peers configuration for LE Connection Oriented
 *                   Channel.
 *
 *  Parameters:      local channel id
 *                   Pointers to peers configuration storage area
 *
 *  Return value:    true if peer is connected
 *
 ******************************************************************************/
bool L2CA_GetPeerLECocConfig(uint16_t lcid, tL2CAP_LE_CFG_INFO* peer_cfg) {
  if (bluetooth::shim::is_gd_l2cap_enabled()) {
    return bluetooth::shim::L2CA_GetPeerLECocConfig(lcid, peer_cfg);
  }

  L2CAP_TRACE_API("%s CID: 0x%04x", __func__, lcid);

  tL2C_CCB* p_ccb = l2cu_find_ccb_by_cid(NULL, lcid);
  if (p_ccb == NULL) {
    L2CAP_TRACE_ERROR("%s No CCB for CID:0x%04x", __func__, lcid);
    return false;
  }

  if (peer_cfg != NULL)
    memcpy(peer_cfg, &p_ccb->peer_conn_cfg, sizeof(tL2CAP_LE_CFG_INFO));

  return true;
}

/*******************************************************************************
 *
 *  Function         L2CA_GetPeerLECocCredit
 *
 *  Description      Get peers current credit for LE Connection Oriented
 *                   Channel.
 *
 *  Return value:    Number of the peer current credit
 *
 ******************************************************************************/
uint16_t L2CA_GetPeerLECocCredit(const RawAddress& bd_addr, uint16_t lcid) {
  /* First, find the link control block */
  tL2C_LCB* p_lcb = l2cu_find_lcb_by_bd_addr(bd_addr, BT_TRANSPORT_LE);
  if (p_lcb == NULL) {
    /* No link. Get an LCB and start link establishment */
    L2CAP_TRACE_WARNING("%s no LCB", __func__);
    return L2CAP_LE_CREDIT_MAX;
  }

  tL2C_CCB* p_ccb = l2cu_find_ccb_by_cid(p_lcb, lcid);
  if (p_ccb == NULL) {
    L2CAP_TRACE_ERROR("%s No CCB for CID:0x%04x", __func__, lcid);
    return L2CAP_LE_CREDIT_MAX;
  }

  return p_ccb->peer_conn_cfg.credits;
}

/*******************************************************************************
 *
 * Function         L2CA_ConnectCreditBasedRsp
 *
 * Description      Response for the pL2CA_CreditBasedConnectInd_Cb which is the
 *                  indication for peer requesting credit based connection.
 *
 * Parameters:      BD address of the peer
 *                  Identifier of the transaction
 *                  Vector of accepted lcids by upper layer
 *                  L2CAP result
 *                  Local channel configuration
 *
 * Returns          true for success, false for failure
 *
 ******************************************************************************/
bool L2CA_ConnectCreditBasedRsp(const RawAddress& p_bd_addr, uint8_t id,
                                std::vector<uint16_t>& accepted_lcids,
                                uint16_t result, tL2CAP_LE_CFG_INFO* p_cfg) {
  if (bluetooth::shim::is_gd_l2cap_enabled()) {
    return bluetooth::shim::L2CA_ConnectCreditBasedRsp(
        p_bd_addr, id, accepted_lcids, result, p_cfg);
  }

  VLOG(1) << __func__ << " BDA: " << p_bd_addr
          << StringPrintf(" num of cids: %d Result: %d",
                          int(accepted_lcids.size()), +result);

  /* First, find the link control block */
  tL2C_LCB* p_lcb = l2cu_find_lcb_by_bd_addr(p_bd_addr, BT_TRANSPORT_LE);
  if (p_lcb == NULL) {
    /* No link. Get an LCB and start link establishment */
    L2CAP_TRACE_WARNING("%s no LCB", __func__);
    return false;
  }

  /* Now, find the channel control block. We kept lead cid.
   */
  tL2C_CCB* p_ccb = l2cu_find_ccb_by_cid(p_lcb, p_lcb->pending_lead_cid);

  for (uint16_t cid : accepted_lcids) {
    tL2C_CCB* temp_p_ccb = l2cu_find_ccb_by_cid(p_lcb, cid);
    if (temp_p_ccb == NULL) {
      L2CAP_TRACE_WARNING("%s no CCB", __func__);
      return false;
    }

    if (p_cfg) {
      temp_p_ccb->local_conn_cfg = *p_cfg;
      temp_p_ccb->remote_credit_count = p_cfg->credits;
    }
  }

  /* The IDs must match */
  if (p_ccb->remote_id != id) {
    L2CAP_TRACE_WARNING("%s bad id. Expected: %d  Got: %d", __func__,
                        p_ccb->remote_id, id);
    return false;
  }

  tL2C_CONN_INFO conn_info;
  conn_info.lcids = accepted_lcids;
  conn_info.bd_addr = p_bd_addr;
  conn_info.l2cap_result = result;

  if (accepted_lcids.size() > 0) {
    l2c_csm_execute(p_ccb, L2CEVT_L2CA_CREDIT_BASED_CONNECT_RSP, &conn_info);
  } else {
    l2c_csm_execute(p_ccb, L2CEVT_L2CA_CREDIT_BASED_CONNECT_RSP_NEG,
                    &conn_info);
  }

  return true;
}
/*******************************************************************************
 *
 *  Function         L2CA_ConnectCreditBasedReq
 *
 *  Description      Initiate Create Credit Based connections.
 *
 *  Parameters:      PSM for the L2CAP channel
 *                   BD address of the peer
 *                   Local channel configuration
 *
 *  Return value:    Vector of allocated local cids.
 *
 ******************************************************************************/

std::vector<uint16_t> L2CA_ConnectCreditBasedReq(uint16_t psm,
                                                 const RawAddress& p_bd_addr,
                                                 tL2CAP_LE_CFG_INFO* p_cfg) {
  if (bluetooth::shim::is_gd_l2cap_enabled()) {
    return bluetooth::shim::L2CA_ConnectCreditBasedReq(psm, p_bd_addr, p_cfg);
  }

  VLOG(1) << __func__ << " BDA: " << p_bd_addr
          << StringPrintf(" PSM: 0x%04x", psm);

  std::vector<uint16_t> allocated_cids;

  /* Fail if we have not established communications with the controller */
  if (!BTM_IsDeviceUp()) {
    L2CAP_TRACE_WARNING("%s BTU not ready", __func__);
    return allocated_cids;
  }

  if (!p_cfg) {
    L2CAP_TRACE_WARNING("%s p_cfg is NULL", __func__);
    return allocated_cids;
  }

  /* Fail if the PSM is not registered */
  tL2C_RCB* p_rcb = l2cu_find_ble_rcb_by_psm(psm);
  if (p_rcb == NULL) {
    L2CAP_TRACE_WARNING("%s No BLE RCB, PSM: 0x%04x", __func__, psm);
    return allocated_cids;
  }

  /* First, see if we already have a le link to the remote */
  tL2C_LCB* p_lcb = l2cu_find_lcb_by_bd_addr(p_bd_addr, BT_TRANSPORT_LE);
  if (p_lcb == NULL) {
    L2CAP_TRACE_WARNING("%s No link available", __func__);
    return allocated_cids;
  }

  if (p_lcb->link_state != LST_CONNECTED) {
    L2CAP_TRACE_WARNING("%s incorrect link state: %d", __func__,
                        p_lcb->link_state);
    return allocated_cids;
  }

  L2CAP_TRACE_DEBUG("%s LE Link is up", __func__);

  tL2C_CCB* p_ccb_primary;

  for (int i = 0; i < 5; i++) {
    /* Allocate a channel control block */
    tL2C_CCB* p_ccb = l2cu_allocate_ccb(p_lcb, 0);
    if (p_ccb == NULL) {
      if (i == 0) {
        L2CAP_TRACE_WARNING("%s no CCB, PSM: 0x%04x", __func__, psm);
        return allocated_cids;
      } else {
        break;
      }
    }

    p_ccb->ecoc = true;
    p_ccb->local_conn_cfg = *p_cfg;
    p_ccb->remote_credit_count = p_cfg->credits;
    /* Save registration info */
    p_ccb->p_rcb = p_rcb;
    if (i == 0) {
      p_ccb_primary = p_ccb;
    } else {
      /* Only primary channel we keep in closed state, as in that
       * context we will run state machine where security is checked etc.
       * Others we can directly put into waiting for connect
       * response, so those are not confused by system as incomming connections
       */
      p_ccb->chnl_state = CST_W4_L2CAP_CONNECT_RSP;
    }

    allocated_cids.push_back(p_ccb->local_cid);
  }

  for (int i = 0; i < (int)(allocated_cids.size()); i++)
    p_lcb->pending_ecoc_connection_cids[i] = allocated_cids[i];

  p_lcb->pending_ecoc_conn_cnt = (uint16_t)(allocated_cids.size());
  l2c_csm_execute(p_ccb_primary, L2CEVT_L2CA_CREDIT_BASED_CONNECT_REQ, NULL);

  L2CAP_TRACE_API("%s(psm: 0x%04x) returned CID: 0x%04x", __func__, psm,
                  p_ccb_primary->local_cid);

  return allocated_cids;
}

/*******************************************************************************
 *
 *  Function         L2CA_ReconfigCreditBasedConnsReq
 *
 *  Description      Start reconfigure procedure on Connection Oriented Channel.
 *
 *  Parameters:      Vector of channels for which configuration should be changed
 *                   New local channel configuration
 *
 *  Return value:    true if peer is connected
 *
 ******************************************************************************/

bool L2CA_ReconfigCreditBasedConnsReq(const RawAddress& bda,
                                      std::vector<uint16_t>& lcids,
                                      tL2CAP_LE_CFG_INFO* p_cfg) {
  if (bluetooth::shim::is_gd_l2cap_enabled()) {
    return bluetooth::shim::L2CA_ReconfigCreditBasedConnsReq(bda, lcids, p_cfg);
  }

  tL2C_CCB* p_ccb;

  L2CAP_TRACE_API("L2CA_ReconfigCreditBasedConnsReq() ");

  if (lcids.empty()) {
    L2CAP_TRACE_WARNING("L2CAP - no lcids given to %s", __func__);
    return (false);
  }

  for (uint16_t cid : lcids) {
    p_ccb = l2cu_find_ccb_by_cid(NULL, cid);

    if (!p_ccb) {
      L2CAP_TRACE_WARNING("L2CAP - no CCB for L2CA_cfg_req, CID: %d", cid);
      return (false);
    }

    if ((p_ccb->local_conn_cfg.mtu > p_cfg->mtu) ||
        (p_ccb->local_conn_cfg.mps > p_cfg->mps)) {
      L2CAP_TRACE_WARNING("L2CAP - MPS or MTU reduction, CID: %d", cid);
      return (false);
    }
  }

  if (p_cfg->mtu > L2CAP_MTU_SIZE) {
    L2CAP_TRACE_WARNING("L2CAP - adjust MTU: %u too large", p_cfg->mtu);
    p_cfg->mtu = L2CAP_MTU_SIZE;
  }

  /* Mark all the p_ccbs which going to be reconfigured */
  for (uint16_t cid : lcids) {
    L2CAP_TRACE_API(" cid: %d", cid);
    p_ccb = l2cu_find_ccb_by_cid(NULL, cid);
    if (!p_ccb) {
      LOG(ERROR) << __func__ << "Missing cid? " << int(cid);
      return (false);
    }
    p_ccb->reconfig_started = true;
  }

  tL2C_LCB* p_lcb = p_ccb->p_lcb;

  /* Hack warning - the whole reconfig we are doing in the context of the first
   * p_ccb. In the p_lcp we store configuration and cid in which context we are
   * doing reconfiguration.
   */
  for (p_ccb = p_lcb->ccb_queue.p_first_ccb; p_ccb; p_ccb = p_ccb->p_next_ccb)
    if ((p_ccb->in_use) && (p_ccb->ecoc) && (p_ccb->reconfig_started)) {
      p_ccb->p_lcb->pending_ecoc_reconfig_cfg = *p_cfg;
      p_ccb->p_lcb->pending_ecoc_reconfig_cnt = lcids.size();
      break;
    }

  l2c_csm_execute(p_ccb, L2CEVT_L2CA_CREDIT_BASED_RECONFIG_REQ, p_cfg);

  return (true);
}

/*******************************************************************************
 *
 * Function         L2CA_DisconnectReq
 *
 * Description      Higher layers call this function to disconnect a channel.
 *
 * Returns          true if disconnect sent, else false
 *
 ******************************************************************************/
bool L2CA_DisconnectReq(uint16_t cid) {
  if (bluetooth::shim::is_gd_l2cap_enabled()) {
    return bluetooth::shim::L2CA_DisconnectReq(cid);
  }

  tL2C_CCB* p_ccb;

  /* Find the channel control block. We don't know the link it is on. */
  p_ccb = l2cu_find_ccb_by_cid(NULL, cid);
  if (p_ccb == NULL) {
    LOG_WARN("L2CAP - no CCB for L2CA_disc_req, CID: %d", cid);
    return (false);
  }

  LOG_DEBUG("L2CAP Local disconnect request CID: 0x%04x", cid);

  l2c_csm_execute(p_ccb, L2CEVT_L2CA_DISCONNECT_REQ, NULL);

  return (true);
}

bool L2CA_DisconnectLECocReq(uint16_t cid) {
  if (bluetooth::shim::is_gd_l2cap_enabled()) {
    return bluetooth::shim::L2CA_DisconnectLECocReq(cid);
  }
  return L2CA_DisconnectReq(cid);
}

bool L2CA_GetRemoteCid(uint16_t lcid, uint16_t* rcid) {
  if (bluetooth::shim::is_gd_l2cap_enabled()) {
    return bluetooth::shim::L2CA_GetRemoteCid(lcid, rcid);
  }

  tL2C_CCB* control_block = l2cu_find_ccb_by_cid(NULL, lcid);
  if (!control_block) return false;

  if (rcid) *rcid = control_block->remote_cid;

  return true;
}

/*******************************************************************************
 *
 * Function         L2CA_SetIdleTimeoutByBdAddr
 *
 * Description      Higher layers call this function to set the idle timeout for
 *                  a connection. The "idle timeout" is the amount of time that
 *                  a connection can remain up with no L2CAP channels on it.
 *                  A timeout of zero means that the connection will be torn
 *                  down immediately when the last channel is removed.
 *                  A timeout of 0xFFFF means no timeout. Values are in seconds.
 *                  A bd_addr is the remote BD address. If bd_addr =
 *                  RawAddress::kAny, then the idle timeouts for all active
 *                  l2cap links will be changed.
 *
 * Returns          true if command succeeded, false if failed
 *
 * NOTE             This timeout applies to all logical channels active on the
 *                  ACL link.
 ******************************************************************************/
bool L2CA_SetIdleTimeoutByBdAddr(const RawAddress& bd_addr, uint16_t timeout,
                                 tBT_TRANSPORT transport) {
  if (bluetooth::shim::is_gd_l2cap_enabled()) {
    return bluetooth::shim::L2CA_SetIdleTimeoutByBdAddr(bd_addr, timeout,
                                                        transport);
  }

  tL2C_LCB* p_lcb;

  if (RawAddress::kAny != bd_addr) {
    p_lcb = l2cu_find_lcb_by_bd_addr(bd_addr, transport);
    if ((p_lcb) && (p_lcb->in_use) && (p_lcb->link_state == LST_CONNECTED)) {
      p_lcb->idle_timeout = timeout;

      if (!p_lcb->ccb_queue.p_first_ccb) l2cu_no_dynamic_ccbs(p_lcb);
    } else
      return false;
  } else {
    int xx;
    tL2C_LCB* p_lcb = &l2cb.lcb_pool[0];

    for (xx = 0; xx < MAX_L2CAP_LINKS; xx++, p_lcb++) {
      if ((p_lcb->in_use) && (p_lcb->link_state == LST_CONNECTED)) {
        p_lcb->idle_timeout = timeout;

        if (!p_lcb->ccb_queue.p_first_ccb) l2cu_no_dynamic_ccbs(p_lcb);
      }
    }
  }

  return true;
}

/*******************************************************************************
 *
 * Function         L2CA_SetTraceLevel
 *
 * Description      This function sets the trace level for L2CAP. If called with
 *                  a value of 0xFF, it simply reads the current trace level.
 *
 * Returns          the new (current) trace level
 *
 ******************************************************************************/
uint8_t L2CA_SetTraceLevel(uint8_t new_level) {
  if (new_level != 0xFF) l2cb.l2cap_trace_level = new_level;

  return (l2cb.l2cap_trace_level);
}

/*******************************************************************************
 *
 * Function         L2CA_SetAclPriority
 *
 * Description      Sets the transmission priority for a channel.
 *                  (For initial implementation only two values are valid.
 *                  L2CAP_PRIORITY_NORMAL and L2CAP_PRIORITY_HIGH).
 *
 * Returns          true if a valid channel, else false
 *
 ******************************************************************************/
bool L2CA_SetAclPriority(const RawAddress& bd_addr, tL2CAP_PRIORITY priority) {
  if (bluetooth::shim::is_gd_l2cap_enabled()) {
    return bluetooth::shim::L2CA_SetAclPriority(bd_addr, priority);
  }

  VLOG(1) << __func__ << " BDA: " << bd_addr
          << ", priority: " << std::to_string(priority);
  return (l2cu_set_acl_priority(bd_addr, priority, false));
}

/*******************************************************************************
 *
 * Function         L2CA_SetTxPriority
 *
 * Description      Sets the transmission priority for a channel.
 *
 * Returns          true if a valid channel, else false
 *
 ******************************************************************************/
bool L2CA_SetTxPriority(uint16_t cid, tL2CAP_CHNL_PRIORITY priority) {
  if (bluetooth::shim::is_gd_l2cap_enabled()) {
    return bluetooth::shim::L2CA_SetTxPriority(cid, priority);
  }

  tL2C_CCB* p_ccb;

  L2CAP_TRACE_API("L2CA_SetTxPriority()  CID: 0x%04x, priority:%d", cid,
                  priority);

  /* Find the channel control block. We don't know the link it is on. */
  p_ccb = l2cu_find_ccb_by_cid(NULL, cid);
  if (p_ccb == NULL) {
    L2CAP_TRACE_WARNING("L2CAP - no CCB for L2CA_SetTxPriority, CID: %d", cid);
    return (false);
  }

  /* it will update the order of CCB in LCB by priority and update round robin
   * service variables */
  l2cu_change_pri_ccb(p_ccb, priority);

  return (true);
}

/*******************************************************************************
 *
 *  Function         L2CA_GetPeerFeatures
 *
 *  Description      Get a peers features and fixed channel map
 *
 *  Parameters:      BD address of the peer
 *                   Pointers to features and channel mask storage area
 *
 *  Return value:    true if peer is connected
 *
 ******************************************************************************/
bool L2CA_GetPeerFeatures(const RawAddress& bd_addr, uint32_t* p_ext_feat,
                          uint8_t* p_chnl_mask) {
  if (bluetooth::shim::is_gd_l2cap_enabled()) {
    return bluetooth::shim::L2CA_GetPeerFeatures(bd_addr, p_ext_feat,
                                                 p_chnl_mask);
  }

  tL2C_LCB* p_lcb;

  /* We must already have a link to the remote */
  p_lcb = l2cu_find_lcb_by_bd_addr(bd_addr, BT_TRANSPORT_BR_EDR);
  if (p_lcb == NULL) {
    LOG(WARNING) << __func__ << " No BDA: " << bd_addr;
    return false;
  }

  VLOG(1) << __func__ << " BDA: " << bd_addr
          << StringPrintf(" ExtFea: 0x%08x Chnl_Mask[0]: 0x%02x",
                          p_lcb->peer_ext_fea, p_lcb->peer_chnl_mask[0]);

  *p_ext_feat = p_lcb->peer_ext_fea;

  memcpy(p_chnl_mask, p_lcb->peer_chnl_mask, L2CAP_FIXED_CHNL_ARRAY_SIZE);

  return true;
}

/*******************************************************************************
 *
 *  Function        L2CA_RegisterFixedChannel
 *
 *  Description     Register a fixed channel.
 *
 *  Parameters:     Fixed Channel #
 *                  Channel Callbacks and config
 *
 *  Return value:   -
 *
 ******************************************************************************/
static std::string fixed_channel_text(const uint16_t& fixed_cid) {
  switch (fixed_cid) {
    case L2CAP_SIGNALLING_CID:
      return std::string("br_edr signalling");
    case L2CAP_CONNECTIONLESS_CID:
      return std::string("connectionless");
    case L2CAP_AMP_CID:
      return std::string("amp");
    case L2CAP_ATT_CID:
      return std::string("att");
    case L2CAP_BLE_SIGNALLING_CID:
      return std::string("ble signalling");
    case L2CAP_SMP_CID:
      return std::string("smp");
    case L2CAP_SMP_BR_CID:
      return std::string("br_edr smp");
    default:
      return std::string("unknown");
  }
}

bool L2CA_RegisterFixedChannel(uint16_t fixed_cid,
                               tL2CAP_FIXED_CHNL_REG* p_freg) {
  if (bluetooth::shim::is_gd_l2cap_enabled()) {
    return bluetooth::shim::L2CA_RegisterFixedChannel(fixed_cid, p_freg);
  }

  if ((fixed_cid < L2CAP_FIRST_FIXED_CHNL) ||
      (fixed_cid > L2CAP_LAST_FIXED_CHNL)) {
    LOG_ERROR("Invalid fixed CID: 0x%04x", fixed_cid);
    return false;
  }

  l2cb.fixed_reg[fixed_cid - L2CAP_FIRST_FIXED_CHNL] = *p_freg;
  LOG_DEBUG("Registered fixed channel:%s",
            fixed_channel_text(fixed_cid).c_str());
  return true;
}

/*******************************************************************************
 *
 *  Function        L2CA_ConnectFixedChnl
 *
 *  Description     Connect an fixed signalling channel to a remote device.
 *
 *  Parameters:     Fixed CID
 *                  BD Address of remote
 *
 *  Return value:   true if connection started
 *
 ******************************************************************************/
bool L2CA_ConnectFixedChnl(uint16_t fixed_cid, const RawAddress& rem_bda) {
  if (bluetooth::shim::is_gd_l2cap_enabled()) {
    return bluetooth::shim::L2CA_ConnectFixedChnl(fixed_cid, rem_bda);
  }

  tL2C_LCB* p_lcb;
  tBT_TRANSPORT transport = BT_TRANSPORT_BR_EDR;

  LOG_DEBUG(" fixed_cid:0x%04x", fixed_cid);

  // Check CID is valid and registered
  if ((fixed_cid < L2CAP_FIRST_FIXED_CHNL) ||
      (fixed_cid > L2CAP_LAST_FIXED_CHNL) ||
      (l2cb.fixed_reg[fixed_cid - L2CAP_FIRST_FIXED_CHNL].pL2CA_FixedData_Cb ==
       NULL)) {
    LOG_ERROR("Invalid fixed_cid:0x%04x", fixed_cid);
    return (false);
  }

  // Fail if BT is not yet up
  if (!BTM_IsDeviceUp()) {
    LOG_WARN("Bt controller is not ready fixed_cid:0x%04x", fixed_cid);
    return (false);
  }

  if (fixed_cid >= L2CAP_ATT_CID && fixed_cid <= L2CAP_SMP_CID)
    transport = BT_TRANSPORT_LE;

  tL2C_BLE_FIXED_CHNLS_MASK peer_channel_mask;

  // If we already have a link to the remote, check if it supports that CID
  p_lcb = l2cu_find_lcb_by_bd_addr(rem_bda, transport);
  if (p_lcb != NULL) {
    // Fixed channels are mandatory on LE transports so ignore the received
    // channel mask and use the locally cached LE channel mask.

    if (transport == BT_TRANSPORT_LE)
      peer_channel_mask = l2cb.l2c_ble_fixed_chnls_mask;
    else
      peer_channel_mask = p_lcb->peer_chnl_mask[0];

    // Check for supported channel
    if (!(peer_channel_mask & (1 << fixed_cid))) {
      LOG_INFO("Peer device does not support fixed_cid:0x%04x", fixed_cid);
      return false;
    }

    // Get a CCB and link the lcb to it
    if (!l2cu_initialize_fixed_ccb(p_lcb, fixed_cid)) {
      LOG_WARN("Unable to allocate fixed channel resource fixed_cid:0x%04x",
               fixed_cid);
      return false;
    }

    // racing with disconnecting, queue the connection request
    if (p_lcb->link_state == LST_DISCONNECTING) {
      LOG_DEBUG(
          "Link is disconnecting so deferring connection fixed_cid:0x%04x",
          fixed_cid);
      /* Save ccb so it can be started after disconnect is finished */
      p_lcb->p_pending_ccb =
          p_lcb->p_fixed_ccbs[fixed_cid - L2CAP_FIRST_FIXED_CHNL];
      return true;
    }

    (*l2cb.fixed_reg[fixed_cid - L2CAP_FIRST_FIXED_CHNL].pL2CA_FixedConn_Cb)(
        fixed_cid, p_lcb->remote_bd_addr, true, 0, p_lcb->transport);
    return true;
  }

  // No link. Get an LCB and start link establishment
  p_lcb = l2cu_allocate_lcb(rem_bda, false, transport);
  if (p_lcb == NULL) {
    LOG_WARN("Unable to allocate link resource for connection fixed_cid:0x%04x",
             fixed_cid);
    return false;
  }

  // Get a CCB and link the lcb to it
  if (!l2cu_initialize_fixed_ccb(p_lcb, fixed_cid)) {
    LOG_WARN("Unable to allocate fixed channel resource fixed_cid:0x%04x",
             fixed_cid);
    l2cu_release_lcb(p_lcb);
    return false;
  }

  if (transport == BT_TRANSPORT_LE) {
    bool ret = l2cu_create_conn_le(p_lcb);
    if (!ret) {
      LOG_WARN("Unable to create fixed channel le connection fixed_cid:0x%04x",
               fixed_cid);
      l2cu_release_lcb(p_lcb);
      return false;
    }
  } else {
    l2cu_create_conn_br_edr(p_lcb);
  }
  return true;
}

/*******************************************************************************
 *
 *  Function        L2CA_SendFixedChnlData
 *
 *  Description     Write data on a fixed channel.
 *
 *  Parameters:     Fixed CID
 *                  BD Address of remote
 *                  Pointer to buffer of type BT_HDR
 *
 * Return value     L2CAP_DW_SUCCESS, if data accepted
 *                  L2CAP_DW_FAILED,  if error
 *
 ******************************************************************************/
uint16_t L2CA_SendFixedChnlData(uint16_t fixed_cid, const RawAddress& rem_bda,
                                BT_HDR* p_buf) {
  if (bluetooth::shim::is_gd_l2cap_enabled()) {
    return bluetooth::shim::L2CA_SendFixedChnlData(fixed_cid, rem_bda, p_buf);
  }

  tL2C_LCB* p_lcb;
  tBT_TRANSPORT transport = BT_TRANSPORT_BR_EDR;

  if (fixed_cid >= L2CAP_ATT_CID && fixed_cid <= L2CAP_SMP_CID)
    transport = BT_TRANSPORT_LE;

  if ((fixed_cid < L2CAP_FIRST_FIXED_CHNL) ||
      (fixed_cid > L2CAP_LAST_FIXED_CHNL) ||
      (l2cb.fixed_reg[fixed_cid - L2CAP_FIRST_FIXED_CHNL].pL2CA_FixedData_Cb ==
       NULL)) {
    LOG_WARN("No service registered or invalid CID: 0x%04x", fixed_cid);
    osi_free(p_buf);
    return (L2CAP_DW_FAILED);
  }

  if (!BTM_IsDeviceUp()) {
    LOG_WARN("Controller is not ready CID: 0x%04x", fixed_cid);
    osi_free(p_buf);
    return (L2CAP_DW_FAILED);
  }

  p_lcb = l2cu_find_lcb_by_bd_addr(rem_bda, transport);
  if (p_lcb == NULL || p_lcb->link_state == LST_DISCONNECTING) {
    /* if link is disconnecting, also report data sending failure */
    LOG_WARN("Link is disconnecting or does not exist CID: 0x%04x", fixed_cid);
    osi_free(p_buf);
    return (L2CAP_DW_FAILED);
  }

  tL2C_BLE_FIXED_CHNLS_MASK peer_channel_mask;

  // Select peer channels mask to use depending on transport
  if (transport == BT_TRANSPORT_LE)
    peer_channel_mask = l2cb.l2c_ble_fixed_chnls_mask;
  else
    peer_channel_mask = p_lcb->peer_chnl_mask[0];

  if ((peer_channel_mask & (1 << fixed_cid)) == 0) {
    LOG_WARN("Peer does not support fixed channel CID: 0x%04x", fixed_cid);
    osi_free(p_buf);
    return (L2CAP_DW_FAILED);
  }

  p_buf->event = 0;
  p_buf->layer_specific = L2CAP_FLUSHABLE_CH_BASED;

  if (!p_lcb->p_fixed_ccbs[fixed_cid - L2CAP_FIRST_FIXED_CHNL]) {
    if (!l2cu_initialize_fixed_ccb(p_lcb, fixed_cid)) {
      LOG_WARN("No channel control block found for CID: 0x%4x", fixed_cid);
      osi_free(p_buf);
      return (L2CAP_DW_FAILED);
    }
  }

  if (p_lcb->p_fixed_ccbs[fixed_cid - L2CAP_FIRST_FIXED_CHNL]->cong_sent) {
    LOG_WARN(
        "Unable to send data due to congestion CID: 0x%04x xmit_hold_q.count: "
        "%zu buff_quota: %u",
        fixed_cid,
        fixed_queue_length(
            p_lcb->p_fixed_ccbs[fixed_cid - L2CAP_FIRST_FIXED_CHNL]
                ->xmit_hold_q),
        p_lcb->p_fixed_ccbs[fixed_cid - L2CAP_FIRST_FIXED_CHNL]->buff_quota);
    osi_free(p_buf);
    return (L2CAP_DW_FAILED);
  }

  LOG_DEBUG("Enqueued data for CID: 0x%04x len:%hu", fixed_cid, p_buf->len);
  l2c_enqueue_peer_data(p_lcb->p_fixed_ccbs[fixed_cid - L2CAP_FIRST_FIXED_CHNL],
                        p_buf);

  l2c_link_check_send_pkts(p_lcb, 0, NULL);

  // If there is no dynamic CCB on the link, restart the idle timer each time
  // something is sent
  if (p_lcb->in_use && p_lcb->link_state == LST_CONNECTED &&
      !p_lcb->ccb_queue.p_first_ccb) {
    l2cu_no_dynamic_ccbs(p_lcb);
  }

  if (p_lcb->p_fixed_ccbs[fixed_cid - L2CAP_FIRST_FIXED_CHNL]->cong_sent) {
    LOG_DEBUG("Link congested for CID: 0x%04x", fixed_cid);
    return (L2CAP_DW_CONGESTED);
  }

  return (L2CAP_DW_SUCCESS);
}

/*******************************************************************************
 *
 *  Function        L2CA_RemoveFixedChnl
 *
 *  Description     Remove a fixed channel to a remote device.
 *
 *  Parameters:     Fixed CID
 *                  BD Address of remote
 *                  Idle timeout to use (or 0xFFFF if don't care)
 *
 *  Return value:   true if channel removed
 *
 ******************************************************************************/
bool L2CA_RemoveFixedChnl(uint16_t fixed_cid, const RawAddress& rem_bda) {
  if (bluetooth::shim::is_gd_l2cap_enabled()) {
    return bluetooth::shim::L2CA_RemoveFixedChnl(fixed_cid, rem_bda);
  }

  tL2C_LCB* p_lcb;
  tL2C_CCB* p_ccb;
  tBT_TRANSPORT transport = BT_TRANSPORT_BR_EDR;

  /* Check CID is valid and registered */
  if ((fixed_cid < L2CAP_FIRST_FIXED_CHNL) ||
      (fixed_cid > L2CAP_LAST_FIXED_CHNL) ||
      (l2cb.fixed_reg[fixed_cid - L2CAP_FIRST_FIXED_CHNL].pL2CA_FixedData_Cb ==
       NULL)) {
    L2CAP_TRACE_ERROR("L2CA_RemoveFixedChnl()  Invalid CID: 0x%04x", fixed_cid);
    return (false);
  }

  if (fixed_cid >= L2CAP_ATT_CID && fixed_cid <= L2CAP_SMP_CID)
    transport = BT_TRANSPORT_LE;

  /* Is a fixed channel connected to the remote BDA ?*/
  p_lcb = l2cu_find_lcb_by_bd_addr(rem_bda, transport);

  if (((p_lcb) == NULL) ||
      (!p_lcb->p_fixed_ccbs[fixed_cid - L2CAP_FIRST_FIXED_CHNL])) {
    LOG(WARNING) << __func__ << " BDA: " << rem_bda
                 << StringPrintf(" CID: 0x%04x not connected", fixed_cid);
    return (false);
  }

  VLOG(2) << __func__ << " BDA: " << rem_bda
          << StringPrintf(" CID: 0x%04x", fixed_cid);

  /* Release the CCB, starting an inactivity timeout on the LCB if no other CCBs
   * exist */
  p_ccb = p_lcb->p_fixed_ccbs[fixed_cid - L2CAP_FIRST_FIXED_CHNL];

  p_lcb->p_fixed_ccbs[fixed_cid - L2CAP_FIRST_FIXED_CHNL] = NULL;
  p_lcb->SetDisconnectReason(HCI_ERR_CONN_CAUSE_LOCAL_HOST);

  // Retain the link for a few more seconds after SMP pairing is done, since
  // the Android platform always does service discovery after pairing is
  // complete. This will avoid the link down (pairing is complete) and an
  // immediate re-connection for service discovery.
  // Some devices do not do auto advertising when link is dropped, thus fail
  // the second connection and service discovery.
  if ((fixed_cid == L2CAP_ATT_CID) && !p_lcb->ccb_queue.p_first_ccb)
    p_lcb->idle_timeout = 0;

  l2cu_release_ccb(p_ccb);

  return (true);
}

/*******************************************************************************
 *
 * Function         L2CA_SetLeGattTimeout
 *
 * Description      Higher layers call this function to set the idle timeout for
 *                  a fixed channel. The "idle timeout" is the amount of time
 *                  that a connection can remain up with no L2CAP channels on
 *                  it. A timeout of zero means that the connection will be torn
 *                  down immediately when the last channel is removed.
 *                  A timeout of 0xFFFF means no timeout. Values are in seconds.
 *                  A bd_addr is the remote BD address.
 *
 * Returns          true if command succeeded, false if failed
 *
 ******************************************************************************/
bool L2CA_SetLeGattTimeout(const RawAddress& rem_bda, uint16_t idle_tout) {
  if (bluetooth::shim::is_gd_l2cap_enabled()) {
    return bluetooth::shim::L2CA_SetLeGattTimeout(rem_bda, idle_tout);
  }

  constexpr uint16_t kAttCid = 4;

  /* Is a fixed channel connected to the remote BDA ?*/
  tL2C_LCB* p_lcb = l2cu_find_lcb_by_bd_addr(rem_bda, BT_TRANSPORT_LE);
  if (((p_lcb) == NULL) ||
      (!p_lcb->p_fixed_ccbs[kAttCid - L2CAP_FIRST_FIXED_CHNL])) {
    LOG(WARNING) << __func__ << " BDA: " << rem_bda
                 << StringPrintf(" CID: 0x%04x not connected", kAttCid);
    return (false);
  }

  p_lcb->p_fixed_ccbs[kAttCid - L2CAP_FIRST_FIXED_CHNL]->fixed_chnl_idle_tout =
      idle_tout;

  if (p_lcb->in_use && p_lcb->link_state == LST_CONNECTED &&
      !p_lcb->ccb_queue.p_first_ccb) {
    /* If there are no dynamic CCBs, (re)start the idle timer in case we changed
     * it */
    l2cu_no_dynamic_ccbs(p_lcb);
  }

  return true;
}

/*******************************************************************************
 *
 * Function         L2CA_DataWrite
 *
 * Description      Higher layers call this function to write data.
 *
 * Returns          L2CAP_DW_SUCCESS, if data accepted, else false
 *                  L2CAP_DW_CONGESTED, if data accepted and the channel is
 *                                      congested
 *                  L2CAP_DW_FAILED, if error
 *
 ******************************************************************************/
uint8_t L2CA_DataWrite(uint16_t cid, BT_HDR* p_data) {
  if (bluetooth::shim::is_gd_l2cap_enabled()) {
    return bluetooth::shim::L2CA_DataWrite(cid, p_data);
  }

  L2CAP_TRACE_API("L2CA_DataWrite()  CID: 0x%04x  Len: %d", cid, p_data->len);
  return l2c_data_write(cid, p_data, L2CAP_FLUSHABLE_CH_BASED);
}

uint8_t L2CA_LECocDataWrite(uint16_t cid, BT_HDR* p_data) {
  if (bluetooth::shim::is_gd_l2cap_enabled()) {
    return bluetooth::shim::L2CA_LECocDataWrite(cid, p_data);
  }

  return L2CA_DataWrite(cid, p_data);
}

/*******************************************************************************
 *
 * Function         L2CA_SetChnlFlushability
 *
 * Description      Higher layers call this function to set a channels
 *                  flushability flags
 *
 * Returns          true if CID found, else false
 *
 ******************************************************************************/
bool L2CA_SetChnlFlushability(uint16_t cid, bool is_flushable) {
  if (bluetooth::shim::is_gd_l2cap_enabled()) {
    return bluetooth::shim::L2CA_SetChnlFlushability(cid, is_flushable);
  }

  tL2C_CCB* p_ccb;

  /* Find the channel control block. We don't know the link it is on. */
  p_ccb = l2cu_find_ccb_by_cid(NULL, cid);
  if (p_ccb == NULL) {
    L2CAP_TRACE_WARNING("L2CAP - no CCB for L2CA_SetChnlFlushability, CID: %d",
                        cid);
    return (false);
  }

  p_ccb->is_flushable = is_flushable;

  L2CAP_TRACE_API("L2CA_SetChnlFlushability()  CID: 0x%04x  is_flushable: %d",
                  cid, is_flushable);

  return (true);
}

/*******************************************************************************
 *
 * Function     L2CA_FlushChannel
 *
 * Description  This function flushes none, some or all buffers queued up
 *              for xmission for a particular CID. If called with
 *              L2CAP_FLUSH_CHANS_GET (0), it simply returns the number
 *              of buffers queued for that CID L2CAP_FLUSH_CHANS_ALL (0xffff)
 *              flushes all buffers.  All other values specifies the maximum
 *              buffers to flush.
 *
 * Returns      Number of buffers left queued for that CID
 *
 ******************************************************************************/
uint16_t L2CA_FlushChannel(uint16_t lcid, uint16_t num_to_flush) {
  if (bluetooth::shim::is_gd_l2cap_enabled()) {
    return bluetooth::shim::L2CA_FlushChannel(lcid, num_to_flush);
  }

  tL2C_CCB* p_ccb;
  tL2C_LCB* p_lcb;
  uint16_t num_left = 0, num_flushed1 = 0, num_flushed2 = 0;

  p_ccb = l2cu_find_ccb_by_cid(NULL, lcid);

  if (!p_ccb || (p_ccb->p_lcb == NULL)) {
    L2CAP_TRACE_WARNING(
        "L2CA_FlushChannel()  abnormally returning 0  CID: 0x%04x", lcid);
    return (0);
  }
  p_lcb = p_ccb->p_lcb;

  if (num_to_flush != L2CAP_FLUSH_CHANS_GET) {
    L2CAP_TRACE_API(
        "L2CA_FlushChannel (FLUSH)  CID: 0x%04x  NumToFlush: %d  QC: %u  "
        "pFirst: 0x%08x",
        lcid, num_to_flush, fixed_queue_length(p_ccb->xmit_hold_q),
        fixed_queue_try_peek_first(p_ccb->xmit_hold_q));
  } else {
    L2CAP_TRACE_API("L2CA_FlushChannel (QUERY)  CID: 0x%04x", lcid);
  }

  /* Cannot flush eRTM buffers once they have a sequence number */
  if (p_ccb->peer_cfg.fcr.mode != L2CAP_FCR_ERTM_MODE) {
    const controller_t* controller = controller_get_interface();
    if (num_to_flush != L2CAP_FLUSH_CHANS_GET) {
      /* If the controller supports enhanced flush, flush the data queued at the
       * controller */
      if (controller->supports_non_flushable_pb() &&
          (BTM_GetNumScoLinks() == 0)) {
        /* The only packet type defined - 0 - Automatically-Flushable Only */
        btsnd_hcic_enhanced_flush(p_lcb->Handle(), 0);
      }
    }

    // Iterate though list and flush the amount requested from
    // the transmit data queue that satisfy the layer and event conditions.
    for (const list_node_t* node = list_begin(p_lcb->link_xmit_data_q);
         (num_to_flush > 0) && node != list_end(p_lcb->link_xmit_data_q);) {
      BT_HDR* p_buf = (BT_HDR*)list_node(node);
      node = list_next(node);
      if ((p_buf->layer_specific == 0) && (p_buf->event == lcid)) {
        num_to_flush--;
        num_flushed1++;

        list_remove(p_lcb->link_xmit_data_q, p_buf);
        osi_free(p_buf);
      }
    }
  }

  /* If needed, flush buffers in the CCB xmit hold queue */
  while ((num_to_flush != 0) && (!fixed_queue_is_empty(p_ccb->xmit_hold_q))) {
    BT_HDR* p_buf = (BT_HDR*)fixed_queue_try_dequeue(p_ccb->xmit_hold_q);
    osi_free(p_buf);
    num_to_flush--;
    num_flushed2++;
  }

  /* If app needs to track all packets, call it */
  if ((p_ccb->p_rcb) && (p_ccb->p_rcb->api.pL2CA_TxComplete_Cb) &&
      (num_flushed2))
    (*p_ccb->p_rcb->api.pL2CA_TxComplete_Cb)(p_ccb->local_cid, num_flushed2);

  /* Now count how many are left */
  for (const list_node_t* node = list_begin(p_lcb->link_xmit_data_q);
       node != list_end(p_lcb->link_xmit_data_q); node = list_next(node)) {
    BT_HDR* p_buf = (BT_HDR*)list_node(node);
    if (p_buf->event == lcid) num_left++;
  }

  /* Add in the number in the CCB xmit queue */
  num_left += fixed_queue_length(p_ccb->xmit_hold_q);

  /* Return the local number of buffers left for the CID */
  L2CAP_TRACE_DEBUG("L2CA_FlushChannel()  flushed: %u + %u,  num_left: %u",
                    num_flushed1, num_flushed2, num_left);

  /* If we were congested, and now we are not, tell the app */
  l2cu_check_channel_congestion(p_ccb);

  return (num_left);
}

bool L2CA_IsLinkEstablished(const RawAddress& bd_addr,
                            tBT_TRANSPORT transport) {
  if (bluetooth::shim::is_gd_l2cap_enabled()) {
    return bluetooth::shim::L2CA_IsLinkEstablished(bd_addr, transport);
  }

  return l2cu_find_lcb_by_bd_addr(bd_addr, transport) != nullptr;
}
