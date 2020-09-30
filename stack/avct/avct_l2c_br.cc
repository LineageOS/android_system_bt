/******************************************************************************
 *
 *  Copyright 2008-2016 Broadcom Corporation
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

/*****************************************************************************
 *
 *  Name:           avct_l2c_br.cc
 *
 *  Description:    This AVCTP module interfaces to L2CAP
 *
 *****************************************************************************/

#include "avct_api.h"
#include "avct_int.h"
#include "bt_target.h"
#include "l2c_api.h"
#include "l2cdefs.h"
#include "osi/include/osi.h"

/* callback function declarations */
void avct_l2c_br_connect_ind_cback(const RawAddress& bd_addr, uint16_t lcid,
                                   uint16_t psm, uint8_t id);
void avct_l2c_br_connect_cfm_cback(uint16_t lcid, uint16_t result);
void avct_l2c_br_config_cfm_cback(uint16_t lcid, uint16_t result,
                                  tL2CAP_CFG_INFO* p_cfg);
void avct_l2c_br_config_ind_cback(uint16_t lcid, tL2CAP_CFG_INFO* p_cfg);
void avct_l2c_br_disconnect_ind_cback(uint16_t lcid, bool ack_needed);
void avct_l2c_br_congestion_ind_cback(uint16_t lcid, bool is_congested);
void avct_l2c_br_data_ind_cback(uint16_t lcid, BT_HDR* p_buf);
void avct_br_on_l2cap_error(uint16_t lcid, uint16_t result);

/* L2CAP callback function structure */
const tL2CAP_APPL_INFO avct_l2c_br_appl = {
    avct_l2c_br_connect_ind_cback,    avct_l2c_br_connect_cfm_cback,
    avct_l2c_br_config_ind_cback,     avct_l2c_br_config_cfm_cback,
    avct_l2c_br_disconnect_ind_cback, avct_l2c_br_data_ind_cback,
    avct_l2c_br_congestion_ind_cback, NULL,
    avct_br_on_l2cap_error,
};

/*******************************************************************************
 *
 * Function         avct_l2c_br_connect_ind_cback
 *
 * Description      This is the L2CAP connect indication callback function.
 *
 *
 * Returns          void
 *
 ******************************************************************************/
void avct_l2c_br_connect_ind_cback(const RawAddress& bd_addr, uint16_t lcid,
                                   UNUSED_ATTR uint16_t psm, uint8_t id) {
  tAVCT_LCB* p_lcb;
  uint16_t result = L2CAP_CONN_NO_RESOURCES;
  tAVCT_BCB* p_bcb;
  tL2CAP_ERTM_INFO ertm_info;

  p_lcb = avct_lcb_by_bd(bd_addr);
  if (p_lcb != NULL) {
    /* control channel exists */
    p_bcb = avct_bcb_by_lcb(p_lcb);
    p_bcb->peer_addr = bd_addr;

    if (p_bcb->allocated == 0) {
      /* browsing channel does not exist yet and the browsing channel is
       * registered
       * - accept connection */
      p_bcb->allocated = p_lcb->allocated; /* copy the index from lcb */

      result = L2CAP_CONN_OK;
    }
  }
  /* else no control channel yet, reject */

  /* Set the FCR options: Browsing channel mandates ERTM */
  ertm_info.preferred_mode = L2CAP_FCR_ERTM_MODE;

  /* If we reject the connection, send DisconnectReq */
  if (result != L2CAP_CONN_OK) {
    L2CA_DisconnectReq(lcid);
  }

  /* if result ok, proceed with connection */
  if (result == L2CAP_CONN_OK) {
    /* store LCID */
    p_bcb->ch_lcid = lcid;

    /* transition to configuration state */
    p_bcb->ch_state = AVCT_CH_CFG;
  }
}

void avct_br_on_l2cap_error(uint16_t lcid, uint16_t result) {
  tAVCT_BCB* p_lcb = avct_bcb_by_lcid(lcid);
  if (p_lcb == nullptr) return;

  /* store result value */
  p_lcb->ch_result = result;

  /* Send L2CAP disconnect req */
  avct_l2c_br_disconnect(lcid, 0);
}

/*******************************************************************************
 *
 * Function         avct_l2c_br_connect_cfm_cback
 *
 * Description      This is the L2CAP connect confirm callback function.
 *
 *
 * Returns          void
 *
 ******************************************************************************/
void avct_l2c_br_connect_cfm_cback(uint16_t lcid, uint16_t result) {
  tAVCT_BCB* p_lcb;

  /* look up lcb for this channel */
  p_lcb = avct_bcb_by_lcid(lcid);
  if ((p_lcb == NULL) || (p_lcb->ch_state != AVCT_CH_CONN)) return;

  if (result != L2CAP_CONN_OK) {
    LOG(ERROR) << __func__ << ": invoked with non OK status";
    return;
  }

  /* result is successful */
  /* set channel state */
  p_lcb->ch_state = AVCT_CH_CFG;
}

/*******************************************************************************
 *
 * Function         avct_l2c_br_config_cfm_cback
 *
 * Description      This is the L2CAP config confirm callback function.
 *
 *
 * Returns          void
 *
 ******************************************************************************/
void avct_l2c_br_config_cfm_cback(uint16_t lcid, uint16_t initiator,
                                  tL2CAP_CFG_INFO* p_cfg) {
  avct_l2c_br_config_ind_cback(lcid, p_cfg);

  tAVCT_BCB* p_lcb;

  /* look up lcb for this channel */
  p_lcb = avct_bcb_by_lcid(lcid);
  if ((p_lcb == NULL) || (p_lcb->ch_state != AVCT_CH_CFG)) return;

  p_lcb->ch_state = AVCT_CH_OPEN;
  avct_bcb_event(p_lcb, AVCT_LCB_LL_OPEN_EVT, NULL);
}

/*******************************************************************************
 *
 * Function         avct_l2c_br_config_ind_cback
 *
 * Description      This is the L2CAP config indication callback function.
 *
 *
 * Returns          void
 *
 ******************************************************************************/
void avct_l2c_br_config_ind_cback(uint16_t lcid, tL2CAP_CFG_INFO* p_cfg) {
  tAVCT_BCB* p_lcb;
  uint16_t max_mtu = BT_DEFAULT_BUFFER_SIZE - L2CAP_MIN_OFFSET - BT_HDR_SIZE;

  /* look up lcb for this channel */
  p_lcb = avct_bcb_by_lcid(lcid);
  if (p_lcb == NULL) return;

  /* store the mtu in tbl */
  p_lcb->peer_mtu = L2CAP_DEFAULT_MTU;
  if (p_cfg->mtu_present) {
    p_lcb->peer_mtu = p_cfg->mtu;
  }

  if (p_lcb->peer_mtu > max_mtu) {
    p_lcb->peer_mtu = max_mtu;
  }

  AVCT_TRACE_DEBUG("%s peer_mtu:%d use:%d", __func__, p_lcb->peer_mtu, max_mtu);
}

/*******************************************************************************
 *
 * Function         avct_l2c_br_disconnect_ind_cback
 *
 * Description      This is the L2CAP disconnect indication callback function.
 *
 *
 * Returns          void
 *
 ******************************************************************************/
void avct_l2c_br_disconnect_ind_cback(uint16_t lcid, bool ack_needed) {
  tAVCT_BCB* p_lcb;
  uint16_t result = AVCT_RESULT_FAIL;

  /* look up lcb for this channel */
  p_lcb = avct_bcb_by_lcid(lcid);
  if (p_lcb == NULL) return;

  tAVCT_LCB_EVT avct_lcb_evt;
  avct_lcb_evt.result = result;
  avct_bcb_event(p_lcb, AVCT_LCB_LL_CLOSE_EVT, &avct_lcb_evt);
}

void avct_l2c_br_disconnect(uint16_t lcid, uint16_t result) {
  L2CA_DisconnectReq(lcid);

  tAVCT_BCB* p_lcb;
  uint16_t res;

  /* look up lcb for this channel */
  p_lcb = avct_bcb_by_lcid(lcid);
  if (p_lcb == NULL) return;

  /* result value may be previously stored */
  res = (p_lcb->ch_result != 0) ? p_lcb->ch_result : result;
  p_lcb->ch_result = 0;

  tAVCT_LCB_EVT avct_lcb_evt;
  avct_lcb_evt.result = res;
  avct_bcb_event(p_lcb, AVCT_LCB_LL_CLOSE_EVT, &avct_lcb_evt);
}

/*******************************************************************************
 *
 * Function         avct_l2c_br_congestion_ind_cback
 *
 * Description      This is the L2CAP congestion indication callback function.
 *
 *
 * Returns          void
 *
 ******************************************************************************/
void avct_l2c_br_congestion_ind_cback(uint16_t lcid, bool is_congested) {
  tAVCT_BCB* p_lcb;

  /* look up lcb for this channel */
  p_lcb = avct_bcb_by_lcid(lcid);
  if (p_lcb == NULL) return;

  tAVCT_LCB_EVT avct_lcb_evt;
  avct_lcb_evt.cong = is_congested;
  avct_bcb_event(p_lcb, AVCT_LCB_LL_CONG_EVT, &avct_lcb_evt);
}

/*******************************************************************************
 *
 * Function         avct_l2c_br_data_ind_cback
 *
 * Description      This is the L2CAP data indication callback function.
 *
 *
 * Returns          void
 *
 ******************************************************************************/
void avct_l2c_br_data_ind_cback(uint16_t lcid, BT_HDR* p_buf) {
  tAVCT_BCB* p_lcb;
  tAVCT_LCB_EVT evt_data;

  /* look up lcb for this channel */
  p_lcb = avct_bcb_by_lcid(lcid);
  if (p_lcb == NULL) {
    /* prevent buffer leak */
    osi_free(p_buf);
    return;
  }

  evt_data.p_buf = p_buf;
  avct_bcb_event(p_lcb, AVCT_LCB_LL_MSG_EVT, &evt_data);
}
