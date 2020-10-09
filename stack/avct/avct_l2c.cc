/******************************************************************************
 *
 *  Copyright 2003-2012 Broadcom Corporation
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
 *  This AVCTP module interfaces to L2CAP
 *
 ******************************************************************************/

#include "avct_api.h"
#include "avct_int.h"
#include "bt_target.h"
#include "bt_types.h"
#include "l2c_api.h"
#include "l2cdefs.h"
#include "osi/include/osi.h"

/* callback function declarations */
void avct_l2c_connect_ind_cback(const RawAddress& bd_addr, uint16_t lcid,
                                uint16_t psm, uint8_t id);
void avct_l2c_connect_cfm_cback(uint16_t lcid, uint16_t result);
void avct_l2c_config_cfm_cback(uint16_t lcid, uint16_t result,
                               tL2CAP_CFG_INFO* p_cfg);
void avct_l2c_config_ind_cback(uint16_t lcid, tL2CAP_CFG_INFO* p_cfg);
void avct_l2c_disconnect_ind_cback(uint16_t lcid, bool ack_needed);
void avct_l2c_congestion_ind_cback(uint16_t lcid, bool is_congested);
void avct_l2c_data_ind_cback(uint16_t lcid, BT_HDR* p_buf);
static void avct_on_l2cap_error(uint16_t lcid, uint16_t result);

/* L2CAP callback function structure */
const tL2CAP_APPL_INFO avct_l2c_appl = {
    avct_l2c_connect_ind_cback,    avct_l2c_connect_cfm_cback,
    avct_l2c_config_ind_cback,     avct_l2c_config_cfm_cback,
    avct_l2c_disconnect_ind_cback, avct_l2c_data_ind_cback,
    avct_l2c_congestion_ind_cback, NULL,
    avct_on_l2cap_error,           NULL,
    NULL,                          NULL,
};

/*******************************************************************************
 *
 * Function         avct_l2c_is_passive
 *
 * Description      check is the CCB associated with the given LCB was created
 *                  as passive
 *
 * Returns          true, if the given LCB is created as AVCT_PASSIVE
 *
 ******************************************************************************/
static bool avct_l2c_is_passive(tAVCT_LCB* p_lcb) {
  bool is_passive = false;
  tAVCT_CCB* p_ccb = &avct_cb.ccb[0];
  int i;

  for (i = 0; i < AVCT_NUM_CONN; i++, p_ccb++) {
    if (p_ccb->allocated && (p_ccb->p_lcb == p_lcb)) {
      AVCT_TRACE_DEBUG("avct_l2c_is_ct control:x%x", p_ccb->cc.control);
      if (p_ccb->cc.control & AVCT_PASSIVE) {
        is_passive = true;
        break;
      }
    }
  }
  return is_passive;
}

/*******************************************************************************
 *
 * Function         avct_l2c_connect_ind_cback
 *
 * Description      This is the L2CAP connect indication callback function.
 *
 *
 * Returns          void
 *
 ******************************************************************************/
void avct_l2c_connect_ind_cback(const RawAddress& bd_addr, uint16_t lcid,
                                UNUSED_ATTR uint16_t psm, uint8_t id) {
  tAVCT_LCB* p_lcb;
  uint16_t result = L2CAP_CONN_OK;

  /* do we already have a channel for this peer? */
  p_lcb = avct_lcb_by_bd(bd_addr);
  if (p_lcb == NULL) {
    /* no, allocate lcb */
    p_lcb = avct_lcb_alloc(bd_addr);
    if (p_lcb == NULL) {
      /* no ccb available, reject L2CAP connection */
      result = L2CAP_CONN_NO_RESOURCES;
    }
  }
  /* else we already have a channel for this peer */
  else {
    if (!avct_l2c_is_passive(p_lcb) || (p_lcb->ch_state == AVCT_CH_OPEN)) {
      /* this LCB included CT role - reject */
      result = L2CAP_CONN_NO_RESOURCES;
    } else {
      /* TG role only - accept the connection from CT. move the channel ID to
       * the conflict list */
      p_lcb->conflict_lcid = p_lcb->ch_lcid;
      AVCT_TRACE_DEBUG("avct_l2c_connect_ind_cback conflict_lcid:0x%x",
                       p_lcb->conflict_lcid);
    }
  }

  if (p_lcb) {
    AVCT_TRACE_DEBUG("avct_l2c_connect_ind_cback: 0x%x, res: %d, ch_state: %d",
                     lcid, result, p_lcb->ch_state);
  }

  /* If we reject the connection, send DisconnectReq */
  if (result != L2CAP_CONN_OK) {
    L2CA_DisconnectReq(lcid);
  }

  /* if result ok, proceed with connection */
  if (result == L2CAP_CONN_OK) {
    /* store LCID */
    p_lcb->ch_lcid = lcid;

    /* transition to configuration state */
    p_lcb->ch_state = AVCT_CH_CFG;
  }

  if (p_lcb) AVCT_TRACE_DEBUG("ch_state cni: %d ", p_lcb->ch_state);
}

static void avct_on_l2cap_error(uint16_t lcid, uint16_t result) {
  tAVCT_LCB* p_lcb = avct_lcb_by_lcid(lcid);
  if (p_lcb == nullptr) return;
  if (p_lcb->ch_state == AVCT_CH_CONN) {
    AVCT_TRACE_DEBUG("avct_l2c_connect_cfm_cback conflict_lcid:0x%x",
                     p_lcb->conflict_lcid);
    if (p_lcb->conflict_lcid == lcid) {
      p_lcb->conflict_lcid = 0;
    } else {
      tAVCT_LCB_EVT avct_lcb_evt;
      avct_lcb_evt.result = result;
      avct_lcb_event(p_lcb, AVCT_LCB_LL_CLOSE_EVT, &avct_lcb_evt);
    }
  } else if (p_lcb->ch_state == AVCT_CH_CFG) {
    AVCT_TRACE_DEBUG("ERROR avct_l2c_config_cfm_cback L2CA_DisconnectReq %d ",
                     p_lcb->ch_state);
    /* store result value */
    p_lcb->ch_result = result;

    /* Send L2CAP disconnect req */
    L2CA_DisconnectReq(lcid);
  }
}

/*******************************************************************************
 *
 * Function         avct_l2c_connect_cfm_cback
 *
 * Description      This is the L2CAP connect confirm callback function.
 *
 *
 * Returns          void
 *
 ******************************************************************************/
void avct_l2c_connect_cfm_cback(uint16_t lcid, uint16_t result) {
  tAVCT_LCB* p_lcb;

  /* look up lcb for this channel */
  p_lcb = avct_lcb_by_lcid(lcid);
  if (p_lcb != NULL) {
    AVCT_TRACE_DEBUG(
        "avct_l2c_connect_cfm_cback lcid:0x%x result: %d ch_state: %d, "
        "conflict_lcid:0x%x",
        lcid, result, p_lcb->ch_state, p_lcb->conflict_lcid);
    /* if in correct state */
    if (p_lcb->ch_state == AVCT_CH_CONN) {
      /* if result successful */
      if (result == L2CAP_CONN_OK) {
        /* set channel state */
        p_lcb->ch_state = AVCT_CH_CFG;
      }
      /* else failure */
      else {
        LOG(ERROR) << __func__ << ": invoked with non OK status";
      }
    } else if (p_lcb->conflict_lcid == lcid) {
      /* we must be in AVCT_CH_CFG state for the ch_lcid channel */
      AVCT_TRACE_DEBUG(
          "avct_l2c_connect_cfm_cback ch_state: %d, conflict_lcid:0x%x",
          p_lcb->ch_state, p_lcb->conflict_lcid);
      if (result == L2CAP_CONN_OK) {
        /* just in case the peer also accepts our connection - Send L2CAP
         * disconnect req */
        L2CA_DisconnectReq(lcid);
      }
      p_lcb->conflict_lcid = 0;
    }
    AVCT_TRACE_DEBUG("ch_state cnc: %d ", p_lcb->ch_state);
  }
}

/*******************************************************************************
 *
 * Function         avct_l2c_config_cfm_cback
 *
 * Description      This is the L2CAP config confirm callback function.
 *
 *
 * Returns          void
 *
 ******************************************************************************/
void avct_l2c_config_cfm_cback(uint16_t lcid, uint16_t initiator,
                               tL2CAP_CFG_INFO* p_cfg) {
  avct_l2c_config_ind_cback(lcid, p_cfg);

  tAVCT_LCB* p_lcb;

  /* look up lcb for this channel */
  p_lcb = avct_lcb_by_lcid(lcid);
  if (p_lcb != NULL) {
    AVCT_TRACE_DEBUG("avct_l2c_config_cfm_cback: 0x%x, ch_state: %d,", lcid,
                     p_lcb->ch_state);
    /* if in correct state */
    if (p_lcb->ch_state == AVCT_CH_CFG) {
      p_lcb->ch_state = AVCT_CH_OPEN;
      avct_lcb_event(p_lcb, AVCT_LCB_LL_OPEN_EVT, NULL);
    }
    AVCT_TRACE_DEBUG("ch_state cfc: %d ", p_lcb->ch_state);
  }
}

/*******************************************************************************
 *
 * Function         avct_l2c_config_ind_cback
 *
 * Description      This is the L2CAP config indication callback function.
 *
 *
 * Returns          void
 *
 ******************************************************************************/
void avct_l2c_config_ind_cback(uint16_t lcid, tL2CAP_CFG_INFO* p_cfg) {
  tAVCT_LCB* p_lcb;

  /* look up lcb for this channel */
  p_lcb = avct_lcb_by_lcid(lcid);
  if (p_lcb != NULL) {
    AVCT_TRACE_DEBUG("avct_l2c_config_ind_cback: 0x%x, ch_state: %d", lcid,
                     p_lcb->ch_state);
    /* store the mtu in tbl */
    if (p_cfg->mtu_present) {
      p_lcb->peer_mtu = p_cfg->mtu;
    } else {
      p_lcb->peer_mtu = L2CAP_DEFAULT_MTU;
    }
  }
}

/*******************************************************************************
 *
 * Function         avct_l2c_disconnect_ind_cback
 *
 * Description      This is the L2CAP disconnect indication callback function.
 *
 *
 * Returns          void
 *
 ******************************************************************************/
void avct_l2c_disconnect_ind_cback(uint16_t lcid, bool ack_needed) {
  tAVCT_LCB* p_lcb;
  uint16_t result = AVCT_RESULT_FAIL;

  /* look up lcb for this channel */
  p_lcb = avct_lcb_by_lcid(lcid);
  if (p_lcb != NULL) {
    AVCT_TRACE_DEBUG("avct_l2c_disconnect_ind_cback: 0x%x, ch_state: %d", lcid,
                     p_lcb->ch_state);
    tAVCT_LCB_EVT avct_lcb_evt;
    avct_lcb_evt.result = result;
    avct_lcb_event(p_lcb, AVCT_LCB_LL_CLOSE_EVT, &avct_lcb_evt);
    AVCT_TRACE_DEBUG("ch_state di: %d ", p_lcb->ch_state);
  }
}

void avct_l2c_disconnect(uint16_t lcid, uint16_t result) {
  L2CA_DisconnectReq(lcid);

  tAVCT_LCB* p_lcb;
  uint16_t res;

  /* look up lcb for this channel */
  p_lcb = avct_lcb_by_lcid(lcid);
  if (p_lcb != NULL) {
    AVCT_TRACE_DEBUG(
        "avct_l2c_disconnect_cfm_cback: 0x%x, ch_state: %d, res: %d", lcid,
        p_lcb->ch_state, result);
    /* result value may be previously stored */
    res = (p_lcb->ch_result != 0) ? p_lcb->ch_result : result;
    p_lcb->ch_result = 0;

    tAVCT_LCB_EVT avct_lcb_evt;
    avct_lcb_evt.result = res;
    avct_lcb_event(p_lcb, AVCT_LCB_LL_CLOSE_EVT, &avct_lcb_evt);
    AVCT_TRACE_DEBUG("ch_state dc: %d ", p_lcb->ch_state);
  }
}

/*******************************************************************************
 *
 * Function         avct_l2c_congestion_ind_cback
 *
 * Description      This is the L2CAP congestion indication callback function.
 *
 *
 * Returns          void
 *
 ******************************************************************************/
void avct_l2c_congestion_ind_cback(uint16_t lcid, bool is_congested) {
  tAVCT_LCB* p_lcb;

  AVCT_TRACE_DEBUG("avct_l2c_congestion_ind_cback: 0x%x", lcid);
  /* look up lcb for this channel */
  p_lcb = avct_lcb_by_lcid(lcid);
  if (p_lcb != NULL) {
    tAVCT_LCB_EVT avct_lcb_evt;
    avct_lcb_evt.cong = is_congested;
    avct_lcb_event(p_lcb, AVCT_LCB_LL_CONG_EVT, &avct_lcb_evt);
  }
}

/*******************************************************************************
 *
 * Function         avct_l2c_data_ind_cback
 *
 * Description      This is the L2CAP data indication callback function.
 *
 *
 * Returns          void
 *
 ******************************************************************************/
void avct_l2c_data_ind_cback(uint16_t lcid, BT_HDR* p_buf) {
  tAVCT_LCB* p_lcb;

  AVCT_TRACE_DEBUG("avct_l2c_data_ind_cback: 0x%x", lcid);
  /* look up lcb for this channel */
  p_lcb = avct_lcb_by_lcid(lcid);
  if (p_lcb != NULL) {
    avct_lcb_event(p_lcb, AVCT_LCB_LL_MSG_EVT, (tAVCT_LCB_EVT*)&p_buf);
  } else /* prevent buffer leak */
  {
    AVCT_TRACE_WARNING("ERROR -> avct_l2c_data_ind_cback drop buffer");
    osi_free(p_buf);
  }
}
