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
 *  This file contains the L2CAP channel state machine
 *
 ******************************************************************************/
#define LOG_TAG "l2c_csm"

#include <string>

#include "bt_common.h"
#include "bt_target.h"
#include "common/time_util.h"
#include "hcidefs.h"
#include "l2c_int.h"
#include "l2cdefs.h"
#include "osi/include/log.h"
#include "stack/btm/btm_sec.h"
#include "stack/include/acl_api.h"

/******************************************************************************/
/*            L O C A L    F U N C T I O N     P R O T O T Y P E S            */
/******************************************************************************/
static void l2c_csm_closed(tL2C_CCB* p_ccb, uint16_t event, void* p_data);
static void l2c_csm_orig_w4_sec_comp(tL2C_CCB* p_ccb, uint16_t event,
                                     void* p_data);
static void l2c_csm_term_w4_sec_comp(tL2C_CCB* p_ccb, uint16_t event,
                                     void* p_data);
static void l2c_csm_w4_l2cap_connect_rsp(tL2C_CCB* p_ccb, uint16_t event,
                                         void* p_data);
static void l2c_csm_w4_l2ca_connect_rsp(tL2C_CCB* p_ccb, uint16_t event,
                                        void* p_data);
static void l2c_csm_config(tL2C_CCB* p_ccb, uint16_t event, void* p_data);
static void l2c_csm_open(tL2C_CCB* p_ccb, uint16_t event, void* p_data);
static void l2c_csm_w4_l2cap_disconnect_rsp(tL2C_CCB* p_ccb, uint16_t event,
                                            void* p_data);
static void l2c_csm_w4_l2ca_disconnect_rsp(tL2C_CCB* p_ccb, uint16_t event,
                                           void* p_data);

static const char* l2c_csm_get_event_name(uint16_t event);

// Send a connect response with result OK and adjust the state machine
static void l2c_csm_send_connect_rsp(tL2C_CCB* p_ccb) {
  l2c_csm_execute(p_ccb, L2CEVT_L2CA_CONNECT_RSP, NULL);
}

// Send a config request and adjust the state machine
static void l2c_csm_send_config_req(tL2C_CCB* p_ccb) {
  tL2CAP_CFG_INFO config{};
  config.mtu_present = true;
  config.mtu = p_ccb->p_rcb->my_mtu;
  p_ccb->max_rx_mtu = config.mtu;
  if (p_ccb->p_rcb->ertm_info.preferred_mode != L2CAP_FCR_BASIC_MODE) {
    config.fcr_present = true;
    config.fcr = kDefaultErtmOptions;
  }
  p_ccb->our_cfg = config;
  l2c_csm_execute(p_ccb, L2CEVT_L2CA_CONFIG_REQ, &config);
}

// Send a config response with result OK and adjust the state machine
static void l2c_csm_send_config_rsp_ok(tL2C_CCB* p_ccb) {
  tL2CAP_CFG_INFO config{};
  config.result = L2CAP_CFG_OK;
  l2c_csm_execute(p_ccb, L2CEVT_L2CA_CONFIG_RSP, &config);
}

static void l2c_csm_send_disconnect_rsp(tL2C_CCB* p_ccb) {
  l2c_csm_execute(p_ccb, L2CEVT_L2CA_DISCONNECT_RSP, NULL);
}

static void l2c_csm_indicate_connection_open(tL2C_CCB* p_ccb) {
  if (p_ccb->connection_initiator == L2CAP_INITIATOR_LOCAL) {
    (*p_ccb->p_rcb->api.pL2CA_ConnectCfm_Cb)(p_ccb->local_cid, L2CAP_CONN_OK);
  } else {
    (*p_ccb->p_rcb->api.pL2CA_ConnectInd_Cb)(
        p_ccb->p_lcb->remote_bd_addr, p_ccb->local_cid, p_ccb->p_rcb->psm,
        p_ccb->remote_id);
  }
  if (p_ccb->chnl_state == CST_OPEN && !p_ccb->p_lcb->is_transport_ble()) {
    (*p_ccb->p_rcb->api.pL2CA_ConfigCfm_Cb)(
        p_ccb->local_cid, p_ccb->connection_initiator, &p_ccb->peer_cfg);
  }
}

static std::string channel_state_text(const tL2C_CHNL_STATE& state) {
  switch (state) {
    case CST_CLOSED: /* Channel is in closed state */
      return std::string("closed");
    case CST_ORIG_W4_SEC_COMP: /* Originator waits security clearence */
      return std::string("security pending(orig)");
    case CST_TERM_W4_SEC_COMP: /* Acceptor waits security clearence */
      return std::string("security pending(term)");
    case CST_W4_L2CAP_CONNECT_RSP: /* Waiting for peer connect response */
      return std::string("wait connect response from peer");
    case CST_W4_L2CA_CONNECT_RSP: /* Waiting for upper layer connect rsp */
      return std::string("wait connect response from upper");
    case CST_CONFIG: /* Negotiating configuration */
      return std::string("configuring");
    case CST_OPEN: /* Data transfer state */
      return std::string("open");
    case CST_W4_L2CAP_DISCONNECT_RSP: /* Waiting for peer disconnect rsp */
      return std::string("wait disconnect response from peer");
    case CST_W4_L2CA_DISCONNECT_RSP: /* Waiting for upper layer disc rsp */
      return std::string("wait disconnect response from upper");
  }
}

/*******************************************************************************
 *
 * Function         l2c_csm_execute
 *
 * Description      This function executes the state machine.
 *
 * Returns          void
 *
 ******************************************************************************/
void l2c_csm_execute(tL2C_CCB* p_ccb, uint16_t event, void* p_data) {
  if (!l2cu_is_ccb_active(p_ccb)) {
    LOG_WARN("CCB not in use, event (%d) cannot be processed", event);
    return;
  }

  LOG_DEBUG("Entry chnl_state=%s [%d], event=%s [%d]",
            channel_state_text(p_ccb->chnl_state).c_str(), p_ccb->chnl_state,
            l2c_csm_get_event_name(event), event);

  switch (p_ccb->chnl_state) {
    case CST_CLOSED:
      l2c_csm_closed(p_ccb, event, p_data);
      break;

    case CST_ORIG_W4_SEC_COMP:
      l2c_csm_orig_w4_sec_comp(p_ccb, event, p_data);
      break;

    case CST_TERM_W4_SEC_COMP:
      l2c_csm_term_w4_sec_comp(p_ccb, event, p_data);
      break;

    case CST_W4_L2CAP_CONNECT_RSP:
      l2c_csm_w4_l2cap_connect_rsp(p_ccb, event, p_data);
      break;

    case CST_W4_L2CA_CONNECT_RSP:
      l2c_csm_w4_l2ca_connect_rsp(p_ccb, event, p_data);
      break;

    case CST_CONFIG:
      l2c_csm_config(p_ccb, event, p_data);
      break;

    case CST_OPEN:
      l2c_csm_open(p_ccb, event, p_data);
      break;

    case CST_W4_L2CAP_DISCONNECT_RSP:
      l2c_csm_w4_l2cap_disconnect_rsp(p_ccb, event, p_data);
      break;

    case CST_W4_L2CA_DISCONNECT_RSP:
      l2c_csm_w4_l2ca_disconnect_rsp(p_ccb, event, p_data);
      break;

    default:
      LOG_ERROR("Unhandled state %d, event %d", p_ccb->chnl_state, event);
      break;
  }
}

/*******************************************************************************
 *
 * Function         l2c_csm_closed
 *
 * Description      This function handles events when the channel is in
 *                  CLOSED state. This state exists only when the link is
 *                  being initially established.
 *
 * Returns          void
 *
 ******************************************************************************/
static void l2c_csm_closed(tL2C_CCB* p_ccb, uint16_t event, void* p_data) {
  tL2C_CONN_INFO* p_ci = (tL2C_CONN_INFO*)p_data;
  uint16_t local_cid = p_ccb->local_cid;
  tL2CA_DISCONNECT_IND_CB* disconnect_ind;

  if (p_ccb->p_rcb == NULL) {
    LOG_ERROR("LCID: 0x%04x  st: CLOSED  evt: %s p_rcb == NULL",
              p_ccb->local_cid, l2c_csm_get_event_name(event));
    return;
  }

  disconnect_ind = p_ccb->p_rcb->api.pL2CA_DisconnectInd_Cb;

  LOG_DEBUG("LCID: 0x%04x  st: CLOSED  evt: %s", p_ccb->local_cid,
            l2c_csm_get_event_name(event));

  switch (event) {
    case L2CEVT_LP_DISCONNECT_IND: /* Link was disconnected */
      LOG_DEBUG("Calling Disconnect_Ind_Cb(), CID: 0x%04x  No Conf Needed",
                p_ccb->local_cid);
      l2cu_release_ccb(p_ccb);
      (*disconnect_ind)(local_cid, false);
      break;

    case L2CEVT_LP_CONNECT_CFM: /* Link came up         */
      if (p_ccb->p_lcb->transport == BT_TRANSPORT_LE) {
        p_ccb->chnl_state = CST_ORIG_W4_SEC_COMP;
        l2ble_sec_access_req(p_ccb->p_lcb->remote_bd_addr, p_ccb->p_rcb->psm,
                             true, &l2c_link_sec_comp2, p_ccb);
      } else {
        p_ccb->chnl_state = CST_ORIG_W4_SEC_COMP;
        btm_sec_l2cap_access_req(p_ccb->p_lcb->remote_bd_addr,
                                 p_ccb->p_rcb->psm, true, &l2c_link_sec_comp,
                                 p_ccb);
      }
      break;

    case L2CEVT_LP_CONNECT_CFM_NEG: /* Link failed          */
      if (p_ci->status == HCI_ERR_CONNECTION_EXISTS) {
        btm_acl_notif_conn_collision(p_ccb->p_lcb->remote_bd_addr);
      } else {
        l2cu_release_ccb(p_ccb);
        (*p_ccb->p_rcb->api.pL2CA_Error_Cb)(local_cid, L2CAP_CONN_OTHER_ERROR);
      }
      break;

    case L2CEVT_L2CA_CREDIT_BASED_CONNECT_REQ: /* API connect request  */
    case L2CEVT_L2CA_CONNECT_REQ:
      if (p_ccb->p_lcb->transport == BT_TRANSPORT_LE) {
        p_ccb->chnl_state = CST_ORIG_W4_SEC_COMP;
        l2ble_sec_access_req(p_ccb->p_lcb->remote_bd_addr, p_ccb->p_rcb->psm,
                             true, &l2c_link_sec_comp2, p_ccb);
      } else {
        if (!BTM_SetLinkPolicyActiveMode(p_ccb->p_lcb->remote_bd_addr)) {
          LOG_WARN("Unable to set link policy active");
        }
        /* If sec access does not result in started SEC_COM or COMP_NEG are
         * already processed */
        if (btm_sec_l2cap_access_req(
                p_ccb->p_lcb->remote_bd_addr, p_ccb->p_rcb->psm, true,
                &l2c_link_sec_comp, p_ccb) == BTM_CMD_STARTED) {
          p_ccb->chnl_state = CST_ORIG_W4_SEC_COMP;
        }
      }
      break;

    case L2CEVT_SEC_COMP:
      p_ccb->chnl_state = CST_W4_L2CAP_CONNECT_RSP;

      /* Wait for the info resp in this state before sending connect req (if
       * needed) */
      if (!p_ccb->p_lcb->w4_info_rsp) {
        /* Need to have at least one compatible channel to continue */
        if (!l2c_fcr_chk_chan_modes(p_ccb)) {
          l2cu_release_ccb(p_ccb);
          (*p_ccb->p_rcb->api.pL2CA_Error_Cb)(local_cid,
                                              L2CAP_CONN_OTHER_ERROR);
        } else {
          l2cu_send_peer_connect_req(p_ccb);
          alarm_set_on_mloop(p_ccb->l2c_ccb_timer,
                             L2CAP_CHNL_CONNECT_TIMEOUT_MS,
                             l2c_ccb_timer_timeout, p_ccb);
        }
      }
      break;

    case L2CEVT_SEC_COMP_NEG: /* something is really bad with security */
      l2cu_release_ccb(p_ccb);
      (*p_ccb->p_rcb->api.pL2CA_Error_Cb)(local_cid, L2CAP_CONN_OTHER_ERROR);
      break;

    case L2CEVT_L2CAP_CREDIT_BASED_CONNECT_REQ: /* Peer connect request */
    case L2CEVT_L2CAP_CONNECT_REQ:
      /* stop link timer to avoid race condition between A2MP, Security, and
       * L2CAP */
      alarm_cancel(p_ccb->p_lcb->l2c_lcb_timer);

      if (p_ccb->p_lcb->transport == BT_TRANSPORT_LE) {
        p_ccb->chnl_state = CST_TERM_W4_SEC_COMP;
        tL2CAP_LE_RESULT_CODE result = l2ble_sec_access_req(
            p_ccb->p_lcb->remote_bd_addr, p_ccb->p_rcb->psm, false,
            &l2c_link_sec_comp2, p_ccb);

        switch (result) {
          case L2CAP_LE_RESULT_INSUFFICIENT_AUTHORIZATION:
          case L2CAP_LE_RESULT_UNACCEPTABLE_PARAMETERS:
          case L2CAP_LE_RESULT_INVALID_PARAMETERS:
          case L2CAP_LE_RESULT_INSUFFICIENT_AUTHENTICATION:
          case L2CAP_LE_RESULT_INSUFFICIENT_ENCRYP_KEY_SIZE:
          case L2CAP_LE_RESULT_INSUFFICIENT_ENCRYP:
            l2cu_reject_ble_connection(p_ccb, p_ccb->remote_id, result);
            l2cu_release_ccb(p_ccb);
            break;
          case L2CAP_LE_RESULT_CONN_OK:
          case L2CAP_LE_RESULT_NO_PSM:
          case L2CAP_LE_RESULT_NO_RESOURCES:
          case L2CAP_LE_RESULT_INVALID_SOURCE_CID:
          case L2CAP_LE_RESULT_SOURCE_CID_ALREADY_ALLOCATED:
            break;
        }
      } else {
        if (!BTM_SetLinkPolicyActiveMode(p_ccb->p_lcb->remote_bd_addr)) {
          LOG_WARN("Unable to set link policy active");
        }
        p_ccb->chnl_state = CST_TERM_W4_SEC_COMP;
        auto status = btm_sec_l2cap_access_req(p_ccb->p_lcb->remote_bd_addr,
                                               p_ccb->p_rcb->psm, false,
                                               &l2c_link_sec_comp, p_ccb);
        if (status == BTM_CMD_STARTED) {
          // started the security process, tell the peer to set a longer timer
          l2cu_send_peer_connect_rsp(p_ccb, L2CAP_CONN_PENDING, 0);
        } else {
          LOG_INFO("Check security for psm 0x%04x, status %d",
                   p_ccb->p_rcb->psm, status);
        }
      }
      break;

    case L2CEVT_TIMEOUT:
      l2cu_release_ccb(p_ccb);
      (*p_ccb->p_rcb->api.pL2CA_Error_Cb)(local_cid, L2CAP_CONN_OTHER_ERROR);
      break;

    case L2CEVT_L2CAP_DATA:      /* Peer data packet rcvd    */
    case L2CEVT_L2CA_DATA_WRITE: /* Upper layer data to send */
      osi_free(p_data);
      break;

    case L2CEVT_L2CA_DISCONNECT_REQ: /* Upper wants to disconnect */
      l2cu_release_ccb(p_ccb);
      break;
  }
  LOG_DEBUG("Exit chnl_state=%s [%d], event=%s [%d]",
            channel_state_text(p_ccb->chnl_state).c_str(), p_ccb->chnl_state,
            l2c_csm_get_event_name(event), event);
}

/*******************************************************************************
 *
 * Function         l2c_csm_orig_w4_sec_comp
 *
 * Description      This function handles events when the channel is in
 *                  CST_ORIG_W4_SEC_COMP state.
 *
 * Returns          void
 *
 ******************************************************************************/
static void l2c_csm_orig_w4_sec_comp(tL2C_CCB* p_ccb, uint16_t event,
                                     void* p_data) {
  tL2CA_DISCONNECT_IND_CB* disconnect_ind =
      p_ccb->p_rcb->api.pL2CA_DisconnectInd_Cb;
  uint16_t local_cid = p_ccb->local_cid;

  LOG_DEBUG("%s - LCID: 0x%04x  st: ORIG_W4_SEC_COMP  evt: %s",
            ((p_ccb->p_lcb) && (p_ccb->p_lcb->transport == BT_TRANSPORT_LE))
                ? "LE "
                : "",
            p_ccb->local_cid, l2c_csm_get_event_name(event));

  switch (event) {
    case L2CEVT_LP_DISCONNECT_IND: /* Link was disconnected */
      LOG_DEBUG("Calling Disconnect_Ind_Cb(), CID: 0x%04x  No Conf Needed",
                p_ccb->local_cid);
      l2cu_release_ccb(p_ccb);
      (*disconnect_ind)(local_cid, false);
      break;

    case L2CEVT_SEC_RE_SEND_CMD: /* BTM has enough info to proceed */
    case L2CEVT_LP_CONNECT_CFM:  /* Link came up         */
      if (p_ccb->p_lcb->transport == BT_TRANSPORT_LE) {
        l2ble_sec_access_req(p_ccb->p_lcb->remote_bd_addr, p_ccb->p_rcb->psm,
                             false, &l2c_link_sec_comp2, p_ccb);
      } else {
        btm_sec_l2cap_access_req(p_ccb->p_lcb->remote_bd_addr,
                                 p_ccb->p_rcb->psm, true, &l2c_link_sec_comp,
                                 p_ccb);
      }
      break;

    case L2CEVT_SEC_COMP: /* Security completed success */
      /* Wait for the info resp in this state before sending connect req (if
       * needed) */
      p_ccb->chnl_state = CST_W4_L2CAP_CONNECT_RSP;
      if (p_ccb->p_lcb->transport == BT_TRANSPORT_LE) {
        alarm_set_on_mloop(p_ccb->l2c_ccb_timer, L2CAP_CHNL_CONNECT_TIMEOUT_MS,
                           l2c_ccb_timer_timeout, p_ccb);
        l2cble_credit_based_conn_req(p_ccb); /* Start Connection     */
      } else {
        if (!p_ccb->p_lcb->w4_info_rsp) {
          /* Need to have at least one compatible channel to continue */
          if (!l2c_fcr_chk_chan_modes(p_ccb)) {
            l2cu_release_ccb(p_ccb);
            (*p_ccb->p_rcb->api.pL2CA_Error_Cb)(local_cid,
                                                L2CAP_CONN_OTHER_ERROR);
          } else {
            alarm_set_on_mloop(p_ccb->l2c_ccb_timer,
                               L2CAP_CHNL_CONNECT_TIMEOUT_MS,
                               l2c_ccb_timer_timeout, p_ccb);
            l2cu_send_peer_connect_req(p_ccb); /* Start Connection     */
          }
        }
      }
      break;

    case L2CEVT_SEC_COMP_NEG:
      /* If last channel immediately disconnect the ACL for better security.
         Also prevents a race condition between BTM and L2CAP */
      if ((p_ccb == p_ccb->p_lcb->ccb_queue.p_first_ccb) &&
          (p_ccb == p_ccb->p_lcb->ccb_queue.p_last_ccb)) {
        p_ccb->p_lcb->idle_timeout = 0;
      }

      l2cu_release_ccb(p_ccb);
      (*p_ccb->p_rcb->api.pL2CA_Error_Cb)(local_cid, L2CAP_CONN_OTHER_ERROR);
      break;

    case L2CEVT_L2CA_DATA_WRITE: /* Upper layer data to send */
    case L2CEVT_L2CAP_DATA:      /* Peer data packet rcvd    */
      osi_free(p_data);
      break;

    case L2CEVT_L2CA_DISCONNECT_REQ: /* Upper wants to disconnect */
      /* Tell security manager to abort */
      btm_sec_abort_access_req(p_ccb->p_lcb->remote_bd_addr);

      l2cu_release_ccb(p_ccb);
      break;
  }
  LOG_DEBUG("Exit chnl_state=%s [%d], event=%s [%d]",
            channel_state_text(p_ccb->chnl_state).c_str(), p_ccb->chnl_state,
            l2c_csm_get_event_name(event), event);
}

/*******************************************************************************
 *
 * Function         l2c_csm_term_w4_sec_comp
 *
 * Description      This function handles events when the channel is in
 *                  CST_TERM_W4_SEC_COMP state.
 *
 * Returns          void
 *
 ******************************************************************************/
static void l2c_csm_term_w4_sec_comp(tL2C_CCB* p_ccb, uint16_t event,
                                     void* p_data) {
  LOG_DEBUG("LCID: 0x%04x  st: TERM_W4_SEC_COMP  evt: %s", p_ccb->local_cid,
            l2c_csm_get_event_name(event));

  switch (event) {
    case L2CEVT_LP_DISCONNECT_IND: /* Link was disconnected */
      /* Tell security manager to abort */
      btm_sec_abort_access_req(p_ccb->p_lcb->remote_bd_addr);

      l2cu_release_ccb(p_ccb);
      break;

    case L2CEVT_SEC_COMP:
      p_ccb->chnl_state = CST_W4_L2CA_CONNECT_RSP;

      /* Wait for the info resp in next state before sending connect ind (if
       * needed) */
      if (!p_ccb->p_lcb->w4_info_rsp) {
        LOG_DEBUG("Not waiting for info response, sending connect response");
        /* Don't need to get info from peer or already retrieved so continue */
        alarm_set_on_mloop(p_ccb->l2c_ccb_timer, L2CAP_CHNL_CONNECT_TIMEOUT_MS,
                           l2c_ccb_timer_timeout, p_ccb);

        if (p_ccb->p_lcb->transport != BT_TRANSPORT_LE) {
          LOG_DEBUG("Not LE connection, sending configure request");
          l2c_csm_send_connect_rsp(p_ccb);
          l2c_csm_send_config_req(p_ccb);
        } else {
          if (p_ccb->ecoc) {
            /* Handle Credit Based Connection */
            LOG_DEBUG("Calling CreditBasedConnect_Ind_Cb(), num of cids: %d",
                      p_ccb->p_lcb->pending_ecoc_conn_cnt);

            std::vector<uint16_t> pending_cids;
            for (int i = 0; i < p_ccb->p_lcb->pending_ecoc_conn_cnt; i++) {
              uint16_t cid = p_ccb->p_lcb->pending_ecoc_connection_cids[i];
              if (cid != 0) pending_cids.push_back(cid);
            }

            (*p_ccb->p_rcb->api.pL2CA_CreditBasedConnectInd_Cb)(
                p_ccb->p_lcb->remote_bd_addr, pending_cids, p_ccb->p_rcb->psm,
                p_ccb->peer_cfg.mtu, p_ccb->remote_id);
          } else {
            /* Handle BLE CoC */
            LOG_DEBUG("Calling Connect_Ind_Cb(), CID: 0x%04x",
                      p_ccb->local_cid);
            l2c_csm_send_connect_rsp(p_ccb);
            l2c_csm_indicate_connection_open(p_ccb);
          }
        }
      } else {
        /*
        ** L2CAP Connect Response will be sent out by 3 sec timer expiration
        ** because Bluesoleil doesn't respond to L2CAP Information Request.
        ** Bluesoleil seems to disconnect ACL link as failure case, because
        ** it takes too long (4~7secs) to get response.
        ** product version : Bluesoleil 2.1.1.0 EDR Release 060123
        ** stack version   : 05.04.11.20060119
        */

        /* Waiting for the info resp, tell the peer to set a longer timer */
        LOG_DEBUG("Waiting for info response, sending connect pending");
        l2cu_send_peer_connect_rsp(p_ccb, L2CAP_CONN_PENDING, 0);
      }
      break;

    case L2CEVT_SEC_COMP_NEG:
      if (((tL2C_CONN_INFO*)p_data)->status == BTM_DELAY_CHECK) {
        /* start a timer - encryption change not received before L2CAP connect
         * req */
        alarm_set_on_mloop(p_ccb->l2c_ccb_timer,
                           L2CAP_DELAY_CHECK_SM4_TIMEOUT_MS,
                           l2c_ccb_timer_timeout, p_ccb);
      } else {
        if (p_ccb->p_lcb->transport == BT_TRANSPORT_LE)
          l2cu_reject_ble_connection(
              p_ccb, p_ccb->remote_id,
              L2CAP_LE_RESULT_INSUFFICIENT_AUTHENTICATION);
        else
          l2cu_send_peer_connect_rsp(p_ccb, L2CAP_CONN_SECURITY_BLOCK, 0);
        l2cu_release_ccb(p_ccb);
      }
      break;

    case L2CEVT_L2CA_DATA_WRITE: /* Upper layer data to send */
    case L2CEVT_L2CAP_DATA:      /* Peer data packet rcvd    */
      osi_free(p_data);
      break;

    case L2CEVT_L2CA_DISCONNECT_REQ: /* Upper wants to disconnect */
      l2cu_release_ccb(p_ccb);
      break;

    case L2CEVT_L2CAP_DISCONNECT_REQ: /* Peer disconnected request */
      l2cu_send_peer_disc_rsp(p_ccb->p_lcb, p_ccb->remote_id, p_ccb->local_cid,
                              p_ccb->remote_cid);

      /* Tell security manager to abort */
      btm_sec_abort_access_req(p_ccb->p_lcb->remote_bd_addr);

      l2cu_release_ccb(p_ccb);
      break;

    case L2CEVT_TIMEOUT:
      /* SM4 related. */
      acl_disconnect_from_handle(p_ccb->p_lcb->Handle(), HCI_ERR_AUTH_FAILURE);
      break;

    case L2CEVT_SEC_RE_SEND_CMD: /* BTM has enough info to proceed */
      btm_sec_l2cap_access_req(p_ccb->p_lcb->remote_bd_addr, p_ccb->p_rcb->psm,
                               false, &l2c_link_sec_comp, p_ccb);
      break;
  }
  LOG_DEBUG("Exit chnl_state=%s [%d], event=%s [%d]",
            channel_state_text(p_ccb->chnl_state).c_str(), p_ccb->chnl_state,
            l2c_csm_get_event_name(event), event);
}

/*******************************************************************************
 *
 * Function         l2c_csm_w4_l2cap_connect_rsp
 *
 * Description      This function handles events when the channel is in
 *                  CST_W4_L2CAP_CONNECT_RSP state.
 *
 * Returns          void
 *
 ******************************************************************************/
static void l2c_csm_w4_l2cap_connect_rsp(tL2C_CCB* p_ccb, uint16_t event,
                                         void* p_data) {
  tL2C_CONN_INFO* p_ci = (tL2C_CONN_INFO*)p_data;
  tL2CA_DISCONNECT_IND_CB* disconnect_ind =
      p_ccb->p_rcb->api.pL2CA_DisconnectInd_Cb;
  tL2CA_CREDIT_BASED_CONNECT_CFM_CB* credit_based_connect_cfm =
      p_ccb->p_rcb->api.pL2CA_CreditBasedConnectCfm_Cb;
  uint16_t local_cid = p_ccb->local_cid;
  tL2C_LCB* p_lcb = p_ccb->p_lcb;

  LOG_DEBUG("LCID: 0x%04x  st: W4_L2CAP_CON_RSP  evt: %s", p_ccb->local_cid,
            l2c_csm_get_event_name(event));

  switch (event) {
    case L2CEVT_LP_DISCONNECT_IND: /* Link was disconnected */
      /* Send disc indication unless peer to peer race condition AND normal
       * disconnect */
      /* *((uint8_t *)p_data) != HCI_ERR_PEER_USER happens when peer device try
       * to disconnect for normal reason */
      p_ccb->chnl_state = CST_CLOSED;
      if ((p_ccb->flags & CCB_FLAG_NO_RETRY) || !p_data ||
          (*((uint8_t*)p_data) != HCI_ERR_PEER_USER)) {
        LOG_DEBUG("Calling Disconnect_Ind_Cb(), CID: 0x%04x  No Conf Needed",
                  p_ccb->local_cid);
        l2cu_release_ccb(p_ccb);
        (*disconnect_ind)(local_cid, false);
      }
      p_ccb->flags |= CCB_FLAG_NO_RETRY;
      break;

    case L2CEVT_L2CAP_CONNECT_RSP: /* Got peer connect confirm */
      p_ccb->remote_cid = p_ci->remote_cid;
      if (p_ccb->p_lcb->transport == BT_TRANSPORT_LE) {
        /* Connection is completed */
        alarm_cancel(p_ccb->l2c_ccb_timer);
        p_ccb->chnl_state = CST_OPEN;
        l2c_csm_indicate_connection_open(p_ccb);
        p_ccb->local_conn_cfg = p_ccb->p_rcb->coc_cfg;
        p_ccb->remote_credit_count = p_ccb->p_rcb->coc_cfg.credits;
        l2c_csm_execute(p_ccb, L2CEVT_L2CA_CONNECT_RSP, NULL);
      } else {
        p_ccb->chnl_state = CST_CONFIG;
        alarm_set_on_mloop(p_ccb->l2c_ccb_timer, L2CAP_CHNL_CFG_TIMEOUT_MS,
                           l2c_ccb_timer_timeout, p_ccb);
      }
      LOG_DEBUG("Calling Connect_Cfm_Cb(), CID: 0x%04x, Success",
                p_ccb->local_cid);

      l2c_csm_send_config_req(p_ccb);
      break;

    case L2CEVT_L2CAP_CONNECT_RSP_PND: /* Got peer connect pending */
      p_ccb->remote_cid = p_ci->remote_cid;
      alarm_set_on_mloop(p_ccb->l2c_ccb_timer,
                         L2CAP_CHNL_CONNECT_EXT_TIMEOUT_MS,
                         l2c_ccb_timer_timeout, p_ccb);
      break;

    case L2CEVT_L2CAP_CREDIT_BASED_CONNECT_RSP:
      alarm_cancel(p_ccb->l2c_ccb_timer);
      p_ccb->chnl_state = CST_OPEN;
      LOG_DEBUG(
          "Calling credit_based_connect_cfm(),"
          "cid %d, result 0x%04x",
          p_ccb->local_cid, L2CAP_CONN_OK);

      (*credit_based_connect_cfm)(p_lcb->remote_bd_addr, p_ccb->local_cid,
                                  p_ci->peer_mtu, L2CAP_CONN_OK);
      break;

    case L2CEVT_L2CAP_CREDIT_BASED_CONNECT_RSP_NEG:
      LOG_DEBUG(
          "Calling pL2CA_Error_Cb(),"
          "cid %d, result 0x%04x",
          local_cid, p_ci->l2cap_result);
      (*p_ccb->p_rcb->api.pL2CA_Error_Cb)(local_cid, p_ci->l2cap_result);

      l2cu_release_ccb(p_ccb);
      break;

    case L2CEVT_L2CAP_CONNECT_RSP_NEG: /* Peer rejected connection */
      LOG(WARNING) << __func__ << ": L2CAP connection rejected, lcid="
                   << loghex(p_ccb->local_cid)
                   << ", reason=" << loghex(p_ci->l2cap_result);
      l2cu_release_ccb(p_ccb);
      (*p_ccb->p_rcb->api.pL2CA_Error_Cb)(local_cid, L2CAP_CONN_OTHER_ERROR);
      break;

    case L2CEVT_TIMEOUT:
      LOG(WARNING) << __func__ << ": L2CAP connection timeout";

      if (p_ccb->ecoc) {
        for (int i = 0; i < p_lcb->pending_ecoc_conn_cnt; i++) {
          uint16_t cid = p_lcb->pending_ecoc_connection_cids[i];
          tL2C_CCB* temp_p_ccb = l2cu_find_ccb_by_cid(p_lcb, cid);
          LOG(WARNING) << __func__ << ": lcid= " << loghex(cid);
          (*p_ccb->p_rcb->api.pL2CA_Error_Cb)(p_ccb->local_cid,
                                              L2CAP_CONN_TIMEOUT);
          l2cu_release_ccb(temp_p_ccb);
        }
        p_lcb->pending_ecoc_conn_cnt = 0;
        memset(p_lcb->pending_ecoc_connection_cids, 0,
               L2CAP_CREDIT_BASED_MAX_CIDS);

      } else {
        LOG(WARNING) << __func__ << ": lcid= " << loghex(p_ccb->local_cid);
        l2cu_release_ccb(p_ccb);
        (*p_ccb->p_rcb->api.pL2CA_Error_Cb)(local_cid, L2CAP_CONN_OTHER_ERROR);
      }
      break;

    case L2CEVT_L2CA_DISCONNECT_REQ: /* Upper wants to disconnect */
      /* If we know peer CID from connect pending, we can send disconnect */
      if (p_ccb->remote_cid != 0) {
        l2cu_send_peer_disc_req(p_ccb);
        p_ccb->chnl_state = CST_W4_L2CAP_DISCONNECT_RSP;
        alarm_set_on_mloop(p_ccb->l2c_ccb_timer,
                           L2CAP_CHNL_DISCONNECT_TIMEOUT_MS,
                           l2c_ccb_timer_timeout, p_ccb);
      } else {
        l2cu_release_ccb(p_ccb);
      }
      break;

    case L2CEVT_L2CA_DATA_WRITE: /* Upper layer data to send */
    case L2CEVT_L2CAP_DATA:      /* Peer data packet rcvd    */
      osi_free(p_data);
      break;

    case L2CEVT_L2CAP_INFO_RSP:
      /* Need to have at least one compatible channel to continue */
      if (!l2c_fcr_chk_chan_modes(p_ccb)) {
        l2cu_release_ccb(p_ccb);
        (*p_ccb->p_rcb->api.pL2CA_Error_Cb)(local_cid, L2CAP_CONN_OTHER_ERROR);
      } else {
        /* We have feature info, so now send peer connect request */
        alarm_set_on_mloop(p_ccb->l2c_ccb_timer, L2CAP_CHNL_CONNECT_TIMEOUT_MS,
                           l2c_ccb_timer_timeout, p_ccb);
        l2cu_send_peer_connect_req(p_ccb); /* Start Connection     */
      }
      break;
  }
  LOG_DEBUG("Exit chnl_state=%s [%d], event=%s [%d]",
            channel_state_text(p_ccb->chnl_state).c_str(), p_ccb->chnl_state,
            l2c_csm_get_event_name(event), event);
}

/*******************************************************************************
 *
 * Function         l2c_csm_w4_l2ca_connect_rsp
 *
 * Description      This function handles events when the channel is in
 *                  CST_W4_L2CA_CONNECT_RSP state.
 *
 * Returns          void
 *
 ******************************************************************************/
static void l2c_csm_w4_l2ca_connect_rsp(tL2C_CCB* p_ccb, uint16_t event,
                                        void* p_data) {
  tL2C_CONN_INFO* p_ci;
  tL2CA_DISCONNECT_IND_CB* disconnect_ind =
      p_ccb->p_rcb->api.pL2CA_DisconnectInd_Cb;
  uint16_t local_cid = p_ccb->local_cid;

  LOG_DEBUG("LCID: 0x%04x  st: W4_L2CA_CON_RSP  evt: %s", p_ccb->local_cid,
            l2c_csm_get_event_name(event));

  switch (event) {
    case L2CEVT_LP_DISCONNECT_IND: /* Link was disconnected */
      LOG_DEBUG("Calling Disconnect_Ind_Cb(), CID: 0x%04x  No Conf Needed",
                p_ccb->local_cid);
      l2cu_release_ccb(p_ccb);
      (*disconnect_ind)(local_cid, false);
      break;

    case L2CEVT_L2CA_CREDIT_BASED_CONNECT_RSP:
      p_ci = (tL2C_CONN_INFO*)p_data;
      if (p_ccb->p_lcb && p_ccb->p_lcb->transport != BT_TRANSPORT_LE) {
        LOG_WARN("LE link doesn't exist");
        return;
      }
      l2cu_send_peer_credit_based_conn_res(p_ccb, p_ci->lcids,
                                           p_ci->l2cap_result);
      alarm_cancel(p_ccb->l2c_ccb_timer);

      for (int i = 0; i < p_ccb->p_lcb->pending_ecoc_conn_cnt; i++) {
        uint16_t cid = p_ccb->p_lcb->pending_ecoc_connection_cids[i];
        tL2C_CCB* temp_p_ccb = l2cu_find_ccb_by_cid(p_ccb->p_lcb, cid);
        auto it = std::find(p_ci->lcids.begin(), p_ci->lcids.end(), cid);
        if (it != p_ci->lcids.end()) {
          temp_p_ccb->chnl_state = CST_OPEN;
        } else {
          l2cu_release_ccb(temp_p_ccb);
        }
      }
      p_ccb->p_lcb->pending_ecoc_conn_cnt = 0;
      memset(p_ccb->p_lcb->pending_ecoc_connection_cids, 0,
             L2CAP_CREDIT_BASED_MAX_CIDS);

      break;
    case L2CEVT_L2CA_CONNECT_RSP:
      p_ci = (tL2C_CONN_INFO*)p_data;
      if (p_ccb->p_lcb->transport == BT_TRANSPORT_LE) {
        /* Result should be OK or Reject */
        if ((!p_ci) || (p_ci->l2cap_result == L2CAP_CONN_OK)) {
          l2cble_credit_based_conn_res(p_ccb, L2CAP_CONN_OK);
          p_ccb->chnl_state = CST_OPEN;
          alarm_cancel(p_ccb->l2c_ccb_timer);
        } else {
          l2cble_credit_based_conn_res(p_ccb, p_ci->l2cap_result);
          l2cu_release_ccb(p_ccb);
        }
      } else {
        /* Result should be OK or PENDING */
        if ((!p_ci) || (p_ci->l2cap_result == L2CAP_CONN_OK)) {
          LOG_DEBUG("Sending connection ok for BR_EDR");
          l2cu_send_peer_connect_rsp(p_ccb, L2CAP_CONN_OK, 0);
          p_ccb->chnl_state = CST_CONFIG;
          alarm_set_on_mloop(p_ccb->l2c_ccb_timer, L2CAP_CHNL_CFG_TIMEOUT_MS,
                             l2c_ccb_timer_timeout, p_ccb);
        } else {
          /* If pending, stay in same state and start extended timer */
          LOG_DEBUG("Sending connection result %d and status %d",
                    p_ci->l2cap_result, p_ci->l2cap_status);
          l2cu_send_peer_connect_rsp(p_ccb, p_ci->l2cap_result,
                                     p_ci->l2cap_status);
          alarm_set_on_mloop(p_ccb->l2c_ccb_timer,
                             L2CAP_CHNL_CONNECT_EXT_TIMEOUT_MS,
                             l2c_ccb_timer_timeout, p_ccb);
        }
      }
      break;

    case L2CEVT_L2CA_CREDIT_BASED_CONNECT_RSP_NEG:
      p_ci = (tL2C_CONN_INFO*)p_data;
      if (p_ccb->p_lcb && p_ccb->p_lcb->transport == BT_TRANSPORT_LE) {
        l2cu_send_peer_credit_based_conn_res(p_ccb, p_ci->lcids,
                                             p_ci->l2cap_result);
      }
      alarm_cancel(p_ccb->l2c_ccb_timer);
      for (int i = 0; i < p_ccb->p_lcb->pending_ecoc_conn_cnt; i++) {
        uint16_t cid = p_ccb->p_lcb->pending_ecoc_connection_cids[i];
        tL2C_CCB* temp_p_ccb = l2cu_find_ccb_by_cid(p_ccb->p_lcb, cid);
        l2cu_release_ccb(temp_p_ccb);
      }

      p_ccb->p_lcb->pending_ecoc_conn_cnt = 0;
      memset(p_ccb->p_lcb->pending_ecoc_connection_cids, 0,
             L2CAP_CREDIT_BASED_MAX_CIDS);

      break;
    case L2CEVT_L2CA_CONNECT_RSP_NEG:
      p_ci = (tL2C_CONN_INFO*)p_data;
      if (p_ccb->p_lcb->transport == BT_TRANSPORT_LE)
        l2cble_credit_based_conn_res(p_ccb, p_ci->l2cap_result);
      else
        l2cu_send_peer_connect_rsp(p_ccb, p_ci->l2cap_result,
                                   p_ci->l2cap_status);
      l2cu_release_ccb(p_ccb);
      break;

    case L2CEVT_TIMEOUT:
      l2cu_send_peer_connect_rsp(p_ccb, L2CAP_CONN_NO_PSM, 0);
      LOG_DEBUG("Calling Disconnect_Ind_Cb(), CID: 0x%04x  No Conf Needed",
                p_ccb->local_cid);
      l2cu_release_ccb(p_ccb);
      (*disconnect_ind)(local_cid, false);
      break;

    case L2CEVT_L2CA_DATA_WRITE: /* Upper layer data to send */
    case L2CEVT_L2CAP_DATA:      /* Peer data packet rcvd    */
      osi_free(p_data);
      break;

    case L2CEVT_L2CA_DISCONNECT_REQ: /* Upper wants to disconnect */
      l2cu_send_peer_disc_req(p_ccb);
      p_ccb->chnl_state = CST_W4_L2CAP_DISCONNECT_RSP;
      alarm_set_on_mloop(p_ccb->l2c_ccb_timer, L2CAP_CHNL_DISCONNECT_TIMEOUT_MS,
                         l2c_ccb_timer_timeout, p_ccb);
      break;

    case L2CEVT_L2CAP_INFO_RSP:
      /* We have feature info, so now give the upper layer connect IND */
      alarm_set_on_mloop(p_ccb->l2c_ccb_timer, L2CAP_CHNL_CONNECT_TIMEOUT_MS,
                         l2c_ccb_timer_timeout, p_ccb);
      LOG_DEBUG("Calling Connect_Ind_Cb(), CID: 0x%04x", p_ccb->local_cid);

      l2c_csm_send_connect_rsp(p_ccb);
      l2c_csm_send_config_req(p_ccb);
      break;
  }
  LOG_DEBUG("Exit chnl_state=%s [%d], event=%s [%d]",
            channel_state_text(p_ccb->chnl_state).c_str(), p_ccb->chnl_state,
            l2c_csm_get_event_name(event), event);
}

/*******************************************************************************
 *
 * Function         l2c_csm_config
 *
 * Description      This function handles events when the channel is in
 *                  CONFIG state.
 *
 * Returns          void
 *
 ******************************************************************************/
static void l2c_csm_config(tL2C_CCB* p_ccb, uint16_t event, void* p_data) {
  tL2CAP_CFG_INFO* p_cfg = (tL2CAP_CFG_INFO*)p_data;
  tL2CA_DISCONNECT_IND_CB* disconnect_ind =
      p_ccb->p_rcb->api.pL2CA_DisconnectInd_Cb;
  uint16_t local_cid = p_ccb->local_cid;
  uint8_t cfg_result;
  tL2C_LCB* p_lcb = p_ccb->p_lcb;
  tL2C_CCB* temp_p_ccb;
  tL2CAP_LE_CFG_INFO* p_le_cfg = (tL2CAP_LE_CFG_INFO*)p_data;

  LOG_DEBUG("LCID: 0x%04x  st: CONFIG  evt: %s", p_ccb->local_cid,
            l2c_csm_get_event_name(event));

  switch (event) {
    case L2CEVT_LP_DISCONNECT_IND: /* Link was disconnected */
      LOG_DEBUG("Calling Disconnect_Ind_Cb(), CID: 0x%04x  No Conf Needed",
                p_ccb->local_cid);
      l2cu_release_ccb(p_ccb);
      (*disconnect_ind)(local_cid, false);
      break;

    case L2CEVT_L2CAP_CREDIT_BASED_RECONFIG_REQ:
      /* For ecoc reconfig is handled below in l2c_ble. In case of success
       * let us notify upper layer about the reconfig
       */
      LOG_DEBUG("Calling LeReconfigCompleted_Cb(), CID: 0x%04x",
                p_ccb->local_cid);

      (*p_ccb->p_rcb->api.pL2CA_CreditBasedReconfigCompleted_Cb)(
          p_lcb->remote_bd_addr, p_ccb->local_cid, false, p_le_cfg);
      break;
    case L2CEVT_L2CAP_CONFIG_REQ: /* Peer config request   */
      cfg_result = l2cu_process_peer_cfg_req(p_ccb, p_cfg);
      if (cfg_result == L2CAP_PEER_CFG_OK) {
        LOG_DEBUG("Calling Config_Req_Cb(), CID: 0x%04x, C-bit %d",
                  p_ccb->local_cid, (p_cfg->flags & L2CAP_CFG_FLAGS_MASK_CONT));
        l2c_csm_send_config_rsp_ok(p_ccb);
        if (p_ccb->config_done & OB_CFG_DONE) {
          if (p_ccb->remote_config_rsp_result == L2CAP_CFG_OK) {
            l2c_csm_indicate_connection_open(p_ccb);
          } else {
            if (p_ccb->connection_initiator == L2CAP_INITIATOR_LOCAL) {
              (*p_ccb->p_rcb->api.pL2CA_Error_Cb)(p_ccb->local_cid,
                                                  L2CAP_CFG_FAILED_NO_REASON);
            }
          }
        }
      } else if (cfg_result == L2CAP_PEER_CFG_DISCONNECT) {
        /* Disconnect if channels are incompatible */
        LOG_DEBUG("incompatible configurations disconnect");
        l2cu_disconnect_chnl(p_ccb);
      } else /* Return error to peer so it can renegotiate if possible */
      {
        LOG_DEBUG("incompatible configurations trying reconfig");
        l2cu_send_peer_config_rsp(p_ccb, p_cfg);
      }
      break;

    case L2CEVT_L2CAP_CREDIT_BASED_RECONFIG_RSP:
      p_ccb->config_done |= OB_CFG_DONE;
      p_ccb->config_done |= RECONFIG_FLAG;
      p_ccb->chnl_state = CST_OPEN;
      alarm_cancel(p_ccb->l2c_ccb_timer);

      LOG_DEBUG("Calling Config_Rsp_Cb(), CID: 0x%04x", p_ccb->local_cid);

      p_ccb->p_rcb->api.pL2CA_CreditBasedReconfigCompleted_Cb(
          p_lcb->remote_bd_addr, p_ccb->local_cid, true, p_le_cfg);

      break;
    case L2CEVT_L2CAP_CONFIG_RSP: /* Peer config response  */
      l2cu_process_peer_cfg_rsp(p_ccb, p_cfg);

      /* TBD: When config options grow beyong minimum MTU (48 bytes)
       *      logic needs to be added to handle responses with
       *      continuation bit set in flags field.
       *       1. Send additional config request out until C-bit is cleared in
       * response
       */
      p_ccb->config_done |= OB_CFG_DONE;

      if (p_ccb->config_done & IB_CFG_DONE) {
        /* Verify two sides are in compatible modes before continuing */
        if (p_ccb->our_cfg.fcr.mode != p_ccb->peer_cfg.fcr.mode) {
          l2cu_send_peer_disc_req(p_ccb);
          LOG_WARN(
              "Calling Disconnect_Ind_Cb(Incompatible CFG), CID: "
              "0x%04x  No Conf Needed",
              p_ccb->local_cid);
          l2cu_release_ccb(p_ccb);
          (*disconnect_ind)(local_cid, false);
          break;
        }

        p_ccb->config_done |= RECONFIG_FLAG;
        p_ccb->chnl_state = CST_OPEN;
        l2c_link_adjust_chnl_allocation();
        alarm_cancel(p_ccb->l2c_ccb_timer);

        /* If using eRTM and waiting for an ACK, restart the ACK timer */
        if (p_ccb->fcrb.wait_ack) l2c_fcr_start_timer(p_ccb);

        /*
         ** check p_ccb->our_cfg.fcr.mon_tout and
         *p_ccb->our_cfg.fcr.rtrans_tout
         ** we may set them to zero when sending config request during
         *renegotiation
         */
        if ((p_ccb->our_cfg.fcr.mode == L2CAP_FCR_ERTM_MODE) &&
            ((p_ccb->our_cfg.fcr.mon_tout == 0) ||
             (p_ccb->our_cfg.fcr.rtrans_tout))) {
          l2c_fcr_adj_monitor_retran_timeout(p_ccb);
        }

        /* See if we can forward anything on the hold queue */
        if (!fixed_queue_is_empty(p_ccb->xmit_hold_q)) {
          l2c_link_check_send_pkts(p_ccb->p_lcb, 0, NULL);
        }
      }

      LOG_DEBUG("Calling Config_Rsp_Cb(), CID: 0x%04x", p_ccb->local_cid);
      p_ccb->remote_config_rsp_result = p_cfg->result;
      if (p_ccb->config_done & IB_CFG_DONE) {
        l2c_csm_indicate_connection_open(p_ccb);
      }
      break;

    case L2CEVT_L2CAP_CONFIG_RSP_NEG: /* Peer config error rsp */
                                      /* Disable the Timer */
      alarm_cancel(p_ccb->l2c_ccb_timer);

      /* If failure was channel mode try to renegotiate */
      if (!l2c_fcr_renegotiate_chan(p_ccb, p_cfg)) {
        LOG_DEBUG("Calling Config_Rsp_Cb(), CID: 0x%04x, Failure: %d",
                  p_ccb->local_cid, p_cfg->result);
        if (p_ccb->connection_initiator == L2CAP_INITIATOR_LOCAL) {
          (*p_ccb->p_rcb->api.pL2CA_Error_Cb)(p_ccb->local_cid,
                                              L2CAP_CFG_FAILED_NO_REASON);
        }
      }
      break;

    case L2CEVT_L2CAP_DISCONNECT_REQ: /* Peer disconnected request */
      alarm_set_on_mloop(p_ccb->l2c_ccb_timer, L2CAP_CHNL_DISCONNECT_TIMEOUT_MS,
                         l2c_ccb_timer_timeout, p_ccb);
      p_ccb->chnl_state = CST_W4_L2CA_DISCONNECT_RSP;
      LOG_DEBUG("Calling Disconnect_Ind_Cb(), CID: 0x%04x  Conf Needed",
                p_ccb->local_cid);
      (*p_ccb->p_rcb->api.pL2CA_DisconnectInd_Cb)(p_ccb->local_cid, true);
      l2c_csm_send_disconnect_rsp(p_ccb);
      break;

    case L2CEVT_L2CA_CREDIT_BASED_RECONFIG_REQ:
      l2cu_send_credit_based_reconfig_req(p_ccb, (tL2CAP_LE_CFG_INFO*)p_data);
      alarm_set_on_mloop(p_ccb->l2c_ccb_timer, L2CAP_CHNL_CFG_TIMEOUT_MS,
                         l2c_ccb_timer_timeout, p_ccb);
      break;
    case L2CEVT_L2CA_CONFIG_REQ: /* Upper layer config req   */
      l2cu_process_our_cfg_req(p_ccb, p_cfg);
      l2cu_send_peer_config_req(p_ccb, p_cfg);
      alarm_set_on_mloop(p_ccb->l2c_ccb_timer, L2CAP_CHNL_CFG_TIMEOUT_MS,
                         l2c_ccb_timer_timeout, p_ccb);
      break;

    case L2CEVT_L2CA_CONFIG_RSP: /* Upper layer config rsp   */
      l2cu_process_our_cfg_rsp(p_ccb, p_cfg);

      p_ccb->config_done |= IB_CFG_DONE;

      if (p_ccb->config_done & OB_CFG_DONE) {
        /* Verify two sides are in compatible modes before continuing */
        if (p_ccb->our_cfg.fcr.mode != p_ccb->peer_cfg.fcr.mode) {
          l2cu_send_peer_disc_req(p_ccb);
          LOG_WARN(
              "Calling Disconnect_Ind_Cb(Incompatible CFG), CID: "
              "0x%04x  No Conf Needed",
              p_ccb->local_cid);
          l2cu_release_ccb(p_ccb);
          (*disconnect_ind)(local_cid, false);
          break;
        }

        p_ccb->config_done |= RECONFIG_FLAG;
        p_ccb->chnl_state = CST_OPEN;
        l2c_link_adjust_chnl_allocation();
        alarm_cancel(p_ccb->l2c_ccb_timer);
      }

      l2cu_send_peer_config_rsp(p_ccb, p_cfg);

      /* If using eRTM and waiting for an ACK, restart the ACK timer */
      if (p_ccb->fcrb.wait_ack) l2c_fcr_start_timer(p_ccb);

      /* See if we can forward anything on the hold queue */
      if ((p_ccb->chnl_state == CST_OPEN) &&
          (!fixed_queue_is_empty(p_ccb->xmit_hold_q))) {
        l2c_link_check_send_pkts(p_ccb->p_lcb, 0, NULL);
      }
      break;

    case L2CEVT_L2CA_DISCONNECT_REQ: /* Upper wants to disconnect */
      l2cu_send_peer_disc_req(p_ccb);
      p_ccb->chnl_state = CST_W4_L2CAP_DISCONNECT_RSP;
      alarm_set_on_mloop(p_ccb->l2c_ccb_timer, L2CAP_CHNL_DISCONNECT_TIMEOUT_MS,
                         l2c_ccb_timer_timeout, p_ccb);
      break;

    case L2CEVT_L2CAP_DATA: /* Peer data packet rcvd    */
      LOG_DEBUG("Calling DataInd_Cb(), CID: 0x%04x", p_ccb->local_cid);
      if (p_ccb->local_cid >= L2CAP_FIRST_FIXED_CHNL &&
          p_ccb->local_cid <= L2CAP_LAST_FIXED_CHNL) {
        if (p_ccb->local_cid < L2CAP_BASE_APPL_CID) {
          if (l2cb.fixed_reg[p_ccb->local_cid - L2CAP_FIRST_FIXED_CHNL]
                  .pL2CA_FixedData_Cb)
            (*l2cb.fixed_reg[p_ccb->local_cid - L2CAP_FIRST_FIXED_CHNL]
                  .pL2CA_FixedData_Cb)(p_ccb->local_cid,
                                       p_ccb->p_lcb->remote_bd_addr,
                                       (BT_HDR*)p_data);
          else
            osi_free(p_data);
          break;
        }
      }
      (*p_ccb->p_rcb->api.pL2CA_DataInd_Cb)(p_ccb->local_cid, (BT_HDR*)p_data);
      break;

    case L2CEVT_L2CA_DATA_WRITE: /* Upper layer data to send */
      if (p_ccb->config_done & OB_CFG_DONE)
        l2c_enqueue_peer_data(p_ccb, (BT_HDR*)p_data);
      else
        osi_free(p_data);
      break;

    case L2CEVT_TIMEOUT:
      if (p_ccb->ecoc) {
        for (temp_p_ccb = p_lcb->ccb_queue.p_first_ccb; temp_p_ccb;
             temp_p_ccb = temp_p_ccb->p_next_ccb) {
          if ((temp_p_ccb->in_use) && (temp_p_ccb->reconfig_started)) {
            (*temp_p_ccb->p_rcb->api.pL2CA_DisconnectInd_Cb)(
                temp_p_ccb->local_cid, false);
            l2cu_release_ccb(temp_p_ccb);
          }
        }

        acl_disconnect_from_handle(p_ccb->p_lcb->Handle(),
                                   HCI_ERR_CONN_CAUSE_LOCAL_HOST);
        return;
      }

      l2cu_send_peer_disc_req(p_ccb);
      LOG_DEBUG("Calling Disconnect_Ind_Cb(), CID: 0x%04x  No Conf Needed",
                p_ccb->local_cid);
      l2cu_release_ccb(p_ccb);
      (*disconnect_ind)(local_cid, false);
      break;
  }
  LOG_DEBUG("Exit chnl_state=%s [%d], event=%s [%d]",
            channel_state_text(p_ccb->chnl_state).c_str(), p_ccb->chnl_state,
            l2c_csm_get_event_name(event), event);
}

/*******************************************************************************
 *
 * Function         l2c_csm_open
 *
 * Description      This function handles events when the channel is in
 *                  OPEN state.
 *
 * Returns          void
 *
 ******************************************************************************/
static void l2c_csm_open(tL2C_CCB* p_ccb, uint16_t event, void* p_data) {
  uint16_t local_cid = p_ccb->local_cid;
  tL2CAP_CFG_INFO* p_cfg;
  tL2C_CHNL_STATE tempstate;
  uint8_t tempcfgdone;
  uint8_t cfg_result;
  uint16_t credit = 0;
  tL2CAP_LE_CFG_INFO* p_le_cfg = (tL2CAP_LE_CFG_INFO*)p_data;

  LOG_DEBUG("LCID: 0x%04x  st: OPEN  evt: %s", p_ccb->local_cid,
            l2c_csm_get_event_name(event));

  switch (event) {
    case L2CEVT_LP_DISCONNECT_IND: /* Link was disconnected */
      LOG_DEBUG("Calling Disconnect_Ind_Cb(), CID: 0x%04x  No Conf Needed",
                p_ccb->local_cid);
      l2cu_release_ccb(p_ccb);
      if (p_ccb->p_rcb)
        (*p_ccb->p_rcb->api.pL2CA_DisconnectInd_Cb)(local_cid, false);
      break;

    case L2CEVT_L2CAP_CREDIT_BASED_RECONFIG_REQ:
      /* For ecoc reconfig is handled below in l2c_ble. In case of success
       * let us notify upper layer about the reconfig
       */
      LOG_DEBUG("Calling LeReconfigCompleted_Cb(), CID: 0x%04x",
                p_ccb->local_cid);

      (*p_ccb->p_rcb->api.pL2CA_CreditBasedReconfigCompleted_Cb)(
          p_ccb->p_lcb->remote_bd_addr, p_ccb->local_cid, false, p_le_cfg);
      break;

    case L2CEVT_L2CAP_CONFIG_REQ: /* Peer config request   */
      p_cfg = (tL2CAP_CFG_INFO*)p_data;

      tempstate = p_ccb->chnl_state;
      tempcfgdone = p_ccb->config_done;
      p_ccb->chnl_state = CST_CONFIG;
      // clear cached configuration in case reconfig takes place later
      p_ccb->peer_cfg.mtu_present = false;
      p_ccb->peer_cfg.flush_to_present = false;
      p_ccb->peer_cfg.qos_present = false;
      p_ccb->config_done &= ~IB_CFG_DONE;

      alarm_set_on_mloop(p_ccb->l2c_ccb_timer, L2CAP_CHNL_CFG_TIMEOUT_MS,
                         l2c_ccb_timer_timeout, p_ccb);

      cfg_result = l2cu_process_peer_cfg_req(p_ccb, p_cfg);
      if (cfg_result == L2CAP_PEER_CFG_OK) {
        (*p_ccb->p_rcb->api.pL2CA_ConfigInd_Cb)(p_ccb->local_cid, p_cfg);
        l2c_csm_send_config_rsp_ok(p_ccb);
      }

      /* Error in config parameters: reset state and config flag */
      else if (cfg_result == L2CAP_PEER_CFG_UNACCEPTABLE) {
        alarm_cancel(p_ccb->l2c_ccb_timer);
        p_ccb->chnl_state = tempstate;
        p_ccb->config_done = tempcfgdone;
        l2cu_send_peer_config_rsp(p_ccb, p_cfg);
      } else /* L2CAP_PEER_CFG_DISCONNECT */
      {
        /* Disconnect if channels are incompatible
         * Note this should not occur if reconfigure
         * since this should have never passed original config.
         */
        l2cu_disconnect_chnl(p_ccb);
      }
      break;

    case L2CEVT_L2CAP_DISCONNECT_REQ: /* Peer disconnected request */
      if (p_ccb->p_lcb->transport != BT_TRANSPORT_LE) {
        if (!BTM_SetLinkPolicyActiveMode(p_ccb->p_lcb->remote_bd_addr)) {
          LOG_WARN("Unable to set link policy active");
        }
      }

      p_ccb->chnl_state = CST_W4_L2CA_DISCONNECT_RSP;
      alarm_set_on_mloop(p_ccb->l2c_ccb_timer, L2CAP_CHNL_DISCONNECT_TIMEOUT_MS,
                         l2c_ccb_timer_timeout, p_ccb);
      LOG_DEBUG("Calling Disconnect_Ind_Cb(), CID: 0x%04x  Conf Needed",
                p_ccb->local_cid);
      (*p_ccb->p_rcb->api.pL2CA_DisconnectInd_Cb)(p_ccb->local_cid, true);
      l2c_csm_send_disconnect_rsp(p_ccb);
      break;

    case L2CEVT_L2CAP_DATA: /* Peer data packet rcvd    */
      if ((p_ccb->p_rcb) && (p_ccb->p_rcb->api.pL2CA_DataInd_Cb))
        (*p_ccb->p_rcb->api.pL2CA_DataInd_Cb)(p_ccb->local_cid,
                                              (BT_HDR*)p_data);
      break;

    case L2CEVT_L2CA_DISCONNECT_REQ: /* Upper wants to disconnect */
      if (p_ccb->p_lcb->transport != BT_TRANSPORT_LE) {
        /* Make sure we are not in sniff mode */
        if (!BTM_SetLinkPolicyActiveMode(p_ccb->p_lcb->remote_bd_addr)) {
          LOG_WARN("Unable to set link policy active");
        }
      }

      if (p_ccb->p_lcb->transport == BT_TRANSPORT_LE)
        l2cble_send_peer_disc_req(p_ccb);
      else
        l2cu_send_peer_disc_req(p_ccb);

      p_ccb->chnl_state = CST_W4_L2CAP_DISCONNECT_RSP;
      alarm_set_on_mloop(p_ccb->l2c_ccb_timer, L2CAP_CHNL_DISCONNECT_TIMEOUT_MS,
                         l2c_ccb_timer_timeout, p_ccb);
      break;

    case L2CEVT_L2CA_DATA_WRITE: /* Upper layer data to send */
      l2c_enqueue_peer_data(p_ccb, (BT_HDR*)p_data);
      l2c_link_check_send_pkts(p_ccb->p_lcb, 0, NULL);
      break;

    case L2CEVT_L2CA_CREDIT_BASED_RECONFIG_REQ:
      p_ccb->chnl_state = CST_CONFIG;
      p_ccb->config_done &= ~OB_CFG_DONE;

      l2cu_send_credit_based_reconfig_req(p_ccb, (tL2CAP_LE_CFG_INFO*)p_data);

      alarm_set_on_mloop(p_ccb->l2c_ccb_timer, L2CAP_CHNL_CFG_TIMEOUT_MS,
                         l2c_ccb_timer_timeout, p_ccb);
      break;

    case L2CEVT_L2CA_CONFIG_REQ: /* Upper layer config req   */
      LOG_ERROR(
          "Dropping L2CAP re-config request because there is no usage and "
          "should not be invoked");
      break;

    case L2CEVT_TIMEOUT:
      /* Process the monitor/retransmission time-outs in flow control/retrans
       * mode */
      if (p_ccb->peer_cfg.fcr.mode == L2CAP_FCR_ERTM_MODE)
        l2c_fcr_proc_tout(p_ccb);
      break;

    case L2CEVT_ACK_TIMEOUT:
      l2c_fcr_proc_ack_tout(p_ccb);
      break;

    case L2CEVT_L2CA_SEND_FLOW_CONTROL_CREDIT:
      LOG_DEBUG("Sending credit");
      credit = *(uint16_t*)p_data;
      l2cble_send_flow_control_credit(p_ccb, credit);
      break;

    case L2CEVT_L2CAP_RECV_FLOW_CONTROL_CREDIT:
      credit = *(uint16_t*)p_data;
      LOG_DEBUG("Credits received %d", credit);
      if ((p_ccb->peer_conn_cfg.credits + credit) > L2CAP_LE_CREDIT_MAX) {
        /* we have received credits more than max coc credits,
         * so disconnecting the Le Coc Channel
         */
        l2cble_send_peer_disc_req(p_ccb);
      } else {
        p_ccb->peer_conn_cfg.credits += credit;
        l2c_link_check_send_pkts(p_ccb->p_lcb, 0, NULL);
      }
      break;
  }
  LOG_DEBUG("Exit chnl_state=%s [%d], event=%s [%d]",
            channel_state_text(p_ccb->chnl_state).c_str(), p_ccb->chnl_state,
            l2c_csm_get_event_name(event), event);
}

/*******************************************************************************
 *
 * Function         l2c_csm_w4_l2cap_disconnect_rsp
 *
 * Description      This function handles events when the channel is in
 *                  CST_W4_L2CAP_DISCONNECT_RSP state.
 *
 * Returns          void
 *
 ******************************************************************************/
static void l2c_csm_w4_l2cap_disconnect_rsp(tL2C_CCB* p_ccb, uint16_t event,
                                            void* p_data) {
  LOG_DEBUG("LCID: 0x%04x  st: W4_L2CAP_DISC_RSP  evt: %s", p_ccb->local_cid,
            l2c_csm_get_event_name(event));

  switch (event) {
    case L2CEVT_L2CAP_DISCONNECT_RSP: /* Peer disconnect response */
      l2cu_release_ccb(p_ccb);
      break;

    case L2CEVT_L2CAP_DISCONNECT_REQ: /* Peer disconnect request  */
      l2cu_send_peer_disc_rsp(p_ccb->p_lcb, p_ccb->remote_id, p_ccb->local_cid,
                              p_ccb->remote_cid);
      l2cu_release_ccb(p_ccb);
      break;

    case L2CEVT_LP_DISCONNECT_IND: /* Link was disconnected */
    case L2CEVT_TIMEOUT:           /* Timeout */
      l2cu_release_ccb(p_ccb);
      break;

    case L2CEVT_L2CAP_DATA:      /* Peer data packet rcvd    */
    case L2CEVT_L2CA_DATA_WRITE: /* Upper layer data to send */
      osi_free(p_data);
      break;
  }
  LOG_DEBUG("Exit chnl_state=%s [%d], event=%s [%d]",
            channel_state_text(p_ccb->chnl_state).c_str(), p_ccb->chnl_state,
            l2c_csm_get_event_name(event), event);
}

/*******************************************************************************
 *
 * Function         l2c_csm_w4_l2ca_disconnect_rsp
 *
 * Description      This function handles events when the channel is in
 *                  CST_W4_L2CA_DISCONNECT_RSP state.
 *
 * Returns          void
 *
 ******************************************************************************/
static void l2c_csm_w4_l2ca_disconnect_rsp(tL2C_CCB* p_ccb, uint16_t event,
                                           void* p_data) {
  tL2CA_DISCONNECT_IND_CB* disconnect_ind =
      p_ccb->p_rcb->api.pL2CA_DisconnectInd_Cb;
  uint16_t local_cid = p_ccb->local_cid;

  LOG_DEBUG("LCID: 0x%04x  st: W4_L2CA_DISC_RSP  evt: %s", p_ccb->local_cid,
            l2c_csm_get_event_name(event));

  switch (event) {
    case L2CEVT_LP_DISCONNECT_IND: /* Link was disconnected */
      LOG_DEBUG("Calling Disconnect_Ind_Cb(), CID: 0x%04x  No Conf Needed",
                p_ccb->local_cid);
      l2cu_release_ccb(p_ccb);
      (*disconnect_ind)(local_cid, false);
      break;

    case L2CEVT_TIMEOUT:
      l2cu_send_peer_disc_rsp(p_ccb->p_lcb, p_ccb->remote_id, p_ccb->local_cid,
                              p_ccb->remote_cid);
      LOG_DEBUG("Calling Disconnect_Ind_Cb(), CID: 0x%04x  No Conf Needed",
                p_ccb->local_cid);
      l2cu_release_ccb(p_ccb);
      (*disconnect_ind)(local_cid, false);
      break;

    case L2CEVT_L2CA_DISCONNECT_REQ: /* Upper disconnect request */
    case L2CEVT_L2CA_DISCONNECT_RSP: /* Upper disconnect response */
      l2cu_send_peer_disc_rsp(p_ccb->p_lcb, p_ccb->remote_id, p_ccb->local_cid,
                              p_ccb->remote_cid);
      l2cu_release_ccb(p_ccb);
      break;

    case L2CEVT_L2CAP_DATA:      /* Peer data packet rcvd    */
    case L2CEVT_L2CA_DATA_WRITE: /* Upper layer data to send */
      osi_free(p_data);
      break;
  }
  LOG_DEBUG("Exit chnl_state=%s [%d], event=%s [%d]",
            channel_state_text(p_ccb->chnl_state).c_str(), p_ccb->chnl_state,
            l2c_csm_get_event_name(event), event);
}

/*******************************************************************************
 *
 * Function         l2c_csm_get_event_name
 *
 * Description      This function returns the event name.
 *
 * NOTE             conditionally compiled to save memory.
 *
 * Returns          pointer to the name
 *
 ******************************************************************************/
static const char* l2c_csm_get_event_name(uint16_t event) {
  switch (event) {
    case L2CEVT_LP_CONNECT_CFM: /* Lower layer connect confirm          */
      return ("LOWER_LAYER_CONNECT_CFM");
    case L2CEVT_LP_CONNECT_CFM_NEG: /* Lower layer connect confirm (failed) */
      return ("LOWER_LAYER_CONNECT_CFM_NEG");
    case L2CEVT_LP_CONNECT_IND: /* Lower layer connect indication       */
      return ("LOWER_LAYER_CONNECT_IND");
    case L2CEVT_LP_DISCONNECT_IND: /* Lower layer disconnect indication    */
      return ("LOWER_LAYER_DISCONNECT_IND");

    case L2CEVT_SEC_COMP: /* Security cleared successfully        */
      return ("SECURITY_COMPLETE");
    case L2CEVT_SEC_COMP_NEG: /* Security procedure failed            */
      return ("SECURITY_COMPLETE_NEG");

    case L2CEVT_L2CAP_CONNECT_REQ: /* Peer connection request              */
      return ("PEER_CONNECT_REQ");
    case L2CEVT_L2CAP_CONNECT_RSP: /* Peer connection response             */
      return ("PEER_CONNECT_RSP");
    case L2CEVT_L2CAP_CONNECT_RSP_PND: /* Peer connection response pending */
      return ("PEER_CONNECT_RSP_PND");
    case L2CEVT_L2CAP_CONNECT_RSP_NEG: /* Peer connection response (failed) */
      return ("PEER_CONNECT_RSP_NEG");
    case L2CEVT_L2CAP_CONFIG_REQ: /* Peer configuration request           */
      return ("PEER_CONFIG_REQ");
    case L2CEVT_L2CAP_CONFIG_RSP: /* Peer configuration response          */
      return ("PEER_CONFIG_RSP");
    case L2CEVT_L2CAP_CONFIG_RSP_NEG: /* Peer configuration response (failed) */
      return ("PEER_CONFIG_RSP_NEG");
    case L2CEVT_L2CAP_DISCONNECT_REQ: /* Peer disconnect request              */
      return ("PEER_DISCONNECT_REQ");
    case L2CEVT_L2CAP_DISCONNECT_RSP: /* Peer disconnect response             */
      return ("PEER_DISCONNECT_RSP");
    case L2CEVT_L2CAP_DATA: /* Peer data                            */
      return ("PEER_DATA");

    case L2CEVT_L2CA_CONNECT_REQ: /* Upper layer connect request          */
      return ("UPPER_LAYER_CONNECT_REQ");
    case L2CEVT_L2CA_CONNECT_RSP: /* Upper layer connect response         */
      return ("UPPER_LAYER_CONNECT_RSP");
    case L2CEVT_L2CA_CONNECT_RSP_NEG: /* Upper layer connect response (failed)*/
      return ("UPPER_LAYER_CONNECT_RSP_NEG");
    case L2CEVT_L2CA_CONFIG_REQ: /* Upper layer config request           */
      return ("UPPER_LAYER_CONFIG_REQ");
    case L2CEVT_L2CA_CONFIG_RSP: /* Upper layer config response          */
      return ("UPPER_LAYER_CONFIG_RSP");
    case L2CEVT_L2CA_DISCONNECT_REQ: /* Upper layer disconnect request       */
      return ("UPPER_LAYER_DISCONNECT_REQ");
    case L2CEVT_L2CA_DISCONNECT_RSP: /* Upper layer disconnect response      */
      return ("UPPER_LAYER_DISCONNECT_RSP");
    case L2CEVT_L2CA_DATA_READ: /* Upper layer data read                */
      return ("UPPER_LAYER_DATA_READ");
    case L2CEVT_L2CA_DATA_WRITE: /* Upper layer data write               */
      return ("UPPER_LAYER_DATA_WRITE");
    case L2CEVT_TIMEOUT: /* Timeout                              */
      return ("TIMEOUT");
    case L2CEVT_SEC_RE_SEND_CMD:
      return ("SEC_RE_SEND_CMD");
    case L2CEVT_L2CAP_INFO_RSP: /* Peer information response            */
      return ("L2CEVT_L2CAP_INFO_RSP");
    case L2CEVT_ACK_TIMEOUT:
      return ("L2CEVT_ACK_TIMEOUT");
    case L2CEVT_L2CA_SEND_FLOW_CONTROL_CREDIT: /* Upper layer send credit packet
                                                */
      return ("SEND_FLOW_CONTROL_CREDIT");
    case L2CEVT_L2CA_CREDIT_BASED_CONNECT_REQ: /* Upper layer credit based
                                                  connect request */
      return ("SEND_CREDIT_BASED_CONNECT_REQ");
    case L2CEVT_L2CA_CREDIT_BASED_CONNECT_RSP: /* Upper layer credit based
                                                  connect response */
      return ("SEND_CREDIT_BASED_CONNECT_RSP");
    case L2CEVT_L2CA_CREDIT_BASED_RECONFIG_REQ: /* Upper layer credit based
                                                   reconfig request */
      return ("SEND_CREDIT_BASED_RECONFIG_REQ");
    case L2CEVT_L2CAP_RECV_FLOW_CONTROL_CREDIT: /* Peer send credit packet */
      return ("RECV_FLOW_CONTROL_CREDIT");
    case L2CEVT_L2CAP_CREDIT_BASED_CONNECT_REQ: /* Peer send credit based
                                                   connect request */
      return ("RECV_CREDIT_BASED_CONNECT_REQ");
    case L2CEVT_L2CAP_CREDIT_BASED_CONNECT_RSP: /* Peer send credit based
                                                   connect response */
      return ("RECV_CREDIT_BASED_CONNECT_RSP");
    case L2CEVT_L2CAP_CREDIT_BASED_CONNECT_RSP_NEG: /* Peer send reject credit
                                                       based connect response */
      return ("RECV_CREDIT_BASED_CONNECT_RSP_NEG");
    case L2CEVT_L2CAP_CREDIT_BASED_RECONFIG_REQ: /* Peer send credit based
                                                    reconfig request */
      return ("RECV_CREDIT_BASED_RECONFIG_REQ");
    case L2CEVT_L2CAP_CREDIT_BASED_RECONFIG_RSP: /* Peer send credit based
                                                    reconfig response */
      return ("RECV_CREDIT_BASED_RECONFIG_RSP");
    default:
      return ("???? UNKNOWN EVENT");
  }
}

/*******************************************************************************
 *
 * Function         l2c_enqueue_peer_data
 *
 * Description      Enqueues data destined for the peer in the ccb. Handles
 *                  FCR segmentation and checks for congestion.
 *
 * Returns          void
 *
 ******************************************************************************/
void l2c_enqueue_peer_data(tL2C_CCB* p_ccb, BT_HDR* p_buf) {
  uint8_t* p;

  if (p_ccb->peer_cfg.fcr.mode != L2CAP_FCR_BASIC_MODE) {
    p_buf->event = 0;
  } else {
    /* Save the channel ID for faster counting */
    p_buf->event = p_ccb->local_cid;

    /* Step back to add the L2CAP header */
    p_buf->offset -= L2CAP_PKT_OVERHEAD;
    p_buf->len += L2CAP_PKT_OVERHEAD;

    /* Set the pointer to the beginning of the data */
    p = (uint8_t*)(p_buf + 1) + p_buf->offset;

    /* Now the L2CAP header */
    UINT16_TO_STREAM(p, p_buf->len - L2CAP_PKT_OVERHEAD);
    UINT16_TO_STREAM(p, p_ccb->remote_cid);
  }

  if (p_ccb->xmit_hold_q == NULL) {
    LOG_ERROR(
        "empty queue: p_ccb = %p p_ccb->in_use = %d p_ccb->chnl_state = %d "
        "p_ccb->local_cid = %u p_ccb->remote_cid = %u",
        p_ccb, p_ccb->in_use, p_ccb->chnl_state, p_ccb->local_cid,
        p_ccb->remote_cid);
  }
  fixed_queue_enqueue(p_ccb->xmit_hold_q, p_buf);

  l2cu_check_channel_congestion(p_ccb);

  /* if new packet is higher priority than serving ccb and it is not overrun */
  if ((p_ccb->p_lcb->rr_pri > p_ccb->ccb_priority) &&
      (p_ccb->p_lcb->rr_serv[p_ccb->ccb_priority].quota > 0)) {
    /* send out higher priority packet */
    p_ccb->p_lcb->rr_pri = p_ccb->ccb_priority;
  }

  /* if we are doing a round robin scheduling, set the flag */
  if (p_ccb->p_lcb->link_xmit_quota == 0) l2cb.check_round_robin = true;
}
