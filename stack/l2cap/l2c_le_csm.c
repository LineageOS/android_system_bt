/******************************************************************************
 *
 *  Copyright (c) 2014, The Linux Foundation. All rights reserved.
 *  Not a Contribution.
 *  Copyright (C) 1999-2012 Broadcom Corporation
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
 *  This file contains the LE L2CAP channel SM handlers implementation
 *
 ******************************************************************************/

#include "bt_target.h"

#if (defined(LE_L2CAP_CFC_INCLUDED) && (LE_L2CAP_CFC_INCLUDED == TRUE))

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "gki.h"
#include "hcidefs.h"
#include "hcimsgs.h"
#include "l2cdefs.h"
#include "l2c_int.h"
#include "btm_int.h"
#include "btu.h"
#include "hcimsgs.h"

/********************************************************************************/
/*              L O C A L    F U N C T I O N     P R O T O T Y P E S            */
/********************************************************************************/
static void l2c_le_csm_closed (tL2C_CCB *p_ccb, UINT16 event, void *p_data);
static void l2c_le_csm_orig_w4_sec_comp (tL2C_CCB *p_ccb, UINT16 event,
                                                    void *p_data);
static void l2c_csm_w4_l2cap_le_connect_rsp (tL2C_CCB *p_ccb, UINT16 event,
                                                    void *p_data);
static void l2c_csm_w4_l2ca_le_connect_rsp (tL2C_CCB *p_ccb, UINT16 event,
                                                    void *p_data);
static void l2c_le_csm_open (tL2C_CCB *p_ccb, UINT16 event, void *p_data);
static void l2c_csm_w4_l2cap_le_disconnect_rsp (tL2C_CCB *p_ccb, UINT16 event,
                                                    void *p_data);
static void l2c_csm_w4_l2ca_le_disconnect_rsp (tL2C_CCB *p_ccb, UINT16 event,
                                                    void *p_data);

/*******************************************************************************
 **
 ** Function         dump_le_l2cap_conn_info
 **
 ** Description      This function dumps the LE L2CAP connection info.
 **
 ** Returns          void
 **
 *******************************************************************************/
static void dump_le_l2cap_conn_info(short type, tL2C_CCB *p_ccb)
{
    tL2CAP_LE_CONN_INFO *le_cb_conn_req;

    if((BT_TRANSPORT_LE != l2cu_get_chnl_transport(p_ccb)) ||
       (p_ccb->is_le_coc == FALSE))
    {
        L2CAP_TRACE_WARNING("LE-L2CAP: Error: Not a LE COC chnl\n");
        return;
    }

    if(!type)
    {
        le_cb_conn_req = &p_ccb->le_loc_conn_info;
        L2CAP_TRACE_WARNING("LE-L2CAP: Local Dev Connection Params\n");
    }
    else
    {
        le_cb_conn_req = &p_ccb->le_rmt_conn_info;
        L2CAP_TRACE_WARNING("LE-L2CAP: Remote Dev Connection Params\n");
    }
    L2CAP_TRACE_WARNING("LE-L2CAP: LCID:0x%04x RCID:0x%04x psm:%d mtu:%d mps:%d" \
        "credits:%d", p_ccb->local_cid, p_ccb->remote_cid, le_cb_conn_req->le_psm,
      le_cb_conn_req->le_mtu, le_cb_conn_req->le_mps, le_cb_conn_req->init_credits);
}

/*******************************************************************************
 **
 ** Function         l2c_le_csm_execute
 **
 ** Description      This function executes the LE L2CAP state machine.
 **
 ** Returns          void
 **
 *******************************************************************************/
void l2c_le_csm_execute (tL2C_CCB *p_ccb, UINT16 event, void *p_data)
{
    if ((BT_TRANSPORT_LE != l2cu_get_chnl_transport(p_ccb)) || !p_ccb->p_rcb)
    {
        L2CAP_TRACE_ERROR ("LE-L2CAP: SM ERROR %s CCB:%p evt:0x%04x p_rcb:%p",
                __FUNCTION__, p_ccb, event, (p_ccb ? p_ccb->p_rcb: NULL));
        return;
    }

    switch (p_ccb->chnl_state)
    {
        case CST_CLOSED:
            l2c_le_csm_closed (p_ccb, event, p_data);
            break;

        case CST_ORIG_W4_SEC_COMP:
            l2c_le_csm_orig_w4_sec_comp (p_ccb, event, p_data);
            break;

        case CST_W4_L2CAP_CONNECT_RSP:
            l2c_csm_w4_l2cap_le_connect_rsp (p_ccb, event, p_data);
            break;

        case CST_W4_L2CA_CONNECT_RSP:
            l2c_csm_w4_l2ca_le_connect_rsp (p_ccb, event, p_data);
            break;

        case CST_OPEN:
            l2c_le_csm_open (p_ccb, event, p_data);
            break;

        case CST_W4_L2CAP_DISCONNECT_RSP:
            l2c_csm_w4_l2cap_le_disconnect_rsp (p_ccb, event, p_data);
            break;

        case CST_W4_L2CA_DISCONNECT_RSP:
            l2c_csm_w4_l2ca_le_disconnect_rsp (p_ccb, event, p_data);
            break;

        default:
            break;
    }
}

/*******************************************************************************
 **
 ** Function         l2c_le_csm_closed
 **
 ** Description      This function handles events when the channel is in
 **                  CLOSED state. This state exists only when the le link is
 **                  being initially established.
 **
 ** Returns          void
 **
 *******************************************************************************/
static void l2c_le_csm_closed (tL2C_CCB *p_ccb, UINT16 event, void *p_data)
{
    UINT16 local_cid = p_ccb->local_cid;
    tL2CA_DISCONNECT_IND_CB *disconnect_ind =
                            p_ccb->p_rcb->api.pL2CA_DisconnectInd_Cb;
    tL2CA_LE_CONNECT_CFM_CB *le_connect_cfm =
                            p_ccb->p_rcb->api.pL2CA_LE_ConnectCfm_Cb;
    tL2CA_LE_CONNECT_IND_CB *le_connect_ind =
                            p_ccb->p_rcb->api.pL2CA_LE_ConnectInd_Cb;
    UINT32 status;

    L2CAP_TRACE_WARNING ("LE-L2CAP - st: CLOSED evt:%d LCID:0x%04x psm:%d",
            event, p_ccb->local_cid, p_ccb->p_rcb->psm);

    switch (event)
    {
        case L2CEVT_LP_DISCONNECT_IND:    /* Link was disconnected */
            l2cu_release_ccb (p_ccb);
            (*disconnect_ind)(local_cid, FALSE);
            break;

        case L2CEVT_LP_CONNECT_CFM_NEG:  /* Link failed */
            /* Disconnect unless the connection is already exists */
            if ( *((UINT8 *)(p_data)) != HCI_ERR_CONNECTION_EXISTS)
            {
                L2CAP_TRACE_ERROR ("LE-L2CAP: Connection Faied: CID:0x%04x",
                        p_ccb->local_cid);
                p_ccb->le_loc_conn_info.result = L2CAP_LE_CONN_NO_RESOURCES;
                (*le_connect_cfm)(local_cid, &p_ccb->le_loc_conn_info);
                l2cu_release_ccb (p_ccb);
            }
            break;

        case L2CEVT_LP_CONNECT_CFM:      /* Link came up */
        case L2CEVT_L2CA_LE_CONNECT_REQ:  /* API connect request  */
            dump_le_l2cap_conn_info(0, p_ccb);
            if (btm_sec_l2cap_le_access_req (p_ccb->p_lcb->remote_bd_addr,
                        p_ccb->p_rcb->psm, p_ccb->p_lcb->handle, TRUE,
                        &l2c_le_link_sec_comp, p_ccb) == BTM_CMD_STARTED)
            {
                p_ccb->chnl_state = CST_ORIG_W4_SEC_COMP;
            }
            break;

        case L2CEVT_SEC_COMP:
            p_ccb->chnl_state = CST_W4_L2CAP_CONNECT_RSP;
            l2cu_send_peer_le_credit_based_conn_req (p_ccb);
            btu_start_timer (&p_ccb->timer_entry, BTU_TTYPE_L2CAP_CHNL,
                    L2CAP_CHNL_CONNECT_TOUT);
            break;

        case L2CEVT_SEC_COMP_NEG:
            L2CAP_TRACE_ERROR ("LE-L2CAP: Security Failed : status:%d CID:0x%04x",
                    *((UINT8 *)(p_data)) , p_ccb->local_cid);

            p_ccb->le_loc_conn_info.result = *((UINT8 *)(p_data));
            (*le_connect_cfm)(local_cid, &p_ccb->le_loc_conn_info);
            l2cu_release_ccb (p_ccb);
            break;

        case L2CEVT_L2CAP_LE_CONNECT_REQ:   /* Peer connect request */
            dump_le_l2cap_conn_info(1, p_ccb);
            /* check for le-l2cap access request */
            status = btm_sec_l2cap_le_access_req (p_ccb->p_lcb->remote_bd_addr,
                    p_ccb->p_rcb->psm, p_ccb->p_lcb->handle, FALSE,
                    NULL, p_ccb);

            if(status == BTM_BLE_SUCCESS)
            {
                p_ccb->chnl_state = CST_W4_L2CA_CONNECT_RSP;
                btu_start_timer (&p_ccb->timer_entry, BTU_TTYPE_L2CAP_CHNL,
                        L2CAP_CHNL_CONNECT_TOUT);

                (*le_connect_ind) (p_ccb->p_lcb->remote_bd_addr, p_ccb->local_cid,
                        p_ccb->remote_id,  &p_ccb->le_rmt_conn_info);
            }
            else
            {
                L2CAP_TRACE_ERROR ("LE-L2CAP: Security Failed : status:%d CID:0x%04x",
                        p_ccb->local_cid, status);
                l2cu_send_peer_le_credit_based_conn_rsp (p_ccb, status);
                l2cu_release_ccb (p_ccb);
            }
            break;

        case L2CEVT_TIMEOUT:
            L2CAP_TRACE_WARNING ("LE-L2CAP: Timeout CID: 0x%04x ", p_ccb->local_cid);
            p_ccb->le_loc_conn_info.result = L2CAP_CONN_TIMEOUT;
            (*le_connect_cfm)(local_cid, &p_ccb->le_loc_conn_info);
            l2cu_release_ccb (p_ccb);
            break;

        case L2CEVT_L2CAP_DATA:    /* Peer data packet rcvd    */
        case L2CEVT_L2CA_DATA_WRITE:  /* Upper layer data to send */
            GKI_freebuf (p_data);
            break;

        case L2CEVT_L2CA_DISCONNECT_REQ: /* Upper wants to disconnect */
            l2cu_release_ccb (p_ccb);
            break;

        default:
            L2CAP_TRACE_WARNING ("LE-L2CAP - st: CLOSED unhandled evt:%d", event);
            break;
    }
}

/*******************************************************************************
 **
 ** Function         l2c_le_csm_orig_w4_sec_comp
 **
 ** Description      This function handles events when the le channel is in
 **                  CST_ORIG_W4_SEC_COMP state.
 **
 ** Returns          void
 **
 *******************************************************************************/
static void l2c_le_csm_orig_w4_sec_comp (tL2C_CCB *p_ccb, UINT16 event,
        void *p_data)
{
    tL2CA_DISCONNECT_IND_CB *disconnect_ind =
                            p_ccb->p_rcb->api.pL2CA_DisconnectInd_Cb;
    tL2CA_LE_CONNECT_CFM_CB *le_connect_cfm =
                            p_ccb->p_rcb->api.pL2CA_LE_ConnectCfm_Cb;
    UINT16  local_cid = p_ccb->local_cid;

    L2CAP_TRACE_WARNING ("LE-L2CAP - st: ORIG_W4_SEC_COMP evt:%d LCID:0x%04x psm:%d",
            event, p_ccb->local_cid, p_ccb->p_rcb->psm);

    switch (event)
    {
        case L2CEVT_LP_DISCONNECT_IND:    /* Link was disconnected */
            l2cu_release_ccb (p_ccb);
            (*disconnect_ind)(local_cid, FALSE);
            break;

        case L2CEVT_SEC_COMP:
            p_ccb->chnl_state = CST_W4_L2CAP_CONNECT_RSP;
            l2cu_send_peer_le_credit_based_conn_req (p_ccb);
            btu_start_timer (&p_ccb->timer_entry, BTU_TTYPE_L2CAP_CHNL,
                    L2CAP_CHNL_CONNECT_TOUT);
            break;

        case L2CEVT_SEC_COMP_NEG:
            L2CAP_TRACE_ERROR ("LE-L2CAP: Security Failed : status:%d CID:0x%04x",
                    *((UINT8 *)(p_data)), p_ccb->local_cid);

            p_ccb->le_loc_conn_info.result = *((UINT8 *)(p_data));
            (*le_connect_cfm)(local_cid, &p_ccb->le_loc_conn_info);
            l2cu_release_ccb (p_ccb);
            break;

        case L2CEVT_L2CA_DATA_WRITE:   /* Upper layer data to send */
        case L2CEVT_L2CAP_DATA:        /* Peer data packet rcvd    */
            GKI_freebuf (p_data);
            break;

        case L2CEVT_L2CA_DISCONNECT_REQ:  /* Upper wants to disconnect */
            l2cu_release_ccb (p_ccb);
            break;

        default:
            L2CAP_TRACE_WARNING ("LE-L2CAP - st: ORIG_W4_SEC_COMP unhandled evt:%d",
                    event);
            break;
    }
}

/*******************************************************************************
 **
 ** Function         l2c_csm_w4_l2cap_le_connect_rsp
 **
 ** Description      This function handles events when the le channel is in
 **                  CST_W4_L2CAP_CONNECT_RSP state.
 **
 ** Returns          void
 **
 *******************************************************************************/
static void l2c_csm_w4_l2cap_le_connect_rsp (tL2C_CCB *p_ccb, UINT16 event,
        void *p_data)
{
    tL2CA_DISCONNECT_IND_CB *disconnect_ind =
                                p_ccb->p_rcb->api.pL2CA_DisconnectInd_Cb;
    tL2CA_LE_CONNECT_CFM_CB *le_connect_cfm =
                                p_ccb->p_rcb->api.pL2CA_LE_ConnectCfm_Cb;
    UINT16  local_cid = p_ccb->local_cid;

    L2CAP_TRACE_WARNING ("LE-L2CAP - st: W4_L2CAP_LE_CON_RSP evt:%d LCID:0x%04x psm:%d",
            event, p_ccb->local_cid, p_ccb->p_rcb->psm);
    switch (event)
    {
        case L2CEVT_LP_DISCONNECT_IND:    /* Link was disconnected */
            p_ccb->chnl_state = CST_CLOSED;
            l2cu_release_ccb (p_ccb);
            (*disconnect_ind)(local_cid, FALSE);
            break;

        case L2CEVT_L2CAP_LE_CONNECT_RSP:  /* Got peer LE CB onnect confirm */
            p_ccb->chnl_state = CST_OPEN;
            dump_le_l2cap_conn_info(1, p_ccb);
            l2c_link_adjust_chnl_allocation ();
            /* stop the Timer */
            btu_stop_timer (&p_ccb->timer_entry);
            (*le_connect_cfm)(local_cid, &p_ccb->le_rmt_conn_info);
            break;
        case L2CEVT_L2CAP_LE_CONNECT_RSP_NEG: /* Peer rejected connection */
            /* stop the Timer */
            btu_stop_timer (&p_ccb->timer_entry);
            (*le_connect_cfm)(local_cid, &p_ccb->le_rmt_conn_info);
            l2cu_release_ccb (p_ccb);
            break;

        case L2CEVT_TIMEOUT:
            L2CAP_TRACE_WARNING ("LE-L2CAP: Timeout CID: 0x%04x ", p_ccb->local_cid);
            p_ccb->le_loc_conn_info.result = L2CAP_CONN_TIMEOUT;
            (*le_connect_cfm)(local_cid, &p_ccb->le_loc_conn_info);
            l2cu_release_ccb (p_ccb);
            break;

        case L2CEVT_L2CA_DATA_WRITE:    /* Upper layer data to send */
        case L2CEVT_L2CAP_DATA:         /* Peer data packet rcvd    */
            GKI_freebuf (p_data);
            break;

        default:
            L2CAP_TRACE_WARNING ("LE-L2CAP - st: W4_L2CAP_LE_CON_RSP unhandled evt:%d",
                    event);
            break;
    }
}

/*******************************************************************************
 **
 ** Function         l2c_csm_w4_l2ca_le_connect_rsp
 **
 ** Description      This function handles events when the le channel is in
 **                  CST_W4_L2CA_CONNECT_RSP state.
 **
 ** Returns          void
 **
 *******************************************************************************/
static void l2c_csm_w4_l2ca_le_connect_rsp (tL2C_CCB *p_ccb, UINT16 event,
        void *p_data)
{
    tL2CA_DISCONNECT_IND_CB *disconnect_ind =
                                p_ccb->p_rcb->api.pL2CA_DisconnectInd_Cb;
    UINT16  local_cid = p_ccb->local_cid;

    L2CAP_TRACE_WARNING ("LE-L2CAP - st: W4_L2CA_LE_CON_RSP evt:%d LCID:0x%04x psm:%d",
            event, p_ccb->local_cid, p_ccb->p_rcb->psm);

    switch (event)
    {
        case L2CEVT_LP_DISCONNECT_IND:    /* Link was disconnected */
            p_ccb->chnl_state = CST_CLOSED;
            l2cu_release_ccb (p_ccb);
            (*disconnect_ind)(local_cid, FALSE);
            break;

        case L2CEVT_L2CA_LE_CONNECT_RSP:
            l2cu_send_peer_le_credit_based_conn_rsp (p_ccb, L2CAP_LE_CONN_OK);
            p_ccb->chnl_state = CST_OPEN;
            dump_le_l2cap_conn_info(0, p_ccb);
            l2c_link_adjust_chnl_allocation ();
            /* stop the Timer */
            btu_stop_timer (&p_ccb->timer_entry);
            break;

        case L2CEVT_L2CA_LE_CONNECT_RSP_NEG:
            /* stop the Timer */
            btu_stop_timer (&p_ccb->timer_entry);
            /* send the response to the remote */
            l2cu_send_peer_le_credit_based_conn_rsp (p_ccb,
                    p_ccb->le_loc_conn_info.result);
            l2cu_release_ccb (p_ccb);
            break;

        case L2CEVT_TIMEOUT:
            l2cu_send_peer_le_credit_based_conn_rsp (p_ccb, L2CAP_LE_CONN_NO_PSM);
            l2cu_release_ccb (p_ccb);
            (*disconnect_ind)(local_cid, FALSE);
            break;

        case L2CEVT_L2CA_DATA_WRITE:    /* Upper layer data to send */
        case L2CEVT_L2CAP_DATA:         /* Peer data packet rcvd    */
            GKI_freebuf (p_data);
            break;

        default:
            L2CAP_TRACE_WARNING ("LE-L2CAP - st: W4_L2CA_LE_CON_RSP unhandled evt:%d",
                    event);
            break;
    }
}

/*******************************************************************************
 **
 ** Function         l2c_le_csm_open
 **
 ** Description      This function handles events when the le channel is in
 **                  OPEN state.
 **
 ** Returns          void
 **
 *******************************************************************************/
static void l2c_le_csm_open (tL2C_CCB *p_ccb, UINT16 event, void *p_data)
{
    tL2CA_DISCONNECT_IND_CB *disconnect_ind =
                                  p_ccb->p_rcb->api.pL2CA_DisconnectInd_Cb;
    tL2CA_DATA_IND_CB       *data_ind = p_ccb->p_rcb->api.pL2CA_DataInd_Cb;
    UINT16                  local_cid = p_ccb->local_cid;

    L2CAP_TRACE_WARNING ("LE-L2CAP - st: OPEN evt:%d LCID:0x%04x psm:%d",
            event, p_ccb->local_cid, p_ccb->p_rcb->psm);

    switch (event)
    {
        case L2CEVT_LP_DISCONNECT_IND:       /* Link was disconnected */
            l2cu_release_ccb (p_ccb);
            (*disconnect_ind)(local_cid, FALSE);
            break;

        case L2CEVT_L2CAP_DISCONNECT_REQ: /* Peer disconnected request */
            p_ccb->chnl_state = CST_W4_L2CA_DISCONNECT_RSP;
            btu_start_timer (&p_ccb->timer_entry, BTU_TTYPE_L2CAP_CHNL,
                    L2CAP_CHNL_DISCONNECT_TOUT);
            (*disconnect_ind)(local_cid, TRUE);
            break;

        case L2CEVT_L2CAP_DATA:  /* Peer data packet rcvd */
            (*data_ind) (local_cid, (BT_HDR *)p_data);
            break;

        case L2CEVT_L2CA_DISCONNECT_REQ:  /* Upper wants to disconnect */
            l2cu_send_peer_disc_req (p_ccb);
            p_ccb->chnl_state = CST_W4_L2CAP_DISCONNECT_RSP;
            btu_start_timer (&p_ccb->timer_entry, BTU_TTYPE_L2CAP_CHNL,
                    L2CAP_CHNL_DISCONNECT_TOUT);
            break;

        case L2CEVT_L2CA_DATA_WRITE:      /* Upper layer data to send */
            l2c_enqueue_peer_data (p_ccb, (BT_HDR *)p_data);
            l2c_link_check_send_pkts (p_ccb->p_lcb, NULL, NULL);
            break;

        default:
            L2CAP_TRACE_WARNING ("LE-L2CAP - st: OPEN unhandled evt:%d",
                    event);
            break;
    }
}

/*******************************************************************************
 **
 ** Function         l2c_csm_w4_l2cap_le_disconnect_rsp
 **
 ** Description      This function handles events when the le channel is in
 **                  CST_W4_L2CAP_DISCONNECT_RSP state.
 **
 ** Returns          void
 **
 *******************************************************************************/
static void l2c_csm_w4_l2cap_le_disconnect_rsp (tL2C_CCB *p_ccb, UINT16 event,
        void *p_data)
{
    tL2CA_DISCONNECT_CFM_CB *disconnect_cfm =
                                     p_ccb->p_rcb->api.pL2CA_DisconnectCfm_Cb;
    UINT16                  local_cid = p_ccb->local_cid;

    L2CAP_TRACE_WARNING ("LE-L2CAP - st: W4_L2CAP_DISC_RSP evt:%d LCID:0x%04x psm:%d",
            event, p_ccb->local_cid, p_ccb->p_rcb->psm);
    switch (event)
    {
        case L2CEVT_L2CAP_DISCONNECT_RSP:  /* Peer disconnect response */
            /* stop the Timer */
            btu_stop_timer (&p_ccb->timer_entry);
            l2cu_release_ccb (p_ccb);
            (*disconnect_cfm)(local_cid, L2CAP_DISC_OK);
            break;

        case L2CEVT_L2CAP_DISCONNECT_REQ:  /* Peer disconnect request  */
            /* disconnection collision */
            /* stop the Timer */
            btu_stop_timer (&p_ccb->timer_entry);
            l2cu_send_peer_disc_rsp (p_ccb->p_lcb, p_ccb->remote_id,
                    p_ccb->local_cid, p_ccb->remote_cid);
            l2cu_release_ccb (p_ccb);
            (*disconnect_cfm)(local_cid, L2CAP_DISC_OK);
            break;

        case L2CEVT_LP_DISCONNECT_IND:    /* Link was disconnected */
        case L2CEVT_TIMEOUT:              /* Timeout */
            l2cu_release_ccb (p_ccb);
            (*disconnect_cfm)(local_cid, L2CAP_DISC_OK);
            break;

        case L2CEVT_L2CAP_DATA:           /* Peer data packet rcvd    */
        case L2CEVT_L2CA_DATA_WRITE:      /* Upper layer data to send */
            GKI_freebuf (p_data);
            break;

        default:
            L2CAP_TRACE_WARNING ("LE-L2CAP - st: W4_L2CAP_DISC_RSP unhandled evt:%d",
                    event);
            break;
    }
}

/*******************************************************************************
 **
 ** Function         l2c_csm_w4_l2ca_le_disconnect_rsp
 **
 ** Description      This function handles events when the le channel is in
 **                  CST_W4_L2CA_DISCONNECT_RSP state.
 **
 ** Returns          void
 **
 *******************************************************************************/
static void l2c_csm_w4_l2ca_le_disconnect_rsp (tL2C_CCB *p_ccb, UINT16 event,
        void *p_data)
{
    tL2CA_DISCONNECT_IND_CB *disconnect_ind =
                                    p_ccb->p_rcb->api.pL2CA_DisconnectInd_Cb;
    UINT16  local_cid = p_ccb->local_cid;

    L2CAP_TRACE_WARNING ("LE-L2CAP - st: W4_L2CA_DISC_RSP evt:%d LCID:0x%04x psm:%d",
            event, p_ccb->local_cid, p_ccb->p_rcb->psm);

    switch (event)
    {
        case L2CEVT_LP_DISCONNECT_IND:   /* Link was disconnected */
            l2cu_release_ccb (p_ccb);
            (*disconnect_ind)(local_cid, FALSE);
            break;

        case L2CEVT_TIMEOUT:
            l2cu_send_peer_disc_rsp (p_ccb->p_lcb, p_ccb->remote_id,
                    p_ccb->local_cid, p_ccb->remote_cid);
            l2cu_release_ccb (p_ccb);
            (*disconnect_ind)(local_cid, FALSE);
            break;

        case L2CEVT_L2CA_DISCONNECT_REQ: /* Upper disconnect request */
        case L2CEVT_L2CA_DISCONNECT_RSP: /* Upper disconnect response */
            l2cu_send_peer_disc_rsp (p_ccb->p_lcb, p_ccb->remote_id,
                    p_ccb->local_cid, p_ccb->remote_cid);
            l2cu_release_ccb (p_ccb);
            break;

        case L2CEVT_L2CAP_DATA:       /* Peer data packet rcvd    */
        case L2CEVT_L2CA_DATA_WRITE:  /* Upper layer data to send */
            GKI_freebuf (p_data);
            break;

        default:
            L2CAP_TRACE_WARNING ("LE-L2CAP - st: W4_L2CA_DISC_RSP unhandled evt:%d",
                    event);
            break;
    }
}
#endif /* LE_L2CAP_CFC_INCLUDED */
