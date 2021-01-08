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
 *  this file contains the functions relating to link management. A "link"
 *  is a connection between this device and another device. Only ACL links
 *  are managed.
 *
 ******************************************************************************/
#define LOG_TAG "l2c_link"

#include <cstdint>

#include "device/include/controller.h"
#include "main/shim/l2c_api.h"
#include "main/shim/shim.h"
#include "osi/include/log.h"
#include "osi/include/osi.h"
#include "stack/btm/btm_dev.h"
#include "stack/btm/btm_int_types.h"
#include "stack/btm/btm_sec.h"
#include "stack/include/bt_types.h"
#include "stack/l2cap/l2c_int.h"
#include "types/bt_transport.h"
#include "types/raw_address.h"

extern tBTM_CB btm_cb;

void btm_sco_acl_removed(const RawAddress* bda);
void btm_ble_decrement_link_topology_mask(uint8_t link_role);

static void l2c_link_send_to_lower(tL2C_LCB* p_lcb, BT_HDR* p_buf);
static BT_HDR* l2cu_get_next_buffer_to_send(tL2C_LCB* p_lcb);

/*******************************************************************************
 *
 * Function         l2c_link_hci_conn_req
 *
 * Description      This function is called when an HCI Connection Request
 *                  event is received.
 *
 ******************************************************************************/
void l2c_link_hci_conn_req(const RawAddress& bd_addr) {
  tL2C_LCB* p_lcb;
  tL2C_LCB* p_lcb_cur;
  int xx;
  bool no_links;

  /* See if we have a link control block for the remote device */
  p_lcb = l2cu_find_lcb_by_bd_addr(bd_addr, BT_TRANSPORT_BR_EDR);

  /* If we don't have one, create one and accept the connection. */
  if (!p_lcb) {
    p_lcb = l2cu_allocate_lcb(bd_addr, false, BT_TRANSPORT_BR_EDR);
    if (!p_lcb) {
      btsnd_hcic_reject_conn(bd_addr, HCI_ERR_HOST_REJECT_RESOURCES);
      LOG_ERROR("L2CAP failed to allocate LCB");
      return;
    }

    no_links = true;

    /* If we already have connection, accept as a central */
    for (xx = 0, p_lcb_cur = &l2cb.lcb_pool[0]; xx < MAX_L2CAP_LINKS;
         xx++, p_lcb_cur++) {
      if (p_lcb_cur == p_lcb) continue;

      if (p_lcb_cur->in_use) {
        no_links = false;
        p_lcb->SetLinkRoleAsCentral();
        break;
      }
    }

    if (no_links) {
      if (!btm_dev_support_role_switch(bd_addr))
        p_lcb->SetLinkRoleAsPeripheral();
      else
        p_lcb->SetLinkRoleAsCentral();
    }

    /* Tell the other side we accept the connection */
    acl_accept_connection_request(bd_addr, p_lcb->LinkRole());

    p_lcb->link_state = LST_CONNECTING;

    /* Start a timer waiting for connect complete */
    alarm_set_on_mloop(p_lcb->l2c_lcb_timer, L2CAP_LINK_CONNECT_TIMEOUT_MS,
                       l2c_lcb_timer_timeout, p_lcb);
    return;
  }

  /* We already had a link control block. Check what state it is in
   */
  if ((p_lcb->link_state == LST_CONNECTING) ||
      (p_lcb->link_state == LST_CONNECT_HOLDING)) {
    if (!btm_dev_support_role_switch(bd_addr))
      p_lcb->SetLinkRoleAsPeripheral();
    else
      p_lcb->SetLinkRoleAsCentral();

    acl_accept_connection_request(bd_addr, p_lcb->LinkRole());

    p_lcb->link_state = LST_CONNECTING;
  } else if (p_lcb->link_state == LST_DISCONNECTING) {
    acl_reject_connection_request(bd_addr, HCI_ERR_HOST_REJECT_DEVICE);
  } else {
    LOG_ERROR("L2CAP got conn_req while connected (state:%d). Reject it",
              p_lcb->link_state);
    acl_reject_connection_request(bd_addr, HCI_ERR_CONNECTION_EXISTS);
  }
}

void l2c_link_hci_conn_comp(uint8_t status, uint16_t handle,
                            const RawAddress& p_bda) {
  if (bluetooth::shim::is_gd_l2cap_enabled()) {
    return;
  }
  tL2C_CONN_INFO ci;
  tL2C_LCB* p_lcb;
  tL2C_CCB* p_ccb;

  /* Save the parameters */
  ci.status = status;
  ci.bd_addr = p_bda;

  /* See if we have a link control block for the remote device */
  p_lcb = l2cu_find_lcb_by_bd_addr(ci.bd_addr, BT_TRANSPORT_BR_EDR);

  /* If we don't have one, allocate one */
  if (p_lcb == nullptr) {
    LOG_WARN("No available link control block, try allocate one");
    p_lcb = l2cu_allocate_lcb(ci.bd_addr, false, BT_TRANSPORT_BR_EDR);
    if (p_lcb == nullptr) {
      LOG_WARN("Failed to allocate an LCB");
      return;
    }
    p_lcb->link_state = LST_CONNECTING;
  }

  if ((p_lcb->link_state == LST_CONNECTED) &&
      (status == HCI_ERR_CONNECTION_EXISTS)) {
    LOG_WARN("An ACL connection already exists. Handle:%d", handle);
    return;
  } else if (p_lcb->link_state != LST_CONNECTING) {
    LOG_ERROR("L2CAP got conn_comp in bad state: %d  status: 0x%d",
              p_lcb->link_state, status);

    if (status != HCI_SUCCESS) l2c_link_hci_disc_comp(p_lcb->Handle(), status);

    return;
  }

  /* Save the handle */
  l2cu_set_lcb_handle(*p_lcb, handle);

  if (ci.status == HCI_SUCCESS) {
    /* Connected OK. Change state to connected */
    p_lcb->link_state = LST_CONNECTED;

    /* Get the peer information if the l2cap flow-control/rtrans is supported */
    l2cu_send_peer_info_req(p_lcb, L2CAP_EXTENDED_FEATURES_INFO_TYPE);

    BTM_SetLinkSuperTout(ci.bd_addr, acl_get_link_supervision_timeout());

    /* If dedicated bonding do not process any further */
    if (p_lcb->IsBonding()) {
      if (l2cu_start_post_bond_timer(handle)) return;
    }

    /* Update the timeouts in the hold queue */
    l2c_process_held_packets(false);

    alarm_cancel(p_lcb->l2c_lcb_timer);

    /* For all channels, send the event through their FSMs */
    for (p_ccb = p_lcb->ccb_queue.p_first_ccb; p_ccb;
         p_ccb = p_ccb->p_next_ccb) {
      l2c_csm_execute(p_ccb, L2CEVT_LP_CONNECT_CFM, &ci);
    }

    if (!p_lcb->ccb_queue.p_first_ccb) {
      uint64_t timeout_ms = L2CAP_LINK_STARTUP_TOUT * 1000;
      alarm_set_on_mloop(p_lcb->l2c_lcb_timer, timeout_ms,
                         l2c_lcb_timer_timeout, p_lcb);
    }
  }
  /* Max number of acl connections.                          */
  /* If there's an lcb disconnecting set this one to holding */
  else if ((ci.status == HCI_ERR_MAX_NUM_OF_CONNECTIONS) &&
           l2cu_lcb_disconnecting()) {
    p_lcb->link_state = LST_CONNECT_HOLDING;
    p_lcb->InvalidateHandle();
  } else {
    /* Just in case app decides to try again in the callback context */
    p_lcb->link_state = LST_DISCONNECTING;

    /* Connection failed. For all channels, send the event through */
    /* their FSMs. The CCBs should remove themselves from the LCB  */
    for (p_ccb = p_lcb->ccb_queue.p_first_ccb; p_ccb;) {
      tL2C_CCB* pn = p_ccb->p_next_ccb;

      l2c_csm_execute(p_ccb, L2CEVT_LP_CONNECT_CFM_NEG, &ci);

      p_ccb = pn;
    }

    p_lcb->SetDisconnectReason(status);
    /* Release the LCB */
    if (p_lcb->ccb_queue.p_first_ccb == NULL)
      l2cu_release_lcb(p_lcb);
    else /* there are any CCBs remaining */
    {
      if (ci.status == HCI_ERR_CONNECTION_EXISTS) {
        /* we are in collision situation, wait for connecttion request from
         * controller */
        p_lcb->link_state = LST_CONNECTING;
      } else {
        l2cu_create_conn_br_edr(p_lcb);
      }
    }
  }
  return;
}

/*******************************************************************************
 *
 * Function         l2c_link_sec_comp
 *
 * Description      This function is called when required security procedures
 *                  are completed.
 *
 * Returns          void
 *
 ******************************************************************************/
void l2c_link_sec_comp(const RawAddress* p_bda,
                       UNUSED_ATTR tBT_TRANSPORT transport, void* p_ref_data,
                       uint8_t status) {
  l2c_link_sec_comp2(*p_bda, transport, p_ref_data, status);
}

void l2c_link_sec_comp2(const RawAddress& p_bda,
                        UNUSED_ATTR tBT_TRANSPORT transport, void* p_ref_data,
                        uint8_t status) {
  tL2C_CONN_INFO ci;
  tL2C_LCB* p_lcb;
  tL2C_CCB* p_ccb;
  tL2C_CCB* p_next_ccb;
  uint8_t event;

  LOG_DEBUG("status=%d, BD_ADDR=%s, transport=%d", status,
            p_bda.ToString().c_str(), transport);

  if (status == BTM_SUCCESS_NO_SECURITY) {
    status = BTM_SUCCESS;
  }

  /* Save the parameters */
  ci.status = status;
  ci.bd_addr = p_bda;

  p_lcb = l2cu_find_lcb_by_bd_addr(p_bda, transport);

  /* If we don't have one, this is an error */
  if (!p_lcb) {
    LOG_WARN("L2CAP got sec_comp for unknown BD_ADDR");
    return;
  }

  /* Match p_ccb with p_ref_data returned by sec manager */
  for (p_ccb = p_lcb->ccb_queue.p_first_ccb; p_ccb; p_ccb = p_next_ccb) {
    p_next_ccb = p_ccb->p_next_ccb;

    if (p_ccb == p_ref_data) {
      switch (status) {
        case BTM_SUCCESS:
          event = L2CEVT_SEC_COMP;
          break;

        case BTM_DELAY_CHECK:
          /* start a timer - encryption change not received before L2CAP connect
           * req */
          alarm_set_on_mloop(p_ccb->l2c_ccb_timer,
                             L2CAP_DELAY_CHECK_SM4_TIMEOUT_MS,
                             l2c_ccb_timer_timeout, p_ccb);
          return;

        default:
          event = L2CEVT_SEC_COMP_NEG;
      }
      l2c_csm_execute(p_ccb, event, &ci);
      break;
    }
  }
}

/*******************************************************************************
 *
 * Function         l2c_link_hci_disc_comp
 *
 * Description      This function is called when an HCI Disconnect Complete
 *                  event is received.
 *
 * Returns          true if the link is known about, else false
 *
 ******************************************************************************/
bool l2c_link_hci_disc_comp(uint16_t handle, uint8_t reason) {
  if (bluetooth::shim::is_gd_l2cap_enabled()) {
    return false;
  }

  tL2C_LCB* p_lcb = l2cu_find_lcb_by_handle(handle);
  tL2C_CCB* p_ccb;
  bool status = true;
  bool lcb_is_free = true;

  /* If we don't have one, maybe an SCO link. Send to MM */
  if (!p_lcb) {
    status = false;
  } else {
    /* There can be a case when we rejected PIN code authentication */
    /* otherwise save a new reason */
    if (acl_get_disconnect_reason() != HCI_ERR_HOST_REJECT_SECURITY) {
      acl_set_disconnect_reason(static_cast<tHCI_STATUS>(reason));
    }

    p_lcb->SetDisconnectReason(acl_get_disconnect_reason());

    /* Just in case app decides to try again in the callback context */
    p_lcb->link_state = LST_DISCONNECTING;

    /* Check for BLE and handle that differently */
    if (p_lcb->transport == BT_TRANSPORT_LE)
      btm_ble_decrement_link_topology_mask(p_lcb->LinkRole());
    /* Link is disconnected. For all channels, send the event through */
    /* their FSMs. The CCBs should remove themselves from the LCB     */
    for (p_ccb = p_lcb->ccb_queue.p_first_ccb; p_ccb;) {
      tL2C_CCB* pn = p_ccb->p_next_ccb;

      /* Keep connect pending control block (if exists)
       * Possible Race condition when a reconnect occurs
       * on the channel during a disconnect of link. This
       * ccb will be automatically retried after link disconnect
       * arrives
       */
      if (p_ccb != p_lcb->p_pending_ccb) {
        l2c_csm_execute(p_ccb, L2CEVT_LP_DISCONNECT_IND, &reason);
      }
      p_ccb = pn;
    }

    if (p_lcb->transport == BT_TRANSPORT_BR_EDR)
      /* Tell SCO management to drop any SCOs on this ACL */
      btm_sco_acl_removed(&p_lcb->remote_bd_addr);

    /* If waiting for disconnect and reconnect is pending start the reconnect
       now
       race condition where layer above issued connect request on link that was
       disconnecting
     */
    if (p_lcb->ccb_queue.p_first_ccb != NULL || p_lcb->p_pending_ccb) {
      LOG_DEBUG("l2c_link_hci_disc_comp: Restarting pending ACL request");
      /* Release any held buffers */
      while (!list_is_empty(p_lcb->link_xmit_data_q)) {
        BT_HDR* p_buf =
            static_cast<BT_HDR*>(list_front(p_lcb->link_xmit_data_q));
        list_remove(p_lcb->link_xmit_data_q, p_buf);
        osi_free(p_buf);
      }
      /* for LE link, always drop and re-open to ensure to get LE remote feature
       */
      if (p_lcb->transport == BT_TRANSPORT_LE) {
        btm_acl_removed(handle);
      } else {
        /* If we are going to re-use the LCB without dropping it, release all
        fixed channels
        here */
        int xx;
        for (xx = 0; xx < L2CAP_NUM_FIXED_CHNLS; xx++) {
          if (p_lcb->p_fixed_ccbs[xx] &&
              p_lcb->p_fixed_ccbs[xx] != p_lcb->p_pending_ccb) {
            (*l2cb.fixed_reg[xx].pL2CA_FixedConn_Cb)(
                xx + L2CAP_FIRST_FIXED_CHNL, p_lcb->remote_bd_addr, false,
                p_lcb->DisconnectReason(), p_lcb->transport);
            if (p_lcb->p_fixed_ccbs[xx] == NULL) {
              LOG_ERROR(
                  "unexpected p_fixed_ccbs[%d] is NULL remote_bd_addr = %s "
                  "p_lcb = %p in_use = %d link_state = %d handle = %d "
                  "link_role = %d is_bonding = %d disc_reason = %d transport = "
                  "%d",
                  xx, p_lcb->remote_bd_addr.ToString().c_str(), p_lcb,
                  p_lcb->in_use, p_lcb->link_state, p_lcb->Handle(),
                  p_lcb->LinkRole(), p_lcb->IsBonding(),
                  p_lcb->DisconnectReason(), p_lcb->transport);
            }
            CHECK(p_lcb->p_fixed_ccbs[xx] != NULL);
            l2cu_release_ccb(p_lcb->p_fixed_ccbs[xx]);

            p_lcb->p_fixed_ccbs[xx] = NULL;
          }
        }
      }
      if (p_lcb->transport == BT_TRANSPORT_LE) {
        if (l2cu_create_conn_le(p_lcb))
          lcb_is_free = false; /* still using this lcb */
      } else {
        l2cu_create_conn_br_edr(p_lcb);
        lcb_is_free = false; /* still using this lcb */
      }
    }

    p_lcb->p_pending_ccb = NULL;

    /* Release the LCB */
    if (lcb_is_free) l2cu_release_lcb(p_lcb);
  }

  /* Now that we have a free acl connection, see if any lcbs are pending */
  if (lcb_is_free &&
      ((p_lcb = l2cu_find_lcb_by_state(LST_CONNECT_HOLDING)) != NULL)) {
    /* we found one-- create a connection */
    l2cu_create_conn_br_edr(p_lcb);
  }

  return status;
}

/*******************************************************************************
 *
 * Function         l2c_link_timeout
 *
 * Description      This function is called when a link timer expires
 *
 * Returns          void
 *
 ******************************************************************************/
void l2c_link_timeout(tL2C_LCB* p_lcb) {
  tL2C_CCB* p_ccb;
  tBTM_STATUS rc;

  LOG_DEBUG("L2CAP - l2c_link_timeout() link state:%s is_bonding:%s",
            link_state_text(p_lcb->link_state).c_str(),
            logbool(p_lcb->IsBonding()).c_str());

  /* If link was connecting or disconnecting, clear all channels and drop the
   * LCB */
  if ((p_lcb->link_state == LST_CONNECTING_WAIT_SWITCH) ||
      (p_lcb->link_state == LST_CONNECTING) ||
      (p_lcb->link_state == LST_CONNECT_HOLDING) ||
      (p_lcb->link_state == LST_DISCONNECTING)) {
    p_lcb->p_pending_ccb = NULL;

    /* For all channels, send a disconnect indication event through */
    /* their FSMs. The CCBs should remove themselves from the LCB   */
    for (p_ccb = p_lcb->ccb_queue.p_first_ccb; p_ccb;) {
      tL2C_CCB* pn = p_ccb->p_next_ccb;

      l2c_csm_execute(p_ccb, L2CEVT_LP_DISCONNECT_IND, NULL);

      p_ccb = pn;
    }

    /* Release the LCB */
    l2cu_release_lcb(p_lcb);
  }

  /* If link is connected, check for inactivity timeout */
  if (p_lcb->link_state == LST_CONNECTED) {
    /* If no channels in use, drop the link. */
    if (!p_lcb->ccb_queue.p_first_ccb) {
      uint64_t timeout_ms;
      bool start_timeout = true;

      rc = btm_sec_disconnect(p_lcb->Handle(), HCI_ERR_PEER_USER);

      if (rc == BTM_CMD_STORED) {
        /* Security Manager will take care of disconnecting, state will be
         * updated at that time */
        start_timeout = false;
      } else if (rc == BTM_CMD_STARTED) {
        p_lcb->link_state = LST_DISCONNECTING;
        timeout_ms = L2CAP_LINK_DISCONNECT_TIMEOUT_MS;
      } else if (rc == BTM_SUCCESS) {
        l2cu_process_fixed_disc_cback(p_lcb);
        /* BTM SEC will make sure that link is release (probably after pairing
         * is done) */
        p_lcb->link_state = LST_DISCONNECTING;
        start_timeout = false;
      } else if (rc == BTM_BUSY) {
        /* BTM is still executing security process. Let lcb stay as connected */
        start_timeout = false;
      } else if (p_lcb->IsBonding()) {
        acl_disconnect(p_lcb->remote_bd_addr, p_lcb->transport,
                       HCI_ERR_PEER_USER);
        l2cu_process_fixed_disc_cback(p_lcb);
        p_lcb->link_state = LST_DISCONNECTING;
        timeout_ms = L2CAP_LINK_DISCONNECT_TIMEOUT_MS;
      } else {
        /* probably no buffer to send disconnect */
        timeout_ms = BT_1SEC_TIMEOUT_MS;
      }

      if (start_timeout) {
        alarm_set_on_mloop(p_lcb->l2c_lcb_timer, timeout_ms,
                           l2c_lcb_timer_timeout, p_lcb);
      }
    } else {
      /* Check in case we were flow controlled */
      l2c_link_check_send_pkts(p_lcb, 0, NULL);
    }
  }
}

/*******************************************************************************
 *
 * Function         l2c_info_resp_timer_timeout
 *
 * Description      This function is called when an info request times out
 *
 * Returns          void
 *
 ******************************************************************************/
void l2c_info_resp_timer_timeout(void* data) {
  tL2C_LCB* p_lcb = (tL2C_LCB*)data;
  tL2C_CCB* p_ccb;
  tL2C_CONN_INFO ci;

  /* If we timed out waiting for info response, just continue using basic if
   * allowed */
  if (p_lcb->w4_info_rsp) {
    /* If waiting for security complete, restart the info response timer */
    for (p_ccb = p_lcb->ccb_queue.p_first_ccb; p_ccb;
         p_ccb = p_ccb->p_next_ccb) {
      if ((p_ccb->chnl_state == CST_ORIG_W4_SEC_COMP) ||
          (p_ccb->chnl_state == CST_TERM_W4_SEC_COMP)) {
        alarm_set_on_mloop(p_lcb->info_resp_timer,
                           L2CAP_WAIT_INFO_RSP_TIMEOUT_MS,
                           l2c_info_resp_timer_timeout, p_lcb);
        return;
      }
    }

    p_lcb->w4_info_rsp = false;

    /* If link is in process of being brought up */
    if ((p_lcb->link_state != LST_DISCONNECTED) &&
        (p_lcb->link_state != LST_DISCONNECTING)) {
      /* Notify active channels that peer info is finished */
      if (p_lcb->ccb_queue.p_first_ccb) {
        ci.status = HCI_SUCCESS;
        ci.bd_addr = p_lcb->remote_bd_addr;

        for (p_ccb = p_lcb->ccb_queue.p_first_ccb; p_ccb;
             p_ccb = p_ccb->p_next_ccb) {
          l2c_csm_execute(p_ccb, L2CEVT_L2CAP_INFO_RSP, &ci);
        }
      }
    }
  }
}

/*******************************************************************************
 *
 * Function         l2c_link_adjust_allocation
 *
 * Description      This function is called when a link is created or removed
 *                  to calculate the amount of packets each link may send to
 *                  the HCI without an ack coming back.
 *
 *                  Currently, this is a simple allocation, dividing the
 *                  number of Controller Packets by the number of links. In
 *                  the future, QOS configuration should be examined.
 *
 * Returns          void
 *
 ******************************************************************************/
void l2c_link_adjust_allocation(void) {
  uint16_t qq, yy, qq_remainder;
  tL2C_LCB* p_lcb;
  uint16_t hi_quota, low_quota;
  uint16_t num_lowpri_links = 0;
  uint16_t num_hipri_links = 0;
  uint16_t controller_xmit_quota = l2cb.num_lm_acl_bufs;
  uint16_t high_pri_link_quota = L2CAP_HIGH_PRI_MIN_XMIT_QUOTA_A;
  bool is_share_buffer =
      (l2cb.num_lm_ble_bufs == L2C_DEF_NUM_BLE_BUF_SHARED) ? true : false;

  /* If no links active, reset buffer quotas and controller buffers */
  if (l2cb.num_used_lcbs == 0) {
    l2cb.controller_xmit_window = l2cb.num_lm_acl_bufs;
    l2cb.round_robin_quota = l2cb.round_robin_unacked = 0;
    return;
  }

  /* First, count the links */
  for (yy = 0, p_lcb = &l2cb.lcb_pool[0]; yy < MAX_L2CAP_LINKS; yy++, p_lcb++) {
    if (p_lcb->in_use &&
        (is_share_buffer || p_lcb->transport != BT_TRANSPORT_LE)) {
      if (p_lcb->acl_priority == L2CAP_PRIORITY_HIGH)
        num_hipri_links++;
      else
        num_lowpri_links++;
    }
  }

  /* now adjust high priority link quota */
  low_quota = num_lowpri_links ? 1 : 0;
  while ((num_hipri_links * high_pri_link_quota + low_quota) >
         controller_xmit_quota)
    high_pri_link_quota--;

  /* Work out the xmit quota and buffer quota high and low priorities */
  hi_quota = num_hipri_links * high_pri_link_quota;
  low_quota =
      (hi_quota < controller_xmit_quota) ? controller_xmit_quota - hi_quota : 1;

  /* Work out and save the HCI xmit quota for each low priority link */

  /* If each low priority link cannot have at least one buffer */
  if (num_lowpri_links > low_quota) {
    l2cb.round_robin_quota = low_quota;
    qq = qq_remainder = 1;
  }
  /* If each low priority link can have at least one buffer */
  else if (num_lowpri_links > 0) {
    l2cb.round_robin_quota = 0;
    l2cb.round_robin_unacked = 0;
    qq = low_quota / num_lowpri_links;
    qq_remainder = low_quota % num_lowpri_links;
  }
  /* If no low priority link */
  else {
    l2cb.round_robin_quota = 0;
    l2cb.round_robin_unacked = 0;
    qq = qq_remainder = 1;
  }

  LOG_DEBUG(
      "l2c_link_adjust_allocation  num_hipri: %u  num_lowpri: %u  low_quota: "
      "%u  round_robin_quota: %u  qq: %u",
      num_hipri_links, num_lowpri_links, low_quota, l2cb.round_robin_quota, qq);

  /* Now, assign the quotas to each link */
  for (yy = 0, p_lcb = &l2cb.lcb_pool[0]; yy < MAX_L2CAP_LINKS; yy++, p_lcb++) {
    if (p_lcb->in_use &&
        (is_share_buffer || p_lcb->transport != BT_TRANSPORT_LE)) {
      if (p_lcb->acl_priority == L2CAP_PRIORITY_HIGH) {
        p_lcb->link_xmit_quota = high_pri_link_quota;
      } else {
        /* Safety check in case we switched to round-robin with something
         * outstanding */
        /* if sent_not_acked is added into round_robin_unacked then don't add it
         * again */
        /* l2cap keeps updating sent_not_acked for exiting from round robin */
        if ((p_lcb->link_xmit_quota > 0) && (qq == 0))
          l2cb.round_robin_unacked += p_lcb->sent_not_acked;

        p_lcb->link_xmit_quota = qq;
        if (qq_remainder > 0) {
          p_lcb->link_xmit_quota++;
          qq_remainder--;
        }
      }

      LOG_DEBUG(
          "l2c_link_adjust_allocation LCB %d   Priority: %d  XmitQuota: %d", yy,
          p_lcb->acl_priority, p_lcb->link_xmit_quota);

      LOG_DEBUG("        SentNotAcked: %d  RRUnacked: %d",
                p_lcb->sent_not_acked, l2cb.round_robin_unacked);

      /* There is a special case where we have readjusted the link quotas and */
      /* this link may have sent anything but some other link sent packets so */
      /* so we may need a timer to kick off this link's transmissions. */
      if ((p_lcb->link_state == LST_CONNECTED) &&
          (!list_is_empty(p_lcb->link_xmit_data_q)) &&
          (p_lcb->sent_not_acked < p_lcb->link_xmit_quota)) {
        alarm_set_on_mloop(p_lcb->l2c_lcb_timer,
                           L2CAP_LINK_FLOW_CONTROL_TIMEOUT_MS,
                           l2c_lcb_timer_timeout, p_lcb);
      }
    }
  }
}

/*******************************************************************************
 *
 * Function         l2c_link_adjust_chnl_allocation
 *
 * Description      This function is called to calculate the amount of packets
 *                  each non-F&EC channel may have outstanding.
 *
 *                  Currently, this is a simple allocation, dividing the number
 *                  of packets allocated to the link by the number of channels.
 *                  In the future, QOS configuration should be examined.
 *
 * Returns          void
 *
 ******************************************************************************/
void l2c_link_adjust_chnl_allocation(void) {
  /* assign buffer quota to each channel based on its data rate requirement */
  for (uint8_t xx = 0; xx < MAX_L2CAP_CHANNELS; xx++) {
    tL2C_CCB* p_ccb = l2cb.ccb_pool + xx;

    if (!p_ccb->in_use) continue;

    tL2CAP_CHNL_DATA_RATE data_rate = p_ccb->tx_data_rate + p_ccb->rx_data_rate;
    p_ccb->buff_quota = L2CAP_CBB_DEFAULT_DATA_RATE_BUFF_QUOTA * data_rate;
    LOG_DEBUG(
        "CID:0x%04x FCR Mode:%u Priority:%u TxDataRate:%u RxDataRate:%u "
        "Quota:%u",
        p_ccb->local_cid, p_ccb->peer_cfg.fcr.mode, p_ccb->ccb_priority,
        p_ccb->tx_data_rate, p_ccb->rx_data_rate, p_ccb->buff_quota);

    /* quota may be change so check congestion */
    l2cu_check_channel_congestion(p_ccb);
  }
}

void l2c_link_init() {
  if (bluetooth::shim::is_gd_l2cap_enabled()) {
    // GD L2cap gets this info through GD ACL
    return;
  }

  const controller_t* controller = controller_get_interface();

  l2cb.num_lm_acl_bufs = controller->get_acl_buffer_count_classic();
  l2cb.controller_xmit_window = controller->get_acl_buffer_count_classic();
}

/*******************************************************************************
 *
 * Function         l2c_link_role_changed
 *
 * Description      This function is called whan a link's central/peripheral
 *role change event is received. It simply updates the link control block.
 *
 * Returns          void
 *
 ******************************************************************************/
void l2c_link_role_changed(const RawAddress* bd_addr, uint8_t new_role,
                           uint8_t hci_status) {
  /* Make sure not called from HCI Command Status (bd_addr and new_role are
   * invalid) */
  if (bd_addr != nullptr) {
    /* If here came form hci role change event */
    tL2C_LCB* p_lcb = l2cu_find_lcb_by_bd_addr(*bd_addr, BT_TRANSPORT_BR_EDR);
    if (p_lcb) {
      if (new_role == HCI_ROLE_CENTRAL) {
        p_lcb->SetLinkRoleAsCentral();
      } else {
        p_lcb->SetLinkRoleAsPeripheral();
      }

      /* Reset high priority link if needed */
      if (hci_status == HCI_SUCCESS)
        l2cu_set_acl_priority(*bd_addr, p_lcb->acl_priority, true);
    }
  }

  /* Check if any LCB was waiting for switch to be completed */
  tL2C_LCB* p_lcb = &l2cb.lcb_pool[0];
  for (uint8_t xx = 0; xx < MAX_L2CAP_LINKS; xx++, p_lcb++) {
    if ((p_lcb->in_use) && (p_lcb->link_state == LST_CONNECTING_WAIT_SWITCH)) {
      l2cu_create_conn_after_switch(p_lcb);
    }
  }
}

/*******************************************************************************
 *
 * Function         l2c_pin_code_request
 *
 * Description      This function is called whan a pin-code request is received
 *                  on a connection. If there are no channels active yet on the
 *                  link, it extends the link first connection timer.  Make sure
 *                  that inactivity timer is not extended if PIN code happens
 *                  to be after last ccb released.
 *
 * Returns          void
 *
 ******************************************************************************/
void l2c_pin_code_request(const RawAddress& bd_addr) {
  tL2C_LCB* p_lcb = l2cu_find_lcb_by_bd_addr(bd_addr, BT_TRANSPORT_BR_EDR);

  if ((p_lcb) && (!p_lcb->ccb_queue.p_first_ccb)) {
    alarm_set_on_mloop(p_lcb->l2c_lcb_timer, L2CAP_LINK_CONNECT_EXT_TIMEOUT_MS,
                       l2c_lcb_timer_timeout, p_lcb);
  }
}

/*******************************************************************************
 *
 * Function         l2c_link_check_power_mode
 *
 * Description      This function is called to check power mode.
 *
 * Returns          true if link is going to be active from park
 *                  false if nothing to send or not in park mode
 *
 ******************************************************************************/
static bool l2c_link_check_power_mode(tL2C_LCB* p_lcb) {
  bool need_to_active = false;

  /*
   * We only switch park to active only if we have unsent packets
   */
  if (list_is_empty(p_lcb->link_xmit_data_q)) {
    for (tL2C_CCB* p_ccb = p_lcb->ccb_queue.p_first_ccb; p_ccb;
         p_ccb = p_ccb->p_next_ccb) {
      if (!fixed_queue_is_empty(p_ccb->xmit_hold_q)) {
        need_to_active = true;
        break;
      }
    }
  } else {
    need_to_active = true;
  }

  /* if we have packets to send */
  if (need_to_active && !p_lcb->is_transport_ble()) {
    /* check power mode */
    tBTM_PM_MODE mode;
    if (BTM_ReadPowerMode(p_lcb->remote_bd_addr, &mode)) {
      if (mode == BTM_PM_STS_PENDING) {
        LOG_DEBUG("LCB(0x%x) is in PM pending state", p_lcb->Handle());
        return true;
      }
    }
  }
  return false;
}

/*******************************************************************************
 *
 * Function         l2c_link_check_send_pkts
 *
 * Description      This function is called to check if it can send packets
 *                  to the Host Controller. It may be passed the address of
 *                  a packet to send.
 *
 * Returns          void
 *
 ******************************************************************************/
void l2c_link_check_send_pkts(tL2C_LCB* p_lcb, uint16_t local_cid,
                              BT_HDR* p_buf) {
  bool single_write = false;

  /* Save the channel ID for faster counting */
  if (p_buf) {
    p_buf->event = local_cid;
    if (local_cid != 0) {
      single_write = true;
    }

    p_buf->layer_specific = 0;
    list_append(p_lcb->link_xmit_data_q, p_buf);

    if (p_lcb->link_xmit_quota == 0) {
      if (p_lcb->transport == BT_TRANSPORT_LE)
        l2cb.ble_check_round_robin = true;
      else
        l2cb.check_round_robin = true;
    }
  }

  /* If this is called from uncongested callback context break recursive
   *calling.
   ** This LCB will be served when receiving number of completed packet event.
   */
  if (l2cb.is_cong_cback_context) {
    LOG_INFO("skipping, is_cong_cback_context=true");
    return;
  }

  /* If we are in a scenario where there are not enough buffers for each link to
  ** have at least 1, then do a round-robin for all the LCBs
  */
  if ((p_lcb == NULL) || (p_lcb->link_xmit_quota == 0)) {
    LOG_DEBUG("Round robin");
    if (p_lcb == NULL) {
      p_lcb = l2cb.lcb_pool;
    } else if (!single_write) {
      p_lcb++;
    }

    /* Loop through, starting at the next */
    for (int xx = 0; xx < MAX_L2CAP_LINKS; xx++, p_lcb++) {
      /* Check for wraparound */
      if (p_lcb == &l2cb.lcb_pool[MAX_L2CAP_LINKS]) p_lcb = &l2cb.lcb_pool[0];

      /* If controller window is full, nothing to do */
      if (((l2cb.controller_xmit_window == 0 ||
            (l2cb.round_robin_unacked >= l2cb.round_robin_quota)) &&
           (p_lcb->transport == BT_TRANSPORT_BR_EDR)) ||
          (p_lcb->transport == BT_TRANSPORT_LE &&
           (l2cb.ble_round_robin_unacked >= l2cb.ble_round_robin_quota ||
            l2cb.controller_le_xmit_window == 0))) {
        LOG_DEBUG("Skipping lcb %d due to controller window full", xx);
        continue;
      }

      if ((!p_lcb->in_use) || (p_lcb->partial_segment_being_sent) ||
          (p_lcb->link_state != LST_CONNECTED) ||
          (p_lcb->link_xmit_quota != 0) || (l2c_link_check_power_mode(p_lcb))) {
        LOG_DEBUG("Skipping lcb %d due to quota", xx);
        continue;
      }

      /* See if we can send anything from the Link Queue */
      if (!list_is_empty(p_lcb->link_xmit_data_q)) {
        LOG_DEBUG("Sending to lower layer");
        p_buf = (BT_HDR*)list_front(p_lcb->link_xmit_data_q);
        list_remove(p_lcb->link_xmit_data_q, p_buf);
        l2c_link_send_to_lower(p_lcb, p_buf);
      } else if (single_write) {
        /* If only doing one write, break out */
        LOG_DEBUG("single_write is true, skipping");
        break;
      }
      /* If nothing on the link queue, check the channel queue */
      else {
        LOG_DEBUG("Check next buffer");
        p_buf = l2cu_get_next_buffer_to_send(p_lcb);
        if (p_buf != NULL) {
          LOG_DEBUG("Sending next buffer");
          l2c_link_send_to_lower(p_lcb, p_buf);
        }
      }
    }

    /* If we finished without using up our quota, no need for a safety check */
    if ((l2cb.controller_xmit_window > 0) &&
        (l2cb.round_robin_unacked < l2cb.round_robin_quota) &&
        (p_lcb->transport == BT_TRANSPORT_BR_EDR))
      l2cb.check_round_robin = false;

    if ((l2cb.controller_le_xmit_window > 0) &&
        (l2cb.ble_round_robin_unacked < l2cb.ble_round_robin_quota) &&
        (p_lcb->transport == BT_TRANSPORT_LE))
      l2cb.ble_check_round_robin = false;
  } else /* if this is not round-robin service */
  {
    /* If a partial segment is being sent, can't send anything else */
    if ((p_lcb->partial_segment_being_sent) ||
        (p_lcb->link_state != LST_CONNECTED) ||
        (l2c_link_check_power_mode(p_lcb))) {
      LOG_INFO("A partial segment is being sent, cannot send anything else");
      return;
    }
    LOG_DEBUG(
        "Direct send, transport=%d, xmit_window=%d, le_xmit_window=%d, "
        "sent_not_acked=%d, link_xmit_quota=%d",
        p_lcb->transport, l2cb.controller_xmit_window,
        l2cb.controller_le_xmit_window, p_lcb->sent_not_acked,
        p_lcb->link_xmit_quota);

    /* See if we can send anything from the link queue */
    while (((l2cb.controller_xmit_window != 0 &&
             (p_lcb->transport == BT_TRANSPORT_BR_EDR)) ||
            (l2cb.controller_le_xmit_window != 0 &&
             (p_lcb->transport == BT_TRANSPORT_LE))) &&
           (p_lcb->sent_not_acked < p_lcb->link_xmit_quota)) {
      if (list_is_empty(p_lcb->link_xmit_data_q)) {
        LOG_DEBUG("No transmit data, skipping");
        break;
      }
      LOG_DEBUG("Sending to lower layer");
      p_buf = (BT_HDR*)list_front(p_lcb->link_xmit_data_q);
      list_remove(p_lcb->link_xmit_data_q, p_buf);
      l2c_link_send_to_lower(p_lcb, p_buf);
    }

    if (!single_write) {
      /* See if we can send anything for any channel */
      LOG_DEBUG("Trying to send other data when single_write is false");
      while (((l2cb.controller_xmit_window != 0 &&
               (p_lcb->transport == BT_TRANSPORT_BR_EDR)) ||
              (l2cb.controller_le_xmit_window != 0 &&
               (p_lcb->transport == BT_TRANSPORT_LE))) &&
             (p_lcb->sent_not_acked < p_lcb->link_xmit_quota)) {
        p_buf = l2cu_get_next_buffer_to_send(p_lcb);
        if (p_buf == NULL) {
          LOG_DEBUG("No next buffer, skipping");
          break;
        }
        LOG_DEBUG("Sending to lower layer");
        l2c_link_send_to_lower(p_lcb, p_buf);
      }
    }

    /* There is a special case where we have readjusted the link quotas and  */
    /* this link may have sent anything but some other link sent packets so  */
    /* so we may need a timer to kick off this link's transmissions.         */
    if ((!list_is_empty(p_lcb->link_xmit_data_q)) &&
        (p_lcb->sent_not_acked < p_lcb->link_xmit_quota)) {
      alarm_set_on_mloop(p_lcb->l2c_lcb_timer,
                         L2CAP_LINK_FLOW_CONTROL_TIMEOUT_MS,
                         l2c_lcb_timer_timeout, p_lcb);
    }
  }
}

void l2c_OnHciModeChangeSendPendingPackets(RawAddress remote) {
  tL2C_LCB* p_lcb = l2cu_find_lcb_by_bd_addr(remote, BT_TRANSPORT_BR_EDR);
  if (p_lcb != NULL) {
    /* There might be any pending packets due to SNIFF or PENDING state */
    /* Trigger L2C to start transmission of the pending packets. */
    BTM_TRACE_DEBUG(
        "btm mode change to active; check l2c_link for outgoing packets");
    l2c_link_check_send_pkts(p_lcb, 0, NULL);
  }
}

/*******************************************************************************
 *
 * Function         l2c_link_send_to_lower
 *
 * Description      This function queues the buffer for HCI transmission
 *
 ******************************************************************************/
static void l2c_link_send_to_lower_br_edr(tL2C_LCB* p_lcb, BT_HDR* p_buf) {
  const uint16_t acl_packet_size_classic =
      controller_get_interface()->get_acl_packet_size_classic();
  const uint16_t link_xmit_quota = p_lcb->link_xmit_quota;
  const bool is_bdr_and_fits_in_buffer =
      (p_buf->len <= acl_packet_size_classic);

  if (is_bdr_and_fits_in_buffer) {
    if (link_xmit_quota == 0) {
      l2cb.round_robin_unacked++;
    }
    p_lcb->sent_not_acked++;
    p_buf->layer_specific = 0;
    l2cb.controller_xmit_window--;
  } else {
    uint16_t num_segs =
        (p_buf->len - HCI_DATA_PREAMBLE_SIZE + acl_packet_size_classic - 1) /
        acl_packet_size_classic;

    /* If doing round-robin, then only 1 segment each time */
    if (p_lcb->link_xmit_quota == 0) {
      num_segs = 1;
      p_lcb->partial_segment_being_sent = true;
    } else {
      /* Multi-segment packet. Make sure it can fit */
      if (num_segs > l2cb.controller_xmit_window) {
        num_segs = l2cb.controller_xmit_window;
        p_lcb->partial_segment_being_sent = true;
      }

      if (num_segs > (p_lcb->link_xmit_quota - p_lcb->sent_not_acked)) {
        num_segs = (p_lcb->link_xmit_quota - p_lcb->sent_not_acked);
        p_lcb->partial_segment_being_sent = true;
      }
    }

    p_lcb->sent_not_acked += num_segs;
    p_buf->layer_specific = num_segs;
    l2cb.controller_xmit_window -= num_segs;
    if (p_lcb->link_xmit_quota == 0) l2cb.round_robin_unacked += num_segs;
  }
  acl_send_data_packet_br_edr(p_lcb->remote_bd_addr, p_buf);
  LOG_DEBUG("TotalWin=%d,Hndl=0x%x,Quota=%d,Unack=%d,RRQuota=%d,RRUnack=%d",
            l2cb.controller_xmit_window, p_lcb->Handle(),
            p_lcb->link_xmit_quota, p_lcb->sent_not_acked,
            l2cb.round_robin_quota, l2cb.round_robin_unacked);
}

static void l2c_link_send_to_lower_ble(tL2C_LCB* p_lcb, BT_HDR* p_buf) {
  const uint16_t acl_packet_size_ble =
      controller_get_interface()->get_acl_packet_size_ble();
  const uint16_t link_xmit_quota = p_lcb->link_xmit_quota;
  const bool is_ble_and_fits_in_buffer = (p_buf->len <= acl_packet_size_ble);

  if (is_ble_and_fits_in_buffer) {
    if (link_xmit_quota == 0) {
      l2cb.ble_round_robin_unacked++;
    }
    p_lcb->sent_not_acked++;
    p_buf->layer_specific = 0;
    l2cb.controller_le_xmit_window--;
  } else {
    uint16_t num_segs =
        (p_buf->len - HCI_DATA_PREAMBLE_SIZE + acl_packet_size_ble - 1) /
        acl_packet_size_ble;

    /* If doing round-robin, then only 1 segment each time */
    if (p_lcb->link_xmit_quota == 0) {
      num_segs = 1;
      p_lcb->partial_segment_being_sent = true;
    } else {
      /* Multi-segment packet. Make sure it can fit */
      if (num_segs > l2cb.controller_le_xmit_window) {
        num_segs = l2cb.controller_le_xmit_window;
        p_lcb->partial_segment_being_sent = true;
      }

      if (num_segs > (p_lcb->link_xmit_quota - p_lcb->sent_not_acked)) {
        num_segs = (p_lcb->link_xmit_quota - p_lcb->sent_not_acked);
        p_lcb->partial_segment_being_sent = true;
      }
    }

    p_lcb->sent_not_acked += num_segs;
    p_buf->layer_specific = num_segs;
    l2cb.controller_le_xmit_window -= num_segs;
    if (p_lcb->link_xmit_quota == 0) l2cb.ble_round_robin_unacked += num_segs;
  }
  acl_send_data_packet_ble(p_lcb->remote_bd_addr, p_buf);
  LOG_DEBUG("TotalWin=%d,Hndl=0x%x,Quota=%d,Unack=%d,RRQuota=%d,RRUnack=%d",
            l2cb.controller_le_xmit_window, p_lcb->Handle(),
            p_lcb->link_xmit_quota, p_lcb->sent_not_acked,
            l2cb.ble_round_robin_quota, l2cb.ble_round_robin_unacked);
}

static void l2c_link_send_to_lower(tL2C_LCB* p_lcb, BT_HDR* p_buf) {
  if (p_lcb->transport == BT_TRANSPORT_BR_EDR) {
    l2c_link_send_to_lower_br_edr(p_lcb, p_buf);
  } else {
    l2c_link_send_to_lower_ble(p_lcb, p_buf);
  }
}

/*******************************************************************************
 *
 * Function         l2c_link_process_num_completed_pkts
 *
 * Description      This function is called when a "number-of-completed-packets"
 *                  event is received from the controller. It updates all the
 *                  LCB transmit counts.
 *
 * Returns          void
 *
 ******************************************************************************/
void l2c_link_process_num_completed_pkts(uint8_t* p, uint8_t evt_len) {
  if (bluetooth::shim::is_gd_l2cap_enabled()) {
    return;
  }
  uint8_t num_handles, xx;
  uint16_t handle;
  uint16_t num_sent;
  tL2C_LCB* p_lcb;

  if (evt_len > 0) {
    STREAM_TO_UINT8(num_handles, p);
  } else {
    num_handles = 0;
  }

  if (num_handles > evt_len / (2 * sizeof(uint16_t))) {
    android_errorWriteLog(0x534e4554, "141617601");
    num_handles = evt_len / (2 * sizeof(uint16_t));
  }

  for (xx = 0; xx < num_handles; xx++) {
    STREAM_TO_UINT16(handle, p);
    /* Extract the handle */
    handle = HCID_GET_HANDLE(handle);
    STREAM_TO_UINT16(num_sent, p);

    p_lcb = l2cu_find_lcb_by_handle(handle);

    if (p_lcb) {
      if (p_lcb && (p_lcb->transport == BT_TRANSPORT_LE))
        l2cb.controller_le_xmit_window += num_sent;
      else {
        /* Maintain the total window to the controller */
        l2cb.controller_xmit_window += num_sent;
      }
      /* If doing round-robin, adjust communal counts */
      if (p_lcb->link_xmit_quota == 0) {
        if (p_lcb->transport == BT_TRANSPORT_LE) {
          /* Don't go negative */
          if (l2cb.ble_round_robin_unacked > num_sent)
            l2cb.ble_round_robin_unacked -= num_sent;
          else
            l2cb.ble_round_robin_unacked = 0;
        } else {
          /* Don't go negative */
          if (l2cb.round_robin_unacked > num_sent)
            l2cb.round_robin_unacked -= num_sent;
          else
            l2cb.round_robin_unacked = 0;
        }
      }

      /* Don't go negative */
      if (p_lcb->sent_not_acked > num_sent)
        p_lcb->sent_not_acked -= num_sent;
      else
        p_lcb->sent_not_acked = 0;

      l2c_link_check_send_pkts(p_lcb, 0, NULL);

      /* If we were doing round-robin for low priority links, check 'em */
      if ((p_lcb->acl_priority == L2CAP_PRIORITY_HIGH) &&
          (l2cb.check_round_robin) &&
          (l2cb.round_robin_unacked < l2cb.round_robin_quota)) {
        l2c_link_check_send_pkts(NULL, 0, NULL);
      }
      if ((p_lcb->transport == BT_TRANSPORT_LE) &&
          (p_lcb->acl_priority == L2CAP_PRIORITY_HIGH) &&
          ((l2cb.ble_check_round_robin) &&
           (l2cb.ble_round_robin_unacked < l2cb.ble_round_robin_quota))) {
        l2c_link_check_send_pkts(NULL, 0, NULL);
      }
    }

    if (p_lcb) {
      if (p_lcb->transport == BT_TRANSPORT_LE) {
        LOG_DEBUG("TotalWin=%d,LinkUnack(0x%x)=%d,RRCheck=%d,RRUnack=%d",
                  l2cb.controller_le_xmit_window, p_lcb->Handle(),
                  p_lcb->sent_not_acked, l2cb.ble_check_round_robin,
                  l2cb.ble_round_robin_unacked);
      } else {
        LOG_DEBUG("TotalWin=%d,LinkUnack(0x%x)=%d,RRCheck=%d,RRUnack=%d",
                  l2cb.controller_xmit_window, p_lcb->Handle(),
                  p_lcb->sent_not_acked, l2cb.check_round_robin,
                  l2cb.round_robin_unacked);
      }
    } else {
      LOG_DEBUG("TotalWin=%d  LE_Win: %d, Handle=0x%x, RRCheck=%d, RRUnack=%d",
                l2cb.controller_xmit_window, l2cb.controller_le_xmit_window,
                handle, l2cb.ble_check_round_robin,
                l2cb.ble_round_robin_unacked);
    }
  }
}

void l2c_packets_completed(uint16_t handle, uint16_t num_sent) {
  tL2C_LCB* p_lcb = l2cu_find_lcb_by_handle(handle);
  if (p_lcb == nullptr) {
    LOG_WARN("Received l2c packets completed for unknown ACL");
    return;
  }
  p_lcb->update_outstanding_packets(num_sent);

  switch (p_lcb->transport) {
    case BT_TRANSPORT_BR_EDR:
      l2cb.controller_xmit_window += num_sent;
      if (p_lcb->is_round_robin_scheduling())
        l2cb.update_outstanding_classic_packets(num_sent);
      break;
    case BT_TRANSPORT_LE:
      l2cb.controller_le_xmit_window += num_sent;
      if (p_lcb->is_round_robin_scheduling())
        l2cb.update_outstanding_le_packets(num_sent);
      break;
    default:
      LOG_ERROR("Unknown transport received:%u", p_lcb->transport);
      return;
  }

  l2c_link_check_send_pkts(p_lcb, 0, NULL);

  if (p_lcb->is_high_priority()) {
    switch (p_lcb->transport) {
      case BT_TRANSPORT_LE:
        if (l2cb.ble_check_round_robin &&
            l2cb.is_ble_round_robin_quota_available())
          l2c_link_check_send_pkts(NULL, 0, NULL);
        break;
      case BT_TRANSPORT_BR_EDR:
        if (l2cb.check_round_robin &&
            l2cb.is_classic_round_robin_quota_available()) {
          l2c_link_check_send_pkts(NULL, 0, NULL);
        }
        break;
      default:
        break;
    }
  }
}

/*******************************************************************************
 *
 * Function         l2c_link_segments_xmitted
 *
 * Description      This function is called from the HCI Interface when an ACL
 *                  data packet segment is transmitted.
 *
 * Returns          void
 *
 ******************************************************************************/
void l2c_link_segments_xmitted(BT_HDR* p_msg) {
  uint8_t* p = (uint8_t*)(p_msg + 1) + p_msg->offset;

  /* Extract the handle */
  uint16_t handle{HCI_INVALID_HANDLE};
  STREAM_TO_UINT16(handle, p);
  handle = HCID_GET_HANDLE(handle);

  /* Find the LCB based on the handle */
  tL2C_LCB* p_lcb = l2cu_find_lcb_by_handle(handle);
  if (p_lcb == nullptr) {
    LOG_WARN("Received segment complete for unknown connection handle:%d",
             handle);
    osi_free(p_msg);
    return;
  }

  if (p_lcb->link_state != LST_CONNECTED) {
    LOG_INFO("Received segment complete for unconnected connection handle:%d:",
             handle);
    osi_free(p_msg);
    return;
  }

  /* Enqueue the buffer to the head of the transmit queue, and see */
  /* if we can transmit anything more.                             */
  list_prepend(p_lcb->link_xmit_data_q, p_msg);

  p_lcb->partial_segment_being_sent = false;

  l2c_link_check_send_pkts(p_lcb, 0, NULL);
}

tBTM_STATUS l2cu_ConnectAclForSecurity(const RawAddress& bd_addr) {
  if (bluetooth::shim::is_gd_l2cap_enabled()) {
    bluetooth::shim::L2CA_ConnectForSecurity(bd_addr);
    return BTM_SUCCESS;
  }

  tL2C_LCB* p_lcb = l2cu_find_lcb_by_bd_addr(bd_addr, BT_TRANSPORT_BR_EDR);
  if (p_lcb && (p_lcb->link_state == LST_CONNECTED ||
                p_lcb->link_state == LST_CONNECTING)) {
    LOG_WARN("Connection already exists");
    return BTM_CMD_STARTED;
  }

  /* Make sure an L2cap link control block is available */
  if (!p_lcb &&
      (p_lcb = l2cu_allocate_lcb(bd_addr, true, BT_TRANSPORT_BR_EDR)) == NULL) {
    LOG_WARN("failed allocate LCB for %s", bd_addr.ToString().c_str());
    return BTM_NO_RESOURCES;
  }

  l2cu_create_conn_br_edr(p_lcb);
  btm_acl_set_paging(true);
  return BTM_SUCCESS;
}

void l2cble_update_sec_act(const RawAddress& bd_addr, uint16_t sec_act) {
  tL2C_LCB* lcb = l2cu_find_lcb_by_bd_addr(bd_addr, BT_TRANSPORT_LE);
  lcb->sec_act = sec_act;
}

/******************************************************************************
 *
 * Function         l2cu_get_next_channel_in_rr
 *
 * Description      get the next channel to send on a link. It also adjusts the
 *                  CCB queue to do a basic priority and round-robin scheduling.
 *
 * Returns          pointer to CCB or NULL
 *
 ******************************************************************************/
tL2C_CCB* l2cu_get_next_channel_in_rr(tL2C_LCB* p_lcb) {
  tL2C_CCB* p_serve_ccb = NULL;
  tL2C_CCB* p_ccb;

  int i, j;

  /* scan all of priority until finding a channel to serve */
  for (i = 0; (i < L2CAP_NUM_CHNL_PRIORITY) && (!p_serve_ccb); i++) {
    /* scan all channel within serving priority group until finding a channel to
     * serve */
    for (j = 0; (j < p_lcb->rr_serv[p_lcb->rr_pri].num_ccb) && (!p_serve_ccb);
         j++) {
      /* scaning from next serving channel */
      p_ccb = p_lcb->rr_serv[p_lcb->rr_pri].p_serve_ccb;

      if (!p_ccb) {
        LOG_ERROR("p_serve_ccb is NULL, rr_pri=%d", p_lcb->rr_pri);
        return NULL;
      }

      LOG_DEBUG("RR scan pri=%d, lcid=0x%04x, q_cout=%zu", p_ccb->ccb_priority,
                p_ccb->local_cid, fixed_queue_length(p_ccb->xmit_hold_q));

      /* store the next serving channel */
      /* this channel is the last channel of its priority group */
      if ((p_ccb->p_next_ccb == NULL) ||
          (p_ccb->p_next_ccb->ccb_priority != p_ccb->ccb_priority)) {
        /* next serving channel is set to the first channel in the group */
        p_lcb->rr_serv[p_lcb->rr_pri].p_serve_ccb =
            p_lcb->rr_serv[p_lcb->rr_pri].p_first_ccb;
      } else {
        /* next serving channel is set to the next channel in the group */
        p_lcb->rr_serv[p_lcb->rr_pri].p_serve_ccb = p_ccb->p_next_ccb;
      }

      if (p_ccb->chnl_state != CST_OPEN) continue;

      if (p_ccb->p_lcb->transport == BT_TRANSPORT_LE) {
        LOG_DEBUG("Connection oriented channel");
        if (fixed_queue_is_empty(p_ccb->xmit_hold_q)) continue;

      } else {
        /* eL2CAP option in use */
        if (p_ccb->peer_cfg.fcr.mode != L2CAP_FCR_BASIC_MODE) {
          if (p_ccb->fcrb.wait_ack || p_ccb->fcrb.remote_busy) continue;

          if (fixed_queue_is_empty(p_ccb->fcrb.retrans_q)) {
            if (fixed_queue_is_empty(p_ccb->xmit_hold_q)) continue;

            /* If in eRTM mode, check for window closure */
            if ((p_ccb->peer_cfg.fcr.mode == L2CAP_FCR_ERTM_MODE) &&
                (l2c_fcr_is_flow_controlled(p_ccb)))
              continue;
          }
        } else {
          if (fixed_queue_is_empty(p_ccb->xmit_hold_q)) continue;
        }
      }

      /* found a channel to serve */
      p_serve_ccb = p_ccb;
      /* decrease quota of its priority group */
      p_lcb->rr_serv[p_lcb->rr_pri].quota--;
    }

    /* if there is no more quota of the priority group or no channel to have
     * data to send */
    if ((p_lcb->rr_serv[p_lcb->rr_pri].quota == 0) || (!p_serve_ccb)) {
      /* serve next priority group */
      p_lcb->rr_pri = (p_lcb->rr_pri + 1) % L2CAP_NUM_CHNL_PRIORITY;
      /* initialize its quota */
      p_lcb->rr_serv[p_lcb->rr_pri].quota =
          L2CAP_GET_PRIORITY_QUOTA(p_lcb->rr_pri);
    }
  }

  if (p_serve_ccb) {
    LOG_DEBUG("RR service pri=%d, quota=%d, lcid=0x%04x",
              p_serve_ccb->ccb_priority,
              p_lcb->rr_serv[p_serve_ccb->ccb_priority].quota,
              p_serve_ccb->local_cid);
  }

  return p_serve_ccb;
}

/******************************************************************************
 *
 * Function         l2cu_get_next_buffer_to_send
 *
 * Description      get the next buffer to send on a link. It also adjusts the
 *                  CCB queue to do a basic priority and round-robin scheduling.
 *
 * Returns          pointer to buffer or NULL
 *
 ******************************************************************************/
BT_HDR* l2cu_get_next_buffer_to_send(tL2C_LCB* p_lcb) {
  tL2C_CCB* p_ccb;
  BT_HDR* p_buf;

  /* Highest priority are fixed channels */
  int xx;

  for (xx = 0; xx < L2CAP_NUM_FIXED_CHNLS; xx++) {
    p_ccb = p_lcb->p_fixed_ccbs[xx];
    if (p_ccb == NULL) continue;

    /* eL2CAP option in use */
    if (p_ccb->peer_cfg.fcr.mode != L2CAP_FCR_BASIC_MODE) {
      if (p_ccb->fcrb.wait_ack || p_ccb->fcrb.remote_busy) continue;

      /* No more checks needed if sending from the reatransmit queue */
      if (fixed_queue_is_empty(p_ccb->fcrb.retrans_q)) {
        if (fixed_queue_is_empty(p_ccb->xmit_hold_q)) continue;

        /* If in eRTM mode, check for window closure */
        if ((p_ccb->peer_cfg.fcr.mode == L2CAP_FCR_ERTM_MODE) &&
            (l2c_fcr_is_flow_controlled(p_ccb)))
          continue;
      }

      p_buf = l2c_fcr_get_next_xmit_sdu_seg(p_ccb, 0);
      if (p_buf != NULL) {
        l2cu_check_channel_congestion(p_ccb);
        l2cu_set_acl_hci_header(p_buf, p_ccb);
        return (p_buf);
      }
    } else {
      if (!fixed_queue_is_empty(p_ccb->xmit_hold_q)) {
        p_buf = (BT_HDR*)fixed_queue_try_dequeue(p_ccb->xmit_hold_q);
        if (NULL == p_buf) {
          LOG_ERROR("No data to be sent");
          return (NULL);
        }

        l2cu_check_channel_congestion(p_ccb);
        l2cu_set_acl_hci_header(p_buf, p_ccb);
        return (p_buf);
      }
    }
  }

  /* get next serving channel in round-robin */
  p_ccb = l2cu_get_next_channel_in_rr(p_lcb);

  /* Return if no buffer */
  if (p_ccb == NULL) return (NULL);

  if (p_ccb->p_lcb->transport == BT_TRANSPORT_LE) {
    /* Check credits */
    if (p_ccb->peer_conn_cfg.credits == 0) {
      LOG_DEBUG("No credits to send packets");
      return NULL;
    }

    bool last_piece_of_sdu = false;
    p_buf = l2c_lcc_get_next_xmit_sdu_seg(p_ccb, &last_piece_of_sdu);
    p_ccb->peer_conn_cfg.credits--;

    if (last_piece_of_sdu) {
      // TODO: send callback up the stack. Investigate setting p_cbi->cb to
      // notify after controller ack send.
    }

  } else {
    if (p_ccb->peer_cfg.fcr.mode != L2CAP_FCR_BASIC_MODE) {
      p_buf = l2c_fcr_get_next_xmit_sdu_seg(p_ccb, 0);
      if (p_buf == NULL) return (NULL);
    } else {
      p_buf = (BT_HDR*)fixed_queue_try_dequeue(p_ccb->xmit_hold_q);
      if (NULL == p_buf) {
        LOG_ERROR("#2: No data to be sent");
        return (NULL);
      }
    }
  }

  if (p_ccb->p_rcb && p_ccb->p_rcb->api.pL2CA_TxComplete_Cb &&
      (p_ccb->peer_cfg.fcr.mode != L2CAP_FCR_ERTM_MODE))
    (*p_ccb->p_rcb->api.pL2CA_TxComplete_Cb)(p_ccb->local_cid, 1);

  l2cu_check_channel_congestion(p_ccb);

  l2cu_set_acl_hci_header(p_buf, p_ccb);

  return (p_buf);
}
