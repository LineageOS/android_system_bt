/******************************************************************************
 *
 *  Copyright 2000-2012 Broadcom Corporation
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
 *  This file contains functions that manages ACL link modes.
 *  This includes operations such as active, hold,
 *  park and sniff modes.
 *
 *  This module contains both internal and external (API)
 *  functions. External (API) functions are distinguishable
 *  by their names beginning with uppercase BTM.
 *
 *****************************************************************************/

#define LOG_TAG "bt_btm_pm"

#include <base/strings/stringprintf.h>
#include <cstdint>

#include "bt_target.h"
#include "device/include/controller.h"
#include "device/include/interop.h"
#include "main/shim/dumpsys.h"
#include "main/shim/link_policy.h"
#include "main/shim/shim.h"
#include "osi/include/log.h"
#include "stack/btm/btm_int_types.h"
#include "stack/include/acl_api.h"
#include "stack/include/btm_api.h"
#include "stack/include/btm_api_types.h"
#include "stack/include/btm_status.h"
#include "stack/include/l2cap_hci_link_interface.h"
#include "types/raw_address.h"

void l2c_OnHciModeChangeSendPendingPackets(RawAddress remote);
void btm_sco_chk_pend_unpark(tHCI_STATUS status, uint16_t handle);

extern tBTM_CB btm_cb;

struct StackAclBtmPm {
  tBTM_STATUS btm_pm_snd_md_req(tACL_CONN& p_acl, uint8_t pm_id, int link_ind,
                                const tBTM_PM_PWR_MD* p_mode);
  tBTM_PM_MCB* btm_pm_get_power_manager_from_address(const RawAddress& bda);
  tBTM_PM_MCB* btm_pm_get_power_manager_from_handle(uint16_t handle);
};

namespace {
StackAclBtmPm internal_;

constexpr char kBtmLogTag[] = "ACL";
}

/*****************************************************************************/
/*      to handle different modes                                            */
/*****************************************************************************/
#define BTM_PM_NUM_SET_MODES 3  /* only hold, sniff & park */

#define BTM_PM_GET_MD1 1
#define BTM_PM_GET_MD2 2
#define BTM_PM_GET_COMP 3

uint8_t btm_handle_to_acl_index(uint16_t hci_handle);
tACL_CONN* acl_get_connection_from_address(const RawAddress& bd_addr,
                                           tBT_TRANSPORT transport);
tACL_CONN* acl_get_connection_from_handle(uint16_t handle);

const uint8_t
    btm_pm_md_comp_matrix[BTM_PM_NUM_SET_MODES * BTM_PM_NUM_SET_MODES] = {
        BTM_PM_GET_COMP, BTM_PM_GET_MD2,  BTM_PM_GET_MD2,

        BTM_PM_GET_MD1,  BTM_PM_GET_COMP, BTM_PM_GET_MD1,

        BTM_PM_GET_MD1,  BTM_PM_GET_MD2,  BTM_PM_GET_COMP};

static void send_sniff_subrating(const tACL_CONN& p_acl, uint16_t max_lat,
                                 uint16_t min_rmt_to, uint16_t min_loc_to) {
  btsnd_hcic_sniff_sub_rate(p_acl.hci_handle, max_lat, min_rmt_to, min_loc_to);
  BTM_LogHistory(kBtmLogTag, p_acl.remote_addr, "Sniff subrating",
                 base::StringPrintf(
                     "max_latency:%.2f peer_timeout:%.2f local_timeout:%.2f",
                     ticks_to_seconds(max_lat), ticks_to_seconds(min_rmt_to),
                     ticks_to_seconds(min_loc_to)));
}

/*****************************************************************************/
/*                     P U B L I C  F U N C T I O N S                        */
/*****************************************************************************/
/*******************************************************************************
 *
 * Function         BTM_PmRegister
 *
 * Description      register or deregister with power manager
 *
 * Returns          BTM_SUCCESS if successful,
 *                  BTM_NO_RESOURCES if no room to hold registration
 *                  BTM_ILLEGAL_VALUE
 *
 ******************************************************************************/
tBTM_STATUS BTM_PmRegister(uint8_t mask, uint8_t* p_pm_id,
                           tBTM_PM_STATUS_CBACK* p_cb) {
  int xx;

  if (bluetooth::shim::is_gd_link_policy_enabled()) {
    ASSERT(p_pm_id != nullptr);
    ASSERT(p_cb != nullptr);
    if (mask & BTM_PM_DEREG) {
      return (bluetooth::shim::UnregisterLinkPolicyClient(p_cb))
                 ? (BTM_SUCCESS)
                 : (BTM_NO_RESOURCES);
    } else {
      *p_pm_id = 0;
      return (bluetooth::shim::RegisterLinkPolicyClient(p_cb))
                 ? (BTM_SUCCESS)
                 : (BTM_NO_RESOURCES);
    }
  }

  /* de-register */
  if (mask & BTM_PM_DEREG) {
    if (*p_pm_id >= BTM_MAX_PM_RECORDS) return BTM_ILLEGAL_VALUE;
    btm_cb.acl_cb_.pm_reg_db[*p_pm_id].mask = BTM_PM_REC_NOT_USED;
    return BTM_SUCCESS;
  }

  for (xx = 0; xx < BTM_MAX_PM_RECORDS; xx++) {
    /* find an unused entry */
    if (btm_cb.acl_cb_.pm_reg_db[xx].mask == BTM_PM_REC_NOT_USED) {
      /* if register for notification, should provide callback routine */
      if (mask & BTM_PM_REG_NOTIF) {
        if (p_cb == NULL) return BTM_ILLEGAL_VALUE;
        btm_cb.acl_cb_.pm_reg_db[xx].cback = p_cb;
      }
      btm_cb.acl_cb_.pm_reg_db[xx].mask = mask;
      *p_pm_id = xx;
      return BTM_SUCCESS;
    }
  }

  return BTM_NO_RESOURCES;
}

/*******************************************************************************
 *
 * Function         BTM_SetPowerMode
 *
 * Description      store the mode in control block or
 *                  alter ACL connection behavior.
 *
 * Returns          BTM_SUCCESS if successful,
 *                  BTM_UNKNOWN_ADDR if bd addr is not active or bad
 *
 ******************************************************************************/
tBTM_STATUS BTM_SetPowerMode(uint8_t pm_id, const RawAddress& remote_bda,
                             const tBTM_PM_PWR_MD* p_mode) {
  if (pm_id >= BTM_MAX_PM_RECORDS) {
    pm_id = BTM_PM_SET_ONLY_ID;
  }

  if (!p_mode) {
    LOG_ERROR("pm_id: %u, p_mode is null for %s", unsigned(pm_id),
              remote_bda.ToString().c_str());
    return BTM_ILLEGAL_VALUE;
  }

  tACL_CONN* p_acl =
      acl_get_connection_from_address(remote_bda, BT_TRANSPORT_BR_EDR);
  if (p_acl == nullptr) {
    LOG_WARN("Unable to find acl");
    return BTM_UNKNOWN_ADDR;
  }

  tBTM_PM_MODE mode = p_mode->mode;
  if (!is_legal_power_mode(mode)) {
    LOG_ERROR("Unable to set illegal power mode value:0x%02x", mode);
    return BTM_ILLEGAL_VALUE;
  }

  if (p_mode->mode & BTM_PM_MD_FORCE) {
    LOG_INFO("Attempting to force into this power mode");
    /* take out the force bit */
    mode &= (~BTM_PM_MD_FORCE);
  }

  if (bluetooth::shim::is_gd_link_policy_enabled()) {
    tBTM_PM_PWR_MD power_mode_request = *p_mode;
    power_mode_request.mode &= (~BTM_PM_MD_FORCE);
    return bluetooth::shim::BTM_SetPowerMode(*p_acl, power_mode_request);
  }

  int acl_ind = btm_pm_find_acl_ind(remote_bda);
  if (acl_ind == MAX_L2CAP_LINKS) {
    if (btm_pm_is_le_link(remote_bda)) {
      LOG_ERROR("Setting power mode on le link is unsupported");
      return BTM_MODE_UNSUPPORTED;
    }
    LOG_ERROR("br_edr acl addr:%s is unknown", PRIVATE_ADDRESS(remote_bda));
    return BTM_UNKNOWN_ADDR;
  }

  // per ACL link
  tBTM_PM_MCB* p_cb = &(btm_cb.acl_cb_.pm_mode_db[acl_ind]);

  if (mode != BTM_PM_MD_ACTIVE) {
    const controller_t* controller = controller_get_interface();
    if ((mode == BTM_PM_MD_HOLD && !controller->supports_hold_mode()) ||
        (mode == BTM_PM_MD_SNIFF && !controller->supports_sniff_mode()) ||
        (mode == BTM_PM_MD_PARK && !controller->supports_park_mode()) ||
        interop_match_addr(INTEROP_DISABLE_SNIFF, &remote_bda)) {
      LOG_ERROR("pm_id %u mode %u is not supported for %s", pm_id, mode,
                PRIVATE_ADDRESS(remote_bda));
      return BTM_MODE_UNSUPPORTED;
    }
  }

  if (mode == p_cb->state) {
    /* already in the requested mode and the current interval has less latency
     * than the max */
    if ((mode == BTM_PM_MD_ACTIVE) ||
        ((p_mode->mode & BTM_PM_MD_FORCE) && (p_mode->max >= p_cb->interval) &&
         (p_mode->min <= p_cb->interval)) ||
        ((p_mode->mode & BTM_PM_MD_FORCE) == 0 &&
         (p_mode->max >= p_cb->interval))) {
      LOG_INFO(
          "Device is already in requested mode %d, interval: %d, max: %d, min: "
          "%d",
          p_mode->mode, p_cb->interval, p_mode->max, p_mode->min);
      return BTM_SUCCESS;
    }
  }

  int temp_pm_id = pm_id;
  if (pm_id == BTM_PM_SET_ONLY_ID) {
    temp_pm_id = BTM_MAX_PM_RECORDS;
  }

  /* update mode database */
  if (((pm_id != BTM_PM_SET_ONLY_ID) &&
       (btm_cb.acl_cb_.pm_reg_db[pm_id].mask & BTM_PM_REG_SET)) ||
      ((pm_id == BTM_PM_SET_ONLY_ID) &&
       (btm_cb.acl_cb_.pm_pend_link != MAX_L2CAP_LINKS))) {
    LOG_VERBOSE("saving cmd acl_ind %d temp_pm_id %d", acl_ind, temp_pm_id);
    /* Make sure mask is set to BTM_PM_REG_SET */
    btm_cb.acl_cb_.pm_reg_db[temp_pm_id].mask |= BTM_PM_REG_SET;
    *(&p_cb->req_mode[temp_pm_id]) = *p_mode;
    p_cb->chg_ind = true;
  }

  /* if mode == hold or pending, return */
  if ((p_cb->state == BTM_PM_STS_HOLD) || (p_cb->state == BTM_PM_STS_PENDING) ||
      (btm_cb.acl_cb_.pm_pend_link != MAX_L2CAP_LINKS)) {
    LOG_INFO(
        "Current power mode is hold or pending status or pending links"
        " state:%s[%hhu] pm_pending_link:%hhu",
        power_mode_state_text(p_cb->state).c_str(), p_cb->state,
        btm_cb.acl_cb_.pm_pend_link);
    /* command pending */
    if (acl_ind != btm_cb.acl_cb_.pm_pend_link) {
      p_cb->state |= BTM_PM_STORED_MASK;
      LOG_INFO("Setting stored bitmask for peer:%s",
               PRIVATE_ADDRESS(remote_bda));
    }
    return BTM_CMD_STORED;
  }

  LOG_INFO(
      "Setting power mode for peer:%s current_mode:%s[%hhu] new_mode:%s[%hhu]",
      PRIVATE_ADDRESS(remote_bda), power_mode_state_text(p_cb->state).c_str(),
      p_cb->state, power_mode_text(p_mode->mode).c_str(), p_mode->mode);

  return internal_.btm_pm_snd_md_req(*p_acl, pm_id, acl_ind, p_mode);
}

bool BTM_SetLinkPolicyActiveMode(const RawAddress& remote_bda) {
  tBTM_PM_PWR_MD settings;
  memset((void*)&settings, 0, sizeof(settings));
  settings.mode = BTM_PM_MD_ACTIVE;

  switch (BTM_SetPowerMode(BTM_PM_SET_ONLY_ID, remote_bda, &settings)) {
    case BTM_CMD_STORED:
    case BTM_SUCCESS:
      return true;
    default:
      return false;
  }
}

bool BTM_ReadPowerMode(const RawAddress& remote_bda, tBTM_PM_MODE* p_mode) {
  if (p_mode == nullptr) {
    LOG_ERROR("power mode is nullptr");
    return false;
  }
  tBTM_PM_MCB* p_mcb =
      internal_.btm_pm_get_power_manager_from_address(remote_bda);
  if (p_mcb == nullptr) {
    LOG_WARN("Unknown device:%s", PRIVATE_ADDRESS(remote_bda));
    return false;
  }
  *p_mode = static_cast<tBTM_PM_MODE>(p_mcb->State());
  return true;
}

/*******************************************************************************
 *
 * Function         BTM_SetSsrParams
 *
 * Description      This sends the given SSR parameters for the given ACL
 *                  connection if it is in ACTIVE mode.
 *
 * Input Param      remote_bda - device address of desired ACL connection
 *                  max_lat    - maximum latency (in 0.625ms)(0-0xFFFE)
 *                  min_rmt_to - minimum remote timeout
 *                  min_loc_to - minimum local timeout
 *
 *
 * Returns          BTM_SUCCESS if the HCI command is issued successful,
 *                  BTM_UNKNOWN_ADDR if bd addr is not active or bad
 *                  BTM_CMD_STORED if the command is stored
 *
 ******************************************************************************/
tBTM_STATUS BTM_SetSsrParams(const RawAddress& remote_bda, uint16_t max_lat,
                             uint16_t min_rmt_to, uint16_t min_loc_to) {
  int acl_ind = btm_pm_find_acl_ind(remote_bda);
  if (acl_ind == MAX_L2CAP_LINKS) return (BTM_UNKNOWN_ADDR);

  tBTM_PM_MCB* p_cb = &btm_cb.acl_cb_.pm_mode_db[acl_ind];
  tACL_CONN* p_acl =
      acl_get_connection_from_address(remote_bda, BT_TRANSPORT_BR_EDR);
  if (p_acl == nullptr) {
    LOG_WARN("Unable to find acl for peer:%s", PRIVATE_ADDRESS(remote_bda));
    return BTM_UNKNOWN_ADDR;
  }

  if (bluetooth::shim::is_gd_link_policy_enabled()) {
    return bluetooth::shim::BTM_SetSsrParams(*p_acl, max_lat, min_rmt_to,
                                             min_loc_to);
  }

  if (p_cb->state == BTM_PM_ST_ACTIVE || p_cb->state == BTM_PM_ST_SNIFF) {
    LOG_INFO(
        "Set sniff subrating state:%s[%d] max_latency:0x%04x "
        "min_remote_timeout:0x%04x"
        " min_local_timeout:0x%04x",
        power_mode_state_text(btm_cb.acl_cb_.pm_mode_db[acl_ind].state).c_str(),
        btm_cb.acl_cb_.pm_mode_db[acl_ind].state, max_lat, min_rmt_to,
        min_loc_to);
    send_sniff_subrating(*p_acl, max_lat, min_rmt_to, min_loc_to);
    return BTM_SUCCESS;
  }
  LOG_INFO("pm_mode_db state: %d", btm_cb.acl_cb_.pm_mode_db[acl_ind].state);
  p_cb->max_lat = max_lat;
  p_cb->min_rmt_to = min_rmt_to;
  p_cb->min_loc_to = min_loc_to;
  return BTM_CMD_STORED;
}

/*******************************************************************************
 *
 * Function         btm_pm_reset
 *
 * Description      as a part of the BTM reset process.
 *
 * Returns          void
 *
 ******************************************************************************/
void btm_pm_reset(void) {
  int xx;
  tBTM_PM_STATUS_CBACK* cb = NULL;

  /* clear the pending request for application */
  if ((btm_cb.acl_cb_.pm_pend_id != BTM_PM_SET_ONLY_ID) &&
      (btm_cb.acl_cb_.pm_reg_db[btm_cb.acl_cb_.pm_pend_id].mask &
       BTM_PM_REG_NOTIF)) {
    cb = btm_cb.acl_cb_.pm_reg_db[btm_cb.acl_cb_.pm_pend_id].cback;
  }

  /* clear the register record */
  for (xx = 0; xx < BTM_MAX_PM_RECORDS; xx++) {
    btm_cb.acl_cb_.pm_reg_db[xx].mask = BTM_PM_REC_NOT_USED;
  }

  if (cb != NULL && btm_cb.acl_cb_.pm_pend_link < MAX_L2CAP_LINKS) {
    const RawAddress raw_address =
        btm_cb.acl_cb_.acl_db[btm_cb.acl_cb_.pm_pend_link].remote_addr;
    (*cb)(raw_address, BTM_PM_STS_ERROR, BTM_DEV_RESET, HCI_SUCCESS);
  }
  /* no command pending */
  btm_cb.acl_cb_.pm_pend_link = MAX_L2CAP_LINKS;
  LOG_INFO("reset pm");
}

/*******************************************************************************
 *
 * Function     btm_pm_compare_modes
 * Description  get the "more active" mode of the 2
 * Returns      void
 *
 ******************************************************************************/
static tBTM_PM_PWR_MD* btm_pm_compare_modes(const tBTM_PM_PWR_MD* p_md1,
                                            const tBTM_PM_PWR_MD* p_md2,
                                            tBTM_PM_PWR_MD* p_res) {
  uint8_t res;

  if (p_md1 == NULL) {
    *p_res = *p_md2;
    p_res->mode &= ~BTM_PM_MD_FORCE;

    return p_res;
  }

  if (p_md2->mode == BTM_PM_MD_ACTIVE || p_md1->mode == BTM_PM_MD_ACTIVE) {
    return NULL;
  }

  /* check if force bit is involved */
  if (p_md1->mode & BTM_PM_MD_FORCE) {
    *p_res = *p_md1;
    p_res->mode &= ~BTM_PM_MD_FORCE;
    return p_res;
  }

  if (p_md2->mode & BTM_PM_MD_FORCE) {
    *p_res = *p_md2;
    p_res->mode &= ~BTM_PM_MD_FORCE;
    return p_res;
  }

  res = (p_md1->mode - 1) * BTM_PM_NUM_SET_MODES + (p_md2->mode - 1);
  res = btm_pm_md_comp_matrix[res];
  switch (res) {
    case BTM_PM_GET_MD1:
      *p_res = *p_md1;
      return p_res;

    case BTM_PM_GET_MD2:
      *p_res = *p_md2;
      return p_res;

    case BTM_PM_GET_COMP:
      p_res->mode = p_md1->mode;
      /* min of the two */
      p_res->max = (p_md1->max < p_md2->max) ? (p_md1->max) : (p_md2->max);
      /* max of the two */
      p_res->min = (p_md1->min > p_md2->min) ? (p_md1->min) : (p_md2->min);

      /* the intersection is NULL */
      if (p_res->max < p_res->min) return NULL;

      if (p_res->mode == BTM_PM_MD_SNIFF) {
        /* max of the two */
        p_res->attempt = (p_md1->attempt > p_md2->attempt) ? (p_md1->attempt)
                                                           : (p_md2->attempt);
        p_res->timeout = (p_md1->timeout > p_md2->timeout) ? (p_md1->timeout)
                                                           : (p_md2->timeout);
      }
      return p_res;
  }
  return NULL;
}

/*******************************************************************************
 *
 * Function     btm_pm_get_set_mode
 * Description  get the resulting mode from the registered parties, then compare
 *              it with the requested mode, if the command is from an
 *              unregistered party.
 *
 * Returns      void
 *
 ******************************************************************************/
static tBTM_PM_MODE btm_pm_get_set_mode(uint8_t pm_id, tBTM_PM_MCB* p_cb,
                                        const tBTM_PM_PWR_MD* p_mode,
                                        tBTM_PM_PWR_MD* p_res) {
  int xx, loop_max;
  tBTM_PM_PWR_MD* p_md = NULL;

  if (p_mode != NULL && p_mode->mode & BTM_PM_MD_FORCE) {
    *p_res = *p_mode;
    p_res->mode &= ~BTM_PM_MD_FORCE;
    return p_res->mode;
  }

  if (!p_mode)
    loop_max = BTM_MAX_PM_RECORDS + 1;
  else
    loop_max = BTM_MAX_PM_RECORDS;

  for (xx = 0; xx < loop_max; xx++) {
    /* g through all the registered "set" parties */
    if (btm_cb.acl_cb_.pm_reg_db[xx].mask & BTM_PM_REG_SET) {
      if (p_cb->req_mode[xx].mode == BTM_PM_MD_ACTIVE) {
        /* if at least one registered (SET) party says ACTIVE, stay active */
        return BTM_PM_MD_ACTIVE;
      } else {
        /* if registered parties give conflicting information, stay active */
        if ((btm_pm_compare_modes(p_md, &p_cb->req_mode[xx], p_res)) == NULL)
          return BTM_PM_MD_ACTIVE;
        p_md = p_res;
      }
    }
  }

  /* if the resulting mode is NULL(nobody registers SET), use the requested mode
   */
  if (p_md == NULL) {
    if (p_mode)
      *p_res = *((tBTM_PM_PWR_MD*)p_mode);
    else /* p_mode is NULL when internal_.btm_pm_snd_md_req is called from
            btm_pm_proc_mode_change */
      return BTM_PM_MD_ACTIVE;
  } else {
    /* if the command is from unregistered party,
       compare the resulting mode from registered party*/
    if ((pm_id == BTM_PM_SET_ONLY_ID) &&
        ((btm_pm_compare_modes(p_mode, p_md, p_res)) == NULL))
      return BTM_PM_MD_ACTIVE;
  }

  return p_res->mode;
}

/*******************************************************************************
 *
 * Function     btm_pm_snd_md_req
 * Description  get the resulting mode and send the resuest to host controller
 * Returns      tBTM_STATUS
 *, bool    *p_chg_ind
 ******************************************************************************/
tBTM_STATUS StackAclBtmPm::btm_pm_snd_md_req(tACL_CONN& p_acl, uint8_t pm_id,
                                             int link_ind,
                                             const tBTM_PM_PWR_MD* p_mode) {
  tBTM_PM_PWR_MD md_res;
  tBTM_PM_MODE mode;
  tBTM_PM_MCB* p_cb = &btm_cb.acl_cb_.pm_mode_db[link_ind];
  bool chg_ind = false;

  mode = btm_pm_get_set_mode(pm_id, p_cb, p_mode, &md_res);
  md_res.mode = mode;

  if (p_cb->State() == mode) {
    LOG_INFO("Link already in requested mode pm_id:%hhu link_ind:%d mode:%d",
             pm_id, link_ind, mode);

    /* already in the resulting mode */
    if ((mode == BTM_PM_MD_ACTIVE) ||
        ((md_res.max >= p_cb->interval) && (md_res.min <= p_cb->interval)))
      return BTM_CMD_STORED;
    /* Otherwise, needs to wake, then sleep */
    chg_ind = true;
  }
  p_cb->chg_ind = chg_ind;

  /* cannot go directly from current mode to resulting mode. */
  if (mode != BTM_PM_MD_ACTIVE && p_cb->State() != BTM_PM_MD_ACTIVE)
    p_cb->chg_ind = true; /* needs to wake, then sleep */

  if (p_cb->chg_ind) /* needs to wake first */
    md_res.mode = BTM_PM_MD_ACTIVE;
  else if (BTM_PM_MD_SNIFF == md_res.mode && p_cb->max_lat) {
    LOG_DEBUG("Sending sniff subrating to controller");
    send_sniff_subrating(btm_cb.acl_cb_.acl_db[link_ind], p_cb->max_lat,
                         p_cb->min_rmt_to, p_cb->min_loc_to);
    p_cb->max_lat = 0;
  }
  /* Default is failure */
  btm_cb.acl_cb_.pm_pend_link = MAX_L2CAP_LINKS;

  /* send the appropriate HCI command */
  btm_cb.acl_cb_.pm_pend_id = pm_id;

  LOG_INFO("Switching from %s[0x%02x] to %s[0x%02x]",
           power_mode_state_text(p_cb->State()).c_str(), p_cb->State(),
           power_mode_state_text(md_res.mode).c_str(), md_res.mode);
  BTM_LogHistory(
      kBtmLogTag, btm_cb.acl_cb_.acl_db[link_ind].remote_addr,
      "Power mode change",
      base::StringPrintf(
          "%s[0x%02x] ==> %s[0x%02x]",
          power_mode_state_text(p_cb->State()).c_str(), p_cb->State(),
          power_mode_state_text(md_res.mode).c_str(), md_res.mode));

  switch (md_res.mode) {
    case BTM_PM_MD_ACTIVE:
      switch (p_cb->State()) {
        case BTM_PM_MD_SNIFF:
          btsnd_hcic_exit_sniff_mode(
              btm_cb.acl_cb_.acl_db[link_ind].hci_handle);
          btm_cb.acl_cb_.pm_pend_link = link_ind;
          break;
        case BTM_PM_MD_PARK:
          btsnd_hcic_exit_park_mode(btm_cb.acl_cb_.acl_db[link_ind].hci_handle);
          btm_cb.acl_cb_.pm_pend_link = link_ind;
          break;
        default:
          /* Failure btm_cb.acl_cb_.pm_pend_link = MAX_L2CAP_LINKS */
          break;
      }
      break;

    case BTM_PM_MD_HOLD:
      btsnd_hcic_hold_mode(btm_cb.acl_cb_.acl_db[link_ind].hci_handle,
                           md_res.max, md_res.min);
      btm_cb.acl_cb_.pm_pend_link = link_ind;
      break;

    case BTM_PM_MD_SNIFF:
      btsnd_hcic_sniff_mode(btm_cb.acl_cb_.acl_db[link_ind].hci_handle,
                            md_res.max, md_res.min, md_res.attempt,
                            md_res.timeout);
      btm_cb.acl_cb_.pm_pend_link = link_ind;
      break;

    case BTM_PM_MD_PARK:
      btsnd_hcic_park_mode(btm_cb.acl_cb_.acl_db[link_ind].hci_handle,
                           md_res.max, md_res.min);
      btm_cb.acl_cb_.pm_pend_link = link_ind;
      break;
    default:
      /* Failure btm_cb.acl_cb_.pm_pend_link = MAX_L2CAP_LINKS */
      break;
  }

  if (btm_cb.acl_cb_.pm_pend_link == MAX_L2CAP_LINKS) {
    /* the command was not sent */
    LOG_ERROR("pm_pending_link maxed out");
    return (BTM_NO_RESOURCES);
  }

  return BTM_CMD_STARTED;
}

tBTM_PM_MCB* StackAclBtmPm::btm_pm_get_power_manager_from_address(
    const RawAddress& bda) {
  int acl_index = btm_pm_find_acl_ind(bda);
  if (acl_index == MAX_L2CAP_LINKS) return nullptr;
  return &(btm_cb.acl_cb_.pm_mode_db[acl_index]);
}

tBTM_PM_MCB* StackAclBtmPm::btm_pm_get_power_manager_from_handle(
    uint16_t handle) {
  int xx = btm_handle_to_acl_index(handle);
  if (xx >= MAX_L2CAP_LINKS) return nullptr;
  return &(btm_cb.acl_cb_.pm_mode_db[xx]);
}

/*******************************************************************************
 *
 * Function         btm_pm_proc_cmd_status
 *
 * Description      This function is called when an HCI command status event
 *                  occurs for power manager related commands.
 *
 * Input Parms      status - status of the event (HCI_SUCCESS if no errors)
 *
 * Returns          none.
 *
 ******************************************************************************/
void btm_pm_proc_cmd_status(tHCI_STATUS status) {
  if (btm_cb.acl_cb_.pm_pend_link == MAX_L2CAP_LINKS) {
    LOG_ERROR("There are no links pending power mode changes");
    return;
  }

  tBTM_PM_MCB* p_cb = &btm_cb.acl_cb_.pm_mode_db[btm_cb.acl_cb_.pm_pend_link];

  // if the command was not successful. Stay in the same state
  tBTM_PM_STATUS pm_status = BTM_PM_STS_ERROR;
  if (status == HCI_SUCCESS) {
    p_cb->state = BTM_PM_ST_PENDING;
    pm_status = BTM_PM_STS_PENDING;
  }

  /* notify the caller is appropriate */
  if ((btm_cb.acl_cb_.pm_pend_id != BTM_PM_SET_ONLY_ID) &&
      (btm_cb.acl_cb_.pm_reg_db[btm_cb.acl_cb_.pm_pend_id].mask &
       BTM_PM_REG_NOTIF)) {
    const RawAddress bd_addr =
        btm_cb.acl_cb_.acl_db[btm_cb.acl_cb_.pm_pend_link].remote_addr;
    LOG_DEBUG("Notifying callback that link power mode is complete peer:%s",
              PRIVATE_ADDRESS(bd_addr));
    (*btm_cb.acl_cb_.pm_reg_db[btm_cb.acl_cb_.pm_pend_id].cback)(
        bd_addr, pm_status, 0, status);
  }

  LOG_INFO("Clearing pending power mode link state:%s",
           power_mode_state_text(p_cb->state).c_str());
  btm_cb.acl_cb_.pm_pend_link = MAX_L2CAP_LINKS;

  /*******************************************************************************
   *
   * Function         btm_pm_check_stored
   *
   * Description      This function is called when an HCI command status event
   *                  occurs to check if there's any PM command issued while
   *                  waiting for HCI command status.
   *
   * Returns          none.
   *
   ******************************************************************************/
  int xx;
  for (xx = 0; xx < MAX_L2CAP_LINKS; xx++) {
    if (btm_cb.acl_cb_.pm_mode_db[xx].state & BTM_PM_STORED_MASK) {
      btm_cb.acl_cb_.pm_mode_db[xx].state &= ~BTM_PM_STORED_MASK;
      LOG_DEBUG("Found another link requiring power mode change:%s",
                PRIVATE_ADDRESS(btm_cb.acl_cb_.acl_db[xx].remote_addr));
      internal_.btm_pm_snd_md_req(btm_cb.acl_cb_.acl_db[xx], BTM_PM_SET_ONLY_ID,
                                  xx, NULL);
      break;
    }
  }
}

/*******************************************************************************
 *
 * Function         btm_process_mode_change
 *
 * Description      This function is called when an HCI mode change event
 *                  occurs.
 *
 * Input Parms      hci_status - status of the event (HCI_SUCCESS if no errors)
 *                  hci_handle - connection handle associated with the change
 *                  mode - HCI_MODE_ACTIVE, HCI_MODE_HOLD, HCI_MODE_SNIFF, or
 *                         HCI_MODE_PARK
 *                  interval - number of baseband slots (meaning depends on
 *                                                       mode)
 *
 * Returns          none.
 *
 ******************************************************************************/
void btm_pm_proc_mode_change(tHCI_STATUS hci_status, uint16_t hci_handle,
                             tHCI_MODE hci_mode, uint16_t interval) {
  tBTM_PM_STATUS mode = static_cast<tBTM_PM_STATUS>(hci_mode);
  int xx, yy, zz;
  tBTM_PM_STATE old_state;

  tACL_CONN* p_acl = acl_get_connection_from_handle(hci_handle);
  if (p_acl == nullptr) {
    LOG_WARN("Unable to find acl");
    return;
  }

  /* get the index to acl_db */
  xx = btm_handle_to_acl_index(hci_handle);
  if (xx >= MAX_L2CAP_LINKS) return;

  const RawAddress bd_addr = acl_address_from_handle(hci_handle);

  /* update control block */
  tBTM_PM_MCB* p_cb =
      internal_.btm_pm_get_power_manager_from_handle(hci_handle);
  if (p_cb == nullptr) {
    LOG_WARN("Unable to find active acl");
    return;
  }

  old_state = p_cb->state;
  p_cb->state = mode;
  p_cb->interval = interval;

  LOG_INFO("Power mode switched from %s[%hhu] to %s[%hhu]",
           power_mode_state_text(old_state).c_str(), old_state,
           power_mode_state_text(p_cb->state).c_str(), p_cb->state);

  if ((p_cb->state == BTM_PM_ST_ACTIVE) || (p_cb->state == BTM_PM_ST_SNIFF)) {
    l2c_OnHciModeChangeSendPendingPackets(bd_addr);
  }

  /* notify registered parties */
  for (yy = 0; yy <= BTM_MAX_PM_RECORDS; yy++) {
    /* set req_mode  HOLD mode->ACTIVE */
    if ((mode == BTM_PM_MD_ACTIVE) &&
        (p_cb->req_mode[yy].mode == BTM_PM_MD_HOLD))
      p_cb->req_mode[yy].mode = BTM_PM_MD_ACTIVE;
  }

  /* new request has been made. - post a message to BTU task */
  if (old_state & BTM_PM_STORED_MASK) {
    LOG_VERBOSE("Sending stored req: %d", xx);
    internal_.btm_pm_snd_md_req(*p_acl, BTM_PM_SET_ONLY_ID, xx, NULL);
  } else {
    for (zz = 0; zz < MAX_L2CAP_LINKS; zz++) {
      if (btm_cb.acl_cb_.pm_mode_db[zz].chg_ind) {
        LOG_VERBOSE("Sending PM req :%d", zz);
        internal_.btm_pm_snd_md_req(btm_cb.acl_cb_.acl_db[zz],
                                    BTM_PM_SET_ONLY_ID, zz, NULL);
        break;
      }
    }
  }

  /* notify registered parties */
  for (yy = 0; yy < BTM_MAX_PM_RECORDS; yy++) {
    if (btm_cb.acl_cb_.pm_reg_db[yy].mask & BTM_PM_REG_NOTIF) {
      (*btm_cb.acl_cb_.pm_reg_db[yy].cback)(bd_addr, mode, interval,
                                            hci_status);
    }
  }
  /*check if sco disconnect  is waiting for the mode change */
  btm_sco_disc_chk_pend_for_modechange(hci_handle);

  /* If mode change was because of an active role switch or change link key */
  btm_cont_rswitch_from_handle(hci_handle);
}

/*******************************************************************************
 *
 * Function         btm_pm_proc_ssr_evt
 *
 * Description      This function is called when an HCI sniff subrating event
 *                  occurs.
 *
 * Returns          none.
 *
 ******************************************************************************/
void process_ssr_event(tHCI_STATUS status, uint16_t handle,
                       UNUSED_ATTR uint16_t max_tx_lat, uint16_t max_rx_lat) {
  const RawAddress bd_addr = acl_address_from_handle(handle);
  if (bd_addr == RawAddress::kEmpty) {
    LOG_WARN("Received sniff subrating event with no active ACL");
    return;
  }

  tBTM_PM_MCB* p_cb = internal_.btm_pm_get_power_manager_from_handle(handle);
  if (p_cb == nullptr) {
    LOG_WARN("Received sniff subrating event with no active ACL");
    return;
  }

  bool use_ssr = true;
  if (p_cb->interval == max_rx_lat) {
    LOG_DEBUG("Sniff subrating unsupported so dropping to legacy sniff mode");
    use_ssr = false;
  } else {
    LOG_DEBUG("Sniff subrating enabled");
  }

  int cnt = 0;
  for (int yy = 0; yy < BTM_MAX_PM_RECORDS; yy++) {
    if (btm_cb.acl_cb_.pm_reg_db[yy].mask & BTM_PM_REG_NOTIF) {
      (*btm_cb.acl_cb_.pm_reg_db[yy].cback)(bd_addr, BTM_PM_STS_SSR,
                                            (use_ssr) ? 1 : 0, status);
      cnt++;
    }
  }
  LOG_DEBUG(
      "Notified sniff subrating registered clients cnt:%d peer:%s use_ssr:%s "
      "status:%s",
      cnt, PRIVATE_ADDRESS(bd_addr), logbool(use_ssr).c_str(),
      hci_error_code_text(status).c_str());
}

void btm_pm_on_sniff_subrating(tHCI_STATUS status, uint16_t handle,
                               uint16_t maximum_transmit_latency,
                               uint16_t maximum_receive_latency,
                               uint16_t minimum_remote_timeout,
                               uint16_t minimum_local_timeout) {
  if (bluetooth::shim::is_gd_link_policy_enabled()) {
    return bluetooth::shim::btm_pm_on_sniff_subrating(
        status, handle, maximum_transmit_latency, maximum_receive_latency,
        minimum_remote_timeout, minimum_local_timeout);
  }
  process_ssr_event(status, handle, maximum_transmit_latency,
                    maximum_receive_latency);
}

void btm_pm_proc_ssr_evt(uint8_t* p, UNUSED_ATTR uint16_t evt_len) {
  uint8_t status;
  uint16_t handle;
  uint16_t max_tx_lat;
  uint16_t max_rx_lat;

  STREAM_TO_UINT8(status, p);
  STREAM_TO_UINT16(handle, p);
  STREAM_TO_UINT16(max_tx_lat, p);
  STREAM_TO_UINT16(max_rx_lat, p);

  process_ssr_event(static_cast<tHCI_STATUS>(status), handle, max_tx_lat,
                    max_rx_lat);
}

/*******************************************************************************
 *
 * Function         btm_pm_device_in_active_or_sniff_mode
 *
 * Description      This function is called to check if in active or sniff mode
 *
 * Returns          true, if in active or sniff mode
 *
 ******************************************************************************/
bool btm_pm_device_in_active_or_sniff_mode(void) {
  /* The active state is the highest state-includes connected device and sniff
   * mode*/

  /* Covers active and sniff modes */
  if (BTM_GetNumAclLinks() > 0) {
    BTM_TRACE_DEBUG("%s - ACL links: %d", __func__, BTM_GetNumAclLinks());
    return true;
  }

  /* Check BLE states */
  if (!btm_cb.ble_ctr_cb.is_connection_state_idle()) {
    BTM_TRACE_DEBUG("%s - BLE state is not idle", __func__);
    return true;
  }

  return false;
}

/*******************************************************************************
 *
 * Function         btm_pm_device_in_scan_state
 *
 * Description      This function is called to check if in paging, inquiry or
 *                  connecting mode
 *
 * Returns          true, if in paging, inquiry or connecting mode
 *
 ******************************************************************************/
bool btm_pm_device_in_scan_state(void) {
  /* Scan state-paging, inquiry, and trying to connect */

  /* Check for paging */
  if (btm_cb.is_paging || !fixed_queue_is_empty(btm_cb.page_queue)) {
    BTM_TRACE_DEBUG("btm_pm_device_in_scan_state- paging");
    return true;
  }

  /* Check for inquiry */
  if ((btm_cb.btm_inq_vars.inq_active &
       (BTM_BR_INQ_ACTIVE_MASK | BTM_BLE_INQ_ACTIVE_MASK)) != 0) {
    BTM_TRACE_DEBUG("btm_pm_device_in_scan_state- Inq active");
    return true;
  }

  return false;
}

/*******************************************************************************
 *
 * Function         BTM_PM_ReadControllerState
 *
 * Description      This function is called to obtain the controller state
 *
 * Returns          Controller State-BTM_CONTRL_ACTIVE, BTM_CONTRL_SCAN, and
 *                  BTM_CONTRL_IDLE
 *
 ******************************************************************************/
tBTM_CONTRL_STATE BTM_PM_ReadControllerState(void) {
  if (btm_pm_device_in_active_or_sniff_mode())
    return BTM_CONTRL_ACTIVE;
  else if (btm_pm_device_in_scan_state())
    return BTM_CONTRL_SCAN;
  else
    return BTM_CONTRL_IDLE;
}

void btm_pm_on_mode_change(tHCI_STATUS status, uint16_t handle,
                           tHCI_MODE current_mode, uint16_t interval) {
  if (bluetooth::shim::is_gd_link_policy_enabled()) {
    return bluetooth::shim::btm_pm_on_mode_change(status, handle, current_mode,
                                                  interval);
  }

  btm_sco_chk_pend_unpark(status, handle);
  btm_pm_proc_mode_change(status, handle, current_mode, interval);
}
