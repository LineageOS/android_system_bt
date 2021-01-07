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
 *  This is the main implementation file for the BTA system manager.
 *
 ******************************************************************************/

#define LOG_TAG "bt_bta_sys_main"

#include <base/bind.h>
#include <base/logging.h>
#include <string.h>

#include "bt_common.h"
#include "bta_api.h"
#include "bta_sys.h"
#include "bta_sys_int.h"
#include "btm_api.h"
#include "btu.h"
#include "osi/include/alarm.h"
#include "osi/include/fixed_queue.h"
#include "osi/include/log.h"
#include "osi/include/osi.h"
#include "stack/include/acl_client_callbacks.h"
#include "stack/include/btm_client_interface.h"
#include "utl.h"

void BTIF_dm_on_hw_error();

/* system manager control block definition */
tBTA_SYS_CB bta_sys_cb;

/* trace level */
/* TODO Hard-coded trace levels -  Needs to be configurable */
uint8_t appl_trace_level = APPL_INITIAL_TRACE_LEVEL;
uint8_t btif_trace_level = BT_TRACE_LEVEL_WARNING;

/*******************************************************************************
 *
 * Function         bta_sys_init
 *
 * Description      BTA initialization; called from task initialization.
 *
 *
 * Returns          void
 *
 ******************************************************************************/
void bta_sys_init(void) {
  memset(&bta_sys_cb, 0, sizeof(tBTA_SYS_CB));
}

void bta_set_forward_hw_failures(bool value) {
  bta_sys_cb.forward_hw_failures = value;
}

void BTA_sys_signal_hw_error() {
  if (bta_sys_cb.forward_hw_failures) {
    BTIF_dm_on_hw_error();
  }
}

/*******************************************************************************
 *
 * Function         bta_sys_event
 *
 * Description      BTA event handler; called from task event handler.
 *
 *
 * Returns          void
 *
 ******************************************************************************/
static void bta_sys_event(BT_HDR* p_msg) {
  uint8_t id;
  bool freebuf = true;

  APPL_TRACE_EVENT("%s: Event 0x%x", __func__, p_msg->event);

  /* get subsystem id from event */
  id = (uint8_t)(p_msg->event >> 8);

  /* verify id and call subsystem event handler */
  if ((id < BTA_ID_MAX) && (bta_sys_cb.reg[id] != NULL)) {
    freebuf = (*bta_sys_cb.reg[id]->evt_hdlr)(p_msg);
  } else {
    LOG_INFO("Ignoring receipt of unregistered event id:%s",
             BtaIdSysText(id).c_str());
  }

  if (freebuf) {
    osi_free(p_msg);
  }
}

/*******************************************************************************
 *
 * Function         bta_sys_register
 *
 * Description      Called by other BTA subsystems to register their event
 *                  handler.
 *
 *
 * Returns          void
 *
 ******************************************************************************/
void bta_sys_register(uint8_t id, const tBTA_SYS_REG* p_reg) {
  bta_sys_cb.reg[id] = (tBTA_SYS_REG*)p_reg;
  bta_sys_cb.is_reg[id] = true;
}

/*******************************************************************************
 *
 * Function         bta_sys_deregister
 *
 * Description      Called by other BTA subsystems to de-register
 *                  handler.
 *
 *
 * Returns          void
 *
 ******************************************************************************/
void bta_sys_deregister(uint8_t id) { bta_sys_cb.is_reg[id] = false; }

/*******************************************************************************
 *
 * Function         bta_sys_is_register
 *
 * Description      Called by other BTA subsystems to get registeration
 *                  status.
 *
 *
 * Returns          void
 *
 ******************************************************************************/
bool bta_sys_is_register(uint8_t id) { return bta_sys_cb.is_reg[id]; }

/*******************************************************************************
 *
 * Function         bta_sys_sendmsg
 *
 * Description      Send a GKI message to BTA.  This function is designed to
 *                  optimize sending of messages to BTA.  It is called by BTA
 *                  API functions and call-in functions.
 *
 *                  TODO (apanicke): Add location object as parameter for easier
 *                  future debugging when doing alarm refactor
 *
 *
 * Returns          void
 *
 ******************************************************************************/
void bta_sys_sendmsg(void* p_msg) {
  if (do_in_main_thread(
          FROM_HERE, base::Bind(&bta_sys_event, static_cast<BT_HDR*>(p_msg))) !=
      BT_STATUS_SUCCESS) {
    LOG(ERROR) << __func__ << ": do_in_main_thread failed";
  }
}

void bta_sys_sendmsg_delayed(void* p_msg, const base::TimeDelta& delay) {
  if (do_in_main_thread_delayed(
          FROM_HERE, base::Bind(&bta_sys_event, static_cast<BT_HDR*>(p_msg)),
          delay) != BT_STATUS_SUCCESS) {
    LOG(ERROR) << __func__ << ": do_in_main_thread_delayed failed";
  }
}

/*******************************************************************************
 *
 * Function         bta_sys_start_timer
 *
 * Description      Start a protocol timer for the specified amount
 *                  of time in milliseconds.
 *
 * Returns          void
 *
 ******************************************************************************/
void bta_sys_start_timer(alarm_t* alarm, uint64_t interval_ms, uint16_t event,
                         uint16_t layer_specific) {
  BT_HDR* p_buf = (BT_HDR*)osi_malloc(sizeof(BT_HDR));

  p_buf->event = event;
  p_buf->layer_specific = layer_specific;

  alarm_set_on_mloop(alarm, interval_ms, bta_sys_sendmsg, p_buf);
}

/*******************************************************************************
 *
 * Function         bta_sys_disable
 *
 * Description      For each registered subsystem execute its disable function.
 *
 * Returns          void
 *
 ******************************************************************************/
void bta_sys_disable() {
  int bta_id = BTA_ID_DM_SEARCH;
  int bta_id_max = BTA_ID_BLUETOOTH_MAX;

  for (; bta_id <= bta_id_max; bta_id++) {
    if (bta_sys_cb.reg[bta_id] != NULL) {
      if (bta_sys_cb.is_reg[bta_id] &&
          bta_sys_cb.reg[bta_id]->disable != NULL) {
        (*bta_sys_cb.reg[bta_id]->disable)();
      }
    }
  }
}
