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
#include "utl.h"

#if (defined BTA_AR_INCLUDED) && (BTA_AR_INCLUDED == TRUE)
#include "bta_ar_api.h"
#endif

void BTA_dm_sys_hw_cback(tBTA_SYS_HW_EVT status);
void BTA_dm_on_hw_error();

/* system manager control block definition */
tBTA_SYS_CB bta_sys_cb;

/* trace level */
/* TODO Hard-coded trace levels -  Needs to be configurable */
uint8_t appl_trace_level = BT_TRACE_LEVEL_WARNING;  // APPL_INITIAL_TRACE_LEVEL;
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

  appl_trace_level = APPL_INITIAL_TRACE_LEVEL;

#if (defined BTA_AR_INCLUDED) && (BTA_AR_INCLUDED == TRUE)
  bta_ar_init();
#endif
}

void bta_sys_free(void) {
}

void bta_sys_set_state(tBTA_SYS_HW_STATE value) { bta_sys_cb.state = value; }

/*******************************************************************************
 *
 * Function         bta_dm_sm_execute
 *
 * Description      State machine event handling function for DM
 *
 *
 * Returns          void
 *
 ******************************************************************************/
static void bta_sys_sm_execute(tBTA_SYS_HW_EVT event) {
  APPL_TRACE_EVENT("bta_sys_sm_execute state:%d, event:0x%x", bta_sys_cb.state);

  switch (bta_sys_cb.state) {
    case BTA_SYS_HW_OFF:
      switch (event) {
        case BTA_SYS_API_ENABLE_EVT:
          bta_sys_set_state(BTA_SYS_HW_STARTING);
          bta_sys_hw_api_enable();
          break;
        case BTA_SYS_EVT_STACK_ENABLED_EVT:
          bta_sys_set_state(BTA_SYS_HW_ON);
          break;
        case BTA_SYS_API_DISABLE_EVT:
          BTA_dm_sys_hw_cback(BTA_SYS_HW_OFF_EVT);
          break;
        default:
          break;
      }
      break;
    case BTA_SYS_HW_STARTING:
      switch (event) {
        case BTA_SYS_EVT_STACK_ENABLED_EVT:
          bta_sys_set_state(BTA_SYS_HW_ON);
          BTA_dm_sys_hw_cback(BTA_SYS_HW_ON_EVT);
          break;
        case BTA_SYS_API_DISABLE_EVT:
          bta_sys_set_state(BTA_SYS_HW_STOPPING);
          break;
        case BTA_SYS_EVT_DISABLED_EVT:
          bta_sys_set_state(BTA_SYS_HW_STARTING);
          BTA_dm_sys_hw_cback(BTA_SYS_HW_OFF_EVT);
          bta_sys_hw_api_enable();
          break;
        case BTA_SYS_ERROR_EVT:
          bta_sys_set_state(BTA_SYS_HW_ON);
          bta_sys_hw_error();
          break;
        default:
          break;
      }
      break;
    case BTA_SYS_HW_ON:
      switch (event) {
        case BTA_SYS_API_ENABLE_EVT:
          bta_sys_hw_api_enable();
          break;
        case BTA_SYS_API_DISABLE_EVT:
          bta_sys_hw_api_disable();
          break;
        case BTA_SYS_ERROR_EVT:
        case BTA_SYS_EVT_DISABLED_EVT:
          bta_sys_hw_error();
          break;
        default:
          break;
      }
      break;
    case BTA_SYS_HW_STOPPING:
      switch (event) {
        case BTA_SYS_API_ENABLE_EVT:
          bta_sys_set_state(BTA_SYS_HW_STARTING);
          break;
        case BTA_SYS_EVT_STACK_ENABLED_EVT:
          BTA_dm_sys_hw_cback(BTA_SYS_HW_ON_EVT);
          bta_sys_hw_api_disable();
          break;
        case BTA_SYS_EVT_DISABLED_EVT:
          bta_sys_set_state(BTA_SYS_HW_OFF);
          BTA_dm_sys_hw_cback(BTA_SYS_HW_OFF_EVT);
          break;
        case BTA_SYS_ERROR_EVT:
          bta_sys_hw_api_disable();
          break;
        default:
          break;
      }
      break;
    default:
      break;
  }
}

void send_bta_sys_hw_event(tBTA_SYS_HW_EVT event) {
  do_in_main_thread(FROM_HERE, base::Bind(bta_sys_sm_execute, event));
}

/*******************************************************************************
 *
 * Function         bta_sys_hw_error
 *
 * Description     In case the HW device stops answering... Try to turn it off,
 *                 then re-enable all
 *                      previously active SW modules.
 *
 * Returns          success or failure
 *
 ******************************************************************************/
void bta_sys_hw_error() {
  APPL_TRACE_DEBUG("%s", __func__);
  if (bta_sys_cb.bluetooth_active) {
    BTA_dm_on_hw_error();
  }
}

/*******************************************************************************
 *
 * Function         bta_sys_hw_enable
 *
 * Description     this function is called after API enable and HW has been
 *                 turned on
 *
 *
 * Returns          success or failure
 *
 ******************************************************************************/

void bta_sys_hw_api_enable() {
  if (!bta_sys_cb.bluetooth_active && bta_sys_cb.state != BTA_SYS_HW_ON) {
    /* register which HW module was turned on */
    bta_sys_cb.bluetooth_active = true;

    BTM_DeviceReset();
  } else {
    bta_sys_cb.bluetooth_active = true;
    BTA_dm_sys_hw_cback(BTA_SYS_HW_ON_EVT);
  }
}

/*******************************************************************************
 *
 * Function         bta_sys_hw_disable
 *
 * Description     if no other module is using the HW, this function will call
 *                 (if defined) a user-macro to turn off the HW
 *
 *
 * Returns          success or failure
 *
 ******************************************************************************/
void bta_sys_hw_api_disable() {
  /* make sure the related SW blocks were stopped */
  bta_sys_disable();

  /* register which module we turn off */
  bta_sys_cb.bluetooth_active = false;

  /* manually update the state of our system */
  bta_sys_cb.state = BTA_SYS_HW_STOPPING;

  send_bta_sys_hw_event(BTA_SYS_EVT_DISABLED_EVT);
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
void bta_sys_event(BT_HDR* p_msg) {
  uint8_t id;
  bool freebuf = true;

  APPL_TRACE_EVENT("%s: Event 0x%x", __func__, p_msg->event);

  /* get subsystem id from event */
  id = (uint8_t)(p_msg->event >> 8);

  /* verify id and call subsystem event handler */
  if ((id < BTA_ID_MAX) && (bta_sys_cb.reg[id] != NULL)) {
    freebuf = (*bta_sys_cb.reg[id]->evt_hdlr)(p_msg);
  } else {
    APPL_TRACE_WARNING("%s: Received unregistered event id %d", __func__, id);
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

/*******************************************************************************
 *
 * Function         bta_sys_set_trace_level
 *
 * Description      Set trace level for BTA
 *
 * Returns          void
 *
 ******************************************************************************/
void bta_sys_set_trace_level(uint8_t level) { appl_trace_level = level; }
