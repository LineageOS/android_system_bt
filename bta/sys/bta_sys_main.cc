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

/* system manager control block definition */
tBTA_SYS_CB bta_sys_cb;

/* trace level */
/* TODO Hard-coded trace levels -  Needs to be configurable */
uint8_t appl_trace_level = BT_TRACE_LEVEL_WARNING;  // APPL_INITIAL_TRACE_LEVEL;
uint8_t btif_trace_level = BT_TRACE_LEVEL_WARNING;

static const tBTA_SYS_REG bta_sys_hw_reg = {bta_sys_sm_execute, NULL};

/* type for action functions */
typedef void (*tBTA_SYS_ACTION)();

/* action function list */
const tBTA_SYS_ACTION bta_sys_action[] = {
    /* device manager local device API events - cf bta_sys.h for events */
    bta_sys_hw_api_enable,        /* 0  BTA_SYS_HW_API_ENABLE_EVT    */
    bta_sys_hw_evt_stack_enabled, /* 2  BTA_SYS_HW_EVT_STACK_ENABLED_EVT */
    bta_sys_hw_api_disable,       /* 3  BTA_SYS_HW_API_DISABLE_EVT     */
    bta_sys_hw_evt_disabled,      /* 4  BTA_SYS_HW_EVT_DISABLED_EVT  */
    bta_sys_hw_error              /* 5   BTA_SYS_HW_ERROR_EVT  */
};

/* state machine action enumeration list */
enum {
  /* device manager local device API events */
  BTA_SYS_HW_API_ENABLE,
  BTA_SYS_HW_EVT_STACK_ENABLED,
  BTA_SYS_HW_API_DISABLE,
  BTA_SYS_HW_EVT_DISABLED,
  BTA_SYS_HW_ERROR
};

#define BTA_SYS_NUM_ACTIONS (BTA_SYS_MAX_EVT & 0x00ff)
#define BTA_SYS_IGNORE BTA_SYS_NUM_ACTIONS

/* state table information */
#define BTA_SYS_ACTIONS 2    /* number of actions */
#define BTA_SYS_NEXT_STATE 2 /* position of next state */
#define BTA_SYS_NUM_COLS 3   /* number of columns in state tables */

/* state table for OFF state */
const uint8_t bta_sys_hw_off[][BTA_SYS_NUM_COLS] = {
    /* Event                    Action 1               Action 2
       Next State */
    /* API_ENABLE    */ {BTA_SYS_HW_API_ENABLE, BTA_SYS_IGNORE,
                         BTA_SYS_HW_STARTING},
    /* STACK_ENABLED */ {BTA_SYS_IGNORE, BTA_SYS_IGNORE, BTA_SYS_HW_ON},
    /* API_DISABLE   */ {BTA_SYS_HW_EVT_DISABLED, BTA_SYS_IGNORE,
                         BTA_SYS_HW_OFF},
    /* EVT_DISABLED  */ {BTA_SYS_IGNORE, BTA_SYS_IGNORE, BTA_SYS_HW_OFF},
    /* EVT_ERROR     */ {BTA_SYS_IGNORE, BTA_SYS_IGNORE, BTA_SYS_HW_OFF}};

const uint8_t bta_sys_hw_starting[][BTA_SYS_NUM_COLS] = {
    /* Event                    Action 1                   Action 2
       Next State */
    /* API_ENABLE    */ {BTA_SYS_IGNORE, BTA_SYS_IGNORE,
                         BTA_SYS_HW_STARTING}, /* wait for completion event */
    /* STACK_ENABLED */ {BTA_SYS_HW_EVT_STACK_ENABLED, BTA_SYS_IGNORE,
                         BTA_SYS_HW_ON},
    /* API_DISABLE   */ {BTA_SYS_IGNORE, BTA_SYS_IGNORE,
                         BTA_SYS_HW_STOPPING}, /* successive disable/enable:
                                                  change state wait for
                                                  completion to disable */
    /* EVT_DISABLED  */ {BTA_SYS_HW_EVT_DISABLED, BTA_SYS_HW_API_ENABLE,
                         BTA_SYS_HW_STARTING}, /* successive enable/disable:
                                                  notify, then restart HW */
    /* EVT_ERROR */ {BTA_SYS_HW_ERROR, BTA_SYS_IGNORE, BTA_SYS_HW_ON}};

const uint8_t bta_sys_hw_on[][BTA_SYS_NUM_COLS] = {
    /* Event                    Action 1                   Action 2
       Next State */
    /* API_ENABLE    */ {BTA_SYS_HW_API_ENABLE, BTA_SYS_IGNORE, BTA_SYS_HW_ON},
    /* STACK_ENABLED */ {BTA_SYS_IGNORE, BTA_SYS_IGNORE, BTA_SYS_HW_ON},
    /* API_DISABLE   */
    {BTA_SYS_HW_API_DISABLE, BTA_SYS_IGNORE,
     BTA_SYS_HW_ON}, /* don't change the state here, as some
                        other modules might be active */
    /* EVT_DISABLED */ {BTA_SYS_HW_ERROR, BTA_SYS_IGNORE, BTA_SYS_HW_ON},
    /* EVT_ERROR */ {BTA_SYS_HW_ERROR, BTA_SYS_IGNORE, BTA_SYS_HW_ON}};

const uint8_t bta_sys_hw_stopping[][BTA_SYS_NUM_COLS] = {
    /* Event                    Action 1                   Action 2
       Next State */
    /* API_ENABLE    */ {BTA_SYS_IGNORE, BTA_SYS_IGNORE,
                         BTA_SYS_HW_STARTING}, /* change state, and wait for
                                                  completion event to enable */
    /* STACK_ENABLED */ {BTA_SYS_HW_EVT_STACK_ENABLED, BTA_SYS_HW_API_DISABLE,
                         BTA_SYS_HW_STOPPING}, /* successive enable/disable:
                                                  notify, then stop */
    /* API_DISABLE   */ {BTA_SYS_IGNORE, BTA_SYS_IGNORE,
                         BTA_SYS_HW_STOPPING}, /* wait for completion event */
    /* EVT_DISABLED  */ {BTA_SYS_HW_EVT_DISABLED, BTA_SYS_IGNORE,
                         BTA_SYS_HW_OFF},
    /* EVT_ERROR     */ {BTA_SYS_HW_API_DISABLE, BTA_SYS_IGNORE,
                         BTA_SYS_HW_STOPPING}};

typedef const uint8_t (*tBTA_SYS_ST_TBL)[BTA_SYS_NUM_COLS];

/* state table */
const tBTA_SYS_ST_TBL bta_sys_st_tbl[] = {
    bta_sys_hw_off,      /* BTA_SYS_HW_OFF */
    bta_sys_hw_starting, /* BTA_SYS_HW_STARTING */
    bta_sys_hw_on,       /* BTA_SYS_HW_ON */
    bta_sys_hw_stopping  /* BTA_SYS_HW_STOPPING */
};

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

  /* register BTA SYS message handler */
  bta_sys_register(BTA_ID_SYS, &bta_sys_hw_reg);

  /* register for BTM notifications */
  BTM_RegisterForDeviceStatusNotif(&bta_sys_hw_btm_cback);

#if (defined BTA_AR_INCLUDED) && (BTA_AR_INCLUDED == TRUE)
  bta_ar_init();
#endif
}

void bta_sys_free(void) {
}

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
bool bta_sys_sm_execute(BT_HDR* p_msg) {
  bool freebuf = true;
  tBTA_SYS_ST_TBL state_table;
  uint8_t action;
  int i;

  APPL_TRACE_EVENT("bta_sys_sm_execute state:%d, event:0x%x", bta_sys_cb.state,
                   p_msg->event);

  /* look up the state table for the current state */
  state_table = bta_sys_st_tbl[bta_sys_cb.state];
  /* update state */
  bta_sys_cb.state = state_table[p_msg->event & 0x00ff][BTA_SYS_NEXT_STATE];

  /* execute action functions */
  for (i = 0; i < BTA_SYS_ACTIONS; i++) {
    action = state_table[p_msg->event & 0x00ff][i];
    if (action != BTA_SYS_IGNORE) {
      (*bta_sys_action[action])();
    } else {
      break;
    }
  }
  return freebuf;
}

void bta_sys_hw_register(tBTA_SYS_HW_CBACK* cback) {
  bta_sys_cb.sys_hw_cback = cback;
}

void bta_sys_hw_unregister() { bta_sys_cb.sys_hw_cback = NULL; }

/*******************************************************************************
 *
 * Function         bta_sys_hw_btm_cback
 *
 * Description     This function is registered by BTA SYS to BTM in order to get
 *                 status notifications
 *
 *
 * Returns
 *
 ******************************************************************************/
void bta_sys_hw_btm_cback(tBTM_DEV_STATUS status) {
  tBTA_SYS_HW_MSG* sys_event =
      (tBTA_SYS_HW_MSG*)osi_malloc(sizeof(tBTA_SYS_HW_MSG));

  APPL_TRACE_DEBUG("%s was called with parameter: %i", __func__, status);

  /* send a message to BTA SYS */
  if (status == BTM_DEV_STATUS_UP) {
    sys_event->hdr.event = BTA_SYS_EVT_STACK_ENABLED_EVT;
  } else if (status == BTM_DEV_STATUS_DOWN) {
    sys_event->hdr.event = BTA_SYS_ERROR_EVT;
  } else {
    /* BTM_DEV_STATUS_CMD_TOUT is ignored for now. */
    osi_free_and_reset((void**)&sys_event);
  }

  if (sys_event) bta_sys_sendmsg(sys_event);
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
  if (bta_sys_cb.bluetooth_active && bta_sys_cb.sys_hw_cback != NULL) {
    bta_sys_cb.sys_hw_cback(BTA_SYS_HW_ERROR_EVT);
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

    /* HW already in use, so directly notify the caller */
    if (bta_sys_cb.sys_hw_cback != NULL)
      bta_sys_cb.sys_hw_cback(BTA_SYS_HW_ON_EVT);
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

  tBTA_SYS_HW_MSG* p_msg =
      (tBTA_SYS_HW_MSG*)osi_malloc(sizeof(tBTA_SYS_HW_MSG));
  p_msg->hdr.event = BTA_SYS_EVT_DISABLED_EVT;

  bta_sys_sendmsg(p_msg);
}

/*******************************************************************************
 *
 * Function         bta_sys_hw_event_disabled
 *
 * Description
 *
 *
 * Returns          success or failure
 *
 ******************************************************************************/
void bta_sys_hw_evt_disabled() {
  if (bta_sys_cb.sys_hw_cback != NULL) {
    bta_sys_cb.sys_hw_cback(BTA_SYS_HW_OFF_EVT);
  }
}

/*******************************************************************************
 *
 * Function         bta_sys_hw_event_stack_enabled
 *
 * Description     we receive this event once the SW side is ready (stack, FW
 *                 download,... ), i.e. we can really start using the device. So
 *                 notify the app.
 *
 * Returns          success or failure
 *
 ******************************************************************************/
void bta_sys_hw_evt_stack_enabled() {
  if (bta_sys_cb.sys_hw_cback != NULL) {
    bta_sys_cb.sys_hw_cback(BTA_SYS_HW_ON_EVT);
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
