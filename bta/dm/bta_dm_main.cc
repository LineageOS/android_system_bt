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
 *  This is the main implementation file for the BTA device manager.
 *
 ******************************************************************************/

#include "bt_trace.h"
#include "bta/dm/bta_dm_int.h"
#include "stack/include/bt_types.h"

/*****************************************************************************
 * Constants and types
 ****************************************************************************/

tBTA_DM_CB bta_dm_cb;
tBTA_DM_SEARCH_CB bta_dm_search_cb;
tBTA_DM_DI_CB bta_dm_di_cb;

/*******************************************************************************
 *
 * Function         bta_dm_sm_search_disable
 *
 * Description     unregister BTA SEARCH DM
 *
 *
 * Returns          void
 *
 ******************************************************************************/
void bta_dm_search_sm_disable() { bta_sys_deregister(BTA_ID_DM_SEARCH); }

void bta_dm_search_set_state(uint8_t state) { bta_dm_search_cb.state = state; }
uint8_t bta_dm_search_get_state() { return bta_dm_search_cb.state; }

/*******************************************************************************
 *
 * Function         bta_dm_search_sm_execute
 *
 * Description      State machine event handling function for DM
 *
 *
 * Returns          void
 *
 ******************************************************************************/
bool bta_dm_search_sm_execute(BT_HDR_RIGID* p_msg) {
  APPL_TRACE_EVENT("bta_dm_search_sm_execute state:%d, event:0x%x",
                   bta_dm_search_cb.state, p_msg->event);

  tBTA_DM_MSG* message = (tBTA_DM_MSG*)p_msg;
  switch (bta_dm_search_cb.state) {
    case BTA_DM_SEARCH_IDLE:
      switch (p_msg->event) {
        case BTA_DM_API_SEARCH_EVT:
          bta_dm_search_set_state(BTA_DM_SEARCH_ACTIVE);
          bta_dm_search_start(message);
          break;
        case BTA_DM_API_DISCOVER_EVT:
          bta_dm_search_set_state(BTA_DM_DISCOVER_ACTIVE);
          bta_dm_discover(message);
          break;
        case BTA_DM_SDP_RESULT_EVT:
          bta_dm_free_sdp_db();
          break;
        case BTA_DM_DISC_CLOSE_TOUT_EVT:
          bta_dm_close_gatt_conn(message);
          break;
        case BTA_DM_API_QUEUE_SEARCH_EVT:
          bta_dm_queue_search(message);
          break;
        case BTA_DM_API_QUEUE_DISCOVER_EVT:
          bta_dm_queue_disc(message);
          break;
      }
      break;
    case BTA_DM_SEARCH_ACTIVE:
      switch (p_msg->event) {
        case BTA_DM_REMT_NAME_EVT:
          bta_dm_rmt_name(message);
          break;
        case BTA_DM_SDP_RESULT_EVT:
          bta_dm_sdp_result(message);
          break;
        case BTA_DM_SEARCH_CMPL_EVT:
          bta_dm_search_cmpl();
          break;
        case BTA_DM_DISCOVERY_RESULT_EVT:
          bta_dm_search_result(message);
          break;
        case BTA_DM_DISC_CLOSE_TOUT_EVT:
          bta_dm_close_gatt_conn(message);
          break;
        case BTA_DM_API_DISCOVER_EVT:
        case BTA_DM_API_QUEUE_DISCOVER_EVT:
          bta_dm_queue_disc(message);
          break;
      }
      break;
    case BTA_DM_SEARCH_CANCELLING:
      switch (p_msg->event) {
        case BTA_DM_API_SEARCH_EVT:
        case BTA_DM_API_QUEUE_SEARCH_EVT:
          bta_dm_queue_search(message);
          break;
        case BTA_DM_API_DISCOVER_EVT:
        case BTA_DM_API_QUEUE_DISCOVER_EVT:
          bta_dm_queue_disc(message);
          break;
        case BTA_DM_SDP_RESULT_EVT:
        case BTA_DM_REMT_NAME_EVT:
        case BTA_DM_SEARCH_CMPL_EVT:
        case BTA_DM_DISCOVERY_RESULT_EVT:
          bta_dm_search_set_state(BTA_DM_SEARCH_IDLE);
          bta_dm_free_sdp_db();
          bta_dm_search_cancel_notify();
          bta_dm_execute_queued_request();
          break;
      }
      break;
    case BTA_DM_DISCOVER_ACTIVE:
      switch (p_msg->event) {
        case BTA_DM_REMT_NAME_EVT:
          bta_dm_disc_rmt_name(message);
          break;
        case BTA_DM_SDP_RESULT_EVT:
          bta_dm_sdp_result(message);
          break;
        case BTA_DM_SEARCH_CMPL_EVT:
          bta_dm_search_cmpl();
          break;
        case BTA_DM_DISCOVERY_RESULT_EVT:
          bta_dm_disc_result(message);
          break;
        case BTA_DM_API_SEARCH_EVT:
        case BTA_DM_API_QUEUE_SEARCH_EVT:
          bta_dm_queue_search(message);
          break;
        case BTA_DM_API_DISCOVER_EVT:
        case BTA_DM_API_QUEUE_DISCOVER_EVT:
          bta_dm_queue_disc(message);
          break;
      }
      break;
  }
  return true;
}
