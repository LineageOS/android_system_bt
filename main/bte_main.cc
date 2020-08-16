/******************************************************************************
 *
 *  Copyright 2009-2012 Broadcom Corporation
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
 *  Filename:      bte_main.cc
 *
 *  Description:   Contains BTE core stack initialization and shutdown code
 *
 ******************************************************************************/

#define LOG_TAG "bt_main"

#include <base/logging.h>
#include <hardware/bluetooth.h>

#include "bt_common.h"
#include "btcore/include/module.h"
#include "bte.h"
#include "btif/include/btif_config.h"
#include "btsnoop.h"
#include "btu.h"
#include "device/include/interop.h"
#include "hci_layer.h"
#include "osi/include/log.h"
#include "osi/include/osi.h"
#include "shim/hci_layer.h"
#include "shim/shim.h"
#include "stack_config.h"

/*******************************************************************************
 *  Static variables
 ******************************************************************************/
static const hci_t* hci;

/*******************************************************************************
 *  Externs
 ******************************************************************************/
extern void btu_hci_msg_process(BT_HDR* p_msg);

/*******************************************************************************
 *  Static functions
 ******************************************************************************/

/******************************************************************************
 *
 * Function         post_to_hci_message_loop
 *
 * Description      Post an HCI event to the main thread
 *
 * Returns          None
 *
 *****************************************************************************/
void post_to_main_message_loop(const base::Location& from_here, BT_HDR* p_msg) {
  if (do_in_main_thread(from_here, base::Bind(&btu_hci_msg_process, p_msg)) !=
      BT_STATUS_SUCCESS) {
    LOG(ERROR) << __func__ << ": do_in_main_thread failed from "
               << from_here.ToString();
  }
}

void bte_main_init(void) {
  hci = hci_layer_get_interface();
  if (!hci) {
    LOG_ERROR("%s could not get hci layer interface.", __func__);
    return;
  }

  hci->set_data_cb(base::Bind(&post_to_main_message_loop));
}

/******************************************************************************
 *
 * Function         bte_main_hci_send
 *
 * Description      BTE MAIN API - This function is called by the upper stack to
 *                  send an HCI message. The function displays a protocol trace
 *                  message (if enabled), and then calls the 'transmit' function
 *                  associated with the currently selected HCI transport
 *
 * Returns          None
 *
 *****************************************************************************/
void bte_main_hci_send(BT_HDR* p_msg, uint16_t event) {
  uint16_t sub_event = event & BT_SUB_EVT_MASK; /* local controller ID */

  p_msg->event = event;

  if ((sub_event == LOCAL_BR_EDR_CONTROLLER_ID) ||
      (sub_event == LOCAL_BLE_CONTROLLER_ID)) {
    hci->transmit_downward(event, p_msg);
  } else {
    APPL_TRACE_ERROR("Invalid Controller ID. Discarding message.");
    osi_free(p_msg);
  }
}
