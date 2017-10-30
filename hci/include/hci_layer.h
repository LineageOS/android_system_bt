/******************************************************************************
 *
 *  Copyright (C) 2014 Google, Inc.
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

#pragma once

#include <stdbool.h>

#include "osi/include/allocator.h"
#include "osi/include/data_dispatcher.h"
#include "osi/include/fixed_queue.h"
#include "osi/include/future.h"
#include "osi/include/osi.h"
#include "bt_types.h"

#ifdef BLUETOOTH_RTK
#include "bt_hci_bdroid.h"
#endif
static const char HCI_MODULE[] = "hci_module";

///// LEGACY DEFINITIONS /////

/* Message event mask across Host/Controller lib and stack */
#define MSG_EVT_MASK                    0xFF00 /* eq. BT_EVT_MASK */
#define MSG_SUB_EVT_MASK                0x00FF /* eq. BT_SUB_EVT_MASK */

/* Message event ID passed from Host/Controller lib to stack */
#define MSG_HC_TO_STACK_HCI_ERR        0x1300 /* eq. BT_EVT_TO_BTU_HCIT_ERR */
#define MSG_HC_TO_STACK_HCI_ACL        0x1100 /* eq. BT_EVT_TO_BTU_HCI_ACL */
#define MSG_HC_TO_STACK_HCI_SCO        0x1200 /* eq. BT_EVT_TO_BTU_HCI_SCO */
#define MSG_HC_TO_STACK_HCI_EVT        0x1000 /* eq. BT_EVT_TO_BTU_HCI_EVT */
#define MSG_HC_TO_STACK_L2C_SEG_XMIT   0x1900 /* eq. BT_EVT_TO_BTU_L2C_SEG_XMIT */

/* Message event ID passed from stack to vendor lib */
#define MSG_STACK_TO_HC_HCI_ACL        0x2100 /* eq. BT_EVT_TO_LM_HCI_ACL */
#define MSG_STACK_TO_HC_HCI_SCO        0x2200 /* eq. BT_EVT_TO_LM_HCI_SCO */
#define MSG_STACK_TO_HC_HCI_CMD        0x2000 /* eq. BT_EVT_TO_LM_HCI_CMD */

/* Local Bluetooth Controller ID for BR/EDR */
#define LOCAL_BR_EDR_CONTROLLER_ID      0

///// END LEGACY DEFINITIONS /////

typedef struct hci_hal_t hci_hal_t;
typedef struct btsnoop_t btsnoop_t;
typedef struct controller_t controller_t;
typedef struct hci_inject_t hci_inject_t;
typedef struct packet_fragmenter_t packet_fragmenter_t;
typedef struct vendor_t vendor_t;
typedef struct low_power_manager_t low_power_manager_t;

#ifdef BLUETOOTH_RTK
typedef struct {
    uint8_t b[6];
} __packed bdaddr_t;
#else
typedef unsigned char * bdaddr_t;
#endif
typedef uint16_t command_opcode_t;

typedef enum {
  LPM_DISABLE,
  LPM_ENABLE,
  LPM_WAKE_ASSERT,
  LPM_WAKE_DEASSERT
} low_power_command_t;

typedef void (*command_complete_cb)(BT_HDR *response, void *context);
typedef void (*command_status_cb)(uint8_t status, BT_HDR *command, void *context);

#ifdef BLUETOOTH_RTK
typedef void (* p_callback)(void *p_mem);


/******************************************************************************
**  Constants & Macros
******************************************************************************/

/******************************************************************************
**  Type definitions
******************************************************************************/

/** Prototypes for HCI Service interface functions **/
/* Callback function for the returned event of internally issued command */
typedef void (*tINT_CMD_CBACK)(void *p_mem);


/* Initialize transport's control block */
typedef void (*tHCI_INIT)(tINT_CMD_CBACK p_cback,const allocator_t *bufalloc);

/* Do transport's control block clean-up */
typedef void (*tHCI_CLEANUP)(void);

/* Send HCI command/data to the transport */
typedef void (*tHCI_SEND)(HC_BT_HDR *p_msg);

/* Handler for HCI upstream path */
typedef uint16_t (*tHCI_RCV)(uint16_t *byte);





/* Handler for sending HCI command from the local module */
typedef uint8_t (*tHCI_SEND_INT)(uint16_t opcode, HC_BT_HDR *p_buf, \
                                  tINT_CMD_CBACK p_cback);

/* Handler for getting acl data length */
typedef void (*tHCI_ACL_DATA_LEN_HDLR)(void);

/******************************************************************************
**  Extern variables and functions
******************************************************************************/

typedef struct {
    tHCI_INIT init;
    tHCI_CLEANUP cleanup;
    tHCI_SEND send;
    tHCI_SEND_INT send_int_cmd;
    tHCI_ACL_DATA_LEN_HDLR get_acl_max_len;
#ifdef HCI_USE_MCT
    tHCI_RCV evt_rcv;
    tHCI_RCV acl_rcv;
#else
    tHCI_RCV rcv;
#endif
} tHCI_IF;
#endif 
typedef struct hci_t {
  // Send a low power command, if supported and the low power manager is enabled.
  void (*send_low_power_command)(low_power_command_t command);

  // Do the postload sequence (call after the rest of the BT stack initializes).
  void (*do_postload)(void);

  // Register with this data dispatcher to receive events flowing upward out of the HCI layer
  data_dispatcher_t *event_dispatcher;

  // Set the queue to receive ACL data in
  void (*set_data_queue)(fixed_queue_t *queue);
#ifdef BLUETOOTH_RTK
  // Send HCI INT command through the HCI layer
  void (*transmit_int_command)(
      uint16_t opcode,
      void *buffer,
      p_callback callback
  );
#endif

  // Send a command through the HCI layer
  void (*transmit_command)(
      BT_HDR *command,
      command_complete_cb complete_callback,
      command_status_cb status_cb,
      void *context
  );

  future_t *(*transmit_command_futured)(BT_HDR *command);

  // Send some data downward through the HCI layer
  void (*transmit_downward)(data_dispatcher_type_t type, void *data);

  /** SSR cleanup is used in HW reset cases
  ** which would close all the client channels
  ** and turns off the chip*/
  void (*ssr_cleanup)(int reason);
} hci_t;

const hci_t *hci_layer_get_interface();

const hci_t *hci_layer_get_test_interface(
    const allocator_t *buffer_allocator_interface,
    const hci_hal_t *hal_interface,
    const btsnoop_t *btsnoop_interface,
    const hci_inject_t *hci_inject_interface,
    const packet_fragmenter_t *packet_fragmenter_interface,
    const vendor_t *vendor_interface,
    const low_power_manager_t *low_power_manager_interface);

void hci_layer_cleanup_interface();
