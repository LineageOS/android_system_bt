/******************************************************************************
 *
 *  Copyright 2002-2012 Broadcom Corporation
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
 *  This file contains HID connection internal definitions
 *
 ******************************************************************************/

#ifndef HID_CONN_H
#define HID_CONN_H

#include "osi/include/alarm.h"

typedef enum : uint8_t {
  HID_CONN_STATE_UNUSED = 0,
  HID_CONN_STATE_CONNECTING_CTRL = 1,
  HID_CONN_STATE_CONNECTING_INTR = 2,
  HID_CONN_STATE_CONFIG = 3,
  HID_CONN_STATE_CONNECTED = 4,
  HID_CONN_STATE_DISCONNECTING = 5,
  HID_CONN_STATE_SECURITY = 6,
} tHID_CONN_STATE;

/* Define the HID Connection Block
*/
typedef struct hid_conn {

  uint8_t conn_state;

#define HID_CONN_FLAGS_IS_ORIG (0x01)
#define HID_CONN_FLAGS_CONGESTED (0x20)
#define HID_CONN_FLAGS_INACTIVE (0x40)

  uint8_t conn_flags;

  uint16_t ctrl_cid;
  uint16_t intr_cid;
  uint16_t rem_mtu_size;
  uint16_t disc_reason; /* Reason for disconnecting (for HID_HDEV_EVT_CLOSE) */
  alarm_t* process_repage_timer;
} tHID_CONN;

#define HID_SEC_CHN 1
#define HID_NOSEC_CHN 2

#define HIDD_SEC_CHN 3

#endif
