/*
 * Copyright 2020 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include <cstdint>

#include "stack/include/bt_types.h"
#include "stack/include/btm_status.h"
#include "types/raw_address.h"

// Note: From include/btm_api_types.h

/*****************************************************************************
 *  ACL CHANNEL MANAGEMENT
 ****************************************************************************/
/******************
 *  ACL Constants
 ******************/

/* ACL Packet Types */
#define BTM_ACL_PKT_TYPES_MASK_DM1 HCI_PKT_TYPES_MASK_DM1
#define BTM_ACL_PKT_TYPES_MASK_DH1 HCI_PKT_TYPES_MASK_DH1
#define BTM_ACL_PKT_TYPES_MASK_DM3 HCI_PKT_TYPES_MASK_DM3
#define BTM_ACL_PKT_TYPES_MASK_DH3 HCI_PKT_TYPES_MASK_DH3
#define BTM_ACL_PKT_TYPES_MASK_DM5 HCI_PKT_TYPES_MASK_DM5
#define BTM_ACL_PKT_TYPES_MASK_DH5 HCI_PKT_TYPES_MASK_DH5
#define BTM_ACL_PKT_TYPES_MASK_NO_2_DH1 HCI_PKT_TYPES_MASK_NO_2_DH1
#define BTM_ACL_PKT_TYPES_MASK_NO_3_DH1 HCI_PKT_TYPES_MASK_NO_3_DH1
#define BTM_ACL_PKT_TYPES_MASK_NO_2_DH3 HCI_PKT_TYPES_MASK_NO_2_DH3
#define BTM_ACL_PKT_TYPES_MASK_NO_3_DH3 HCI_PKT_TYPES_MASK_NO_3_DH3
#define BTM_ACL_PKT_TYPES_MASK_NO_2_DH5 HCI_PKT_TYPES_MASK_NO_2_DH5
#define BTM_ACL_PKT_TYPES_MASK_NO_3_DH5 HCI_PKT_TYPES_MASK_NO_3_DH5

/***************
 *  ACL Types
 ***************/

/* Structure returned with Role Switch information (in tBTM_CMPL_CB callback
 * function) in response to BTM_SwitchRole call.
 */
typedef struct {
  uint8_t hci_status;        /* HCI status returned with the event */
  uint8_t role;              /* HCI_ROLE_MASTER or HCI_ROLE_SLAVE */
  RawAddress remote_bd_addr; /* Remote BD addr involved with the switch */
} tBTM_ROLE_SWITCH_CMPL;

/* Structure returned with QoS information (in tBTM_CMPL_CB callback function)
 * in response to BTM_SetQoS call.
 */
typedef struct {
  FLOW_SPEC flow;
  uint16_t handle;
  uint8_t status;
} tBTM_QOS_SETUP_CMPL;

/* Structure returned with read RSSI event (in tBTM_CMPL_CB callback function)
 * in response to BTM_ReadRSSI call.
 */
typedef struct {
  tBTM_STATUS status;
  uint8_t hci_status;
  int8_t rssi;
  RawAddress rem_bda;
} tBTM_RSSI_RESULT;

/* Structure returned with read failed contact counter event
 * (in tBTM_CMPL_CB callback function) in response to
 * BTM_ReadFailedContactCounter call.
 */
typedef struct {
  tBTM_STATUS status;
  uint8_t hci_status;
  uint16_t failed_contact_counter;
  RawAddress rem_bda;
} tBTM_FAILED_CONTACT_COUNTER_RESULT;

/* Structure returned with read automatic flush timeout event
 * (in tBTM_CMPL_CB callback function) in response to
 * BTM_ReadAutomaticFlushTimeout call.
 */
typedef struct {
  tBTM_STATUS status;
  uint8_t hci_status;
  uint16_t automatic_flush_timeout;
  RawAddress rem_bda;
} tBTM_AUTOMATIC_FLUSH_TIMEOUT_RESULT;

/* Structure returned with read current TX power event (in tBTM_CMPL_CB callback
 * function) in response to BTM_ReadTxPower call.
 */
typedef struct {
  tBTM_STATUS status;
  uint8_t hci_status;
  int8_t tx_power;
  RawAddress rem_bda;
} tBTM_TX_POWER_RESULT;

/* Structure returned with read link quality event (in tBTM_CMPL_CB callback
 * function) in response to BTM_ReadLinkQuality call.
 */
typedef struct {
  tBTM_STATUS status;
  uint8_t hci_status;
  uint8_t link_quality;
  RawAddress rem_bda;
} tBTM_LINK_QUALITY_RESULT;

/* Structure returned with read inq tx power quality event (in tBTM_CMPL_CB
 * callback function) in response to BTM_ReadInquiryRspTxPower call.
 */
typedef struct {
  tBTM_STATUS status;
  uint8_t hci_status;
  int8_t tx_power;
} tBTM_INQ_TXPWR_RESULT;

enum {
  BTM_BL_CONN_EVT,
  BTM_BL_DISCN_EVT,
  BTM_BL_UPDATE_EVT,
  BTM_BL_ROLE_CHG_EVT,
  BTM_BL_COLLISION_EVT
};
typedef uint8_t tBTM_BL_EVENT;

/* Device features mask definitions */
#define BTM_FEATURE_BYTES_PER_PAGE HCI_FEATURE_BYTES_PER_PAGE
#define BTM_EXT_FEATURES_PAGE_MAX HCI_EXT_FEATURES_PAGE_MAX

/* the data type associated with BTM_BL_CONN_EVT */
typedef struct {
  tBTM_BL_EVENT event;     /* The event reported. */
  const RawAddress* p_bda; /* The address of the newly connected device */
  DEV_CLASS_PTR p_dc;      /* The device class */
  BD_NAME_PTR p_bdn;       /* The device name */
  uint8_t* p_features;     /* pointer to the remote device's features page[0]
                              (supported features page) */
  uint16_t handle;         /* connection handle */
  tBT_TRANSPORT transport; /* link is LE or not */
} tBTM_BL_CONN_DATA;

/* the data type associated with BTM_BL_DISCN_EVT */
typedef struct {
  tBTM_BL_EVENT event;     /* The event reported. */
  const RawAddress* p_bda; /* The address of the disconnected device */
  uint16_t handle;         /* disconnected connection handle */
  tBT_TRANSPORT transport; /* link is LE link or not */
} tBTM_BL_DISCN_DATA;

/* Busy-Level shall have the inquiry_paging mask set when
 * inquiry/paging is in progress, Else the number of ACL links */
#define BTM_BL_INQUIRY_PAGING_MASK 0x10
#define BTM_BL_INQUIRY_STARTED (BTM_BL_INQUIRY_PAGING_MASK | 0x1)
#define BTM_BL_INQUIRY_CANCELLED (BTM_BL_INQUIRY_PAGING_MASK | 0x2)
#define BTM_BL_INQUIRY_COMPLETE (BTM_BL_INQUIRY_PAGING_MASK | 0x3)
/* the data type associated with BTM_BL_UPDATE_EVT */
typedef struct {
  tBTM_BL_EVENT event;      /* The event reported. */
  uint8_t busy_level_flags; /* Notifies actual inquiry/page activities */
} tBTM_BL_UPDATE_DATA;

/* the data type associated with BTM_BL_ROLE_CHG_EVT */
typedef struct {
  tBTM_BL_EVENT event;     /* The event reported. */
  const RawAddress* p_bda; /* The address of the peer connected device */
  uint8_t new_role;
  uint8_t hci_status; /* HCI status returned with the event */
} tBTM_BL_ROLE_CHG_DATA;

typedef union {
  tBTM_BL_EVENT event;        /* The event reported. */
  tBTM_BL_CONN_DATA conn;     /* The data associated with BTM_BL_CONN_EVT */
  tBTM_BL_DISCN_DATA discn;   /* The data associated with BTM_BL_DISCN_EVT */
  tBTM_BL_UPDATE_DATA update; /* The data associated with BTM_BL_UPDATE_EVT */
  tBTM_BL_ROLE_CHG_DATA
      role_chg; /*The data associated with BTM_BL_ROLE_CHG_EVT */
} tBTM_BL_EVENT_DATA;

/* Callback function for notifications when the BTM busy level
 * changes.
 */
typedef void(tBTM_BL_CHANGE_CB)(tBTM_BL_EVENT_DATA* p_data);
