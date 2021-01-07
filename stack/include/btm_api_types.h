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

#ifndef BTM_API_TYPES_H
#define BTM_API_TYPES_H

#include <cstdint>
#include <string>

#include "device/include/esco_parameters.h"
#include "internal_include/bt_target.h"
#include "stack/include/btm_status.h"
#include "stack/include/hcidefs.h"
#include "stack/include/smp_api_types.h"
#include "types/ble_address_with_type.h"
#include "types/bt_transport.h"

/* Device name of peer (may be truncated to save space in BTM database) */
typedef uint8_t tBTM_BD_NAME[BTM_MAX_REM_BD_NAME_LEN + 1];

/* Structure returned with Vendor Specific Command complete callback */
typedef struct {
  uint16_t opcode;
  uint16_t param_len;
  uint8_t* p_param_buf;
} tBTM_VSC_CMPL;

/**************************************************
 *  Device Control and General Callback Functions
 **************************************************/
/* Callback function for when a vendor specific event occurs. The length and
 * array of returned parameter bytes are included. This asynchronous event
 * is enabled/disabled by calling BTM_RegisterForVSEvents().
*/
typedef void(tBTM_VS_EVT_CB)(uint8_t len, uint8_t* p);

/* General callback function for notifying an application that a synchronous
 * BTM function is complete. The pointer contains the address of any returned
 * data.
 */
typedef void(tBTM_CMPL_CB)(void* p1);

/* VSC callback function for notifying an application that a synchronous
 * BTM function is complete. The pointer contains the address of any returned
 * data.
 */
typedef void(tBTM_VSC_CMPL_CB)(tBTM_VSC_CMPL* p1);

/*****************************************************************************
 *  DEVICE DISCOVERY - Inquiry, Remote Name, Discovery, Class of Device
 ****************************************************************************/
/*******************************
 *  Device Discovery Constants
 *******************************/
/****************************
 * minor device class field
 ****************************/

/* 0x00 is used as unclassified for all minor device classes */
#define BTM_COD_MINOR_UNCLASSIFIED 0x00
#define BTM_COD_MINOR_CONFM_HANDSFREE 0x08
#define BTM_COD_MINOR_CAR_AUDIO 0x20
#define BTM_COD_MINOR_SET_TOP_BOX 0x24

/* minor device class field for Peripheral Major Class */
/* Bits 6-7 independently specify mouse, keyboard, or combo mouse/keyboard */
#define BTM_COD_MINOR_KEYBOARD 0x40
#define BTM_COD_MINOR_POINTING 0x80
/* Bits 2-5 OR'd with selection from bits 6-7 */
/* #define BTM_COD_MINOR_UNCLASSIFIED       0x00    */
#define BTM_COD_MINOR_JOYSTICK 0x04
#define BTM_COD_MINOR_GAMEPAD 0x08
#define BTM_COD_MINOR_REMOTE_CONTROL 0x0C
#define BTM_COD_MINOR_DIGITIZING_TABLET 0x14
#define BTM_COD_MINOR_CARD_READER 0x18 /* e.g. SIM card reader */
#define BTM_COD_MINOR_DIGITAL_PAN 0x1C

/* minor device class field for Imaging Major Class */
/* Bits 5-7 independently specify display, camera, scanner, or printer */
#define BTM_COD_MINOR_DISPLAY 0x10
/* Bits 2-3 Reserved */
/* #define BTM_COD_MINOR_UNCLASSIFIED       0x00    */

/* minor device class field for Wearable Major Class */
/* Bits 2-7 meaningful    */
#define BTM_COD_MINOR_WRIST_WATCH 0x04
#define BTM_COD_MINOR_GLASSES 0x14

/* minor device class field for Health Major Class */
/* Bits 2-7 meaningful    */
#define BTM_COD_MINOR_BLOOD_MONITOR 0x04
#define BTM_COD_MINOR_THERMOMETER 0x08
#define BTM_COD_MINOR_WEIGHING_SCALE 0x0C
#define BTM_COD_MINOR_GLUCOSE_METER 0x10
#define BTM_COD_MINOR_PULSE_OXIMETER 0x14
#define BTM_COD_MINOR_HEART_PULSE_MONITOR 0x18
#define BTM_COD_MINOR_STEP_COUNTER 0x20

/***************************
 * major device class field
 ***************************/
#define BTM_COD_MAJOR_COMPUTER 0x01
#define BTM_COD_MAJOR_PHONE 0x02
#define BTM_COD_MAJOR_AUDIO 0x04
#define BTM_COD_MAJOR_PERIPHERAL 0x05
#define BTM_COD_MAJOR_IMAGING 0x06
#define BTM_COD_MAJOR_WEARABLE 0x07
#define BTM_COD_MAJOR_HEALTH 0x09
#define BTM_COD_MAJOR_UNCLASSIFIED 0x1F

/***************************
 * service class fields
 ***************************/
#define BTM_COD_SERVICE_LMTD_DISCOVER 0x0020
#define BTM_COD_SERVICE_POSITIONING 0x0100
#define BTM_COD_SERVICE_NETWORKING 0x0200
#define BTM_COD_SERVICE_RENDERING 0x0400
#define BTM_COD_SERVICE_CAPTURING 0x0800
#define BTM_COD_SERVICE_OBJ_TRANSFER 0x1000
#define BTM_COD_SERVICE_AUDIO 0x2000
#define BTM_COD_SERVICE_TELEPHONY 0x4000
#define BTM_COD_SERVICE_INFORMATION 0x8000

/* class of device field macros */
#define BTM_COD_MINOR_CLASS(u8, pd) \
  { (u8) = (pd)[2] & 0xFC; }
#define BTM_COD_MAJOR_CLASS(u8, pd) \
  { (u8) = (pd)[1] & 0x1F; }
#define BTM_COD_SERVICE_CLASS(u16, pd) \
  {                                    \
    (u16) = (pd)[0];                   \
    (u16) <<= 8;                       \
    (u16) += (pd)[1] & 0xE0;           \
  }

/* to set the fields (assumes that format type is always 0) */
#define FIELDS_TO_COD(pd, mn, mj, sv)                   \
  {                                                     \
    (pd)[2] = mn;                                       \
    (pd)[1] = (mj) + ((sv)&BTM_COD_SERVICE_CLASS_LO_B); \
    (pd)[0] = (sv) >> 8;                                \
  }

/* the COD masks */
#define BTM_COD_MINOR_CLASS_MASK 0xFC
#define BTM_COD_MAJOR_CLASS_MASK 0x1F
#define BTM_COD_SERVICE_CLASS_LO_B 0x00E0
#define BTM_COD_SERVICE_CLASS_MASK 0xFFE0

/* BTM service definitions
 * Used for storing EIR data to bit mask
*/
enum {
  BTM_EIR_UUID_SERVCLASS_SERVICE_DISCOVERY_SERVER,
  /*    BTM_EIR_UUID_SERVCLASS_BROWSE_GROUP_DESCRIPTOR,   */
  /*    BTM_EIR_UUID_SERVCLASS_PUBLIC_BROWSE_GROUP,       */
  BTM_EIR_UUID_SERVCLASS_SERIAL_PORT,
  BTM_EIR_UUID_SERVCLASS_LAN_ACCESS_USING_PPP,
  BTM_EIR_UUID_SERVCLASS_DIALUP_NETWORKING,
  BTM_EIR_UUID_SERVCLASS_IRMC_SYNC,
  BTM_EIR_UUID_SERVCLASS_OBEX_OBJECT_PUSH,
  BTM_EIR_UUID_SERVCLASS_OBEX_FILE_TRANSFER,
  BTM_EIR_UUID_SERVCLASS_IRMC_SYNC_COMMAND,
  BTM_EIR_UUID_SERVCLASS_HEADSET,
  BTM_EIR_UUID_SERVCLASS_CORDLESS_TELEPHONY,
  BTM_EIR_UUID_SERVCLASS_AUDIO_SOURCE,
  BTM_EIR_UUID_SERVCLASS_AUDIO_SINK,
  BTM_EIR_UUID_SERVCLASS_AV_REM_CTRL_TARGET,
  /*    BTM_EIR_UUID_SERVCLASS_ADV_AUDIO_DISTRIBUTION,    */
  BTM_EIR_UUID_SERVCLASS_AV_REMOTE_CONTROL,
  /*    BTM_EIR_UUID_SERVCLASS_VIDEO_CONFERENCING,        */
  BTM_EIR_UUID_SERVCLASS_INTERCOM,
  BTM_EIR_UUID_SERVCLASS_FAX,
  BTM_EIR_UUID_SERVCLASS_HEADSET_AUDIO_GATEWAY,
  /*    BTM_EIR_UUID_SERVCLASS_WAP,                       */
  /*    BTM_EIR_UUID_SERVCLASS_WAP_CLIENT,                */
  BTM_EIR_UUID_SERVCLASS_PANU,
  BTM_EIR_UUID_SERVCLASS_NAP,
  BTM_EIR_UUID_SERVCLASS_GN,
  BTM_EIR_UUID_SERVCLASS_DIRECT_PRINTING,
  /*    BTM_EIR_UUID_SERVCLASS_REFERENCE_PRINTING,        */
  BTM_EIR_UUID_SERVCLASS_IMAGING,
  BTM_EIR_UUID_SERVCLASS_IMAGING_RESPONDER,
  BTM_EIR_UUID_SERVCLASS_IMAGING_AUTO_ARCHIVE,
  BTM_EIR_UUID_SERVCLASS_IMAGING_REF_OBJECTS,
  BTM_EIR_UUID_SERVCLASS_HF_HANDSFREE,
  BTM_EIR_UUID_SERVCLASS_AG_HANDSFREE,
  BTM_EIR_UUID_SERVCLASS_DIR_PRT_REF_OBJ_SERVICE,
  /*    BTM_EIR_UUID_SERVCLASS_REFLECTED_UI,              */
  BTM_EIR_UUID_SERVCLASS_BASIC_PRINTING,
  BTM_EIR_UUID_SERVCLASS_PRINTING_STATUS,
  BTM_EIR_UUID_SERVCLASS_HUMAN_INTERFACE,
  BTM_EIR_UUID_SERVCLASS_CABLE_REPLACEMENT,
  BTM_EIR_UUID_SERVCLASS_HCRP_PRINT,
  BTM_EIR_UUID_SERVCLASS_HCRP_SCAN,
  /*    BTM_EIR_UUID_SERVCLASS_COMMON_ISDN_ACCESS,        */
  /*    BTM_EIR_UUID_SERVCLASS_VIDEO_CONFERENCING_GW,     */
  /*    BTM_EIR_UUID_SERVCLASS_UDI_MT,                    */
  /*    BTM_EIR_UUID_SERVCLASS_UDI_TA,                    */
  /*    BTM_EIR_UUID_SERVCLASS_VCP,                       */
  BTM_EIR_UUID_SERVCLASS_SAP,
  BTM_EIR_UUID_SERVCLASS_PBAP_PCE,
  BTM_EIR_UUID_SERVCLASS_PBAP_PSE,
  /*    BTM_EIR_UUID_SERVCLASS_TE_PHONE_ACCESS,           */
  /*    BTM_EIR_UUID_SERVCLASS_ME_PHONE_ACCESS,           */
  BTM_EIR_UUID_SERVCLASS_PHONE_ACCESS,
  BTM_EIR_UUID_SERVCLASS_HEADSET_HS,
  BTM_EIR_UUID_SERVCLASS_PNP_INFORMATION,
  /*    BTM_EIR_UUID_SERVCLASS_GENERIC_NETWORKING,        */
  /*    BTM_EIR_UUID_SERVCLASS_GENERIC_FILETRANSFER,      */
  /*    BTM_EIR_UUID_SERVCLASS_GENERIC_AUDIO,             */
  /*    BTM_EIR_UUID_SERVCLASS_GENERIC_TELEPHONY,         */
  /*    BTM_EIR_UUID_SERVCLASS_UPNP_SERVICE,              */
  /*    BTM_EIR_UUID_SERVCLASS_UPNP_IP_SERVICE,           */
  /*    BTM_EIR_UUID_SERVCLASS_ESDP_UPNP_IP_PAN,          */
  /*    BTM_EIR_UUID_SERVCLASS_ESDP_UPNP_IP_LAP,          */
  /*    BTM_EIR_UUID_SERVCLASS_ESDP_UPNP_IP_L2CAP,        */
  BTM_EIR_UUID_SERVCLASS_VIDEO_SOURCE,
  BTM_EIR_UUID_SERVCLASS_VIDEO_SINK,
  /*    BTM_EIR_UUID_SERVCLASS_VIDEO_DISTRIBUTION         */
  /*    BTM_EIR_UUID_SERVCLASS_HDP_PROFILE                */
  BTM_EIR_UUID_SERVCLASS_MESSAGE_ACCESS,
  BTM_EIR_UUID_SERVCLASS_MESSAGE_NOTIFICATION,
  BTM_EIR_UUID_SERVCLASS_HDP_SOURCE,
  BTM_EIR_UUID_SERVCLASS_HDP_SINK,
  BTM_EIR_MAX_SERVICES
};

/* search result in EIR of inquiry database */
#define BTM_EIR_FOUND 0
#define BTM_EIR_NOT_FOUND 1
#define BTM_EIR_UNKNOWN 2

typedef uint8_t tBTM_EIR_SEARCH_RESULT;

/* 0x01 */
#define BTM_EIR_FLAGS_TYPE HCI_EIR_FLAGS_TYPE
/* 0x02 */
#define BTM_EIR_MORE_16BITS_UUID_TYPE HCI_EIR_MORE_16BITS_UUID_TYPE
/* 0x03 */
#define BTM_EIR_COMPLETE_16BITS_UUID_TYPE HCI_EIR_COMPLETE_16BITS_UUID_TYPE
/* 0x04 */
#define BTM_EIR_MORE_32BITS_UUID_TYPE HCI_EIR_MORE_32BITS_UUID_TYPE
/* 0x05 */
#define BTM_EIR_COMPLETE_32BITS_UUID_TYPE HCI_EIR_COMPLETE_32BITS_UUID_TYPE
/* 0x06 */
#define BTM_EIR_MORE_128BITS_UUID_TYPE HCI_EIR_MORE_128BITS_UUID_TYPE
/* 0x07 */
#define BTM_EIR_COMPLETE_128BITS_UUID_TYPE HCI_EIR_COMPLETE_128BITS_UUID_TYPE
/* 0x08 */
#define BTM_EIR_SHORTENED_LOCAL_NAME_TYPE HCI_EIR_SHORTENED_LOCAL_NAME_TYPE
/* 0x09 */
#define BTM_EIR_COMPLETE_LOCAL_NAME_TYPE HCI_EIR_COMPLETE_LOCAL_NAME_TYPE
/* 0x0A */
#define BTM_EIR_TX_POWER_LEVEL_TYPE HCI_EIR_TX_POWER_LEVEL_TYPE
/* 0xFF */
#define BTM_EIR_MANUFACTURER_SPECIFIC_TYPE HCI_EIR_MANUFACTURER_SPECIFIC_TYPE

#define BTM_BLE_SEC_NONE 0
/* encrypt the link using current key */
#define BTM_BLE_SEC_ENCRYPT 1
#define BTM_BLE_SEC_ENCRYPT_NO_MITM 2
#define BTM_BLE_SEC_ENCRYPT_MITM 3
typedef uint8_t tBTM_BLE_SEC_ACT;

/*******************************************************************************
 * BTM Services MACROS handle array of uint32_t bits for more than 32 services
 ******************************************************************************/
/* Determine the number of uint32_t's necessary for services */
#define BTM_EIR_ARRAY_BITS 32 /* Number of bits in each array element */
#define BTM_EIR_SERVICE_ARRAY_SIZE                         \
  (((uint32_t)BTM_EIR_MAX_SERVICES / BTM_EIR_ARRAY_BITS) + \
   (((uint32_t)BTM_EIR_MAX_SERVICES % BTM_EIR_ARRAY_BITS) ? 1 : 0))

/* MACRO to set the service bit mask in a bit stream */
#define BTM_EIR_SET_SERVICE(p, service)                              \
  (((uint32_t*)(p))[(((uint32_t)(service)) / BTM_EIR_ARRAY_BITS)] |= \
   ((uint32_t)1 << (((uint32_t)(service)) % BTM_EIR_ARRAY_BITS)))

/* MACRO to clear the service bit mask in a bit stream */
#define BTM_EIR_CLR_SERVICE(p, service)                              \
  (((uint32_t*)(p))[(((uint32_t)(service)) / BTM_EIR_ARRAY_BITS)] &= \
   ~((uint32_t)1 << (((uint32_t)(service)) % BTM_EIR_ARRAY_BITS)))

/* MACRO to check the service bit mask in a bit stream */
#define BTM_EIR_HAS_SERVICE(p, service)                               \
  ((((uint32_t*)(p))[(((uint32_t)(service)) / BTM_EIR_ARRAY_BITS)] &  \
    ((uint32_t)1 << (((uint32_t)(service)) % BTM_EIR_ARRAY_BITS))) >> \
   (((uint32_t)(service)) % BTM_EIR_ARRAY_BITS))

/* start of EIR in HCI buffer, 4 bytes = HCI Command(2) + Length(1) + FEC_Req(1)
 */
#define BTM_HCI_EIR_OFFSET (BT_HDR_SIZE + 4)

/***************************
 *  Device Discovery Types
 ***************************/
/* Definitions of the parameters passed to BTM_StartInquiry.
 */
typedef struct /* contains the two device class condition fields */
{
  DEV_CLASS dev_class;
  DEV_CLASS dev_class_mask;
} tBTM_COD_COND;

constexpr uint8_t BLE_EVT_CONNECTABLE_BIT = 0;
constexpr uint8_t BLE_EVT_SCANNABLE_BIT = 1;
constexpr uint8_t BLE_EVT_DIRECTED_BIT = 2;
constexpr uint8_t BLE_EVT_SCAN_RESPONSE_BIT = 3;
constexpr uint8_t BLE_EVT_LEGACY_BIT = 4;

constexpr uint8_t PHY_LE_NO_PACKET = 0x00;
constexpr uint8_t PHY_LE_1M = 0x01;
constexpr uint8_t PHY_LE_2M = 0x02;
constexpr uint8_t PHY_LE_CODED = 0x04;

constexpr uint8_t NO_ADI_PRESENT = 0xFF;
constexpr uint8_t TX_POWER_NOT_PRESENT = 0x7F;

typedef struct {
  uint8_t pcm_intf_rate; /* PCM interface rate: 0: 128kbps, 1: 256 kbps;
                             2:512 bps; 3: 1024kbps; 4: 2048kbps */
  uint8_t frame_type;    /* frame type: 0: short; 1: long */
  uint8_t sync_mode;     /* sync mode: 0: peripheral; 1: central */
  uint8_t clock_mode;    /* clock mode: 0: peripheral; 1: central */

} tBTM_SCO_PCM_PARAM;

/*****************************************************************************
 *  ACL CHANNEL MANAGEMENT
 ****************************************************************************/
// NOTE: Moved to stack/include/acl_api_types.h

/*****************************************************************************
 *  SCO CHANNEL MANAGEMENT
 ****************************************************************************/
/******************
 *  SCO Constants
 ******************/

/* Define an invalid SCO index and an invalid HCI handle */
#define BTM_INVALID_SCO_INDEX 0xFFFF

/* Define an invalid SCO disconnect reason */
#define BTM_INVALID_SCO_DISC_REASON 0xFFFF

#define BTM_SCO_LINK_ONLY_MASK \
  (ESCO_PKT_TYPES_MASK_HV1 | ESCO_PKT_TYPES_MASK_HV2 | ESCO_PKT_TYPES_MASK_HV3)

#define BTM_ESCO_LINK_ONLY_MASK \
  (ESCO_PKT_TYPES_MASK_EV3 | ESCO_PKT_TYPES_MASK_EV4 | ESCO_PKT_TYPES_MASK_EV5)

/***************
 *  SCO Types
 ***************/
#define BTM_LINK_TYPE_SCO HCI_LINK_TYPE_SCO
#define BTM_LINK_TYPE_ESCO HCI_LINK_TYPE_ESCO
typedef uint8_t tBTM_SCO_TYPE;

/*******************
 * SCO Codec Types
 *******************/
// TODO(google) This should use common definitions
#define BTM_SCO_CODEC_NONE 0x0000
#define BTM_SCO_CODEC_CVSD 0x0001
#define BTM_SCO_CODEC_MSBC 0x0002
typedef uint16_t tBTM_SCO_CODEC_TYPE;

/*******************
 * SCO Voice Settings
 *******************/
#define BTM_VOICE_SETTING_CVSD                                         \
  ((uint16_t)(HCI_INP_CODING_LINEAR | HCI_INP_DATA_FMT_2S_COMPLEMENT | \
              HCI_INP_SAMPLE_SIZE_16BIT | HCI_AIR_CODING_FORMAT_CVSD))

#define BTM_VOICE_SETTING_TRANS                                        \
  ((uint16_t)(HCI_INP_CODING_LINEAR | HCI_INP_DATA_FMT_2S_COMPLEMENT | \
              HCI_INP_SAMPLE_SIZE_16BIT | HCI_AIR_CODING_FORMAT_TRANSPNT))

/*******************
 * SCO Data Status
 *******************/
typedef uint8_t tBTM_SCO_DATA_FLAG;

/***************************
 *  SCO Callback Functions
 ***************************/
typedef void(tBTM_SCO_CB)(uint16_t sco_inx);

/***************
 *  eSCO Types
 ***************/
/* tBTM_ESCO_CBACK event types */
#define BTM_ESCO_CHG_EVT 1
#define BTM_ESCO_CONN_REQ_EVT 2
typedef uint8_t tBTM_ESCO_EVT;

/* Structure passed with SCO change command and events.
 * Used by both Sync and Enhanced sync messaging
 */
typedef struct {
  uint16_t max_latency_ms;
  uint16_t packet_types;
  uint8_t retransmission_effort;
} tBTM_CHG_ESCO_PARAMS;

/* Returned by BTM_ReadEScoLinkParms() */
typedef struct {
  uint16_t rx_pkt_len;
  uint16_t tx_pkt_len;
  RawAddress bd_addr;
  uint8_t link_type; /* BTM_LINK_TYPE_SCO or BTM_LINK_TYPE_ESCO */
  uint8_t tx_interval;
  uint8_t retrans_window;
  uint8_t air_mode;
} tBTM_ESCO_DATA;

typedef struct {
  uint16_t sco_inx;
  uint16_t rx_pkt_len;
  uint16_t tx_pkt_len;
  RawAddress bd_addr;
  uint8_t hci_status;
  uint8_t tx_interval;
  uint8_t retrans_window;
} tBTM_CHG_ESCO_EVT_DATA;

typedef struct {
  uint16_t sco_inx;
  RawAddress bd_addr;
  DEV_CLASS dev_class;
  tBTM_SCO_TYPE link_type;
} tBTM_ESCO_CONN_REQ_EVT_DATA;

typedef union {
  tBTM_CHG_ESCO_EVT_DATA chg_evt;
  tBTM_ESCO_CONN_REQ_EVT_DATA conn_evt;
} tBTM_ESCO_EVT_DATA;

/***************************
 *  eSCO Callback Functions
 ***************************/
typedef void(tBTM_ESCO_CBACK)(tBTM_ESCO_EVT event, tBTM_ESCO_EVT_DATA* p_data);

/*****************************************************************************
 *  SECURITY MANAGEMENT
 ****************************************************************************/
/*******************************
 *  Security Manager Constants
 *******************************/

typedef enum : uint8_t {
  BTM_SEC_MODE_SERVICE = 2,
  BTM_SEC_MODE_SP = 4,
  BTM_SEC_MODE_SC = 6,
} tSECURITY_MODE;

enum : uint16_t {
  /* Nothing required */
  BTM_SEC_NONE = 0x0000,
  /* Inbound call requires authentication */
  BTM_SEC_IN_AUTHENTICATE = 0x0002,
  /* Inbound call requires encryption */
  BTM_SEC_IN_ENCRYPT = 0x0004,
  /* Outbound call requires authentication */
  BTM_SEC_OUT_AUTHENTICATE = 0x0010,
  /* Outbound call requires encryption */
  BTM_SEC_OUT_ENCRYPT = 0x0020,
  /* Secure Connections Only Mode */
  BTM_SEC_MODE4_LEVEL4 = 0x0040,
  /* Need to switch connection to be central */
  BTM_SEC_FORCE_CENTRAL = 0x0100,
  /* Need to switch connection to be central */
  BTM_SEC_ATTEMPT_CENTRAL = 0x0200,
  /* Need to switch connection to be slave */
  BTM_SEC_FORCE_PERIPHERAL = 0x0400,
  /* Try to switch connection to be slave */
  BTM_SEC_ATTEMPT_PERIPHERAL = 0x0800,
  /* inbound Do man in the middle protection */
  BTM_SEC_IN_MITM = 0x1000,
  /* outbound Do man in the middle protection */
  BTM_SEC_OUT_MITM = 0x2000,
  /* enforce a minimum of 16 digit for sec mode 2 */
  BTM_SEC_IN_MIN_16_DIGIT_PIN = 0x4000,
};

/* Security Flags [bit mask] (BTM_GetSecurityFlags)
*/
#define BTM_SEC_FLAG_AUTHENTICATED 0x02
#define BTM_SEC_FLAG_ENCRYPTED 0x04
#define BTM_SEC_FLAG_LKEY_KNOWN 0x10
#define BTM_SEC_FLAG_LKEY_AUTHED 0x20

/* Link Key types used to generate the new link key.
 * returned in link key notification callback function
*/
#define BTM_LKEY_TYPE_COMBINATION HCI_LKEY_TYPE_COMBINATION
#define BTM_LKEY_TYPE_REMOTE_UNIT HCI_LKEY_TYPE_REMOTE_UNIT
#define BTM_LKEY_TYPE_UNAUTH_COMB HCI_LKEY_TYPE_UNAUTH_COMB
#define BTM_LKEY_TYPE_AUTH_COMB HCI_LKEY_TYPE_AUTH_COMB
#define BTM_LKEY_TYPE_CHANGED_COMB HCI_LKEY_TYPE_CHANGED_COMB

#define BTM_LKEY_TYPE_UNAUTH_COMB_P_256 HCI_LKEY_TYPE_UNAUTH_COMB_P_256
#define BTM_LKEY_TYPE_AUTH_COMB_P_256 HCI_LKEY_TYPE_AUTH_COMB_P_256

/* "easy" requirements for LK derived from LTK */
#define BTM_LTK_DERIVED_LKEY_OFFSET 0x20
#define BTM_LKEY_TYPE_IGNORE               \
  0xff /* used when event is response from \
          hci return link keys request */

typedef uint8_t tBTM_LINK_KEY_TYPE;

/* Protocol level security (BTM_SetSecurityLevel) */
#define BTM_SEC_PROTO_RFCOMM 3
#define BTM_SEC_PROTO_BNEP 5
#define BTM_SEC_PROTO_HID 6 /* HID      */
#define BTM_SEC_PROTO_AVDT 7

#define BTM_SEC_SERVICE_HEADSET 8
#define BTM_SEC_SERVICE_HEADSET_AG 12
#define BTM_SEC_SERVICE_AG_HANDSFREE 29
#define BTM_SEC_SERVICE_RFC_MUX 42
#define BTM_SEC_SERVICE_HEARING_AID_LEFT 54
#define BTM_SEC_SERVICE_HEARING_AID_RIGHT 55
#define BTM_SEC_SERVICE_EATT 56

/* Update these as services are added */
#define BTM_SEC_SERVICE_FIRST_EMPTY 57

#ifndef BTM_SEC_MAX_SERVICES
#define BTM_SEC_MAX_SERVICES 75
#endif

/*******************************************************************************
 * Security Services MACROS handle array of uint32_t bits for more than 32
 * trusted services
 ******************************************************************************/

/****************************************
 *  Security Manager Callback Functions
 ****************************************/
/* Authorize device for service.  Parameters are
 *              Service Id (NULL - unknown service or unused
 *                                 [BTM_SEC_SERVICE_NAME_LEN set to 0])
*/
typedef uint8_t(tBTM_AUTHORIZE_CALLBACK)(uint8_t service_id);

/* Get PIN for the connection.  Parameters are
 *              BD Address of remote
 *              Device Class of remote
 *              BD Name of remote
 *              Flag indicating the minimum pin code length to be 16 digits
*/
typedef uint8_t(tBTM_PIN_CALLBACK)(const RawAddress& bd_addr,
                                   DEV_CLASS dev_class, tBTM_BD_NAME bd_name,
                                   bool min_16_digit);

/* New Link Key for the connection.  Parameters are
 *              BD Address of remote
 *              Link Key
 *              Key Type: Combination, Local Unit, or Remote Unit
*/
typedef uint8_t(tBTM_LINK_KEY_CALLBACK)(const RawAddress& bd_addr,
                                        DEV_CLASS dev_class,
                                        tBTM_BD_NAME bd_name,
                                        const LinkKey& key, uint8_t key_type);

/* Remote Name Resolved.  Parameters are
 *              BD Address of remote
 *              BD Name of remote
*/
typedef void(tBTM_RMT_NAME_CALLBACK)(const RawAddress& bd_addr, DEV_CLASS dc,
                                     tBTM_BD_NAME bd_name);

/* Authentication complete for the connection.  Parameters are
 *              BD Address of remote
 *              Device Class of remote
 *              BD Name of remote
 *
*/
typedef uint8_t(tBTM_AUTH_COMPLETE_CALLBACK)(const RawAddress& bd_addr,
                                             DEV_CLASS dev_class,
                                             tBTM_BD_NAME bd_name, int result);

enum {
  BTM_SP_IO_REQ_EVT,    /* received IO_CAPABILITY_REQUEST event */
  BTM_SP_IO_RSP_EVT,    /* received IO_CAPABILITY_RESPONSE event */
  BTM_SP_CFM_REQ_EVT,   /* received USER_CONFIRMATION_REQUEST event */
  BTM_SP_KEY_NOTIF_EVT, /* received USER_PASSKEY_NOTIFY event */
  BTM_SP_KEY_REQ_EVT,   /* received USER_PASSKEY_REQUEST event */
  BTM_SP_LOC_OOB_EVT,   /* received result for READ_LOCAL_OOB_DATA command */
  BTM_SP_RMT_OOB_EVT,   /* received REMOTE_OOB_DATA_REQUEST event */
};
typedef uint8_t tBTM_SP_EVT;

enum : uint8_t {
  BTM_IO_CAP_OUT = 0,    /* DisplayOnly */
  BTM_IO_CAP_IO = 1,     /* DisplayYesNo */
  BTM_IO_CAP_IN = 2,     /* KeyboardOnly */
  BTM_IO_CAP_NONE = 3,   /* NoInputNoOutput */
  BTM_IO_CAP_KBDISP = 4, /* Keyboard display */
  BTM_IO_CAP_MAX = 5,
  BTM_IO_CAP_UNKNOWN = 0xFF /* Unknown value */
};
typedef uint8_t tBTM_IO_CAP;

#define BTM_MAX_PASSKEY_VAL (999999)

typedef enum : uint8_t {
  /* MITM Protection Not Required - Single Profile/non-bonding Numeric
   * comparison with automatic accept allowed */
  // NO_BONDING
  BTM_AUTH_SP_NO = 0,
  /* MITM Protection Required - Single Profile/non-bonding. Use IO Capabilities
   * to determine authentication procedure */
  // NO_BONDING_MITM_PROTECTION
  BTM_AUTH_SP_YES = 1,
  /* MITM Protection Not Required - All Profiles/dedicated bonding Numeric
   * comparison with automatic accept allowed */
  // DEDICATED_BONDING
  BTM_AUTH_AP_NO = 2,
  /* MITM Protection Required - All Profiles/dedicated bonding Use IO
   * Capabilities to determine authentication procedure */
  // DEDICATED_BONDING_MITM_PROTECTION
  BTM_AUTH_AP_YES = 3,
  /* MITM Protection Not Required - Single Profiles/general bonding Numeric
   * comparison with automatic accept allowed */
  // GENERAL_BONDING
  BTM_AUTH_SPGB_NO = 4,
  /* MITM Protection Required - Single Profiles/general bonding Use IO
   * Capabilities to determine authentication procedure */
  // GENERAL_BONDING_MITM_PROTECTION
  BTM_AUTH_SPGB_YES = 5,
} tBTM_AUTH;

/* this bit is ORed with BTM_AUTH_SP_* when IO exchange for dedicated bonding */
#define BTM_AUTH_DD_BOND 2
#define BTM_AUTH_BONDS 6  /* the general/dedicated bonding bits  */
#define BTM_AUTH_YN_BIT 1 /* this is the Yes or No bit  */

#define BTM_BLE_INITIATOR_KEY_SIZE 15
#define BTM_BLE_RESPONDER_KEY_SIZE 15
#define BTM_BLE_MAX_KEY_SIZE 16

typedef uint8_t tBTM_AUTH_REQ;

enum { BTM_OOB_NONE, BTM_OOB_PRESENT, BTM_OOB_UNKNOWN };
typedef uint8_t tBTM_OOB_DATA;

/* data type for BTM_SP_IO_REQ_EVT */
typedef struct {
  RawAddress bd_addr;     /* peer address */
  tBTM_IO_CAP io_cap;     /* local IO capabilities */
  tBTM_OOB_DATA oob_data; /* OOB data present (locally) for the peer device */
  tBTM_AUTH_REQ auth_req; /* Authentication required (for local device) */
  bool is_orig;           /* true, if local device initiated the SP process */
} tBTM_SP_IO_REQ;

/* data type for BTM_SP_IO_RSP_EVT */
typedef struct {
  RawAddress bd_addr; /* peer address */
  tBTM_IO_CAP io_cap; /* peer IO capabilities */
  tBTM_OOB_DATA
      oob_data; /* OOB data present at peer device for the local device */
  tBTM_AUTH_REQ auth_req; /* Authentication required for peer device */
} tBTM_SP_IO_RSP;

/* data type for BTM_SP_CFM_REQ_EVT */
typedef struct {
  RawAddress bd_addr;   /* peer address */
  DEV_CLASS dev_class;  /* peer CoD */
  tBTM_BD_NAME bd_name; /* peer device name */
  uint32_t num_val; /* the numeric value for comparison. If just_works, do not
                       show this number to UI */
  bool just_works;  /* true, if "Just Works" association model */
  tBTM_AUTH_REQ loc_auth_req; /* Authentication required for local device */
  tBTM_AUTH_REQ rmt_auth_req; /* Authentication required for peer device */
  tBTM_IO_CAP loc_io_caps;    /* IO Capabilities of the local device */
  tBTM_IO_CAP rmt_io_caps;    /* IO Capabilities of the remot device */
} tBTM_SP_CFM_REQ;

/* data type for BTM_SP_KEY_REQ_EVT */
typedef struct {
  RawAddress bd_addr;   /* peer address */
  DEV_CLASS dev_class;  /* peer CoD */
  tBTM_BD_NAME bd_name; /* peer device name */
} tBTM_SP_KEY_REQ;

/* data type for BTM_SP_KEY_NOTIF_EVT */
typedef struct {
  RawAddress bd_addr;   /* peer address */
  DEV_CLASS dev_class;  /* peer CoD */
  tBTM_BD_NAME bd_name; /* peer device name */
  uint32_t passkey;     /* passkey */
} tBTM_SP_KEY_NOTIF;

/* data type for BTM_SP_LOC_OOB_EVT */
typedef struct {
  tBTM_STATUS status; /* */
  Octet16 c;          /* Simple Pairing Hash C */
  Octet16 r;          /* Simple Pairing Randomnizer R */
} tBTM_SP_LOC_OOB;

/* data type for BTM_SP_RMT_OOB_EVT */
typedef struct {
  RawAddress bd_addr;   /* peer address */
  DEV_CLASS dev_class;  /* peer CoD */
  tBTM_BD_NAME bd_name; /* peer device name */
} tBTM_SP_RMT_OOB;

typedef union {
  tBTM_SP_IO_REQ io_req;       /* BTM_SP_IO_REQ_EVT      */
  tBTM_SP_IO_RSP io_rsp;       /* BTM_SP_IO_RSP_EVT      */
  tBTM_SP_CFM_REQ cfm_req;     /* BTM_SP_CFM_REQ_EVT     */
  tBTM_SP_KEY_NOTIF key_notif; /* BTM_SP_KEY_NOTIF_EVT   */
  tBTM_SP_KEY_REQ key_req;     /* BTM_SP_KEY_REQ_EVT     */
  tBTM_SP_LOC_OOB loc_oob;     /* BTM_SP_LOC_OOB_EVT     */
  tBTM_SP_RMT_OOB rmt_oob;     /* BTM_SP_RMT_OOB_EVT     */
} tBTM_SP_EVT_DATA;

/* Simple Pairing Events.  Called by the stack when Simple Pairing related
 * events occur.
*/
typedef uint8_t(tBTM_SP_CALLBACK)(tBTM_SP_EVT event, tBTM_SP_EVT_DATA* p_data);

typedef void(tBTM_MKEY_CALLBACK)(const RawAddress& bd_addr, uint8_t status,
                                 uint8_t key_flag);

/* Encryption enabled/disabled complete: Optionally passed with
 * BTM_SetEncryption.
 * Parameters are
 *              BD Address of remote
 *              optional data passed in by BTM_SetEncryption
 *              tBTM_STATUS - result of the operation
*/
typedef void(tBTM_SEC_CALLBACK)(const RawAddress* bd_addr,
                                tBT_TRANSPORT trasnport, void* p_ref_data,
                                tBTM_STATUS result);
typedef tBTM_SEC_CALLBACK tBTM_SEC_CALLBACK;

/* Bond Cancel complete. Parameters are
 *              Result of the cancel operation
 *
*/
typedef void(tBTM_BOND_CANCEL_CMPL_CALLBACK)(tBTM_STATUS result);

/* LE related event and data structure */
/* received IO_CAPABILITY_REQUEST event */
#define BTM_LE_IO_REQ_EVT SMP_IO_CAP_REQ_EVT
/* security request event */
#define BTM_LE_SEC_REQUEST_EVT SMP_SEC_REQUEST_EVT
/* received USER_PASSKEY_NOTIFY event */
#define BTM_LE_KEY_NOTIF_EVT SMP_PASSKEY_NOTIF_EVT
/* received USER_PASSKEY_REQUEST event */
#define BTM_LE_KEY_REQ_EVT SMP_PASSKEY_REQ_EVT
/* OOB data request event */
#define BTM_LE_OOB_REQ_EVT SMP_OOB_REQ_EVT
/* Numeric Comparison request event */
#define BTM_LE_NC_REQ_EVT SMP_NC_REQ_EVT
/* Peer keypress notification recd event */
#define BTM_LE_PR_KEYPR_NOT_EVT SMP_PEER_KEYPR_NOT_EVT
/* SC OOB request event (both local and peer OOB data) can be expected in
 * response */
#define BTM_LE_SC_OOB_REQ_EVT SMP_SC_OOB_REQ_EVT
/* SC OOB local data set is created (as result of SMP_CrLocScOobData(...)) */
#define BTM_LE_SC_LOC_OOB_EVT SMP_SC_LOC_OOB_DATA_UP_EVT
/* SMP over BR keys request event */
#define BTM_LE_BR_KEYS_REQ_EVT SMP_BR_KEYS_REQ_EVT
/* SMP complete event */
#define BTM_LE_COMPLT_EVT SMP_COMPLT_EVT
#define BTM_LE_LAST_FROM_SMP BTM_LE_BR_KEYS_REQ_EVT
/* KEY update event */
#define BTM_LE_KEY_EVT (BTM_LE_LAST_FROM_SMP + 1)
#define BTM_LE_CONSENT_REQ_EVT SMP_CONSENT_REQ_EVT
typedef uint8_t tBTM_LE_EVT;

enum : uint8_t {
  BTM_LE_KEY_NONE = 0,
  BTM_LE_KEY_PENC = SMP_SEC_KEY_TYPE_ENC,
  /* identity key of the peer device */
  BTM_LE_KEY_PID = SMP_SEC_KEY_TYPE_ID,
  /* peer SRK */
  BTM_LE_KEY_PCSRK = SMP_SEC_KEY_TYPE_CSRK,
  BTM_LE_KEY_PLK = SMP_SEC_KEY_TYPE_LK,
  BTM_LE_KEY_LLK = (SMP_SEC_KEY_TYPE_LK << 4),
  /* master role security information:div */
  BTM_LE_KEY_LENC = (SMP_SEC_KEY_TYPE_ENC << 4),
  /* master device ID key */
  BTM_LE_KEY_LID = (SMP_SEC_KEY_TYPE_ID << 4),
  /* local CSRK has been deliver to peer */
  BTM_LE_KEY_LCSRK = (SMP_SEC_KEY_TYPE_CSRK << 4),
};
typedef uint8_t tBTM_LE_KEY_TYPE;

#define BTM_LE_AUTH_REQ_NO_BOND SMP_AUTH_NO_BOND /* 0 */
#define BTM_LE_AUTH_REQ_BOND SMP_AUTH_BOND       /* 1 << 0 */
#define BTM_LE_AUTH_REQ_MITM SMP_AUTH_YN_BIT     /* 1 << 2 */
typedef uint8_t tBTM_LE_AUTH_REQ;
#define BTM_LE_SC_SUPPORT_BIT SMP_SC_SUPPORT_BIT /* (1 << 3) */
#define BTM_LE_KP_SUPPORT_BIT SMP_KP_SUPPORT_BIT /* (1 << 4) */
#define BTM_LE_H7_SUPPORT_BIT SMP_H7_SUPPORT_BIT /* (1 << 5) */

#define BTM_LE_AUTH_REQ_SC_ONLY SMP_AUTH_SC_ENC_ONLY     /* 00101000 */
#define BTM_LE_AUTH_REQ_SC_BOND SMP_AUTH_SC_GB           /* 00101001 */
#define BTM_LE_AUTH_REQ_SC_MITM SMP_AUTH_SC_MITM_NB      /* 00101100 */
#define BTM_LE_AUTH_REQ_SC_MITM_BOND SMP_AUTH_SC_MITM_GB /* 00101101 */
#define BTM_LE_AUTH_REQ_MASK SMP_AUTH_MASK               /* 0x3D */

/* LE security level */
#define BTM_LE_SEC_NONE SMP_SEC_NONE
#define BTM_LE_SEC_UNAUTHENTICATE SMP_SEC_UNAUTHENTICATE /* 1 */
#define BTM_LE_SEC_AUTHENTICATED SMP_SEC_AUTHENTICATED   /* 4 */
typedef uint8_t tBTM_LE_SEC;

typedef struct {
  /* local IO capabilities */
  tBTM_IO_CAP io_cap;
  /* OOB data present (locally) for the peer device */
  uint8_t oob_data;
  /* Authentication request (for local device) containing bonding and MITM
   * info */
  tBTM_LE_AUTH_REQ auth_req;
  uint8_t max_key_size;       /* max encryption key size */
  tBTM_LE_KEY_TYPE init_keys; /* keys to be distributed, bit mask */
  tBTM_LE_KEY_TYPE resp_keys; /* keys to be distributed, bit mask */
} tBTM_LE_IO_REQ;

/* data type for tBTM_LE_COMPLT */
typedef struct {
  uint8_t reason;
  uint8_t sec_level;
  bool is_pair_cancel;
  bool smp_over_br;
} tBTM_LE_COMPLT;

/* BLE encryption keys */
typedef struct {
  Octet16 ltk;
  BT_OCTET8 rand;
  uint16_t ediv;
  uint8_t sec_level;
  uint8_t key_size;
} tBTM_LE_PENC_KEYS;

/* BLE CSRK keys */
typedef struct {
  uint32_t counter;
  Octet16 csrk;
  uint8_t sec_level;
} tBTM_LE_PCSRK_KEYS;

/* BLE Encryption reproduction keys */
typedef struct {
  Octet16 ltk;
  uint16_t div;
  uint8_t key_size;
  uint8_t sec_level;
} tBTM_LE_LENC_KEYS;

/* BLE SRK keys */
typedef struct {
  uint32_t counter;
  uint16_t div;
  uint8_t sec_level;
  Octet16 csrk;
} tBTM_LE_LCSRK_KEYS;

typedef struct {
  Octet16 irk;
  tBLE_ADDR_TYPE identity_addr_type;
  RawAddress identity_addr;
} tBTM_LE_PID_KEYS;

typedef union {
  tBTM_LE_PENC_KEYS penc_key;   /* received peer encryption key */
  tBTM_LE_PCSRK_KEYS pcsrk_key; /* received peer device SRK */
  tBTM_LE_PID_KEYS pid_key;     /* peer device ID key */
  tBTM_LE_LENC_KEYS lenc_key;   /* local encryption reproduction keys
                                 * LTK = = d1(ER,DIV,0) */
  tBTM_LE_LCSRK_KEYS lcsrk_key; /* local device CSRK = d1(ER,DIV,1)*/
} tBTM_LE_KEY_VALUE;

typedef struct {
  tBTM_LE_KEY_TYPE key_type;
  tBTM_LE_KEY_VALUE* p_key_value;
} tBTM_LE_KEY;

typedef union {
  tBTM_LE_IO_REQ io_req; /* BTM_LE_IO_REQ_EVT      */
  uint32_t key_notif;    /* BTM_LE_KEY_NOTIF_EVT   */
                         /* BTM_LE_NC_REQ_EVT */
                         /* no callback data for
                          * BTM_LE_KEY_REQ_EVT
                          * and BTM_LE_OOB_REQ_EVT  */
  tBTM_LE_COMPLT complt; /* BTM_LE_COMPLT_EVT      */
  tSMP_OOB_DATA_TYPE req_oob_type;
  tBTM_LE_KEY key;
} tBTM_LE_EVT_DATA;

/* Simple Pairing Events.  Called by the stack when Simple Pairing related
 * events occur.
*/
typedef uint8_t(tBTM_LE_CALLBACK)(tBTM_LE_EVT event, const RawAddress& bda,
                                  tBTM_LE_EVT_DATA* p_data);

#define BTM_BLE_KEY_TYPE_ID 1
#define BTM_BLE_KEY_TYPE_ER 2
#define BTM_BLE_KEY_TYPE_COUNTER 3  // tobe obsolete

typedef struct {
  Octet16 ir;
  Octet16 irk;
  Octet16 dhk;

} tBTM_BLE_LOCAL_ID_KEYS;

typedef union {
  tBTM_BLE_LOCAL_ID_KEYS id_keys;
  Octet16 er;
} tBTM_BLE_LOCAL_KEYS;

/* New LE identity key for local device.
*/
typedef void(tBTM_LE_KEY_CALLBACK)(uint8_t key_type,
                                   tBTM_BLE_LOCAL_KEYS* p_key);

/***************************
 *  Security Manager Types
 ***************************/
/* Structure that applications use to register with BTM_SecRegister */
typedef struct {
  tBTM_PIN_CALLBACK* p_pin_callback;
  tBTM_LINK_KEY_CALLBACK* p_link_key_callback;
  tBTM_AUTH_COMPLETE_CALLBACK* p_auth_complete_callback;
  tBTM_BOND_CANCEL_CMPL_CALLBACK* p_bond_cancel_cmpl_callback;
  tBTM_SP_CALLBACK* p_sp_callback;
  tBTM_LE_CALLBACK* p_le_callback;
  tBTM_LE_KEY_CALLBACK* p_le_key_callback;
} tBTM_APPL_INFO;

/* Callback function for when a link supervision timeout event occurs.
 * This asynchronous event is enabled/disabled by calling BTM_RegForLstoEvt().
*/
typedef void(tBTM_LSTO_CBACK)(const RawAddress& remote_bda, uint16_t timeout);

/*****************************************************************************
 *  POWER MANAGEMENT
 ****************************************************************************/
/****************************
 *  Power Manager Constants
 ****************************/
/* BTM Power manager status codes */
enum : uint8_t {
  BTM_PM_STS_ACTIVE = HCI_MODE_ACTIVE,  // 0x00
  BTM_PM_STS_HOLD = HCI_MODE_HOLD,      // 0x01
  BTM_PM_STS_SNIFF = HCI_MODE_SNIFF,    // 0x02
  BTM_PM_STS_PARK = HCI_MODE_PARK,      // 0x03
  BTM_PM_STS_SSR,     /* report the SSR parameters in HCI_SNIFF_SUB_RATE_EVT */
  BTM_PM_STS_PENDING, /* when waiting for status from controller */
  BTM_PM_STS_ERROR    /* when HCI command status returns error */
};
typedef uint8_t tBTM_PM_STATUS;

inline std::string power_mode_status_text(tBTM_PM_STATUS status) {
  switch (status) {
    case BTM_PM_STS_ACTIVE:
      return std::string("active");
    case BTM_PM_STS_HOLD:
      return std::string("hold");
    case BTM_PM_STS_SNIFF:
      return std::string("sniff");
    case BTM_PM_STS_PARK:
      return std::string("park");
    case BTM_PM_STS_SSR:
      return std::string("sniff_subrating");
    case BTM_PM_STS_PENDING:
      return std::string("pending");
    case BTM_PM_STS_ERROR:
      return std::string("error");
    default:
      return std::string("UNKNOWN");
  }
}

/* BTM Power manager modes */
enum : uint8_t {
  BTM_PM_MD_ACTIVE = HCI_MODE_ACTIVE,  // 0x00
  BTM_PM_MD_HOLD = HCI_MODE_HOLD,      // 0x01
  BTM_PM_MD_SNIFF = HCI_MODE_SNIFF,    // 0x02
  BTM_PM_MD_PARK = HCI_MODE_PARK,      // 0x03
  BTM_PM_MD_FORCE = 0x10, /* OR this to force ACL link to a certain mode */
  BTM_PM_MD_UNKNOWN = 0xEF,
};
typedef uint8_t tBTM_PM_MODE;
#define HCI_TO_BTM_POWER_MODE(mode) (static_cast<tBTM_PM_MODE>(mode))

inline bool is_legal_power_mode(tBTM_PM_MODE mode) {
  switch (mode & ~BTM_PM_MD_FORCE) {
    case BTM_PM_MD_ACTIVE:
    case BTM_PM_MD_HOLD:
    case BTM_PM_MD_SNIFF:
    case BTM_PM_MD_PARK:
      return true;
    default:
      return false;
  }
}

inline std::string power_mode_text(tBTM_PM_MODE mode) {
  std::string s = base::StringPrintf((mode & BTM_PM_MD_FORCE) ? "" : "forced:");
  switch (mode & ~BTM_PM_MD_FORCE) {
    case BTM_PM_MD_ACTIVE:
      return s + std::string("active");
    case BTM_PM_MD_HOLD:
      return s + std::string("hold");
    case BTM_PM_MD_SNIFF:
      return s + std::string("sniff");
    case BTM_PM_MD_PARK:
      return s + std::string("park");
    default:
      return s + std::string("UNKNOWN");
  }
}

#define BTM_PM_SET_ONLY_ID 0x80

/* Operation codes */
typedef enum : uint8_t {
  /* The module wants to set the desired power mode */
  BTM_PM_REG_SET = (1u << 0),
  /* The module wants to receive mode change event */
  BTM_PM_REG_NOTIF = (1u << 1),
  /* The module does not want to involve with PM anymore */
  BTM_PM_DEREG = (1u << 2),
} tBTM_PM_REGISTER;

/************************
 *  Power Manager Types
 ************************/
typedef struct {
  uint16_t max;
  uint16_t min;
  uint16_t attempt;
  uint16_t timeout;
  tBTM_PM_MODE mode;
} tBTM_PM_PWR_MD;

/*************************************
 *  Power Manager Callback Functions
 *************************************/
typedef void(tBTM_PM_STATUS_CBACK)(const RawAddress& p_bda,
                                   tBTM_PM_STATUS status, uint16_t value,
                                   tHCI_STATUS hci_status);

/************************
 *  Stored Linkkey Types
 ************************/
#define BTM_CB_EVT_DELETE_STORED_LINK_KEYS 4

typedef struct {
  uint8_t event;
  uint8_t status;
  uint16_t num_keys;

} tBTM_DELETE_STORED_LINK_KEY_COMPLETE;

/* ACL link on, SCO link ongoing, sniff mode */
#define BTM_CONTRL_ACTIVE 1
/* Scan state - paging/inquiry/trying to connect*/
#define BTM_CONTRL_SCAN 2
/* Idle state - page scan, LE advt, inquiry scan */
#define BTM_CONTRL_IDLE 3

typedef uint8_t tBTM_CONTRL_STATE;

// Bluetooth Quality Report - Report receiver
typedef void(tBTM_BT_QUALITY_REPORT_RECEIVER)(uint8_t len, uint8_t* p_stream);

#endif  // BTM_API_TYPES_H
