/******************************************************************************
 *
 *  Copyright (C) 1999-2012 Broadcom Corporation
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

#include "bt_target.h"
#include "smp_api_types.h"
#include "hcidefs.h"

/* Maximum number of bytes allowed for vendor specific command parameters */
#define BTM_MAX_VENDOR_SPECIFIC_LEN  HCI_COMMAND_SIZE

/* BTM application return status codes */
enum
{
    BTM_SUCCESS = 0,                    /* 0  Command succeeded                 */
    BTM_CMD_STARTED,                    /* 1  Command started OK.               */
    BTM_BUSY,                           /* 2  Device busy with another command  */
    BTM_NO_RESOURCES,                   /* 3  No resources to issue command     */
    BTM_MODE_UNSUPPORTED,               /* 4  Request for 1 or more unsupported modes */
    BTM_ILLEGAL_VALUE,                  /* 5  Illegal parameter value           */
    BTM_WRONG_MODE,                     /* 6  Device in wrong mode for request  */
    BTM_UNKNOWN_ADDR,                   /* 7  Unknown remote BD address         */
    BTM_DEVICE_TIMEOUT,                 /* 8  Device timeout                    */
    BTM_BAD_VALUE_RET,                  /* 9  A bad value was received from HCI */
    BTM_ERR_PROCESSING,                 /* 10 Generic error                     */
    BTM_NOT_AUTHORIZED,                 /* 11 Authorization failed              */
    BTM_DEV_RESET,                      /* 12 Device has been reset             */
    BTM_CMD_STORED,                     /* 13 request is stored in control block */
    BTM_ILLEGAL_ACTION,                 /* 14 state machine gets illegal command */
    BTM_DELAY_CHECK,                    /* 15 delay the check on encryption */
    BTM_SCO_BAD_LENGTH,                 /* 16 Bad SCO over HCI data length */
    BTM_SUCCESS_NO_SECURITY,            /* 17 security passed, no security set  */
    BTM_FAILED_ON_SECURITY,             /* 18 security failed                   */
    BTM_REPEATED_ATTEMPTS,              /* 19 repeated attempts for LE security requests */
    BTM_MODE4_LEVEL4_NOT_SUPPORTED      /* 20 Secure Connections Only Mode can't be supported */
};

typedef uint8_t tBTM_STATUS;

#if (defined(BTA_HOST_INTERLEAVE_SEARCH) && BTA_HOST_INTERLEAVE_SEARCH == TRUE)
typedef enum
{
    BTM_BR_ONE,                         /*0 First state or BR/EDR scan 1*/
    BTM_BLE_ONE,                        /*1BLE scan 1*/
    BTM_BR_TWO,                         /*2 BR/EDR scan 2*/
    BTM_BLE_TWO,                        /*3 BLE scan 2*/
    BTM_FINISH,                         /*4 End of Interleave Scan, or normal scan*/
    BTM_NO_INTERLEAVING                 /*5 No Interleaving*/
}btm_inq_state;
#endif



/*************************
**  Device Control Types
**************************/
#define BTM_DEVICE_ROLE_BR      0x01
#define BTM_DEVICE_ROLE_DUAL    0x02
#define BTM_MAX_DEVICE_ROLE     BTM_DEVICE_ROLE_DUAL
typedef UINT8 tBTM_DEVICE_ROLE;

/* Device name of peer (may be truncated to save space in BTM database) */
typedef UINT8 tBTM_BD_NAME[BTM_MAX_REM_BD_NAME_LEN + 1];

/* Structure returned with local version information */
typedef struct
{
    UINT8       hci_version;
    UINT16      hci_revision;
    UINT8       lmp_version;
    UINT16      manufacturer;
    UINT16      lmp_subversion;
} tBTM_VERSION_INFO;

/* Structure returned with Vendor Specific Command complete callback */
typedef struct
{
    UINT16  opcode;
    UINT16  param_len;
    UINT8   *p_param_buf;
} tBTM_VSC_CMPL;

/* Structure returned with HCI Raw Command complete callback */
typedef struct
{
    UINT8  event_code;
    UINT8  param_len;
    UINT8   *p_param_buf;
} tBTM_RAW_CMPL;

#define  BTM_VSC_CMPL_DATA_SIZE  (BTM_MAX_VENDOR_SPECIFIC_LEN + sizeof(tBTM_VSC_CMPL))
/**************************************************
**  Device Control and General Callback Functions
***************************************************/
/* Callback function for when device status changes. Appl must poll for
** what the new state is (BTM_IsDeviceUp). The event occurs whenever the stack
** has detected that the controller status has changed. This asynchronous event
** is enabled/disabled by calling BTM_RegisterForDeviceStatusNotif().
*/
enum
{
    BTM_DEV_STATUS_UP,
    BTM_DEV_STATUS_DOWN,
    BTM_DEV_STATUS_CMD_TOUT
};

typedef UINT8 tBTM_DEV_STATUS;


typedef void (tBTM_DEV_STATUS_CB) (tBTM_DEV_STATUS status);


/* Callback function for when a vendor specific event occurs. The length and
** array of returned parameter bytes are included. This asynchronous event
** is enabled/disabled by calling BTM_RegisterForVSEvents().
*/
typedef void (tBTM_VS_EVT_CB) (UINT8 len, UINT8 *p);


/* General callback function for notifying an application that a synchronous
** BTM function is complete. The pointer contains the address of any returned data.
*/
typedef void (tBTM_CMPL_CB) (void *p1);

/* VSC callback function for notifying an application that a synchronous
** BTM function is complete. The pointer contains the address of any returned data.
*/
typedef void (tBTM_VSC_CMPL_CB) (tBTM_VSC_CMPL *p1);

/* HCI RAW CMD callback function for notifying an application that a synchronous
** BTM function is complete. The pointer contains the address of any returned data.
*/
typedef void (tBTM_RAW_CMPL_CB) (tBTM_RAW_CMPL *p1);

/* Callback for apps to check connection and inquiry filters.
** Parameters are the BD Address of remote and the Dev Class of remote.
** If the app returns none zero, the connection or inquiry result will be dropped.
*/
typedef UINT8 (tBTM_FILTER_CB) (BD_ADDR bd_addr, DEV_CLASS dc);

/*****************************************************************************
**  DEVICE DISCOVERY - Inquiry, Remote Name, Discovery, Class of Device
*****************************************************************************/
/*******************************
**  Device Discovery Constants
********************************/
/* Discoverable modes */
#define BTM_NON_DISCOVERABLE        0
#define BTM_LIMITED_DISCOVERABLE    1
#define BTM_GENERAL_DISCOVERABLE    2
#define BTM_DISCOVERABLE_MASK       (BTM_LIMITED_DISCOVERABLE|BTM_GENERAL_DISCOVERABLE)
#define BTM_MAX_DISCOVERABLE        BTM_GENERAL_DISCOVERABLE
/* high byte for BLE Discoverable modes */
#define BTM_BLE_NON_DISCOVERABLE        0x0000
#define BTM_BLE_LIMITED_DISCOVERABLE    0x0100
#define BTM_BLE_GENERAL_DISCOVERABLE    0x0200
#define BTM_BLE_MAX_DISCOVERABLE        BTM_BLE_GENERAL_DISCOVERABLE
#define BTM_BLE_DISCOVERABLE_MASK       (BTM_BLE_NON_DISCOVERABLE|BTM_BLE_LIMITED_DISCOVERABLE|BTM_BLE_GENERAL_DISCOVERABLE)

/* Connectable modes */
#define BTM_NON_CONNECTABLE         0
#define BTM_CONNECTABLE             1
#define BTM_CONNECTABLE_MASK        (BTM_NON_CONNECTABLE | BTM_CONNECTABLE)
/* high byte for BLE Connectable modes */
#define BTM_BLE_NON_CONNECTABLE      0x0000
#define BTM_BLE_CONNECTABLE          0x0100
#define BTM_BLE_MAX_CONNECTABLE      BTM_BLE_CONNECTABLE
#define BTM_BLE_CONNECTABLE_MASK    (BTM_BLE_NON_CONNECTABLE | BTM_BLE_CONNECTABLE)

#define BTM_BLE_ADV_STOP            2
/* Inquiry modes
 * Note: These modes are associated with the inquiry active values (BTM_*ACTIVE) */
#define BTM_INQUIRY_NONE            0
#define BTM_GENERAL_INQUIRY         0x01
#define BTM_LIMITED_INQUIRY         0x02
#define BTM_BR_INQUIRY_MASK         (BTM_GENERAL_INQUIRY | BTM_LIMITED_INQUIRY)

/* high byte of inquiry mode for BLE inquiry mode */
#define BTM_BLE_INQUIRY_NONE         0x00
#define BTM_BLE_GENERAL_INQUIRY      0x10
#define BTM_BLE_LIMITED_INQUIRY      0x20
#define BTM_BLE_INQUIRY_MASK         (BTM_BLE_GENERAL_INQUIRY|BTM_BLE_LIMITED_INQUIRY)

/* BTM_IsInquiryActive return values (Bit Mask)
 * Note: These bit masks are associated with the inquiry modes (BTM_*_INQUIRY) */
#define BTM_INQUIRY_INACTIVE        0x0     /* no inquiry in progress */
#define BTM_GENERAL_INQUIRY_ACTIVE  BTM_GENERAL_INQUIRY     /* a general inquiry is in progress */
#define BTM_LIMITED_INQUIRY_ACTIVE  BTM_LIMITED_INQUIRY     /* a limited inquiry is in progress */
#define BTM_PERIODIC_INQUIRY_ACTIVE 0x8     /* a periodic inquiry is active */
#define BTM_SSP_INQUIRY_ACTIVE      0x4     /* SSP is active, so inquiry is disallowed (work around for FW bug) */
#define BTM_LE_GENERAL_INQUIRY_ACTIVE  BTM_BLE_GENERAL_INQUIRY     /* a general inquiry is in progress */
#define BTM_LE_LIMITED_INQUIRY_ACTIVE  BTM_BLE_LIMITED_INQUIRY      /* a limited inquiry is in progress */

/* inquiry activity mask */
#define BTM_BR_INQ_ACTIVE_MASK        (BTM_GENERAL_INQUIRY_ACTIVE|BTM_LIMITED_INQUIRY_ACTIVE|BTM_PERIODIC_INQUIRY_ACTIVE) /* BR/EDR inquiry activity mask */
#define BTM_BLE_SCAN_ACTIVE_MASK      0xF0     /* LE scan activity mask */
#define BTM_BLE_INQ_ACTIVE_MASK       (BTM_LE_GENERAL_INQUIRY_ACTIVE|BTM_LE_LIMITED_INQUIRY_ACTIVE) /* LE inquiry activity mask*/
#define BTM_INQUIRY_ACTIVE_MASK       (BTM_BR_INQ_ACTIVE_MASK | BTM_BLE_INQ_ACTIVE_MASK) /* inquiry activity mask */

/* Define scan types */
#define BTM_SCAN_TYPE_STANDARD      0
#define BTM_SCAN_TYPE_INTERLACED    1       /* 1.2 devices only */

/* Define inquiry results mode */
#define BTM_INQ_RESULT_STANDARD     0
#define BTM_INQ_RESULT_WITH_RSSI    1
#define BTM_INQ_RESULT_EXTENDED     2

#define BTM_INQ_RES_IGNORE_RSSI     0x7f    /* RSSI value not supplied (ignore it) */

/* Inquiry Filter Condition types (see tBTM_INQ_PARMS) */
#define BTM_CLR_INQUIRY_FILTER          0                   /* Inquiry Filtering is turned off */
#define BTM_FILTER_COND_DEVICE_CLASS    HCI_FILTER_COND_DEVICE_CLASS /* Filter on device class */
#define BTM_FILTER_COND_BD_ADDR         HCI_FILTER_COND_BD_ADDR /* Filter on device addr */

/* State of the remote name retrieval during inquiry operations.
** Used in the tBTM_INQ_INFO structure, and returned in the
** BTM_InqDbRead, BTM_InqDbFirst, and BTM_InqDbNext functions.
** The name field is valid when the state returned is
** BTM_INQ_RMT_NAME_DONE */
#define BTM_INQ_RMT_NAME_EMPTY      0
#define BTM_INQ_RMT_NAME_PENDING    1
#define BTM_INQ_RMT_NAME_DONE       2
#define BTM_INQ_RMT_NAME_FAILED     3

/*********************************
 *** Class of Device constants ***
 *********************************/
#define BTM_FORMAT_TYPE_1   0x00

/****************************
** minor device class field
*****************************/

/* 0x00 is used as unclassified for all minor device classes */
#define BTM_COD_MINOR_UNCLASSIFIED          0x00

/* minor device class field for Computer Major Class */
/* #define BTM_COD_MINOR_UNCLASSIFIED       0x00    */
#define BTM_COD_MINOR_DESKTOP_WORKSTATION   0x04
#define BTM_COD_MINOR_SERVER_COMPUTER       0x08
#define BTM_COD_MINOR_LAPTOP                0x0C
#define BTM_COD_MINOR_HANDHELD_PC_PDA       0x10    /* clam shell */
#define BTM_COD_MINOR_PALM_SIZE_PC_PDA      0x14
#define BTM_COD_MINOR_WEARABLE_COMPUTER     0x18    /* watch sized */

/* minor device class field for Phone Major Class */
/* #define BTM_COD_MINOR_UNCLASSIFIED       0x00    */
#define BTM_COD_MINOR_CELLULAR              0x04
#define BTM_COD_MINOR_CORDLESS              0x08
#define BTM_COD_MINOR_SMART_PHONE           0x0C
#define BTM_COD_MINOR_WIRED_MDM_V_GTWY      0x10 /* wired modem or voice gatway */
#define BTM_COD_MINOR_ISDN_ACCESS           0x14

/* minor device class field for LAN Access Point Major Class */
/* Load Factor Field bit 5-7 */
#define BTM_COD_MINOR_FULLY_AVAILABLE       0x00
#define BTM_COD_MINOR_1_17_UTILIZED         0x20
#define BTM_COD_MINOR_17_33_UTILIZED        0x40
#define BTM_COD_MINOR_33_50_UTILIZED        0x60
#define BTM_COD_MINOR_50_67_UTILIZED        0x80
#define BTM_COD_MINOR_67_83_UTILIZED        0xA0
#define BTM_COD_MINOR_83_99_UTILIZED        0xC0
#define BTM_COD_MINOR_NO_SERVICE_AVAILABLE  0xE0
/* sub-Field bit 2-4 */
/* #define BTM_COD_MINOR_UNCLASSIFIED       0x00    */

/* minor device class field for Audio/Video Major Class */
/* #define BTM_COD_MINOR_UNCLASSIFIED       0x00    */
#define BTM_COD_MINOR_CONFM_HEADSET         0x04
#define BTM_COD_MINOR_CONFM_HANDSFREE       0x08
#define BTM_COD_MINOR_MICROPHONE            0x10
#define BTM_COD_MINOR_LOUDSPEAKER           0x14
#define BTM_COD_MINOR_HEADPHONES            0x18
#define BTM_COD_MINOR_PORTABLE_AUDIO        0x1C
#define BTM_COD_MINOR_CAR_AUDIO             0x20
#define BTM_COD_MINOR_SET_TOP_BOX           0x24
#define BTM_COD_MINOR_HIFI_AUDIO            0x28
#define BTM_COD_MINOR_VCR                   0x2C
#define BTM_COD_MINOR_VIDEO_CAMERA          0x30
#define BTM_COD_MINOR_CAMCORDER             0x34
#define BTM_COD_MINOR_VIDEO_MONITOR         0x38
#define BTM_COD_MINOR_VIDDISP_LDSPKR        0x3C
#define BTM_COD_MINOR_VIDEO_CONFERENCING    0x40
#define BTM_COD_MINOR_GAMING_TOY            0x48

/* minor device class field for Peripheral Major Class */
/* Bits 6-7 independently specify mouse, keyboard, or combo mouse/keyboard */
#define BTM_COD_MINOR_KEYBOARD              0x40
#define BTM_COD_MINOR_POINTING              0x80
#define BTM_COD_MINOR_COMBO                 0xC0
/* Bits 2-5 OR'd with selection from bits 6-7 */
/* #define BTM_COD_MINOR_UNCLASSIFIED       0x00    */
#define BTM_COD_MINOR_JOYSTICK              0x04
#define BTM_COD_MINOR_GAMEPAD               0x08
#define BTM_COD_MINOR_REMOTE_CONTROL        0x0C
#define BTM_COD_MINOR_SENSING_DEVICE        0x10
#define BTM_COD_MINOR_DIGITIZING_TABLET     0x14
#define BTM_COD_MINOR_CARD_READER           0x18    /* e.g. SIM card reader */
#define BTM_COD_MINOR_DIGITAL_PAN           0x1C
#define BTM_COD_MINOR_HAND_SCANNER          0x20
#define BTM_COD_MINOR_HAND_GESTURAL_INPUT   0x24

/* minor device class field for Imaging Major Class */
/* Bits 5-7 independently specify display, camera, scanner, or printer */
#define BTM_COD_MINOR_DISPLAY               0x10
#define BTM_COD_MINOR_CAMERA                0x20
#define BTM_COD_MINOR_SCANNER               0x40
#define BTM_COD_MINOR_PRINTER               0x80
/* Bits 2-3 Reserved */
/* #define BTM_COD_MINOR_UNCLASSIFIED       0x00    */

/* minor device class field for Wearable Major Class */
/* Bits 2-7 meaningful    */
#define BTM_COD_MINOR_WRIST_WATCH           0x04
#define BTM_COD_MINOR_PAGER                 0x08
#define BTM_COD_MINOR_JACKET                0x0C
#define BTM_COD_MINOR_HELMET                0x10
#define BTM_COD_MINOR_GLASSES               0x14

/* minor device class field for Toy Major Class */
/* Bits 2-7 meaningful    */
#define BTM_COD_MINOR_ROBOT                 0x04
#define BTM_COD_MINOR_VEHICLE               0x08
#define BTM_COD_MINOR_DOLL_ACTION_FIGURE    0x0C
#define BTM_COD_MINOR_CONTROLLER            0x10
#define BTM_COD_MINOR_GAME                  0x14

/* minor device class field for Health Major Class */
/* Bits 2-7 meaningful    */
#define BTM_COD_MINOR_BLOOD_MONITOR         0x04
#define BTM_COD_MINOR_THERMOMETER           0x08
#define BTM_COD_MINOR_WEIGHING_SCALE        0x0C
#define BTM_COD_MINOR_GLUCOSE_METER         0x10
#define BTM_COD_MINOR_PULSE_OXIMETER        0x14
#define BTM_COD_MINOR_HEART_PULSE_MONITOR   0x18
#define BTM_COD_MINOR_HEALTH_DATA_DISPLAY   0x1C
#define BTM_COD_MINOR_STEP_COUNTER          0x20
#define BTM_COD_MINOR_BODY_COM_ANALYZER     0x24
#define BTM_COD_MINOR_PEAK_FLOW_MONITOR     0x28
#define BTM_COD_MINOR_MEDICATION_MONITOR    0x2C
#define BTM_COD_MINOR_KNEE_PROSTHESIS       0x30
#define BTM_COD_MINOR_ANKLE_PROSTHESIS      0x34


/***************************
** major device class field
****************************/
#define BTM_COD_MAJOR_MISCELLANEOUS         0x00
#define BTM_COD_MAJOR_COMPUTER              0x01
#define BTM_COD_MAJOR_PHONE                 0x02
#define BTM_COD_MAJOR_LAN_ACCESS_PT         0x03
#define BTM_COD_MAJOR_AUDIO                 0x04
#define BTM_COD_MAJOR_PERIPHERAL            0x05
#define BTM_COD_MAJOR_IMAGING               0x06
#define BTM_COD_MAJOR_WEARABLE              0x07
#define BTM_COD_MAJOR_TOY                   0x08
#define BTM_COD_MAJOR_HEALTH                0x09
#define BTM_COD_MAJOR_UNCLASSIFIED          0x1F

/***************************
** service class fields
****************************/
#define BTM_COD_SERVICE_LMTD_DISCOVER       0x0020
#define BTM_COD_SERVICE_POSITIONING         0x0100
#define BTM_COD_SERVICE_NETWORKING          0x0200
#define BTM_COD_SERVICE_RENDERING           0x0400
#define BTM_COD_SERVICE_CAPTURING           0x0800
#define BTM_COD_SERVICE_OBJ_TRANSFER        0x1000
#define BTM_COD_SERVICE_AUDIO               0x2000
#define BTM_COD_SERVICE_TELEPHONY           0x4000
#define BTM_COD_SERVICE_INFORMATION         0x8000

/* class of device field macros */
#define BTM_COD_FORMAT_TYPE(u8, pd)         {u8  = pd[2]&0x03;}
#define BTM_COD_MINOR_CLASS(u8, pd)         {u8  = pd[2]&0xFC;}
#define BTM_COD_MAJOR_CLASS(u8, pd)         {u8  = pd[1]&0x1F;}
#define BTM_COD_SERVICE_CLASS(u16, pd)      {u16 = pd[0]; u16<<=8; u16 += pd[1]&0xE0;}

/* to set the fields (assumes that format type is always 0) */
#define FIELDS_TO_COD(pd, mn, mj, sv) {pd[2] = mn; pd[1] =              \
                                       mj+ ((sv)&BTM_COD_SERVICE_CLASS_LO_B); \
                                       pd[0] = (sv) >> 8;}

/* the COD masks */
#define BTM_COD_FORMAT_TYPE_MASK      0x03
#define BTM_COD_MINOR_CLASS_MASK      0xFC
#define BTM_COD_MAJOR_CLASS_MASK      0x1F
#define BTM_COD_SERVICE_CLASS_LO_B    0x00E0
#define BTM_COD_SERVICE_CLASS_MASK    0xFFE0


/* BTM service definitions
** Used for storing EIR data to bit mask
*/
enum
{
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
#define BTM_EIR_FOUND           0
#define BTM_EIR_NOT_FOUND       1
#define BTM_EIR_UNKNOWN         2

typedef UINT8 tBTM_EIR_SEARCH_RESULT;

#define BTM_EIR_FLAGS_TYPE                  HCI_EIR_FLAGS_TYPE                  /* 0x01 */
#define BTM_EIR_MORE_16BITS_UUID_TYPE       HCI_EIR_MORE_16BITS_UUID_TYPE       /* 0x02 */
#define BTM_EIR_COMPLETE_16BITS_UUID_TYPE   HCI_EIR_COMPLETE_16BITS_UUID_TYPE   /* 0x03 */
#define BTM_EIR_MORE_32BITS_UUID_TYPE       HCI_EIR_MORE_32BITS_UUID_TYPE       /* 0x04 */
#define BTM_EIR_COMPLETE_32BITS_UUID_TYPE   HCI_EIR_COMPLETE_32BITS_UUID_TYPE   /* 0x05 */
#define BTM_EIR_MORE_128BITS_UUID_TYPE      HCI_EIR_MORE_128BITS_UUID_TYPE      /* 0x06 */
#define BTM_EIR_COMPLETE_128BITS_UUID_TYPE  HCI_EIR_COMPLETE_128BITS_UUID_TYPE  /* 0x07 */
#define BTM_EIR_SHORTENED_LOCAL_NAME_TYPE   HCI_EIR_SHORTENED_LOCAL_NAME_TYPE   /* 0x08 */
#define BTM_EIR_COMPLETE_LOCAL_NAME_TYPE    HCI_EIR_COMPLETE_LOCAL_NAME_TYPE    /* 0x09 */
#define BTM_EIR_TX_POWER_LEVEL_TYPE         HCI_EIR_TX_POWER_LEVEL_TYPE         /* 0x0A */
#define BTM_EIR_MANUFACTURER_SPECIFIC_TYPE  HCI_EIR_MANUFACTURER_SPECIFIC_TYPE  /* 0xFF */

/* the following EIR tags are defined to OOB, not regular EIR data */
#define BTM_EIR_OOB_BD_ADDR_TYPE            HCI_EIR_OOB_BD_ADDR_TYPE    /* 6 bytes */
#define BTM_EIR_OOB_COD_TYPE                HCI_EIR_OOB_COD_TYPE        /* 3 bytes */
#define BTM_EIR_OOB_SSP_HASH_C_TYPE         HCI_EIR_OOB_SSP_HASH_C_TYPE /* 16 bytes */
#define BTM_EIR_OOB_SSP_RAND_R_TYPE         HCI_EIR_OOB_SSP_RAND_R_TYPE /* 16 bytes */

#define BTM_OOB_MANDATORY_SIZE      8   /* include 2 bytes length & 6 bytes bd_addr */
#define BTM_OOB_DATA_LEN_SIZE       2
#define BTM_OOB_BD_ADDR_SIZE        6
#define BTM_OOB_COD_SIZE            BT_OOB_COD_SIZE
#define BTM_OOB_HASH_C_SIZE         BT_OOB_HASH_C_SIZE
#define BTM_OOB_RAND_R_SIZE         BT_OOB_RAND_R_SIZE

#define BTM_BLE_SEC_NONE                0
#define BTM_BLE_SEC_ENCRYPT             1 /* encrypt the link using current key */
#define BTM_BLE_SEC_ENCRYPT_NO_MITM     2
#define BTM_BLE_SEC_ENCRYPT_MITM        3
typedef UINT8   tBTM_BLE_SEC_ACT;

/************************************************************************************************
** BTM Services MACROS handle array of UINT32 bits for more than 32 services
*************************************************************************************************/
/* Determine the number of UINT32's necessary for services */
#define BTM_EIR_ARRAY_BITS          32          /* Number of bits in each array element */
#define BTM_EIR_SERVICE_ARRAY_SIZE  (((UINT32)BTM_EIR_MAX_SERVICES / BTM_EIR_ARRAY_BITS) + \
                                    (((UINT32)BTM_EIR_MAX_SERVICES % BTM_EIR_ARRAY_BITS) ? 1 : 0))

/* MACRO to set the service bit mask in a bit stream */
#define BTM_EIR_SET_SERVICE(p, service)  (((UINT32 *)(p))[(((UINT32)(service)) / BTM_EIR_ARRAY_BITS)] |=  \
                                    ((UINT32)1 << (((UINT32)(service)) % BTM_EIR_ARRAY_BITS)))


/* MACRO to clear the service bit mask in a bit stream */
#define BTM_EIR_CLR_SERVICE(p, service)  (((UINT32 *)(p))[(((UINT32)(service)) / BTM_EIR_ARRAY_BITS)] &=  \
                                    ~((UINT32)1 << (((UINT32)(service)) % BTM_EIR_ARRAY_BITS)))

/* MACRO to check the service bit mask in a bit stream */
#define BTM_EIR_HAS_SERVICE(p, service)  ((((UINT32 *)(p))[(((UINT32)(service)) / BTM_EIR_ARRAY_BITS)] &  \
                                    ((UINT32)1 << (((UINT32)(service)) % BTM_EIR_ARRAY_BITS))) >> (((UINT32)(service)) % BTM_EIR_ARRAY_BITS))

/* start of EIR in HCI buffer, 4 bytes = HCI Command(2) + Length(1) + FEC_Req(1) */
#define BTM_HCI_EIR_OFFSET          (BT_HDR_SIZE + 4)

/***************************
**  Device Discovery Types
****************************/
/* Definitions of the parameters passed to BTM_StartInquiry and
** BTM_SetPeriodicInquiryMode.
*/
typedef struct              /* contains the two device class condition fields */
{
    DEV_CLASS       dev_class;
    DEV_CLASS       dev_class_mask;
} tBTM_COD_COND;


typedef union               /* contains the inquiry filter condition */
{
    BD_ADDR         bdaddr_cond;
    tBTM_COD_COND   cod_cond;
} tBTM_INQ_FILT_COND;


typedef struct              /* contains the parameters passed to the inquiry functions */
{
    UINT8   mode;                       /* general or limited */
    UINT8   duration;                   /* duration of the inquiry (1.28 sec increments) */
    UINT8   max_resps;                  /* maximum number of responses to return */
    BOOLEAN report_dup;                 /* report duplicated inquiry response with higher RSSI value */
    UINT8   filter_cond_type;           /* new devices, BD ADDR, COD, or No filtering */
    tBTM_INQ_FILT_COND  filter_cond;    /* filter value based on filter cond type */
#if (defined(BTA_HOST_INTERLEAVE_SEARCH) && BTA_HOST_INTERLEAVE_SEARCH == TRUE)
    UINT8   intl_duration[4];              /*duration array storing the interleave scan's time portions*/
#endif
} tBTM_INQ_PARMS;

#define BTM_INQ_RESULT_BR       0x01
#define BTM_INQ_RESULT_BLE      0x02

#if (BLE_INCLUDED == TRUE)
#define BTM_BLE_EVT_CONN_ADV        0x00
#define BTM_BLE_EVT_CONN_DIR_ADV    0x01
#define BTM_BLE_EVT_DISC_ADV        0x02
#define BTM_BLE_EVT_NON_CONN_ADV    0x03
#define BTM_BLE_EVT_SCAN_RSP        0x04
typedef UINT8 tBTM_BLE_EVT_TYPE;
#endif

/* These are the fields returned in each device's response to the inquiry.  It
** is returned in the results callback if registered.
*/
typedef struct
{
    UINT16      clock_offset;
    BD_ADDR     remote_bd_addr;
    DEV_CLASS   dev_class;
    UINT8       page_scan_rep_mode;
    UINT8       page_scan_per_mode;
    UINT8       page_scan_mode;
    INT8        rssi;       /* Set to BTM_INQ_RES_IGNORE_RSSI if  not valid */
    UINT32      eir_uuid[BTM_EIR_SERVICE_ARRAY_SIZE];
    BOOLEAN     eir_complete_list;
#if (BLE_INCLUDED == TRUE)
    tBT_DEVICE_TYPE         device_type;
    UINT8       inq_result_type;
    UINT8       ble_addr_type;
    tBTM_BLE_EVT_TYPE       ble_evt_type;
    UINT8                   flag;
#endif
} tBTM_INQ_RESULTS;


/* This is the inquiry response information held in its database by BTM, and available
** to applications via BTM_InqDbRead, BTM_InqDbFirst, and BTM_InqDbNext.
*/
typedef struct
{
    tBTM_INQ_RESULTS    results;

    BOOLEAN             appl_knows_rem_name;    /* set by application if it knows the remote name of the peer device.
                                                   This is later used by application to determine if remote name request is
                                                   required to be done. Having the flag here avoid duplicate store of inquiry results */
#if ( BLE_INCLUDED == TRUE)
    UINT16          remote_name_len;
    tBTM_BD_NAME    remote_name;
    UINT8           remote_name_state;
    UINT8           remote_name_type;
#endif

} tBTM_INQ_INFO;


/* Structure returned with inquiry complete callback */
typedef struct
{
    tBTM_STATUS status;
    UINT8       num_resp;       /* Number of results from the current inquiry */
} tBTM_INQUIRY_CMPL;


/* Structure returned with remote name  request */
typedef struct
{
    UINT16      status;
    BD_ADDR     bd_addr;
    UINT16      length;
    BD_NAME     remote_bd_name;
} tBTM_REMOTE_DEV_NAME;

typedef struct
{
    UINT8   pcm_intf_rate;  /* PCM interface rate: 0: 128kbps, 1: 256 kbps;
                                2:512 bps; 3: 1024kbps; 4: 2048kbps */
    UINT8   frame_type;     /* frame type: 0: short; 1: long */
    UINT8   sync_mode;      /* sync mode: 0: slave; 1: master */
    UINT8   clock_mode;     /* clock mode: 0: slave; 1: master */

}tBTM_SCO_PCM_PARAM;

/****************************************
**  Device Discovery Callback Functions
*****************************************/
/* Callback function for asynchronous notifications when the BTM inquiry DB
** changes. First param is inquiry database, second is if added to or removed
** from the inquiry database.
*/
typedef void (tBTM_INQ_DB_CHANGE_CB) (void *p1, BOOLEAN is_new);

/* Callback function for notifications when the BTM gets inquiry response.
** First param is inquiry results database, second is pointer of EIR.
*/
typedef void (tBTM_INQ_RESULTS_CB) (tBTM_INQ_RESULTS *p_inq_results, UINT8 *p_eir);

/*****************************************************************************
**  ACL CHANNEL MANAGEMENT
*****************************************************************************/
/******************
**  ACL Constants
*******************/

/* ACL modes */
#define BTM_ACL_MODE_NORMAL     HCI_MODE_ACTIVE
#define BTM_ACL_MODE_HOLD       HCI_MODE_HOLD
#define BTM_ACL_MODE_SNIFF      HCI_MODE_SNIFF
#define BTM_ACL_MODE_PARK       HCI_MODE_PARK

/* Returned with structure in role switch callback (tBTM_ROLE_SWITCH_CMPL) */
#define BTM_ROLE_MASTER         HCI_ROLE_MASTER
#define BTM_ROLE_SLAVE          HCI_ROLE_SLAVE
#define BTM_ROLE_UNDEFINED      0xff     /* undefined value (error status) */

/* ACL Packet Types */
#define BTM_ACL_PKT_TYPES_MASK_DM1      HCI_PKT_TYPES_MASK_DM1
#define BTM_ACL_PKT_TYPES_MASK_DH1      HCI_PKT_TYPES_MASK_DH1
#define BTM_ACL_PKT_TYPES_MASK_DM3      HCI_PKT_TYPES_MASK_DM3
#define BTM_ACL_PKT_TYPES_MASK_DH3      HCI_PKT_TYPES_MASK_DH3
#define BTM_ACL_PKT_TYPES_MASK_DM5      HCI_PKT_TYPES_MASK_DM5
#define BTM_ACL_PKT_TYPES_MASK_DH5      HCI_PKT_TYPES_MASK_DH5
#define BTM_ACL_PKT_TYPES_MASK_NO_2_DH1 HCI_PKT_TYPES_MASK_NO_2_DH1
#define BTM_ACL_PKT_TYPES_MASK_NO_3_DH1 HCI_PKT_TYPES_MASK_NO_3_DH1
#define BTM_ACL_PKT_TYPES_MASK_NO_2_DH3 HCI_PKT_TYPES_MASK_NO_2_DH3
#define BTM_ACL_PKT_TYPES_MASK_NO_3_DH3 HCI_PKT_TYPES_MASK_NO_3_DH3
#define BTM_ACL_PKT_TYPES_MASK_NO_2_DH5 HCI_PKT_TYPES_MASK_NO_2_DH5
#define BTM_ACL_PKT_TYPES_MASK_NO_3_DH5 HCI_PKT_TYPES_MASK_NO_3_DH5

/***************
**  ACL Types
****************/

/* Structure returned with Role Switch information (in tBTM_CMPL_CB callback function)
** in response to BTM_SwitchRole call.
*/
typedef struct
{
    UINT8   hci_status;     /* HCI status returned with the event */
    UINT8   role;           /* BTM_ROLE_MASTER or BTM_ROLE_SLAVE */
    BD_ADDR remote_bd_addr; /* Remote BD addr involved with the switch */
} tBTM_ROLE_SWITCH_CMPL;

/* Structure returned with QoS information (in tBTM_CMPL_CB callback function)
** in response to BTM_SetQoS call.
*/
typedef struct
{
    FLOW_SPEC flow;
    UINT16 handle;
    UINT8 status;
} tBTM_QOS_SETUP_CMPL;


/* Structure returned with read RSSI event (in tBTM_CMPL_CB callback function)
** in response to BTM_ReadRSSI call.
*/
typedef struct
{
    tBTM_STATUS status;
    UINT8       hci_status;
    INT8        rssi;
    BD_ADDR     rem_bda;
} tBTM_RSSI_RESULTS;

/* Structure returned with read current TX power event (in tBTM_CMPL_CB callback function)
** in response to BTM_ReadTxPower call.
*/
typedef struct
{
    tBTM_STATUS status;
    UINT8       hci_status;
    INT8        tx_power;
    BD_ADDR     rem_bda;
} tBTM_TX_POWER_RESULTS;

/* Structure returned with read link quality event (in tBTM_CMPL_CB callback function)
** in response to BTM_ReadLinkQuality call.
*/
typedef struct
{
    tBTM_STATUS status;
    UINT8       hci_status;
    UINT8       link_quality;
    BD_ADDR     rem_bda;
} tBTM_LINK_QUALITY_RESULTS;

/* Structure returned with read inq tx power quality event (in tBTM_CMPL_CB callback function)
** in response to BTM_ReadInquiryRspTxPower call.
*/
typedef struct
{
    tBTM_STATUS status;
    UINT8       hci_status;
    INT8        tx_power;
} tBTM_INQ_TXPWR_RESULTS;

enum
{
    BTM_BL_CONN_EVT,
    BTM_BL_DISCN_EVT,
    BTM_BL_UPDATE_EVT,
    BTM_BL_ROLE_CHG_EVT,
    BTM_BL_COLLISION_EVT
};
typedef UINT8 tBTM_BL_EVENT;
typedef UINT16 tBTM_BL_EVENT_MASK;

#define BTM_BL_CONN_MASK        0x0001
#define BTM_BL_DISCN_MASK       0x0002
#define BTM_BL_UPDATE_MASK      0x0004
#define BTM_BL_ROLE_CHG_MASK    0x0008

/* Device features mask definitions */
#define BTM_FEATURE_BYTES_PER_PAGE  HCI_FEATURE_BYTES_PER_PAGE
#define BTM_EXT_FEATURES_PAGE_MAX   HCI_EXT_FEATURES_PAGE_MAX

/* the data type associated with BTM_BL_CONN_EVT */
typedef struct
{
    tBTM_BL_EVENT   event;      /* The event reported. */
    BD_ADDR_PTR     p_bda;      /* The address of the newly connected device */
    DEV_CLASS_PTR   p_dc;       /* The device class */
    BD_NAME_PTR     p_bdn;      /* The device name */
    UINT8          *p_features; /* pointer to the remote device's features page[0] (supported features page) */
#if BLE_INCLUDED == TRUE
    UINT16          handle;     /* connection handle */
    tBT_TRANSPORT   transport; /* link is LE or not */
#endif
} tBTM_BL_CONN_DATA;

/* the data type associated with BTM_BL_DISCN_EVT */
typedef struct
{
    tBTM_BL_EVENT   event;  /* The event reported. */
    BD_ADDR_PTR     p_bda;  /* The address of the disconnected device */
#if BLE_INCLUDED == TRUE
    UINT16          handle; /* disconnected connection handle */
    tBT_TRANSPORT   transport; /* link is LE link or not */
#endif
} tBTM_BL_DISCN_DATA;

/* Busy-Level shall have the inquiry_paging mask set when
 * inquiry/paging is in progress, Else the number of ACL links */
#define BTM_BL_INQUIRY_PAGING_MASK 0x10
#define BTM_BL_INQUIRY_STARTED   (BTM_BL_INQUIRY_PAGING_MASK | 0x1)
#define BTM_BL_INQUIRY_CANCELLED (BTM_BL_INQUIRY_PAGING_MASK | 0x2)
#define BTM_BL_INQUIRY_COMPLETE  (BTM_BL_INQUIRY_PAGING_MASK | 0x3)
#define BTM_BL_PAGING_STARTED    (BTM_BL_INQUIRY_PAGING_MASK | 0x4)
#define BTM_BL_PAGING_COMPLETE   (BTM_BL_INQUIRY_PAGING_MASK | 0x5)
/* the data type associated with BTM_BL_UPDATE_EVT */
typedef struct
{
    tBTM_BL_EVENT   event;  /* The event reported. */
    UINT8           busy_level;/* when paging or inquiring, level is between
                                  17 to 21 as the max links can be 16.
                                * Otherwise, the number of ACL links. */
    UINT8           busy_level_flags; /* Notifies actual inquiry/page activities */
} tBTM_BL_UPDATE_DATA;

/* the data type associated with BTM_BL_ROLE_CHG_EVT */
typedef struct
{
    tBTM_BL_EVENT   event;      /* The event reported. */
    BD_ADDR_PTR     p_bda;      /* The address of the peer connected device */
    UINT8           new_role;
    UINT8           hci_status; /* HCI status returned with the event */
} tBTM_BL_ROLE_CHG_DATA;

typedef union
{
    tBTM_BL_EVENT           event;  /* The event reported. */
    tBTM_BL_CONN_DATA       conn;   /* The data associated with BTM_BL_CONN_EVT */
    tBTM_BL_DISCN_DATA      discn;  /* The data associated with BTM_BL_DISCN_EVT */
    tBTM_BL_UPDATE_DATA     update; /* The data associated with BTM_BL_UPDATE_EVT */
    tBTM_BL_ROLE_CHG_DATA   role_chg;/*The data associated with BTM_BL_ROLE_CHG_EVT */
} tBTM_BL_EVENT_DATA;

/* Callback function for notifications when the BTM busy level
** changes.
*/
typedef void (tBTM_BL_CHANGE_CB) (tBTM_BL_EVENT_DATA *p_data);

/***************************
**  ACL Callback Functions
****************************/
/* Callback function for notifications when the BTM ACL connection DB
** changes. First param is BD address, second is if added or removed.
** Registered through BTM_AclRegisterForChanges call.
*/
#if BLE_INCLUDED == TRUE
typedef void (tBTM_ACL_DB_CHANGE_CB) (BD_ADDR p_bda, DEV_CLASS p_dc,
                                      BD_NAME p_bdn, UINT8 *features,
                                      BOOLEAN is_new, UINT16 handle,
                                      tBT_TRANSPORT transport);
#else
typedef void (tBTM_ACL_DB_CHANGE_CB) (BD_ADDR p_bda, DEV_CLASS p_dc,
                                      BD_NAME p_bdn, UINT8 *features,
                                      BOOLEAN is_new);
#endif
/*****************************************************************************
**  SCO CHANNEL MANAGEMENT
*****************************************************************************/
/******************
**  SCO Constants
*******************/

/* Define an invalid SCO index and an invalid HCI handle */
#define BTM_INVALID_SCO_INDEX       0xFFFF
#define BTM_INVALID_HCI_HANDLE      0xFFFF

/* Define an invalid SCO disconnect reason */
#define BTM_INVALID_SCO_DISC_REASON 0xFFFF

/* Define first active SCO index */
#define BTM_FIRST_ACTIVE_SCO_INDEX  BTM_MAX_SCO_LINKS

/* Define SCO packet types used in APIs */
#define BTM_SCO_PKT_TYPES_MASK_HV1  HCI_ESCO_PKT_TYPES_MASK_HV1
#define BTM_SCO_PKT_TYPES_MASK_HV2  HCI_ESCO_PKT_TYPES_MASK_HV2
#define BTM_SCO_PKT_TYPES_MASK_HV3  HCI_ESCO_PKT_TYPES_MASK_HV3
#define BTM_SCO_PKT_TYPES_MASK_EV3  HCI_ESCO_PKT_TYPES_MASK_EV3
#define BTM_SCO_PKT_TYPES_MASK_EV4  HCI_ESCO_PKT_TYPES_MASK_EV4
#define BTM_SCO_PKT_TYPES_MASK_EV5  HCI_ESCO_PKT_TYPES_MASK_EV5
#define BTM_SCO_PKT_TYPES_MASK_NO_2_EV3  HCI_ESCO_PKT_TYPES_MASK_NO_2_EV3
#define BTM_SCO_PKT_TYPES_MASK_NO_3_EV3  HCI_ESCO_PKT_TYPES_MASK_NO_3_EV3
#define BTM_SCO_PKT_TYPES_MASK_NO_2_EV5  HCI_ESCO_PKT_TYPES_MASK_NO_2_EV5
#define BTM_SCO_PKT_TYPES_MASK_NO_3_EV5  HCI_ESCO_PKT_TYPES_MASK_NO_3_EV5

#define BTM_SCO_LINK_ONLY_MASK  (BTM_SCO_PKT_TYPES_MASK_HV1 | \
                                 BTM_SCO_PKT_TYPES_MASK_HV2 | \
                                 BTM_SCO_PKT_TYPES_MASK_HV3)

#define BTM_ESCO_LINK_ONLY_MASK (BTM_SCO_PKT_TYPES_MASK_EV3 | \
                                 BTM_SCO_PKT_TYPES_MASK_EV4 | \
                                 BTM_SCO_PKT_TYPES_MASK_EV5)

#define BTM_SCO_LINK_ALL_PKT_MASK   (BTM_SCO_LINK_ONLY_MASK     | \
                                     BTM_ESCO_LINK_ONLY_MASK)

#define BTM_VALID_SCO_ALL_PKT_TYPE HCI_VALID_SCO_ALL_PKT_TYPE

/* Passed in BTM_CreateSco if the packet type parameter should be ignored */
#define BTM_IGNORE_SCO_PKT_TYPE     0

/***************
**  SCO Types
****************/
#define BTM_LINK_TYPE_SCO           HCI_LINK_TYPE_SCO
#define BTM_LINK_TYPE_ESCO          HCI_LINK_TYPE_ESCO
typedef UINT8 tBTM_SCO_TYPE;


/*******************
** SCO Routing Path
********************/
#define BTM_SCO_ROUTE_PCM           HCI_BRCM_SCO_ROUTE_PCM
#define BTM_SCO_ROUTE_HCI           HCI_BRCM_SCO_ROUTE_HCI
typedef UINT8 tBTM_SCO_ROUTE_TYPE;


/*******************
** SCO Codec Types
********************/
// TODO(google) This should use common definitions
// in hci/include/hci_audio.h
#define BTM_SCO_CODEC_NONE          0x0000
#define BTM_SCO_CODEC_CVSD          0x0001
#define BTM_SCO_CODEC_MSBC          0x0002
typedef UINT16 tBTM_SCO_CODEC_TYPE;



/*******************
** SCO Air Mode Types
********************/
#define BTM_SCO_AIR_MODE_U_LAW          0
#define BTM_SCO_AIR_MODE_A_LAW          1
#define BTM_SCO_AIR_MODE_CVSD           2
#define BTM_SCO_AIR_MODE_TRANSPNT       3
typedef UINT8 tBTM_SCO_AIR_MODE_TYPE;

/*******************
** SCO Voice Settings
********************/
#define BTM_VOICE_SETTING_CVSD  ((UINT16)  (HCI_INP_CODING_LINEAR          |   \
                                            HCI_INP_DATA_FMT_2S_COMPLEMENT |   \
                                            HCI_INP_SAMPLE_SIZE_16BIT      |   \
                                            HCI_AIR_CODING_FORMAT_CVSD))

#define BTM_VOICE_SETTING_TRANS ((UINT16)  (HCI_INP_CODING_LINEAR          |   \
                                            HCI_INP_DATA_FMT_2S_COMPLEMENT |   \
                                            HCI_INP_SAMPLE_SIZE_16BIT      |   \
                                            HCI_AIR_CODING_FORMAT_TRANSPNT))

/*******************
** SCO Data Status
********************/
enum
{
    BTM_SCO_DATA_CORRECT,
    BTM_SCO_DATA_PAR_ERR,
    BTM_SCO_DATA_NONE,
    BTM_SCO_DATA_PAR_LOST
};
typedef UINT8 tBTM_SCO_DATA_FLAG;

/***************************
**  SCO Callback Functions
****************************/
typedef void (tBTM_SCO_CB) (UINT16 sco_inx);
typedef void (tBTM_SCO_DATA_CB) (UINT16 sco_inx, BT_HDR *p_data, tBTM_SCO_DATA_FLAG status);

/******************
**  eSCO Constants
*******************/
#define BTM_64KBITS_RATE            0x00001f40  /* 64 kbits/sec data rate */

/* Retransmission effort */
#define BTM_ESCO_RETRANS_OFF        0
#define BTM_ESCO_RETRANS_POWER      1
#define BTM_ESCO_RETRANS_QUALITY    2
#define BTM_ESCO_RETRANS_DONTCARE   0xff

/* Max Latency Don't Care */
#define BTM_ESCO_MAX_LAT_DONTCARE   0xffff

/***************
**  eSCO Types
****************/
/* tBTM_ESCO_CBACK event types */
#define BTM_ESCO_CHG_EVT        1
#define BTM_ESCO_CONN_REQ_EVT   2
typedef UINT8 tBTM_ESCO_EVT;

/* Passed into BTM_SetEScoMode() */
typedef struct
{
    UINT32 tx_bw;
    UINT32 rx_bw;
    UINT16 max_latency;
    UINT16 voice_contfmt;  /* Voice Settings or Content Format */
    UINT16 packet_types;
    UINT8  retrans_effort;
} tBTM_ESCO_PARAMS;

typedef struct
{
    UINT16 max_latency;
    UINT16 packet_types;
    UINT8  retrans_effort;
} tBTM_CHG_ESCO_PARAMS;

/* Returned by BTM_ReadEScoLinkParms() */
typedef struct
{
    UINT16  rx_pkt_len;
    UINT16  tx_pkt_len;
    BD_ADDR bd_addr;
    UINT8   link_type;  /* BTM_LINK_TYPE_SCO or BTM_LINK_TYPE_ESCO */
    UINT8   tx_interval;
    UINT8   retrans_window;
    UINT8   air_mode;
} tBTM_ESCO_DATA;

typedef struct
{
    UINT16  sco_inx;
    UINT16  rx_pkt_len;
    UINT16  tx_pkt_len;
    BD_ADDR bd_addr;
    UINT8   hci_status;
    UINT8   tx_interval;
    UINT8   retrans_window;
} tBTM_CHG_ESCO_EVT_DATA;

typedef struct
{
    UINT16        sco_inx;
    BD_ADDR       bd_addr;
    DEV_CLASS     dev_class;
    tBTM_SCO_TYPE link_type;
} tBTM_ESCO_CONN_REQ_EVT_DATA;

typedef union
{
    tBTM_CHG_ESCO_EVT_DATA      chg_evt;
    tBTM_ESCO_CONN_REQ_EVT_DATA conn_evt;
} tBTM_ESCO_EVT_DATA;

/***************************
**  eSCO Callback Functions
****************************/
typedef void (tBTM_ESCO_CBACK) (tBTM_ESCO_EVT event, tBTM_ESCO_EVT_DATA *p_data);


/*****************************************************************************
**  SECURITY MANAGEMENT
*****************************************************************************/
/*******************************
**  Security Manager Constants
********************************/

/* Security Mode (BTM_SetSecurityMode) */
#define BTM_SEC_MODE_UNDEFINED      0
#define BTM_SEC_MODE_NONE           1
#define BTM_SEC_MODE_SERVICE        2
#define BTM_SEC_MODE_LINK           3
#define BTM_SEC_MODE_SP             4
#define BTM_SEC_MODE_SP_DEBUG       5
#define BTM_SEC_MODE_SC             6

/* Maximum Number of BTM Security Modes */
#define BTM_SEC_MODES_MAX           7

/* Security Service Levels [bit mask] (BTM_SetSecurityLevel)
** Encryption should not be used without authentication
*/
#define BTM_SEC_NONE               0x0000 /* Nothing required */
#define BTM_SEC_IN_AUTHORIZE       0x0001 /* Inbound call requires authorization */
#define BTM_SEC_IN_AUTHENTICATE    0x0002 /* Inbound call requires authentication */
#define BTM_SEC_IN_ENCRYPT         0x0004 /* Inbound call requires encryption */
#define BTM_SEC_OUT_AUTHORIZE      0x0008 /* Outbound call requires authorization */
#define BTM_SEC_OUT_AUTHENTICATE   0x0010 /* Outbound call requires authentication */
#define BTM_SEC_OUT_ENCRYPT        0x0020 /* Outbound call requires encryption */
#define BTM_SEC_MODE4_LEVEL4       0x0040 /* Secure Connections Only Mode */
#define BTM_SEC_FORCE_MASTER       0x0100 /* Need to switch connection to be master */
#define BTM_SEC_ATTEMPT_MASTER     0x0200 /* Try to switch connection to be master */
#define BTM_SEC_FORCE_SLAVE        0x0400 /* Need to switch connection to be master */
#define BTM_SEC_ATTEMPT_SLAVE      0x0800 /* Try to switch connection to be slave */
#define BTM_SEC_IN_MITM            0x1000 /* inbound Do man in the middle protection */
#define BTM_SEC_OUT_MITM           0x2000 /* outbound Do man in the middle protection */
#define BTM_SEC_IN_MIN_16_DIGIT_PIN 0x4000 /* enforce a minimum of 16 digit for sec mode 2 */

/* Security Flags [bit mask] (BTM_GetSecurityFlags)
*/
#define BTM_SEC_FLAG_AUTHORIZED     0x01
#define BTM_SEC_FLAG_AUTHENTICATED  0x02
#define BTM_SEC_FLAG_ENCRYPTED      0x04
#define BTM_SEC_FLAG_LKEY_KNOWN     0x10
#define BTM_SEC_FLAG_LKEY_AUTHED    0x20

/* PIN types */
#define BTM_PIN_TYPE_VARIABLE       HCI_PIN_TYPE_VARIABLE
#define BTM_PIN_TYPE_FIXED          HCI_PIN_TYPE_FIXED

/* Link Key types used to generate the new link key.
** returned in link key notification callback function
*/
#define BTM_LKEY_TYPE_COMBINATION   HCI_LKEY_TYPE_COMBINATION
#define BTM_LKEY_TYPE_LOCAL_UNIT    HCI_LKEY_TYPE_LOCAL_UNIT
#define BTM_LKEY_TYPE_REMOTE_UNIT   HCI_LKEY_TYPE_REMOTE_UNIT
#define BTM_LKEY_TYPE_DEBUG_COMB    HCI_LKEY_TYPE_DEBUG_COMB
#define BTM_LKEY_TYPE_UNAUTH_COMB   HCI_LKEY_TYPE_UNAUTH_COMB
#define BTM_LKEY_TYPE_AUTH_COMB     HCI_LKEY_TYPE_AUTH_COMB
#define BTM_LKEY_TYPE_CHANGED_COMB  HCI_LKEY_TYPE_CHANGED_COMB

#define BTM_LKEY_TYPE_UNAUTH_COMB_P_256 HCI_LKEY_TYPE_UNAUTH_COMB_P_256
#define BTM_LKEY_TYPE_AUTH_COMB_P_256   HCI_LKEY_TYPE_AUTH_COMB_P_256

#define BTM_LTK_DERIVED_LKEY_OFFSET 0x20    /* "easy" requirements for LK derived from LTK */
#define BTM_LKEY_TYPE_IGNORE        0xff    /* used when event is response from
                                               hci return link keys request */

typedef UINT8 tBTM_LINK_KEY_TYPE;

/* Protocol level security (BTM_SetSecurityLevel) */
#define BTM_SEC_PROTO_L2CAP         0
#define BTM_SEC_PROTO_SDP           1
#define BTM_SEC_PROTO_TCS           2
#define BTM_SEC_PROTO_RFCOMM        3
#define BTM_SEC_PROTO_OBEX          4
#define BTM_SEC_PROTO_BNEP          5
#define BTM_SEC_PROTO_HID           6   /* HID      */
#define BTM_SEC_PROTO_AVDT          7
#define BTM_SEC_PROTO_MCA           8

/* Determine the number of UINT32's necessary for security services */
#define BTM_SEC_ARRAY_BITS          32          /* Number of bits in each array element */
#define BTM_SEC_SERVICE_ARRAY_SIZE  (((UINT32)BTM_SEC_MAX_SERVICES / BTM_SEC_ARRAY_BITS) + \
                                    (((UINT32)BTM_SEC_MAX_SERVICES % BTM_SEC_ARRAY_BITS) ? 1 : 0))

/* Security service definitions (BTM_SetSecurityLevel)
** Used for Authorization APIs
*/
#define BTM_SEC_SERVICE_SDP_SERVER      0
#define BTM_SEC_SERVICE_SERIAL_PORT     1
#define BTM_SEC_SERVICE_LAN_ACCESS      2
#define BTM_SEC_SERVICE_DUN             3
#define BTM_SEC_SERVICE_IRMC_SYNC       4
#define BTM_SEC_SERVICE_IRMC_SYNC_CMD   5
#define BTM_SEC_SERVICE_OBEX            6
#define BTM_SEC_SERVICE_OBEX_FTP        7
#define BTM_SEC_SERVICE_HEADSET         8
#define BTM_SEC_SERVICE_CORDLESS        9
#define BTM_SEC_SERVICE_INTERCOM        10
#define BTM_SEC_SERVICE_FAX             11
#define BTM_SEC_SERVICE_HEADSET_AG      12
#define BTM_SEC_SERVICE_PNP_INFO        13
#define BTM_SEC_SERVICE_GEN_NET         14
#define BTM_SEC_SERVICE_GEN_FILE        15
#define BTM_SEC_SERVICE_GEN_AUDIO       16
#define BTM_SEC_SERVICE_GEN_TEL         17
#define BTM_SEC_SERVICE_CTP_DATA        18
#define BTM_SEC_SERVICE_HCRP_CTRL       19
#define BTM_SEC_SERVICE_HCRP_DATA       20
#define BTM_SEC_SERVICE_HCRP_NOTIF      21
#define BTM_SEC_SERVICE_BPP_JOB         22
#define BTM_SEC_SERVICE_BPP_STATUS      23
#define BTM_SEC_SERVICE_BPP_REF         24
#define BTM_SEC_SERVICE_BNEP_PANU       25
#define BTM_SEC_SERVICE_BNEP_GN         26
#define BTM_SEC_SERVICE_BNEP_NAP        27
#define BTM_SEC_SERVICE_HF_HANDSFREE    28
#define BTM_SEC_SERVICE_AG_HANDSFREE    29
#define BTM_SEC_SERVICE_TE_PHONE_ACCESS 30
#define BTM_SEC_SERVICE_ME_PHONE_ACCESS 31

#define BTM_SEC_SERVICE_HIDH_SEC_CTRL   32
#define BTM_SEC_SERVICE_HIDH_NOSEC_CTRL 33
#define BTM_SEC_SERVICE_HIDH_INTR       34
#define BTM_SEC_SERVICE_BIP             35
#define BTM_SEC_SERVICE_BIP_REF         36
#define BTM_SEC_SERVICE_AVDTP           37
#define BTM_SEC_SERVICE_AVDTP_NOSEC     38
#define BTM_SEC_SERVICE_AVCTP           39
#define BTM_SEC_SERVICE_SAP             40
#define BTM_SEC_SERVICE_PBAP            41
#define BTM_SEC_SERVICE_RFC_MUX         42
#define BTM_SEC_SERVICE_AVCTP_BROWSE    43
#define BTM_SEC_SERVICE_MAP             44
#define BTM_SEC_SERVICE_MAP_NOTIF       45
#define BTM_SEC_SERVICE_MCAP_CTRL       46
#define BTM_SEC_SERVICE_MCAP_DATA       47
#define BTM_SEC_SERVICE_HDP_SNK         48
#define BTM_SEC_SERVICE_HDP_SRC         49
#define BTM_SEC_SERVICE_ATT             50

/* Update these as services are added */
#define BTM_SEC_SERVICE_FIRST_EMPTY     51

#ifndef BTM_SEC_MAX_SERVICES
#define BTM_SEC_MAX_SERVICES            75
#endif

/************************************************************************************************
** Security Services MACROS handle array of UINT32 bits for more than 32 trusted services
*************************************************************************************************/
/* MACRO to set the security service bit mask in a bit stream */
#define BTM_SEC_SET_SERVICE(p, service)  (((UINT32 *)(p))[(((UINT32)(service)) / BTM_SEC_ARRAY_BITS)] |=  \
                                    ((UINT32)1 << (((UINT32)(service)) % BTM_SEC_ARRAY_BITS)))


/* MACRO to clear the security service bit mask in a bit stream */
#define BTM_SEC_CLR_SERVICE(p, service)  (((UINT32 *)(p))[(((UINT32)(service)) / BTM_SEC_ARRAY_BITS)] &=  \
                                    ~((UINT32)1 << (((UINT32)(service)) % BTM_SEC_ARRAY_BITS)))

/* MACRO to check the security service bit mask in a bit stream (Returns TRUE or FALSE) */
#define BTM_SEC_IS_SERVICE_TRUSTED(p, service)    (((((UINT32 *)(p))[(((UINT32)(service)) / BTM_SEC_ARRAY_BITS)]) &   \
                                        (UINT32)(((UINT32)1 << (((UINT32)(service)) % BTM_SEC_ARRAY_BITS)))) ? TRUE : FALSE)

/* MACRO to copy two trusted device bitmask */
#define BTM_SEC_COPY_TRUSTED_DEVICE(p_src, p_dst)   {UINT32 trst; for (trst = 0; trst < BTM_SEC_SERVICE_ARRAY_SIZE; trst++) \
                                                        ((UINT32 *)(p_dst))[trst] = ((UINT32 *)(p_src))[trst];}

/* MACRO to clear two trusted device bitmask */
#define BTM_SEC_CLR_TRUSTED_DEVICE(p_dst)   {UINT32 trst; for (trst = 0; trst < BTM_SEC_SERVICE_ARRAY_SIZE; trst++) \
                                                        ((UINT32 *)(p_dst))[trst] = 0;}

/* Following bits can be provided by host in the trusted_mask array */
/* 0..31 bits of mask[0] (Least Significant Word) */
#define BTM_SEC_TRUST_SDP_SERVER        (1 << BTM_SEC_SERVICE_SDP_SERVER)
#define BTM_SEC_TRUST_SERIAL_PORT       (1 << BTM_SEC_SERVICE_SERIAL_PORT)
#define BTM_SEC_TRUST_LAN_ACCESS        (1 << BTM_SEC_SERVICE_LAN_ACCESS)
#define BTM_SEC_TRUST_DUN               (1 << BTM_SEC_SERVICE_DUN)
#define BTM_SEC_TRUST_IRMC_SYNC         (1 << BTM_SEC_SERVICE_IRMC_SYNC)
#define BTM_SEC_TRUST_IRMC_SYNC_CMD     (1 << BTM_SEC_SERVICE_IRMC_SYNC_CMD)
#define BTM_SEC_TRUST_OBEX              (1 << BTM_SEC_SERVICE_OBEX)
#define BTM_SEC_TRUST_OBEX_FTP          (1 << BTM_SEC_SERVICE_OBEX_FTP)
#define BTM_SEC_TRUST_HEADSET           (1 << BTM_SEC_SERVICE_HEADSET)
#define BTM_SEC_TRUST_CORDLESS          (1 << BTM_SEC_SERVICE_CORDLESS)
#define BTM_SEC_TRUST_INTERCOM          (1 << BTM_SEC_SERVICE_INTERCOM)
#define BTM_SEC_TRUST_FAX               (1 << BTM_SEC_SERVICE_FAX)
#define BTM_SEC_TRUST_HEADSET_AG        (1 << BTM_SEC_SERVICE_HEADSET_AG)
#define BTM_SEC_TRUST_PNP_INFO          (1 << BTM_SEC_SERVICE_PNP_INFO)
#define BTM_SEC_TRUST_GEN_NET           (1 << BTM_SEC_SERVICE_GEN_NET)
#define BTM_SEC_TRUST_GEN_FILE          (1 << BTM_SEC_SERVICE_GEN_FILE)
#define BTM_SEC_TRUST_GEN_AUDIO         (1 << BTM_SEC_SERVICE_GEN_AUDIO)
#define BTM_SEC_TRUST_GEN_TEL           (1 << BTM_SEC_SERVICE_GEN_TEL)
#define BTM_SEC_TRUST_CTP_DATA          (1 << BTM_SEC_SERVICE_CTP_DATA)
#define BTM_SEC_TRUST_HCRP_CTRL         (1 << BTM_SEC_SERVICE_HCRP_CTRL)
#define BTM_SEC_TRUST_HCRP_DATA         (1 << BTM_SEC_SERVICE_HCRP_DATA)
#define BTM_SEC_TRUST_HCRP_NOTIF        (1 << BTM_SEC_SERVICE_HCRP_NOTIF)
#define BTM_SEC_TRUST_BPP_JOB           (1 << BTM_SEC_SERVICE_JOB)
#define BTM_SEC_TRUST_BPP_STATUS        (1 << BTM_SEC_SERVICE_STATUS)
#define BTM_SEC_TRUST_BPP_REF           (1 << BTM_SEC_SERVICE_REF)
#define BTM_SEC_TRUST_BNEP_PANU         (1 << BTM_SEC_SERVICE_BNEP_PANU)
#define BTM_SEC_TRUST_BNEP_GN           (1 << BTM_SEC_SERVICE_BNEP_GN)
#define BTM_SEC_TRUST_BNEP_NAP          (1 << BTM_SEC_SERVICE_BNEP_NAP)
#define BTM_SEC_TRUST_HFP_HF            (1 << BTM_SEC_SERVICE_HF_HANDSFREE)
#define BTM_SEC_TRUST_HFP_AG            (1 << BTM_SEC_SERVICE_AG_HANDSFREE)
#define BTM_SEC_TRUST_TE_PHONE_ACCESS   (1 << BTM_SEC_SERVICE_TE_PHONE_ACCESS)
#define BTM_SEC_TRUST_ME_PHONE_ACCESS   (1 << BTM_SEC_SERVICE_ME_PHONE_ACCESS)

/* 0..31 bits of mask[1] (Most Significant Word) */
#define BTM_SEC_TRUST_HIDH_CTRL         (1 << (BTM_SEC_SERVICE_HIDH_SEC_CTRL - 32))
#define BTM_SEC_TRUST_HIDH_NOSEC_CTRL   (1 << (BTM_SEC_SERVICE_HIDH_NOSEC_CTRL - 32))
#define BTM_SEC_TRUST_HIDH_INTR         (1 << (BTM_SEC_SERVICE_HIDH_INTR - 32))
#define BTM_SEC_TRUST_BIP               (1 << (BTM_SEC_SERVICE_BIP - 32))
#define BTM_SEC_TRUST_BIP_REF           (1 << (BTM_SEC_SERVICE_BIP_REF - 32))
#define BTM_SEC_TRUST_AVDTP             (1 << (BTM_SEC_SERVICE_AVDTP - 32))
#define BTM_SEC_TRUST_AVDTP_NOSEC       (1 << (BTM_SEC_SERVICE_AVDTP_NOSEC - 32))
#define BTM_SEC_TRUST_AVCTP             (1 << (BTM_SEC_SERVICE_AVCTP - 32))
#define BTM_SEC_TRUST_SAP               (1 << (BTM_SEC_SERVICE_SAP - 32))
#define BTM_SEC_TRUST_PBAP              (1 << (BTM_SEC_SERVICE_PBAP - 32))
#define BTM_SEC_TRUST_RFC_MUX           (1 << (BTM_SEC_SERVICE_RFC_MUX - 32))
#define BTM_SEC_TRUST_AVCTP_BROWSE      (1 << (BTM_SEC_SERVICE_AVCTP_BROWSE - 32))
#define BTM_SEC_TRUST_MAP               (1 << (BTM_SEC_SERVICE_MAP - 32))
#define BTM_SEC_TRUST_MAP_NOTIF         (1 << (BTM_SEC_SERVICE_MAP_NOTIF - 32))
#define BTM_SEC_TRUST_MCAP_CTRL         (1 << (BTM_SEC_SERVICE_MCAP_CTRL - 32))
#define BTM_SEC_TRUST_MCAP_DATA         (1 << (BTM_SEC_SERVICE_MCAP_DATA - 32))
#define BTM_SEC_TRUST_HDP_SNK           (1 << (BTM_SEC_SERVICE_HDP_SNK - 32))
#define BTM_SEC_TRUST_HDP_SRC           (1 << (BTM_SEC_SERVICE_HDP_SRC - 32))

#define BTM_SEC_TRUST_ALL               0xFFFFFFFF  /* for each array element */

/****************************************
**  Security Manager Callback Functions
*****************************************/
/* Authorize device for service.  Parameters are
**              BD Address of remote
**              Device Class of remote
**              BD Name of remote
**              Service name
**              Service Id (NULL - unknown service or unused
**                                 [BTM_SEC_SERVICE_NAME_LEN set to 0])
**              Is originator of the connection
**              Result of the operation
*/
typedef UINT8 (tBTM_AUTHORIZE_CALLBACK) (BD_ADDR bd_addr, DEV_CLASS dev_class,
                                         tBTM_BD_NAME bd_name, UINT8 *service_name,
                                         UINT8 service_id, BOOLEAN is_originator);

/* Get PIN for the connection.  Parameters are
**              BD Address of remote
**              Device Class of remote
**              BD Name of remote
**              Flag indicating the minimum pin code length to be 16 digits
*/
typedef UINT8 (tBTM_PIN_CALLBACK) (BD_ADDR bd_addr, DEV_CLASS dev_class,
                                   tBTM_BD_NAME bd_name, BOOLEAN min_16_digit);

/* New Link Key for the connection.  Parameters are
**              BD Address of remote
**              Link Key
**              Key Type: Combination, Local Unit, or Remote Unit
*/
typedef UINT8 (tBTM_LINK_KEY_CALLBACK) (BD_ADDR bd_addr, DEV_CLASS dev_class,
                                        tBTM_BD_NAME bd_name, UINT8 *key,
                                        UINT8 key_type);


/* Remote Name Resolved.  Parameters are
**              BD Address of remote
**              BD Name of remote
*/
typedef void (tBTM_RMT_NAME_CALLBACK) (BD_ADDR bd_addr, DEV_CLASS dc,
                                       tBTM_BD_NAME bd_name);


/* Authentication complete for the connection.  Parameters are
**              BD Address of remote
**              Device Class of remote
**              BD Name of remote
**
*/
typedef UINT8 (tBTM_AUTH_COMPLETE_CALLBACK) (BD_ADDR bd_addr, DEV_CLASS dev_class,
                                             tBTM_BD_NAME bd_name, int result);

enum
{
    BTM_SP_IO_REQ_EVT,      /* received IO_CAPABILITY_REQUEST event */
    BTM_SP_IO_RSP_EVT,      /* received IO_CAPABILITY_RESPONSE event */
    BTM_SP_CFM_REQ_EVT,     /* received USER_CONFIRMATION_REQUEST event */
    BTM_SP_KEY_NOTIF_EVT,   /* received USER_PASSKEY_NOTIFY event */
    BTM_SP_KEY_REQ_EVT,     /* received USER_PASSKEY_REQUEST event */
    BTM_SP_KEYPRESS_EVT,    /* received KEYPRESS_NOTIFY event */
    BTM_SP_LOC_OOB_EVT,     /* received result for READ_LOCAL_OOB_DATA command */
    BTM_SP_RMT_OOB_EVT,     /* received REMOTE_OOB_DATA_REQUEST event */
    BTM_SP_COMPLT_EVT,      /* received SIMPLE_PAIRING_COMPLETE event */
    BTM_SP_UPGRADE_EVT      /* check if the application wants to upgrade the link key */
};
typedef UINT8 tBTM_SP_EVT;

#define BTM_IO_CAP_OUT      0   /* DisplayOnly */
#define BTM_IO_CAP_IO       1   /* DisplayYesNo */
#define BTM_IO_CAP_IN       2   /* KeyboardOnly */
#define BTM_IO_CAP_NONE     3   /* NoInputNoOutput */
#if BLE_INCLUDED == TRUE && SMP_INCLUDED == TRUE
#define BTM_IO_CAP_KBDISP   4   /* Keyboard display */
#define BTM_IO_CAP_MAX      5
#else
#define BTM_IO_CAP_MAX      4
#endif

typedef UINT8 tBTM_IO_CAP;

#define BTM_MAX_PASSKEY_VAL (999999)
#define BTM_MIN_PASSKEY_VAL (0)

#define BTM_AUTH_SP_NO      0   /* MITM Protection Not Required - Single Profile/non-bonding
                                Numeric comparison with automatic accept allowed */
#define BTM_AUTH_SP_YES     1   /* MITM Protection Required - Single Profile/non-bonding
                                Use IO Capabilities to determine authentication procedure */
#define BTM_AUTH_AP_NO      2   /* MITM Protection Not Required - All Profiles/dedicated bonding
                                Numeric comparison with automatic accept allowed */
#define BTM_AUTH_AP_YES     3   /* MITM Protection Required - All Profiles/dedicated bonding
                                Use IO Capabilities to determine authentication procedure */
#define BTM_AUTH_SPGB_NO    4   /* MITM Protection Not Required - Single Profiles/general bonding
                                Numeric comparison with automatic accept allowed */
#define BTM_AUTH_SPGB_YES   5   /* MITM Protection Required - Single Profiles/general bonding
                                Use IO Capabilities to determine authentication procedure */
#define BTM_AUTH_DD_BOND    2   /* this bit is ORed to the BTM_AUTH_SP_* when IO exchange for dedicated bonding */
#define BTM_AUTH_GB_BIT     4   /* the genernal bonding bit */
#define BTM_AUTH_BONDS      6   /* the general/dedicated bonding bits  */
#define BTM_AUTH_YN_BIT     1   /* this is the Yes or No bit  */

#define BTM_BLE_INITIATOR_KEY_SIZE 15
#define BTM_BLE_RESPONDER_KEY_SIZE 15
#define BTM_BLE_MAX_KEY_SIZE       16

typedef UINT8 tBTM_AUTH_REQ;

enum
{
    BTM_OOB_NONE,
    BTM_OOB_PRESENT,
    BTM_OOB_UNKNOWN
};
typedef UINT8 tBTM_OOB_DATA;

/* data type for BTM_SP_IO_REQ_EVT */
typedef struct
{
    BD_ADDR         bd_addr;        /* peer address */
    tBTM_IO_CAP     io_cap;         /* local IO capabilities */
    tBTM_OOB_DATA   oob_data;       /* OOB data present (locally) for the peer device */
    tBTM_AUTH_REQ   auth_req;       /* Authentication required (for local device) */
    BOOLEAN         is_orig;        /* TRUE, if local device initiated the SP process */
} tBTM_SP_IO_REQ;

/* data type for BTM_SP_IO_RSP_EVT */
typedef struct
{
    BD_ADDR         bd_addr;        /* peer address */
    tBTM_IO_CAP     io_cap;         /* peer IO capabilities */
    tBTM_OOB_DATA   oob_data;       /* OOB data present at peer device for the local device */
    tBTM_AUTH_REQ   auth_req;       /* Authentication required for peer device */
} tBTM_SP_IO_RSP;

/* data type for BTM_SP_CFM_REQ_EVT */
typedef struct
{
    BD_ADDR         bd_addr;        /* peer address */
    DEV_CLASS       dev_class;      /* peer CoD */
    tBTM_BD_NAME    bd_name;        /* peer device name */
    UINT32          num_val;        /* the numeric value for comparison. If just_works, do not show this number to UI */
    BOOLEAN         just_works;     /* TRUE, if "Just Works" association model */
    tBTM_AUTH_REQ   loc_auth_req;   /* Authentication required for local device */
    tBTM_AUTH_REQ   rmt_auth_req;   /* Authentication required for peer device */
    tBTM_IO_CAP     loc_io_caps;    /* IO Capabilities of the local device */
    tBTM_IO_CAP     rmt_io_caps;    /* IO Capabilities of the remot device */
} tBTM_SP_CFM_REQ;

/* data type for BTM_SP_KEY_REQ_EVT */
typedef struct
{
    BD_ADDR         bd_addr;        /* peer address */
    DEV_CLASS       dev_class;      /* peer CoD */
    tBTM_BD_NAME    bd_name;        /* peer device name */
} tBTM_SP_KEY_REQ;

/* data type for BTM_SP_KEY_NOTIF_EVT */
typedef struct
{
    BD_ADDR         bd_addr;        /* peer address */
    DEV_CLASS       dev_class;      /* peer CoD */
    tBTM_BD_NAME    bd_name;        /* peer device name */
    UINT32          passkey;        /* passkey */
} tBTM_SP_KEY_NOTIF;

enum
{
    BTM_SP_KEY_STARTED,         /* 0 - passkey entry started */
    BTM_SP_KEY_ENTERED,         /* 1 - passkey digit entered */
    BTM_SP_KEY_ERASED,          /* 2 - passkey digit erased */
    BTM_SP_KEY_CLEARED,         /* 3 - passkey cleared */
    BTM_SP_KEY_COMPLT,          /* 4 - passkey entry completed */
    BTM_SP_KEY_OUT_OF_RANGE     /* 5 - out of range */
};
typedef UINT8   tBTM_SP_KEY_TYPE;

/* data type for BTM_SP_KEYPRESS_EVT */
typedef struct
{
    BD_ADDR             bd_addr;        /* peer address */
    tBTM_SP_KEY_TYPE   notif_type;
} tBTM_SP_KEYPRESS;

/* data type for BTM_SP_LOC_OOB_EVT */
typedef struct
{
    tBTM_STATUS     status;         /* */
    BT_OCTET16      c;              /* Simple Pairing Hash C */
    BT_OCTET16      r;              /* Simple Pairing Randomnizer R */
} tBTM_SP_LOC_OOB;

/* data type for BTM_SP_RMT_OOB_EVT */
typedef struct
{
    BD_ADDR         bd_addr;        /* peer address */
    DEV_CLASS       dev_class;      /* peer CoD */
    tBTM_BD_NAME    bd_name;        /* peer device name */
} tBTM_SP_RMT_OOB;


/* data type for BTM_SP_COMPLT_EVT */
typedef struct
{
    BD_ADDR         bd_addr;        /* peer address */
    DEV_CLASS       dev_class;      /* peer CoD */
    tBTM_BD_NAME    bd_name;        /* peer device name */
    tBTM_STATUS     status;         /* status of the simple pairing process */
} tBTM_SP_COMPLT;

/* data type for BTM_SP_UPGRADE_EVT */
typedef struct
{
    BD_ADDR         bd_addr;        /* peer address */
    BOOLEAN         upgrade;        /* TRUE, to upgrade the link key */
} tBTM_SP_UPGRADE;

typedef union
{
    tBTM_SP_IO_REQ      io_req;     /* BTM_SP_IO_REQ_EVT      */
    tBTM_SP_IO_RSP      io_rsp;     /* BTM_SP_IO_RSP_EVT      */
    tBTM_SP_CFM_REQ     cfm_req;    /* BTM_SP_CFM_REQ_EVT     */
    tBTM_SP_KEY_NOTIF   key_notif;  /* BTM_SP_KEY_NOTIF_EVT   */
    tBTM_SP_KEY_REQ     key_req;    /* BTM_SP_KEY_REQ_EVT     */
    tBTM_SP_KEYPRESS    key_press;  /* BTM_SP_KEYPRESS_EVT    */
    tBTM_SP_LOC_OOB     loc_oob;    /* BTM_SP_LOC_OOB_EVT     */
    tBTM_SP_RMT_OOB     rmt_oob;    /* BTM_SP_RMT_OOB_EVT     */
    tBTM_SP_COMPLT      complt;     /* BTM_SP_COMPLT_EVT      */
    tBTM_SP_UPGRADE     upgrade;    /* BTM_SP_UPGRADE_EVT      */
} tBTM_SP_EVT_DATA;

/* Simple Pairing Events.  Called by the stack when Simple Pairing related
** events occur.
*/
typedef UINT8 (tBTM_SP_CALLBACK) (tBTM_SP_EVT event, tBTM_SP_EVT_DATA *p_data);


typedef void (tBTM_MKEY_CALLBACK) (BD_ADDR bd_addr, UINT8 status, UINT8 key_flag) ;

/* Encryption enabled/disabled complete: Optionally passed with BTM_SetEncryption.
** Parameters are
**              BD Address of remote
**              optional data passed in by BTM_SetEncryption
**              tBTM_STATUS - result of the operation
*/
typedef void (tBTM_SEC_CBACK) (BD_ADDR bd_addr, tBT_TRANSPORT trasnport,
                                void *p_ref_data, tBTM_STATUS result);

/* Bond Cancel complete. Parameters are
**              Result of the cancel operation
**
*/
typedef void (tBTM_BOND_CANCEL_CMPL_CALLBACK) (tBTM_STATUS result);

/* LE related event and data structure
*/
#define BTM_LE_IO_REQ_EVT       SMP_IO_CAP_REQ_EVT     /* received IO_CAPABILITY_REQUEST event */
#define BTM_LE_SEC_REQUEST_EVT  SMP_SEC_REQUEST_EVT    /* security request event */
#define BTM_LE_KEY_NOTIF_EVT    SMP_PASSKEY_NOTIF_EVT  /* received USER_PASSKEY_NOTIFY event */
#define BTM_LE_KEY_REQ_EVT      SMP_PASSKEY_REQ_EVT    /* received USER_PASSKEY_REQUEST event */
#define BTM_LE_OOB_REQ_EVT      SMP_OOB_REQ_EVT        /* OOB data request event */
#define BTM_LE_NC_REQ_EVT       SMP_NC_REQ_EVT          /* Numeric Comparison request event */
#define BTM_LE_PR_KEYPR_NOT_EVT SMP_PEER_KEYPR_NOT_EVT /* Peer keypress notification recd event */
/* SC OOB request event (both local and peer OOB data) can be expected in response */
#define BTM_LE_SC_OOB_REQ_EVT   SMP_SC_OOB_REQ_EVT
/* SC OOB local data set is created (as result of SMP_CrLocScOobData(...)) */
#define BTM_LE_SC_LOC_OOB_EVT   SMP_SC_LOC_OOB_DATA_UP_EVT
#define BTM_LE_BR_KEYS_REQ_EVT  SMP_BR_KEYS_REQ_EVT     /* SMP over BR keys request event */
#define BTM_LE_COMPLT_EVT       SMP_COMPLT_EVT         /* SMP complete event */
#define BTM_LE_LAST_FROM_SMP    BTM_LE_BR_KEYS_REQ_EVT
#define BTM_LE_KEY_EVT          BTM_LE_LAST_FROM_SMP + 1 /* KEY update event */
#define BTM_LE_CONSENT_REQ_EVT  SMP_CONSENT_REQ_EVT
typedef UINT8 tBTM_LE_EVT;

#define BTM_LE_KEY_NONE           0
#define BTM_LE_KEY_PENC      SMP_SEC_KEY_TYPE_ENC        /* encryption information of peer device */
#define BTM_LE_KEY_PID       SMP_SEC_KEY_TYPE_ID         /* identity key of the peer device */
#define BTM_LE_KEY_PCSRK     SMP_SEC_KEY_TYPE_CSRK      /* peer SRK */
#define BTM_LE_KEY_PLK       SMP_SEC_KEY_TYPE_LK
#define BTM_LE_KEY_LLK       (SMP_SEC_KEY_TYPE_LK << 4)
#define BTM_LE_KEY_LENC      (SMP_SEC_KEY_TYPE_ENC << 4)  /* master role security information:div */
#define BTM_LE_KEY_LID       (SMP_SEC_KEY_TYPE_ID << 4)   /* master device ID key */
#define BTM_LE_KEY_LCSRK     (SMP_SEC_KEY_TYPE_CSRK << 4) /* local CSRK has been deliver to peer */
typedef UINT8 tBTM_LE_KEY_TYPE;

#define BTM_LE_AUTH_REQ_NO_BOND SMP_AUTH_NO_BOND   /* 0 */
#define BTM_LE_AUTH_REQ_BOND    SMP_AUTH_GEN_BOND  /* 1 << 0 */
#define BTM_LE_AUTH_REQ_MITM    SMP_AUTH_YN_BIT    /* 1 << 2 */
typedef UINT8 tBTM_LE_AUTH_REQ;
#define BTM_LE_SC_SUPPORT_BIT           SMP_SC_SUPPORT_BIT     /* (1 << 3) */
#define BTM_LE_KP_SUPPORT_BIT           SMP_KP_SUPPORT_BIT     /* (1 << 4) */

#define BTM_LE_AUTH_REQ_SC_ONLY         SMP_AUTH_SC_ENC_ONLY    /* 1 << 3 */
#define BTM_LE_AUTH_REQ_SC_BOND         SMP_AUTH_SC_GB          /* 1001 */
#define BTM_LE_AUTH_REQ_SC_MITM         SMP_AUTH_SC_MITM_NB     /* 1100 */
#define BTM_LE_AUTH_REQ_SC_MITM_BOND    SMP_AUTH_SC_MITM_GB     /* 1101 */
#define BTM_LE_AUTH_REQ_MASK            SMP_AUTH_MASK           /* 0x1D */

/* LE security level */
#define BTM_LE_SEC_NONE             SMP_SEC_NONE
#define BTM_LE_SEC_UNAUTHENTICATE   SMP_SEC_UNAUTHENTICATE      /* 1 */
#define BTM_LE_SEC_AUTHENTICATED    SMP_SEC_AUTHENTICATED       /* 4 */
typedef UINT8 tBTM_LE_SEC;


typedef struct
{
    tBTM_IO_CAP         io_cap;         /* local IO capabilities */
    UINT8               oob_data;       /* OOB data present (locally) for the peer device */
    tBTM_LE_AUTH_REQ    auth_req;       /* Authentication request (for local device) contain bonding and MITM info */
    UINT8               max_key_size;   /* max encryption key size */
    tBTM_LE_KEY_TYPE    init_keys;      /* keys to be distributed, bit mask */
    tBTM_LE_KEY_TYPE    resp_keys;      /* keys to be distributed, bit mask */
} tBTM_LE_IO_REQ;

#if BLE_INCLUDED == TRUE && SMP_INCLUDED == TRUE
/* data type for tBTM_LE_COMPLT */
typedef struct
{
    UINT8 reason;
    UINT8 sec_level;
    BOOLEAN is_pair_cancel;
    BOOLEAN smp_over_br;
}tBTM_LE_COMPLT;
#endif

/* BLE encryption keys */
typedef struct
{
    BT_OCTET16  ltk;
    BT_OCTET8   rand;
    UINT16      ediv;
    UINT8       sec_level;
    UINT8       key_size;
}tBTM_LE_PENC_KEYS;

/* BLE CSRK keys */
typedef struct
{
    UINT32          counter;
    BT_OCTET16      csrk;
    UINT8           sec_level;
}tBTM_LE_PCSRK_KEYS;

/* BLE Encryption reproduction keys */
typedef struct
{
    BT_OCTET16  ltk;
    UINT16      div;
    UINT8       key_size;
    UINT8       sec_level;
}tBTM_LE_LENC_KEYS;

/* BLE SRK keys */
typedef struct
{
    UINT32          counter;
    UINT16          div;
    UINT8           sec_level;
    BT_OCTET16      csrk;
}tBTM_LE_LCSRK_KEYS;

typedef struct
{
    BT_OCTET16          irk;
    tBLE_ADDR_TYPE      addr_type;
    BD_ADDR             static_addr;
}tBTM_LE_PID_KEYS;

typedef union
{
    tBTM_LE_PENC_KEYS   penc_key;       /* received peer encryption key */
    tBTM_LE_PCSRK_KEYS  pcsrk_key;      /* received peer device SRK */
    tBTM_LE_PID_KEYS    pid_key;        /* peer device ID key */
    tBTM_LE_LENC_KEYS   lenc_key;       /* local encryption reproduction keys LTK = = d1(ER,DIV,0)*/
    tBTM_LE_LCSRK_KEYS   lcsrk_key;     /* local device CSRK = d1(ER,DIV,1)*/
}tBTM_LE_KEY_VALUE;

typedef struct
{
    tBTM_LE_KEY_TYPE        key_type;
    tBTM_LE_KEY_VALUE       *p_key_value;
}tBTM_LE_KEY;

typedef union
{
    tBTM_LE_IO_REQ      io_req;     /* BTM_LE_IO_REQ_EVT      */
    UINT32              key_notif;  /* BTM_LE_KEY_NOTIF_EVT   */
                                    /* BTM_LE_NC_REQ_EVT */
                                    /* no callback data for BTM_LE_KEY_REQ_EVT */
                                    /* and BTM_LE_OOB_REQ_EVT  */
#if BLE_INCLUDED == TRUE && SMP_INCLUDED == TRUE
    tBTM_LE_COMPLT      complt;     /* BTM_LE_COMPLT_EVT      */
    tSMP_OOB_DATA_TYPE  req_oob_type;
#endif
    tBTM_LE_KEY         key;
} tBTM_LE_EVT_DATA;

/* Simple Pairing Events.  Called by the stack when Simple Pairing related
** events occur.
*/
typedef UINT8 (tBTM_LE_CALLBACK) (tBTM_LE_EVT event, BD_ADDR bda, tBTM_LE_EVT_DATA *p_data);

#define BTM_BLE_KEY_TYPE_ID         1
#define BTM_BLE_KEY_TYPE_ER         2
#define BTM_BLE_KEY_TYPE_COUNTER    3  //tobe obsolete

typedef struct
{
    BT_OCTET16       ir;
    BT_OCTET16       irk;
    BT_OCTET16       dhk;

}tBTM_BLE_LOCAL_ID_KEYS;

typedef union
{
    tBTM_BLE_LOCAL_ID_KEYS  id_keys;
    BT_OCTET16              er;
}tBTM_BLE_LOCAL_KEYS;


/* New LE identity key for local device.
*/
typedef void (tBTM_LE_KEY_CALLBACK) (UINT8 key_type, tBTM_BLE_LOCAL_KEYS *p_key);


/***************************
**  Security Manager Types
****************************/
/* Structure that applications use to register with BTM_SecRegister */
typedef struct
{
    tBTM_AUTHORIZE_CALLBACK     *p_authorize_callback;
    tBTM_PIN_CALLBACK           *p_pin_callback;
    tBTM_LINK_KEY_CALLBACK      *p_link_key_callback;
    tBTM_AUTH_COMPLETE_CALLBACK *p_auth_complete_callback;
    tBTM_BOND_CANCEL_CMPL_CALLBACK *p_bond_cancel_cmpl_callback;
    tBTM_SP_CALLBACK            *p_sp_callback;
#if BLE_INCLUDED == TRUE
#if SMP_INCLUDED == TRUE
    tBTM_LE_CALLBACK            *p_le_callback;
#endif
    tBTM_LE_KEY_CALLBACK        *p_le_key_callback;
#endif
} tBTM_APPL_INFO;

/* Callback function for when a link supervision timeout event occurs.
** This asynchronous event is enabled/disabled by calling BTM_RegForLstoEvt().
*/
typedef void (tBTM_LSTO_CBACK) (BD_ADDR remote_bda, UINT16 timeout);

/*****************************************************************************
**  POWER MANAGEMENT
*****************************************************************************/
/****************************
**  Power Manager Constants
*****************************/
/* BTM Power manager status codes */
enum
{
    BTM_PM_STS_ACTIVE = HCI_MODE_ACTIVE,
    BTM_PM_STS_HOLD   = HCI_MODE_HOLD,
    BTM_PM_STS_SNIFF  = HCI_MODE_SNIFF,
    BTM_PM_STS_PARK   = HCI_MODE_PARK,
    BTM_PM_STS_SSR,     /* report the SSR parameters in HCI_SNIFF_SUB_RATE_EVT */
    BTM_PM_STS_PENDING,   /* when waiting for status from controller */
    BTM_PM_STS_ERROR   /* when HCI command status returns error */
};
typedef UINT8 tBTM_PM_STATUS;

/* BTM Power manager modes */
enum
{
    BTM_PM_MD_ACTIVE = BTM_PM_STS_ACTIVE,
    BTM_PM_MD_HOLD   = BTM_PM_STS_HOLD,
    BTM_PM_MD_SNIFF  = BTM_PM_STS_SNIFF,
    BTM_PM_MD_PARK   = BTM_PM_STS_PARK,
    BTM_PM_MD_FORCE  = 0x10 /* OR this to force ACL link to a certain mode */
};
typedef UINT8 tBTM_PM_MODE;

#define BTM_PM_SET_ONLY_ID  0x80

/* Operation codes */
#define BTM_PM_REG_SET      1 /* The module wants to set the desired power mode */
#define BTM_PM_REG_NOTIF    2 /* The module wants to receive mode change event */
#define BTM_PM_DEREG        4 /* The module does not want to involve with PM anymore */

/************************
**  Power Manager Types
*************************/
typedef struct
{
    UINT16          max;
    UINT16          min;
    UINT16          attempt;
    UINT16          timeout;
    tBTM_PM_MODE    mode;
} tBTM_PM_PWR_MD;

/*************************************
**  Power Manager Callback Functions
**************************************/
typedef void (tBTM_PM_STATUS_CBACK) (BD_ADDR p_bda, tBTM_PM_STATUS status,
                                     UINT16 value, UINT8 hci_status);


/************************
**  Stored Linkkey Types
*************************/
#define BTM_CB_EVT_DELETE_STORED_LINK_KEYS  4

typedef struct
{
    UINT8          event;
    UINT8          status;
    UINT16         num_keys;

} tBTM_DELETE_STORED_LINK_KEY_COMPLETE;

/* MIP evnets, callbacks    */
enum
{
    BTM_MIP_MODE_CHG_EVT,
    BTM_MIP_DISCONNECT_EVT,
    BTM_MIP_PKTS_COMPL_EVT,
    BTM_MIP_RXDATA_EVT
};
typedef UINT8 tBTM_MIP_EVT;

typedef struct
{
    tBTM_MIP_EVT    event;
    BD_ADDR         bd_addr;
    UINT16          mip_id;
} tBTM_MIP_MODE_CHANGE;

typedef struct
{
    tBTM_MIP_EVT    event;
    UINT16          mip_id;
    UINT8           disc_reason;
} tBTM_MIP_CONN_TIMEOUT;

#define BTM_MIP_MAX_RX_LEN  17

typedef struct
{
    tBTM_MIP_EVT    event;
    UINT16          mip_id;
    UINT8           rx_len;
    UINT8           rx_data[BTM_MIP_MAX_RX_LEN];
} tBTM_MIP_RXDATA;

typedef struct
{
    tBTM_MIP_EVT    event;
    BD_ADDR         bd_addr;
    UINT8           data[11];       /* data[0] shows Vender-specific device type */
} tBTM_MIP_EIR_HANDSHAKE;

typedef struct
{
    tBTM_MIP_EVT    event;
    UINT16          num_sent;       /* Number of packets completed at the controller */
} tBTM_MIP_PKTS_COMPL;

typedef union
{
    tBTM_MIP_EVT            event;
    tBTM_MIP_MODE_CHANGE    mod_chg;
    tBTM_MIP_CONN_TIMEOUT   conn_tmo;
    tBTM_MIP_EIR_HANDSHAKE  eir;
    tBTM_MIP_PKTS_COMPL     completed;
    tBTM_MIP_RXDATA         rxdata;
} tBTM_MIP_EVENT_DATA;

/* MIP event callback function  */
typedef void (tBTM_MIP_EVENTS_CB) (tBTM_MIP_EVT event, tBTM_MIP_EVENT_DATA data);

/* MIP Device query callback function  */
typedef BOOLEAN (tBTM_MIP_QUERY_CB) (BD_ADDR dev_addr, UINT8 *p_mode, LINK_KEY link_key);

#define BTM_CONTRL_ACTIVE  1       /* ACL link on, SCO link ongoing, sniff mode */
#define BTM_CONTRL_SCAN    2       /* Scan state - paging/inquiry/trying to connect*/
#define BTM_CONTRL_IDLE    3       /* Idle state - page scan, LE advt, inquiry scan */

typedef UINT8 tBTM_CONTRL_STATE;

#endif // BTM_API_TYPES_H
