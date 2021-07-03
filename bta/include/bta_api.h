/******************************************************************************
 *
 *  Copyright 2003-2014 Broadcom Corporation
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
 *  This is the public interface file for BTA, Broadcom's Bluetooth
 *  application layer for mobile phones.
 *
 ******************************************************************************/
#ifndef BTA_API_H
#define BTA_API_H

#include <cstdint>
#include <vector>

#include "bt_target.h"  // Must be first to define build configuration

#include "osi/include/log.h"
#include "stack/include/bt_types.h"
#include "stack/include/btm_api_types.h"
#include "stack/include/btm_ble_api_types.h"
#include "stack/include/hci_error_code.h"
#include "stack/include/sdp_api.h"
#include "types/ble_address_with_type.h"
#include "types/bluetooth/uuid.h"
#include "types/bt_transport.h"
#include "types/raw_address.h"

/*****************************************************************************
 *  Constants and data types
 ****************************************************************************/

/* Status Return Value */
typedef enum : uint8_t {
  BTA_SUCCESS = 0, /* Successful operation. */
  BTA_FAILURE = 1, /* Generic failure. */
  BTA_PENDING = 2, /* API cannot be completed right now */
  BTA_BUSY = 3,
  BTA_NO_RESOURCES = 4,
  BTA_WRONG_MODE = 5,
} tBTA_STATUS;

/*
 * Service ID
 */

#define BTA_A2DP_SOURCE_SERVICE_ID 3 /* A2DP Source profile. */
#define BTA_HSP_SERVICE_ID 5         /* Headset profile. */
#define BTA_HFP_SERVICE_ID 6         /* Hands-free profile. */
#define BTA_BIP_SERVICE_ID 13        /* Basic Imaging profile */
#define BTA_A2DP_SINK_SERVICE_ID 18  /* A2DP Sink */
#define BTA_HID_SERVICE_ID 20        /* HID */
#define BTA_HFP_HS_SERVICE_ID 24     /* HSP HS role */
#define BTA_SDP_SERVICE_ID 29        /* SDP Search */
#define BTA_HIDD_SERVICE_ID 30       /* HID Device */

/* BLE profile service ID */
#define BTA_BLE_SERVICE_ID 31  /* GATT profile */
#define BTA_USER_SERVICE_ID 32 /* User requested UUID */
#define BTA_MAX_SERVICE_ID 33

/* service IDs (BTM_SEC_SERVICE_FIRST_EMPTY + 1) to (BTM_SEC_MAX_SERVICES - 1)
 * are used by BTA JV */
#define BTA_FIRST_JV_SERVICE_ID (BTM_SEC_SERVICE_FIRST_EMPTY + 1)
#define BTA_LAST_JV_SERVICE_ID (BTM_SEC_MAX_SERVICES - 1)

typedef uint8_t tBTA_SERVICE_ID;

/* Service ID Mask */
#define BTA_RES_SERVICE_MASK 0x00000001    /* Reserved */
#define BTA_HSP_SERVICE_MASK 0x00000020    /* HSP AG role. */
#define BTA_HFP_SERVICE_MASK 0x00000040    /* HFP AG role */
#define BTA_HL_SERVICE_MASK 0x08000000     /* Health Device Profile */

#define BTA_BLE_SERVICE_MASK 0x40000000  /* GATT based service */
#define BTA_ALL_SERVICE_MASK 0x7FFFFFFF  /* All services supported by BTA. */
#define BTA_USER_SERVICE_MASK 0x80000000 /* Message Notification Profile */

typedef uint32_t tBTA_SERVICE_MASK;

/* Security Setting Mask */
#define BTA_SEC_AUTHENTICATE \
  (BTM_SEC_IN_AUTHENTICATE | \
   BTM_SEC_OUT_AUTHENTICATE) /* Authentication required. */
#define BTA_SEC_ENCRYPT \
  (BTM_SEC_IN_ENCRYPT | BTM_SEC_OUT_ENCRYPT) /* Encryption required. */

typedef uint16_t tBTA_SEC;

#define BTA_APP_ID_PAN_MULTI 0xFE /* app id for pan multiple connection */
#define BTA_ALL_APP_ID 0xFF

/* Discoverable Modes */
#define BTA_DM_NON_DISC BTM_NON_DISCOVERABLE /* Device is not discoverable. */
#define BTA_DM_GENERAL_DISC                         \
  BTM_GENERAL_DISCOVERABLE /* General discoverable. \
                              */
typedef uint16_t
    tBTA_DM_DISC; /* this discoverability mode is a bit mask among BR mode and
                     LE mode */

/* Connectable Modes */
#define BTA_DM_NON_CONN BTM_NON_CONNECTABLE /* Device is not connectable. */
#define BTA_DM_CONN BTM_CONNECTABLE         /* Device is connectable. */

typedef uint16_t tBTA_DM_CONN;

/* Central/peripheral preferred roles */
typedef enum : uint8_t {
  BTA_ANY_ROLE = 0x00,
  BTA_CENTRAL_ROLE_PREF = 0x01,
  BTA_CENTRAL_ROLE_ONLY = 0x02,
  /* Used for PANU only, skip role switch to central */
  BTA_PERIPHERAL_ROLE_ONLY = 0x03,
} tBTA_PREF_ROLES;

inline tBTA_PREF_ROLES toBTA_PREF_ROLES(uint8_t role) {
  ASSERT_LOG(role <= BTA_PERIPHERAL_ROLE_ONLY,
             "Passing illegal preferred role:0x%02x [0x%02x<=>0x%02x]", role,
             BTA_ANY_ROLE, BTA_PERIPHERAL_ROLE_ONLY);
  return static_cast<tBTA_PREF_ROLES>(role);
}

#define CASE_RETURN_TEXT(code) \
  case code:                   \
    return #code

inline std::string preferred_role_text(const tBTA_PREF_ROLES& role) {
  switch (role) {
    CASE_RETURN_TEXT(BTA_ANY_ROLE);
    CASE_RETURN_TEXT(BTA_CENTRAL_ROLE_PREF);
    CASE_RETURN_TEXT(BTA_CENTRAL_ROLE_ONLY);
    CASE_RETURN_TEXT(BTA_PERIPHERAL_ROLE_ONLY);
    default:
      return std::string("UNKNOWN:%hhu", role);
  }
}
#undef CASE_RETURN_TEXT

enum {

  BTA_DM_NO_SCATTERNET,      /* Device doesn't support scatternet, it might
                                support "role switch during connection" for
                                an incoming connection, when it already has
                                another connection in central role */
  BTA_DM_PARTIAL_SCATTERNET, /* Device supports partial scatternet. It can have
                                simultaneous connection in Central and
                                Peripheral roles for short period of time */
  BTA_DM_FULL_SCATTERNET /* Device can have simultaneous connection in central
                            and peripheral roles */

};

typedef struct {
  uint8_t bta_dm_eir_min_name_len; /* minimum length of local name when it is
                                      shortened */
#if (BTA_EIR_CANNED_UUID_LIST == TRUE)
  uint8_t bta_dm_eir_uuid16_len; /* length of 16-bit UUIDs */
  uint8_t* bta_dm_eir_uuid16;    /* 16-bit UUIDs */
#else
  uint32_t uuid_mask[BTM_EIR_SERVICE_ARRAY_SIZE]; /* mask of UUID list in EIR */
#endif
  int8_t* bta_dm_eir_inq_tx_power;     /* Inquiry TX power         */
  uint8_t bta_dm_eir_flag_len;         /* length of flags in bytes */
  uint8_t* bta_dm_eir_flags;           /* flags for EIR */
  uint8_t bta_dm_eir_manufac_spec_len; /* length of manufacturer specific in
                                          bytes */
  uint8_t* bta_dm_eir_manufac_spec;    /* manufacturer specific */
  uint8_t bta_dm_eir_additional_len;   /* length of additional data in bytes */
  uint8_t* bta_dm_eir_additional;      /* additional data */
} tBTA_DM_EIR_CONF;

typedef uint8_t tBTA_DM_BLE_RSSI_ALERT_TYPE;

/* Security Callback Events */
#define BTA_DM_PIN_REQ_EVT 2   /* PIN request. */
#define BTA_DM_AUTH_CMPL_EVT 3 /* Authentication complete indication. */
#define BTA_DM_AUTHORIZE_EVT 4 /* Authorization request. */
#define BTA_DM_LINK_UP_EVT 5   /* Connection UP event */
#define BTA_DM_LINK_DOWN_EVT 6 /* Connection DOWN event */
#define BTA_DM_BOND_CANCEL_CMPL_EVT 9 /* Bond cancel complete indication */
#define BTA_DM_SP_CFM_REQ_EVT                     \
  10 /* Simple Pairing User Confirmation request. \
        */
#define BTA_DM_SP_KEY_NOTIF_EVT 11 /* Simple Pairing Passkey Notification */
#define BTA_DM_BLE_KEY_EVT 15      /* BLE SMP key event for peer device keys */
#define BTA_DM_BLE_SEC_REQ_EVT 16  /* BLE SMP security request */
#define BTA_DM_BLE_PASSKEY_NOTIF_EVT 17 /* SMP passkey notification event */
#define BTA_DM_BLE_PASSKEY_REQ_EVT 18   /* SMP passkey request event */
#define BTA_DM_BLE_OOB_REQ_EVT 19       /* SMP OOB request event */
#define BTA_DM_BLE_LOCAL_IR_EVT 20      /* BLE local IR event */
#define BTA_DM_BLE_LOCAL_ER_EVT 21      /* BLE local ER event */
#define BTA_DM_BLE_NC_REQ_EVT 22 /* SMP Numeric Comparison request event */
#define BTA_DM_SP_RMT_OOB_EXT_EVT \
  23 /* Simple Pairing Remote OOB Extended Data request. */
#define BTA_DM_BLE_AUTH_CMPL_EVT 24 /* BLE Auth complete */
#define BTA_DM_DEV_UNPAIRED_EVT 25
#define BTA_DM_LE_FEATURES_READ                                             \
  27                             /* Cotroller specific LE features are read \
                                    */
#define BTA_DM_ENER_INFO_READ 28 /* Energy info read */
#define BTA_DM_BLE_SC_OOB_REQ_EVT 29 /* SMP SC OOB request event */
#define BTA_DM_BLE_CONSENT_REQ_EVT 30 /* SMP consent request event */
#define BTA_DM_BLE_SC_CR_LOC_OOB_EVT \
  31 /* SMP SC Create Local OOB request event */
typedef uint8_t tBTA_DM_SEC_EVT;

/* Structure associated with BTA_DM_PIN_REQ_EVT */
typedef struct {
  /* Note: First 3 data members must be, bd_addr, dev_class, and bd_name in
   * order */
  RawAddress bd_addr;  /* BD address peer device. */
  DEV_CLASS dev_class; /* Class of Device */
  BD_NAME bd_name;     /* Name of peer device. */
  bool min_16_digit;   /* true if the pin returned must be at least 16 digits */
} tBTA_DM_PIN_REQ;

/* BLE related definition */

#define BTA_DM_AUTH_FAIL_BASE (HCI_ERR_MAX_ERR + 10)

/* Converts SMP error codes defined in smp_api.h to SMP auth fail reasons below.
 */
#define BTA_DM_AUTH_CONVERT_SMP_CODE(x) (BTA_DM_AUTH_FAIL_BASE + (x))

#define BTA_DM_AUTH_SMP_PAIR_AUTH_FAIL \
  (BTA_DM_AUTH_FAIL_BASE + SMP_PAIR_AUTH_FAIL)
#define BTA_DM_AUTH_SMP_CONFIRM_VALUE_FAIL \
  (BTA_DM_AUTH_FAIL_BASE + SMP_CONFIRM_VALUE_ERR)
#define BTA_DM_AUTH_SMP_PAIR_NOT_SUPPORT \
  (BTA_DM_AUTH_FAIL_BASE + SMP_PAIR_NOT_SUPPORT)
#define BTA_DM_AUTH_SMP_UNKNOWN_ERR \
  (BTA_DM_AUTH_FAIL_BASE + SMP_PAIR_FAIL_UNKNOWN)
#define BTA_DM_AUTH_SMP_CONN_TOUT (BTA_DM_AUTH_FAIL_BASE + SMP_CONN_TOUT)

typedef uint8_t tBTA_LE_KEY_TYPE; /* can be used as a bit mask */

typedef union {
  tBTM_LE_PENC_KEYS penc_key;  /* received peer encryption key */
  tBTM_LE_PCSRK_KEYS psrk_key; /* received peer device SRK */
  tBTM_LE_PID_KEYS pid_key;    /* peer device ID key */
  tBTM_LE_LENC_KEYS
      lenc_key; /* local encryption reproduction keys LTK = = d1(ER,DIV,0)*/
  tBTM_LE_LCSRK_KEYS lcsrk_key; /* local device CSRK = d1(ER,DIV,1)*/
  tBTM_LE_PID_KEYS lid_key; /* local device ID key for the particular remote */
} tBTA_LE_KEY_VALUE;

#define BTA_BLE_LOCAL_KEY_TYPE_ID 1
#define BTA_BLE_LOCAL_KEY_TYPE_ER 2
typedef uint8_t tBTA_DM_BLE_LOCAL_KEY_MASK;

typedef struct {
  Octet16 ir;
  Octet16 irk;
  Octet16 dhk;
} tBTA_BLE_LOCAL_ID_KEYS;

#define BTA_DM_SEC_GRANTED BTA_SUCCESS
#define BTA_DM_SEC_PAIR_NOT_SPT BTA_DM_AUTH_SMP_PAIR_NOT_SUPPORT
typedef uint8_t tBTA_DM_BLE_SEC_GRANT;

/* Structure associated with BTA_DM_BLE_SEC_REQ_EVT */
typedef struct {
  RawAddress bd_addr; /* peer address */
  BD_NAME bd_name; /* peer device name */
} tBTA_DM_BLE_SEC_REQ;

typedef struct {
  RawAddress bd_addr; /* peer address */
  tBTM_LE_KEY_TYPE key_type;
  tBTM_LE_KEY_VALUE* p_key_value;
} tBTA_DM_BLE_KEY;

/* Structure associated with BTA_DM_AUTH_CMPL_EVT */
typedef struct {
  RawAddress bd_addr;  /* BD address peer device. */
  BD_NAME bd_name;     /* Name of peer device. */
  bool key_present;    /* Valid link key value in key element */
  LinkKey key;         /* Link key associated with peer device. */
  uint8_t key_type;    /* The type of Link Key */
  bool success;        /* true of authentication succeeded, false if failed. */
  tHCI_REASON
      fail_reason; /* The HCI reason/error code for when success=false */
  tBLE_ADDR_TYPE addr_type; /* Peer device address type */
  tBT_DEVICE_TYPE dev_type;
} tBTA_DM_AUTH_CMPL;

/* Structure associated with BTA_DM_LINK_UP_EVT */
typedef struct {
  RawAddress bd_addr; /* BD address peer device. */
} tBTA_DM_LINK_UP;

/* Structure associated with BTA_DM_LINK_DOWN_EVT */
typedef struct {
  RawAddress bd_addr; /* BD address peer device. */
} tBTA_DM_LINK_DOWN;

#define BTA_AUTH_SP_YES                                                       \
  BTM_AUTH_SP_YES /* 1 MITM Protection Required - Single Profile/non-bonding  \
                    Use IO Capabilities to determine authentication procedure \
                    */

#define BTA_AUTH_DD_BOND \
  BTM_AUTH_DD_BOND /* 2 this bit is set for dedicated bonding */
#define BTA_AUTH_GEN_BOND \
  BTM_AUTH_SPGB_NO /* 4 this bit is set for general bonding */
#define BTA_AUTH_BONDS \
  BTM_AUTH_BONDS /* 6 the general/dedicated bonding bits  */

#define BTA_LE_AUTH_REQ_SC_MITM_BOND BTM_LE_AUTH_REQ_SC_MITM_BOND /* 1101 */

/* Structure associated with BTA_DM_SP_CFM_REQ_EVT */
typedef struct {
  /* Note: First 3 data members must be, bd_addr, dev_class, and bd_name in
   * order */
  RawAddress bd_addr;  /* peer address */
  DEV_CLASS dev_class; /* peer CoD */
  BD_NAME bd_name;     /* peer device name */
  uint32_t num_val; /* the numeric value for comparison. If just_works, do not
                       show this number to UI */
  bool just_works;  /* true, if "Just Works" association model */
  tBTM_AUTH_REQ loc_auth_req; /* Authentication required for local device */
  tBTM_AUTH_REQ rmt_auth_req; /* Authentication required for peer device */
  tBTM_IO_CAP loc_io_caps;    /* IO Capabilities of local device */
  tBTM_AUTH_REQ rmt_io_caps;  /* IO Capabilities of remote device */
} tBTA_DM_SP_CFM_REQ;

/* Structure associated with BTA_DM_SP_KEY_NOTIF_EVT */
typedef struct {
  /* Note: First 3 data members must be, bd_addr, dev_class, and bd_name in
   * order */
  RawAddress bd_addr;  /* peer address */
  DEV_CLASS dev_class; /* peer CoD */
  BD_NAME bd_name;     /* peer device name */
  uint32_t passkey; /* the numeric value for comparison. If just_works, do not
                       show this number to UI */
} tBTA_DM_SP_KEY_NOTIF;

/* Structure associated with BTA_DM_SP_RMT_OOB_EVT */
typedef struct {
  /* Note: First 3 data members must be, bd_addr, dev_class, and bd_name in
   * order */
  RawAddress bd_addr;  /* peer address */
  DEV_CLASS dev_class; /* peer CoD */
  BD_NAME bd_name;     /* peer device name */
} tBTA_DM_SP_RMT_OOB;

/* Structure associated with BTA_DM_BOND_CANCEL_CMPL_EVT */
typedef struct {
  tBTA_STATUS result; /* true of bond cancel succeeded, false if failed. */
} tBTA_DM_BOND_CANCEL_CMPL;

typedef struct {
  Octet16 local_oob_c; /* Local OOB Data Confirmation/Commitment */
  Octet16 local_oob_r; /* Local OOB Data Randomizer */
} tBTA_DM_LOC_OOB_DATA;

/* Union of all security callback structures */
typedef union {
  tBTA_DM_PIN_REQ pin_req;        /* PIN request. */
  tBTA_DM_AUTH_CMPL auth_cmpl;    /* Authentication complete indication. */
  tBTA_DM_LINK_UP link_up;        /* ACL connection down event */
  tBTA_DM_LINK_DOWN link_down;    /* ACL connection down event */
  tBTA_DM_SP_CFM_REQ cfm_req;     /* user confirm request */
  tBTA_DM_SP_KEY_NOTIF key_notif; /* passkey notification */
  tBTA_DM_SP_RMT_OOB rmt_oob;     /* remote oob */
  tBTA_DM_BOND_CANCEL_CMPL
      bond_cancel_cmpl;               /* Bond Cancel Complete indication */
  tBTA_DM_BLE_SEC_REQ ble_req;        /* BLE SMP related request */
  tBTA_DM_BLE_KEY ble_key;            /* BLE SMP keys used when pairing */
  tBTA_BLE_LOCAL_ID_KEYS ble_id_keys; /* IR event */
  Octet16 ble_er;                     /* ER event data */
  tBTA_DM_LOC_OOB_DATA local_oob_data; /* Local OOB data generated by us */
} tBTA_DM_SEC;

/* Security callback */
typedef void(tBTA_DM_SEC_CBACK)(tBTA_DM_SEC_EVT event, tBTA_DM_SEC* p_data);

#define BTA_DM_BLE_PF_LIST_LOGIC_OR 1
#define BTA_DM_BLE_PF_FILT_LOGIC_OR 0

/* Search callback events */
#define BTA_DM_INQ_RES_EVT 0  /* Inquiry result for a peer device. */
#define BTA_DM_INQ_CMPL_EVT 1 /* Inquiry complete. */
#define BTA_DM_DISC_RES_EVT 2 /* Discovery result for a peer device. */
#define BTA_DM_DISC_BLE_RES_EVT \
  3 /* Discovery result for BLE GATT based servoce on a peer device. */
#define BTA_DM_DISC_CMPL_EVT 4          /* Discovery complete. */
#define BTA_DM_SEARCH_CANCEL_CMPL_EVT 6 /* Search cancelled */

typedef uint8_t tBTA_DM_SEARCH_EVT;

/* Structure associated with BTA_DM_INQ_RES_EVT */
typedef struct {
  RawAddress bd_addr;          /* BD address peer device. */
  DEV_CLASS dev_class;         /* Device class of peer device. */
  bool remt_name_not_required; /* Application sets this flag if it already knows
                                  the name of the device */
  /* If the device name is known to application BTA skips the remote name
   * request */
  bool is_limited; /* true, if the limited inquiry bit is set in the CoD */
  int8_t rssi;     /* The rssi value */
  uint8_t* p_eir;  /* received EIR */
  uint16_t eir_len; /* received EIR length */
  uint8_t inq_result_type;
  tBLE_ADDR_TYPE ble_addr_type;
  uint16_t ble_evt_type;
  uint8_t ble_primary_phy;
  uint8_t ble_secondary_phy;
  uint8_t ble_advertising_sid;
  int8_t ble_tx_power;
  uint16_t ble_periodic_adv_int;
  tBT_DEVICE_TYPE device_type;
  uint8_t flag;
} tBTA_DM_INQ_RES;

/* Structure associated with BTA_DM_INQ_CMPL_EVT */
typedef struct {
  uint8_t num_resps; /* Number of inquiry responses. */
} tBTA_DM_INQ_CMPL;

/* Structure associated with BTA_DM_DISC_RES_EVT */
typedef struct {
  RawAddress bd_addr;          /* BD address peer device. */
  BD_NAME bd_name;             /* Name of peer device. */
  tBTA_SERVICE_MASK services;  /* Services found on peer device. */
  tBT_DEVICE_TYPE device_type; /* device type in case it is BLE device */
  uint32_t num_uuids;
  bluetooth::Uuid* p_uuid_list;
  tBTA_STATUS result;
} tBTA_DM_DISC_RES;

/* Structure associated with tBTA_DM_DISC_BLE_RES */
typedef struct {
  RawAddress bd_addr; /* BD address peer device. */
  BD_NAME bd_name;  /* Name of peer device. */
  std::vector<bluetooth::Uuid>*
      services; /* GATT based Services UUID found on peer device. */
} tBTA_DM_DISC_BLE_RES;

/* Union of all search callback structures */
typedef union {
  tBTA_DM_INQ_RES inq_res;   /* Inquiry result for a peer device. */
  tBTA_DM_INQ_CMPL inq_cmpl; /* Inquiry complete. */
  tBTA_DM_DISC_RES disc_res; /* Discovery result for a peer device. */
  tBTA_DM_DISC_BLE_RES
      disc_ble_res;             /* discovery result for GATT based service */
} tBTA_DM_SEARCH;

/* Search callback */
typedef void(tBTA_DM_SEARCH_CBACK)(tBTA_DM_SEARCH_EVT event,
                                   tBTA_DM_SEARCH* p_data);

/* Execute call back */
typedef void(tBTA_DM_EXEC_CBACK)(void* p_param);

/* Encryption callback*/
typedef void(tBTA_DM_ENCRYPT_CBACK)(const RawAddress& bd_addr,
                                    tBT_TRANSPORT transport,
                                    tBTA_STATUS result);

#define BTA_DM_CONTRL_UNKNOWN 0 /* Unknown state */

typedef uint8_t tBTA_DM_CONTRL_STATE;

typedef void(tBTA_BLE_ENERGY_INFO_CBACK)(tBTM_BLE_TX_TIME_MS tx_time,
                                         tBTM_BLE_RX_TIME_MS rx_time,
                                         tBTM_BLE_IDLE_TIME_MS idle_time,
                                         tBTM_BLE_ENERGY_USED energy_used,
                                         tBTA_DM_CONTRL_STATE ctrl_state,
                                         tBTA_STATUS status);

/* Maximum service name length */
#define BTA_SERVICE_NAME_LEN 35

typedef enum : uint8_t {
  /* power mode actions  */
  BTA_DM_PM_NO_ACTION = 0x00, /* no change to the current pm setting */
  BTA_DM_PM_PARK = 0x10,      /* prefers park mode */
  BTA_DM_PM_SNIFF = 0x20,     /* prefers sniff mode */
  BTA_DM_PM_SNIFF1 = 0x21,    /* prefers sniff1 mode */
  BTA_DM_PM_SNIFF2 = 0x22,    /* prefers sniff2 mode */
  BTA_DM_PM_SNIFF3 = 0x23,    /* prefers sniff3 mode */
  BTA_DM_PM_SNIFF4 = 0x24,    /* prefers sniff4 mode */
  BTA_DM_PM_SNIFF5 = 0x25,    /* prefers sniff5 mode */
  BTA_DM_PM_SNIFF6 = 0x26,    /* prefers sniff6 mode */
  BTA_DM_PM_SNIFF7 = 0x27,    /* prefers sniff7 mode */
  BTA_DM_PM_SNIFF_USER0 =
      0x28, /* prefers user-defined sniff0 mode (testtool only) */
  BTA_DM_PM_SNIFF_USER1 =
      0x29, /* prefers user-defined sniff1 mode (testtool only) */
  BTA_DM_PM_ACTIVE = 0x40,  /* prefers active mode */
  BTA_DM_PM_RETRY = 0x80,   /* retry power mode based on current settings */
  BTA_DM_PM_SUSPEND = 0x04, /* prefers suspend mode */
  BTA_DM_PM_NO_PREF = 0x01, /* service has no preference on power mode setting.
                               eg. connection to \ service got closed */
  BTA_DM_PM_SNIFF_MASK = 0x0f,  // Masks the sniff submode
} tBTA_DM_PM_ACTION_BITMASK;
typedef uint8_t tBTA_DM_PM_ACTION;

/* index to bta_dm_ssr_spec */
enum {
  BTA_DM_PM_SSR0 = 0,
  /* BTA_DM_PM_SSR1 will be dedicated for \
     HH SSR setting entry, no other profile can use it */
  BTA_DM_PM_SSR1 = 1,
  BTA_DM_PM_SSR2 = 2,
  BTA_DM_PM_SSR3 = 3,
  BTA_DM_PM_SSR4 = 4,
};

#define BTA_DM_PM_NUM_EVTS 9

#ifndef BTA_DM_PM_PARK_IDX
#define BTA_DM_PM_PARK_IDX \
  6 /* the actual index to bta_dm_pm_md[] for PARK mode */
#endif

#ifndef BTA_DM_PM_SNIFF_A2DP_IDX
#define BTA_DM_PM_SNIFF_A2DP_IDX BTA_DM_PM_SNIFF
#endif

#ifndef BTA_DM_PM_SNIFF_HD_IDLE_IDX
#define BTA_DM_PM_SNIFF_HD_IDLE_IDX BTA_DM_PM_SNIFF2
#endif

#ifndef BTA_DM_PM_SNIFF_SCO_OPEN_IDX
#define BTA_DM_PM_SNIFF_SCO_OPEN_IDX BTA_DM_PM_SNIFF3
#endif

#ifndef BTA_DM_PM_SNIFF_HD_ACTIVE_IDX
#define BTA_DM_PM_SNIFF_HD_ACTIVE_IDX BTA_DM_PM_SNIFF4
#endif

#ifndef BTA_DM_PM_SNIFF_HH_OPEN_IDX
#define BTA_DM_PM_SNIFF_HH_OPEN_IDX BTA_DM_PM_SNIFF2
#endif

#ifndef BTA_DM_PM_SNIFF_HH_ACTIVE_IDX
#define BTA_DM_PM_SNIFF_HH_ACTIVE_IDX BTA_DM_PM_SNIFF2
#endif

#ifndef BTA_DM_PM_SNIFF_HH_IDLE_IDX
#define BTA_DM_PM_SNIFF_HH_IDLE_IDX BTA_DM_PM_SNIFF2
#endif

#ifndef BTA_DM_PM_HH_OPEN_DELAY
#define BTA_DM_PM_HH_OPEN_DELAY 30000
#endif

#ifndef BTA_DM_PM_HH_ACTIVE_DELAY
#define BTA_DM_PM_HH_ACTIVE_DELAY 30000
#endif

#ifndef BTA_DM_PM_HH_IDLE_DELAY
#define BTA_DM_PM_HH_IDLE_DELAY 30000
#endif

/* The Sniff Parameters defined below must be ordered from highest
 * latency (biggest interval) to lowest latency.  If there is a conflict
 * among the connected services the setting with the lowest latency will
 * be selected.  If a device should override a sniff parameter then it
 * must insure that order is maintained.
 */
#ifndef BTA_DM_PM_SNIFF_MAX
#define BTA_DM_PM_SNIFF_MAX 800
#define BTA_DM_PM_SNIFF_MIN 400
#define BTA_DM_PM_SNIFF_ATTEMPT 4
#define BTA_DM_PM_SNIFF_TIMEOUT 1
#endif

#ifndef BTA_DM_PM_SNIFF1_MAX
#define BTA_DM_PM_SNIFF1_MAX 400
#define BTA_DM_PM_SNIFF1_MIN 200
#define BTA_DM_PM_SNIFF1_ATTEMPT 4
#define BTA_DM_PM_SNIFF1_TIMEOUT 1
#endif

#ifndef BTA_DM_PM_SNIFF2_MAX
#define BTA_DM_PM_SNIFF2_MAX 54
#define BTA_DM_PM_SNIFF2_MIN 30
#define BTA_DM_PM_SNIFF2_ATTEMPT 4
#define BTA_DM_PM_SNIFF2_TIMEOUT 1
#endif

#ifndef BTA_DM_PM_SNIFF3_MAX
#define BTA_DM_PM_SNIFF3_MAX 150
#define BTA_DM_PM_SNIFF3_MIN 50
#define BTA_DM_PM_SNIFF3_ATTEMPT 4
#define BTA_DM_PM_SNIFF3_TIMEOUT 1
#endif

#ifndef BTA_DM_PM_SNIFF4_MAX
#define BTA_DM_PM_SNIFF4_MAX 18
#define BTA_DM_PM_SNIFF4_MIN 10
#define BTA_DM_PM_SNIFF4_ATTEMPT 4
#define BTA_DM_PM_SNIFF4_TIMEOUT 1
#endif

#ifndef BTA_DM_PM_SNIFF5_MAX
#define BTA_DM_PM_SNIFF5_MAX 36
#define BTA_DM_PM_SNIFF5_MIN 30
#define BTA_DM_PM_SNIFF5_ATTEMPT 2
#define BTA_DM_PM_SNIFF5_TIMEOUT 0
#endif

#ifndef BTA_DM_PM_SNIFF6_MAX
#define BTA_DM_PM_SNIFF6_MAX 18
#define BTA_DM_PM_SNIFF6_MIN 14
#define BTA_DM_PM_SNIFF6_ATTEMPT 1
#define BTA_DM_PM_SNIFF6_TIMEOUT 0
#endif

#ifndef BTA_DM_PM_PARK_MAX
#define BTA_DM_PM_PARK_MAX 800
#define BTA_DM_PM_PARK_MIN 400
#define BTA_DM_PM_PARK_ATTEMPT 0
#define BTA_DM_PM_PARK_TIMEOUT 0
#endif

/* Device Identification (DI) data structure
*/

#ifndef BTA_DI_NUM_MAX
#define BTA_DI_NUM_MAX 3
#endif

#define IMMEDIATE_DELY_MODE 0x00
#define ALLOW_ALL_FILTER 0x00
#define LOWEST_RSSI_VALUE 129

/*****************************************************************************
 *  External Function Declarations
 ****************************************************************************/

void BTA_dm_init();

/*******************************************************************************
 *
 * Function         BTA_EnableTestMode
 *
 * Description      Enables bluetooth device under test mode
 *
 *
 * Returns          tBTA_STATUS
 *
 ******************************************************************************/
extern void BTA_EnableTestMode(void);

/*******************************************************************************
 *
 * Function         BTA_DmSetDeviceName
 *
 * Description      This function sets the Bluetooth name of the local device.
 *
 *
 * Returns          void
 *
 ******************************************************************************/
extern void BTA_DmSetDeviceName(char* p_name);

/*******************************************************************************
 *
 * Function         BTA_DmSetVisibility
 *
 * Description      This function sets the Bluetooth connectable,discoverable,
 *                  pairable and conn paired only modesmodes of the local
 *                  device.
 *                  This controls whether other Bluetooth devices can find and
 *                  connect to the local device.
 *
 *
 * Returns          void
 *
 ******************************************************************************/
extern bool BTA_DmSetVisibility(bt_scan_mode_t mode);

/*******************************************************************************
 *
 * Function         BTA_DmSearch
 *
 * Description      This function searches for peer Bluetooth devices.  It
 *                  first performs an inquiry; for each device found from the
 *                  inquiry it gets the remote name of the device.  If
 *                  parameter services is nonzero, service discovery will be
 *                  performed on each device for the services specified. If the
 *                  parameter is_bonding_or_sdp is true, the request will be
 *                  queued until bonding or sdp completes
 *
 *
 * Returns          void
 *
 ******************************************************************************/
extern void BTA_DmSearch(tBTA_DM_SEARCH_CBACK* p_cback, bool is_bonding_or_sdp);

/*******************************************************************************
 *
 * Function         BTA_DmSearchCancel
 *
 * Description      This function cancels a search that has been initiated
 *                  by calling BTA_DmSearch().
 *
 *
 * Returns          void
 *
 ******************************************************************************/
extern void BTA_DmSearchCancel(void);

/*******************************************************************************
 *
 * Function         BTA_DmDiscover
 *
 * Description      This function performs service discovery for the services
 *                  of a particular peer device.
 *
 *
 * Returns          void
 *
 ******************************************************************************/
extern void BTA_DmDiscover(const RawAddress& bd_addr,
                           tBTA_DM_SEARCH_CBACK* p_cback,
                           tBT_TRANSPORT transport, bool is_bonding_or_sdp);

/*******************************************************************************
 *
 * Function         BTA_DmGetCachedRemoteName
 *
 * Description      Retieve cached remote name if available
 *
 * Returns          BTA_SUCCESS if cached name was retrieved
 *                  BTA_FAILURE if cached name is not available
 *
 ******************************************************************************/
tBTA_STATUS BTA_DmGetCachedRemoteName(const RawAddress& remote_device,
                                      uint8_t** pp_cached_name);

/*******************************************************************************
 *
 * Function         BTA_DmBond
 *
 * Description      This function initiates a bonding procedure with a peer
 *                  device by designated transport.  The bonding procedure
 *                  enables authentication and optionally encryption on the
 *                  Bluetooth link.
 *
 *
 * Returns          void
 *
 ******************************************************************************/
extern void BTA_DmBond(const RawAddress& bd_addr, tBLE_ADDR_TYPE addr_type,
                       tBT_TRANSPORT transport, int device_type);

/*******************************************************************************
 *
 * Function         BTA_DmBondCancel
 *
 * Description      This function cancels a bonding procedure with a peer
 *                  device.
 *
 *
 * Returns          void
 *
 ******************************************************************************/
extern void BTA_DmBondCancel(const RawAddress& bd_addr);

/*******************************************************************************
 *
 * Function         BTA_DmPinReply
 *
 * Description      This function provides a PIN when one is requested by DM
 *                  during a bonding procedure.  The application should call
 *                  this function after the security callback is called with
 *                  a BTA_DM_PIN_REQ_EVT.
 *
 *
 * Returns          void
 *
 ******************************************************************************/
extern void BTA_DmPinReply(const RawAddress& bd_addr, bool accept,
                           uint8_t pin_len, uint8_t* p_pin);

/*******************************************************************************
 *
 * Function         BTA_DmLocalOob
 *
 * Description      This function retrieves the OOB data from local controller.
 *                  The result is reported by bta_dm_co_loc_oob().
 *
 * Returns          void
 *
 ******************************************************************************/
extern void BTA_DmLocalOob(void);

/*******************************************************************************
 *
 * Function         BTA_DmConfirm
 *
 * Description      This function accepts or rejects the numerical value of the
 *                  Simple Pairing process on BTA_DM_SP_CFM_REQ_EVT
 *
 * Returns          void
 *
 ******************************************************************************/
extern void BTA_DmConfirm(const RawAddress& bd_addr, bool accept);

/*******************************************************************************
 *
 * Function         BTA_DmAddDevice
 *
 * Description      This function adds a device to the security database list
 *                  of peer devices. This function would typically be called
 *                  at system startup to initialize the security database with
 *                  known peer devices.  This is a direct execution function
 *                  that may lock task scheduling on some platforms.
 *
 * Returns          void
 *
 ******************************************************************************/
extern void BTA_DmAddDevice(const RawAddress& bd_addr, DEV_CLASS dev_class,
                            const LinkKey& link_key, uint8_t key_type,
                            uint8_t pin_length);

/*******************************************************************************
 *
 * Function         BTA_DmRemoveDevice
 *
 * Description      This function removes a device from the security database.
 *                  This is a direct execution function that may lock task
 *                  scheduling on some platforms.
 *
 *
 * Returns          BTA_SUCCESS if successful.
 *                  BTA_FAIL if operation failed.
 *
 ******************************************************************************/
extern tBTA_STATUS BTA_DmRemoveDevice(const RawAddress& bd_addr);

/*******************************************************************************
 *
 * Function         BTA_GetEirService
 *
 * Description      This function is called to get BTA service mask from EIR.
 *
 * Parameters       p_eir - pointer of EIR significant part
 *                  eir_len - EIR length
 *                  p_services - return the BTA service mask
 *
 * Returns          None
 *
 ******************************************************************************/
extern void BTA_GetEirService(uint8_t* p_eir, size_t eir_len,
                              tBTA_SERVICE_MASK* p_services);

/*******************************************************************************
 *
 * Function         BTA_AddEirUuid
 *
 * Description      Request to add a new service class UUID to the local
 *                  device's EIR data.
 *
 * Parameters       uuid16 - The service class UUID you wish to add
 *
 * Returns          void
 *
 ******************************************************************************/
extern void BTA_AddEirUuid(uint16_t uuid16);

/*******************************************************************************
 *
 * Function         BTA_RemoveEirUuid
 *
 * Description      Request to remove a service class UID from the local
 *                  device's EIR data.
 *
 * Parameters       uuid16 - The service class UUID you wish to remove
 *
 * Returns          void
 *
 ******************************************************************************/
extern void BTA_RemoveEirUuid(uint16_t uuid16);

/*******************************************************************************
 *
 * Function         BTA_DmGetConnectionState
 *
 * Description      Returns whether the remote device is currently connected.
 *
 * Returns          true if the device is NOT connected, false otherwise.
 *
 ******************************************************************************/
extern bool BTA_DmGetConnectionState(const RawAddress& bd_addr);

/*******************************************************************************
 *
 * Function         BTA_DmSetLocalDiRecord
 *
 * Description      This function adds a DI record to the local SDP database.
 *
 * Returns          BTA_SUCCESS if record set sucessfully, otherwise error code.
 *
 ******************************************************************************/
extern tBTA_STATUS BTA_DmSetLocalDiRecord(tSDP_DI_RECORD* p_device_info,
                                          uint32_t* p_handle);

/*******************************************************************************
 *
 *
 * Function         BTA_DmCloseACL
 *
 * Description      This function force to close an ACL connection and remove
 the
 *                  device from the security database list of known devices.
 *
 * Parameters:      bd_addr       - Address of the peer device
 *                  remove_dev    - remove device or not after link down
 *                  transport     - which transport to close

 *
 * Returns          void.
 *
 ******************************************************************************/
extern void BTA_DmCloseACL(const RawAddress& bd_addr, bool remove_dev,
                           tBT_TRANSPORT transport);

/* BLE related API functions */
/*******************************************************************************
 *
 * Function         BTA_DmBleSecurityGrant
 *
 * Description      Grant security request access.
 *
 * Parameters:      bd_addr          - BD address of the peer
 *                  res              - security grant status.
 *
 * Returns          void
 *
 ******************************************************************************/
extern void BTA_DmBleSecurityGrant(const RawAddress& bd_addr,
                                   tBTA_DM_BLE_SEC_GRANT res);

/*******************************************************************************
 *
 * Function         BTA_DmBlePasskeyReply
 *
 * Description      Send BLE SMP passkey reply.
 *
 * Parameters:      bd_addr          - BD address of the peer
 *                  accept           - passkey entry sucessful or declined.
 *                  passkey          - passkey value, must be a 6 digit number,
 *                                     can be lead by 0.
 *
 * Returns          void
 *
 ******************************************************************************/
extern void BTA_DmBlePasskeyReply(const RawAddress& bd_addr, bool accept,
                                  uint32_t passkey);

/*******************************************************************************
 *
 * Function         BTA_DmBleConfirmReply
 *
 * Description      Send BLE SMP SC user confirmation reply.
 *
 * Parameters:      bd_addr          - BD address of the peer
 *                  accept           - numbers to compare are the same or
 *                                     different.
 *
 * Returns          void
 *
 ******************************************************************************/
extern void BTA_DmBleConfirmReply(const RawAddress& bd_addr, bool accept);

/*******************************************************************************
 *
 * Function         BTA_DmAddBleDevice
 *
 * Description      Add a BLE device.  This function will be normally called
 *                  during host startup to restore all required information
 *                  for a LE device stored in the NVRAM.
 *
 * Parameters:      bd_addr          - BD address of the peer
 *                  dev_type         - Remote device's device type.
 *                  addr_type        - LE device address type.
 *
 * Returns          void
 *
 ******************************************************************************/
extern void BTA_DmAddBleDevice(const RawAddress& bd_addr,
                               tBLE_ADDR_TYPE addr_type,
                               tBT_DEVICE_TYPE dev_type);

/*******************************************************************************
 *
 * Function         BTA_DmAddBleKey
 *
 * Description      Add/modify LE device information.  This function will be
 *                  normally called during host startup to restore all required
 *                  information stored in the NVRAM.
 *
 * Parameters:      bd_addr          - BD address of the peer
 *                  p_le_key         - LE key values.
 *                  key_type         - LE SMP key type.
 *
 * Returns          void
 *
 ******************************************************************************/
extern void BTA_DmAddBleKey(const RawAddress& bd_addr,
                            tBTA_LE_KEY_VALUE* p_le_key,
                            tBTM_LE_KEY_TYPE key_type);

/*******************************************************************************
 *
 * Function         BTA_DmSetBlePrefConnParams
 *
 * Description      This function is called to set the preferred connection
 *                  parameters when default connection parameter is not desired.
 *
 * Parameters:      bd_addr          - BD address of the peripheral
 *                  min_conn_int     - minimum preferred connection interval
 *                  max_conn_int     - maximum preferred connection interval
 *                  peripheral_latency    - preferred peripheral latency
 *                  supervision_tout - preferred supervision timeout
 *
 *
 * Returns          void
 *
 ******************************************************************************/
extern void BTA_DmSetBlePrefConnParams(const RawAddress& bd_addr,
                                       uint16_t min_conn_int,
                                       uint16_t max_conn_int,
                                       uint16_t peripheral_latency,
                                       uint16_t supervision_tout);

/*******************************************************************************
 *
 * Function         BTA_DmSetEncryption
 *
 * Description      This function is called to ensure that connection is
 *                  encrypted.  Should be called only on an open connection.
 *                  Typically only needed for connections that first want to
 *                  bring up unencrypted links, then later encrypt them.
 *
 * Parameters:      bd_addr       - Address of the peer device
 *                  transport     - transport of the link to be encruypted
 *                  p_callback    - Pointer to callback function to indicat the
 *                                  link encryption status
 *                  sec_act       - This is the security action to indicate
 *                                  what kind of BLE security level is required
 *                                  for the BLE link if BLE is supported
 *                                  Note: This parameter is ignored for
 *                                        BR/EDR or if BLE is not supported.
 *
 * Returns          void
 *
 *
 ******************************************************************************/
extern void BTA_DmSetEncryption(const RawAddress& bd_addr,
                                tBT_TRANSPORT transport,
                                tBTA_DM_ENCRYPT_CBACK* p_callback,
                                tBTM_BLE_SEC_ACT sec_act);

/*******************************************************************************
 *
 * Function         BTA_DmBleObserve
 *
 * Description      This procedure keep the device listening for advertising
 *                  events from a broadcast device.
 *
 * Parameters       start: start or stop observe.
 *                  duration : Duration of the scan. Continuous scan if 0 is
 *                             passed
 *                  p_results_cb: Callback to be called with scan results
 *
 * Returns          void
 *
 ******************************************************************************/
extern void BTA_DmBleObserve(bool start, uint8_t duration,
                             tBTA_DM_SEARCH_CBACK* p_results_cb);

/*******************************************************************************
 *
 * Function         BTA_DmBleConfigLocalPrivacy
 *
 * Description      Enable/disable privacy on the local device
 *
 * Parameters:      privacy_enable   - enable/disabe privacy on remote device.
 *
 * Returns          void
 *
 ******************************************************************************/
extern void BTA_DmBleConfigLocalPrivacy(bool privacy_enable);

/*******************************************************************************
 *
 * Function         BTA_DmBleEnableRemotePrivacy
 *
 * Description      Enable/disable privacy on a remote device
 *
 * Parameters:      bd_addr          - BD address of the peer
 *                  privacy_enable   - enable/disabe privacy on remote device.
 *
 * Returns          void
 *
 ******************************************************************************/
extern void BTA_DmBleEnableRemotePrivacy(const RawAddress& bd_addr,
                                         bool privacy_enable);

/*******************************************************************************
 *
 * Function         BTA_DmBleUpdateConnectionParams
 *
 * Description      Update connection parameters, can only be used when
 *                  connection is up.
 *
 * Parameters:      bd_addr   - BD address of the peer
 *                  min_int   - minimum connection interval, [0x0004 ~ 0x4000]
 *                  max_int   - maximum connection interval, [0x0004 ~ 0x4000]
 *                  latency   - peripheral latency [0 ~ 500]
 *                  timeout   - supervision timeout [0x000a ~ 0xc80]
 *
 * Returns          void
 *
 ******************************************************************************/
extern void BTA_DmBleUpdateConnectionParams(const RawAddress& bd_addr,
                                            uint16_t min_int, uint16_t max_int,
                                            uint16_t latency, uint16_t timeout,
                                            uint16_t min_ce_len,
                                            uint16_t max_ce_len);

/*******************************************************************************
 *
 * Function         BTA_DmBleSetDataLength
 *
 * Description      This function is to set maximum LE data packet size
 *
 * Returns          void
 *
 ******************************************************************************/
extern void BTA_DmBleRequestMaxTxDataLength(const RawAddress& remote_device);

/*******************************************************************************
 *
 * Function         BTA_DmBleGetEnergyInfo
 *
 * Description      This function is called to obtain the energy info
 *
 * Parameters       p_cmpl_cback - Command complete callback
 *
 * Returns          void
 *
 ******************************************************************************/
extern void BTA_DmBleGetEnergyInfo(tBTA_BLE_ENERGY_INFO_CBACK* p_cmpl_cback);

/*******************************************************************************
 *
 * Function         BTA_BrcmInit
 *
 * Description      This function initializes Broadcom specific VS handler in
 *                  BTA
 *
 * Returns          void
 *
 ******************************************************************************/
extern void BTA_VendorInit(void);

#endif /* BTA_API_H */
