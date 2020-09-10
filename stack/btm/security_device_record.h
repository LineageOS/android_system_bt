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

#pragma once

#include <cstdint>

#include "gd/crypto_toolbox/crypto_toolbox.h"
#include "osi/include/alarm.h"
#include "stack/include/btm_api_types.h"
#include "types/raw_address.h"

typedef char tBTM_LOC_BD_NAME[BTM_MAX_LOC_BD_NAME_LEN + 1];

#define BTM_IS_BRCM_CONTROLLER()                                 \
  (controller_get_interface()->get_bt_version()->manufacturer == \
   LMP_COMPID_BROADCOM)

typedef struct {
  uint16_t min_conn_int;
  uint16_t max_conn_int;
  uint16_t slave_latency;
  uint16_t supervision_tout;

} tBTM_LE_CONN_PRAMS;

/* Define the Device Management control structure
 */
typedef struct {
  tBTM_VS_EVT_CB* p_vend_spec_cb[BTM_MAX_VSE_CALLBACKS]; /* Register for vendor
                                                            specific events  */

  tBTM_CMPL_CB*
      p_stored_link_key_cmpl_cb; /* Read/Write/Delete stored link key    */

  alarm_t* read_local_name_timer; /* Read local name timer */
  tBTM_CMPL_CB* p_rln_cmpl_cb;    /* Callback function to be called when  */
                                  /* read local name function complete    */

  alarm_t* read_rssi_timer;     /* Read RSSI timer */
  tBTM_CMPL_CB* p_rssi_cmpl_cb; /* Callback function to be called when  */
                                /* read RSSI function completes */

  alarm_t* read_failed_contact_counter_timer; /* Read Failed Contact Counter */
                                              /* timer */
  tBTM_CMPL_CB* p_failed_contact_counter_cmpl_cb; /* Callback function to be */
  /* called when read Failed Contact Counter function completes */

  alarm_t*
      read_automatic_flush_timeout_timer; /* Read Automatic Flush Timeout */
                                          /* timer */
  tBTM_CMPL_CB* p_automatic_flush_timeout_cmpl_cb; /* Callback function to be */
  /* called when read Automatic Flush Timeout function completes */

  alarm_t* read_link_quality_timer;
  tBTM_CMPL_CB* p_link_qual_cmpl_cb; /* Callback function to be called when  */
                                     /* read link quality function completes */

  alarm_t* read_tx_power_timer;     /* Read tx power timer */
  tBTM_CMPL_CB* p_tx_power_cmpl_cb; /* Callback function to be called       */

  DEV_CLASS dev_class; /* Local device class                   */

  tBTM_CMPL_CB*
      p_le_test_cmd_cmpl_cb; /* Callback function to be called when
                             LE test mode command has been sent successfully */

  RawAddress read_tx_pwr_addr; /* read TX power target address     */

#define BTM_LE_SUPPORT_STATE_SIZE 8
  uint8_t le_supported_states[BTM_LE_SUPPORT_STATE_SIZE];

  tBTM_BLE_LOCAL_ID_KEYS id_keys;   /* local BLE ID keys */
  Octet16 ble_encryption_key_value; /* BLE encryption key */

#if (BTM_BLE_CONFORMANCE_TESTING == TRUE)
  bool no_disc_if_pair_fail;
  bool enable_test_mac_val;
  BT_OCTET8 test_mac;
  bool enable_test_local_sign_cntr;
  uint32_t test_local_sign_cntr;
#endif

  tBTM_IO_CAP loc_io_caps;    /* IO capability of the local device */
  tBTM_AUTH_REQ loc_auth_req; /* the auth_req flag  */
} tBTM_DEVCB;

typedef struct {
  uint32_t inq_count; /* Used for determining if a response has already been */
  /* received for the current inquiry operation. (We do not   */
  /* want to flood the caller with multiple responses from    */
  /* the same device.                                         */
  RawAddress bd_addr;
} tINQ_BDADDR;

typedef struct {
  uint64_t time_of_resp;
  uint32_t
      inq_count; /* "timestamps" the entry with a particular inquiry count   */
                 /* Used for determining if a response has already been      */
                 /* received for the current inquiry operation. (We do not   */
                 /* want to flood the caller with multiple responses from    */
                 /* the same device.                                         */
  tBTM_INQ_INFO inq_info;
  bool in_use;
  bool scan_rsp;
} tINQ_DB_ENT;

enum { INQ_NONE, INQ_GENERAL };
typedef uint8_t tBTM_INQ_TYPE;

/* The MSB of the clock offset field indicates whether the offset is valid. */
#define BTM_CLOCK_OFFSET_VALID 0x8000

/*
 * Define structure for Security Service Record.
 * A record exists for each service registered with the Security Manager
 */
#define BTM_SEC_OUT_FLAGS (BTM_SEC_OUT_AUTHENTICATE | BTM_SEC_OUT_ENCRYPT)
#define BTM_SEC_IN_FLAGS (BTM_SEC_IN_AUTHENTICATE | BTM_SEC_IN_ENCRYPT)

#define BTM_SEC_OUT_LEVEL4_FLAGS                                       \
  (BTM_SEC_OUT_AUTHENTICATE | BTM_SEC_OUT_ENCRYPT | BTM_SEC_OUT_MITM | \
   BTM_SEC_MODE4_LEVEL4)

#define BTM_SEC_IN_LEVEL4_FLAGS                                     \
  (BTM_SEC_IN_AUTHENTICATE | BTM_SEC_IN_ENCRYPT | BTM_SEC_IN_MITM | \
   BTM_SEC_MODE4_LEVEL4)
typedef struct {
  uint32_t mx_proto_id;     /* Service runs over this multiplexer protocol */
  uint32_t orig_mx_chan_id; /* Channel on the multiplexer protocol    */
  uint32_t term_mx_chan_id; /* Channel on the multiplexer protocol    */
  uint16_t psm;             /* L2CAP PSM value */
  uint16_t security_flags;  /* Bitmap of required security features */
  uint8_t service_id;       /* Passed in authorization callback */
#if BTM_SEC_SERVICE_NAME_LEN > 0
  uint8_t orig_service_name[BTM_SEC_SERVICE_NAME_LEN + 1];
  uint8_t term_service_name[BTM_SEC_SERVICE_NAME_LEN + 1];
#endif
} tBTM_SEC_SERV_REC;

/* LE Security information of device in Slave Role */
typedef struct {
  Octet16 irk;   /* peer diverified identity root */
  Octet16 pltk;  /* peer long term key */
  Octet16 pcsrk; /* peer SRK peer device used to secured sign local data  */

  Octet16 lltk;  /* local long term key */
  Octet16 lcsrk; /* local SRK peer device used to secured sign local data  */

  BT_OCTET8 rand;        /* random vector for LTK generation */
  uint16_t ediv;         /* LTK diversifier of this slave device */
  uint16_t div;          /* local DIV  to generate local LTK=d1(ER,DIV,0) and
                            CSRK=d1(ER,DIV,1)  */
  uint8_t sec_level;     /* local pairing security level */
  uint8_t key_size;      /* key size of the LTK delivered to peer device */
  uint8_t srk_sec_level; /* security property of peer SRK for this device */
  uint8_t local_csrk_sec_level; /* security property of local CSRK for this
                                   device */

  uint32_t counter;       /* peer sign counter for verifying rcv signed cmd */
  uint32_t local_counter; /* local sign counter for sending signed write cmd*/
} tBTM_SEC_BLE_KEYS;

typedef struct {
  RawAddress pseudo_addr; /* LE pseudo address of the device if different from
                          device address  */
  tBLE_ADDR_TYPE ble_addr_type; /* LE device type: public or random address */

  tBLE_BD_ADDR identity_address_with_type;

#define BTM_WHITE_LIST_BIT 0x01
#define BTM_RESOLVING_LIST_BIT 0x02
  uint8_t in_controller_list; /* in controller resolving list or not */
  uint8_t resolving_list_index;
  RawAddress cur_rand_addr; /* current random address */

  typedef enum : uint8_t {
    BTM_BLE_ADDR_PSEUDO = 0,
    BTM_BLE_ADDR_RRA = 1,
    BTM_BLE_ADDR_STATIC = 2,
  } tADDRESS_TYPE;
  tADDRESS_TYPE active_addr_type;

  tBTM_LE_KEY_TYPE key_type; /* bit mask of valid key types in record */
  tBTM_SEC_BLE_KEYS keys;    /* LE device security info in slave rode */
} tBTM_SEC_BLE;

/* Peering bond type */
typedef enum : uint8_t {
  BOND_TYPE_UNKNOWN = 0,
  BOND_TYPE_PERSISTENT = 1,
  BOND_TYPE_TEMPORARY = 2
} tBTM_BOND_TYPE;

/*
 * Define structure for Security Device Record.
 * A record exists for each device authenticated with this device
 */
typedef struct {
  uint32_t required_security_flags_for_pairing;
  tBTM_SEC_CALLBACK* p_callback;
  void* p_ref_data;
  uint32_t timestamp; /* Timestamp of the last connection   */
  uint16_t hci_handle;     /* Handle to connection when exists   */
  uint16_t clock_offset;   /* Latest known clock offset          */
  RawAddress bd_addr;      /* BD_ADDR of the device              */
  DEV_CLASS dev_class;     /* DEV_CLASS of the device            */
  LinkKey link_key;        /* Device link key                    */
  uint8_t pin_code_length; /* Length of the pin_code used for paring */

#define BTM_SEC_AUTHENTICATED BTM_SEC_FLAG_AUTHENTICATED /* 0x02 */
#define BTM_SEC_ENCRYPTED BTM_SEC_FLAG_ENCRYPTED         /* 0x04 */
#define BTM_SEC_NAME_KNOWN 0x08
#define BTM_SEC_LINK_KEY_KNOWN BTM_SEC_FLAG_LKEY_KNOWN   /* 0x10 */
#define BTM_SEC_LINK_KEY_AUTHED BTM_SEC_FLAG_LKEY_AUTHED /* 0x20 */
#define BTM_SEC_ROLE_SWITCHED 0x40
#define BTM_SEC_IN_USE 0x80
/* LE link security flag */
#define BTM_SEC_LE_AUTHENTICATED \
  0x0200 /* LE link is encrypted after pairing with MITM */
#define BTM_SEC_LE_ENCRYPTED 0x0400  /* LE link is encrypted */
#define BTM_SEC_LE_NAME_KNOWN 0x0800 /* not used */
#define BTM_SEC_LE_LINK_KEY_KNOWN \
  0x1000 /* bonded with peer (peer LTK and/or SRK is saved) */
#define BTM_SEC_LE_LINK_KEY_AUTHED 0x2000 /* pairing is done with MITM */
#define BTM_SEC_16_DIGIT_PIN_AUTHED \
  0x4000 /* pairing is done with 16 digit pin */

  uint16_t sec_flags; /* Current device security state      */

  tBTM_BD_NAME sec_bd_name; /* User friendly name of the device. (may be
                               truncated to save space in dev_rec table) */
  BD_FEATURES feature_pages[HCI_EXT_FEATURES_PAGE_MAX +
                            1]; /* Features supported by the device */
  uint8_t num_read_pages;

#define BTM_SEC_STATE_IDLE 0
#define BTM_SEC_STATE_AUTHENTICATING 1
#define BTM_SEC_STATE_ENCRYPTING 2
#define BTM_SEC_STATE_GETTING_NAME 3
#define BTM_SEC_STATE_AUTHORIZING 4
#define BTM_SEC_STATE_SWITCHING_ROLE 5
#define BTM_SEC_STATE_DISCONNECTING 6 /* disconnecting BR/EDR */
#define BTM_SEC_STATE_DELAY_FOR_ENC \
  7 /* delay to check for encryption to work around */
    /* controller problems */
#define BTM_SEC_STATE_DISCONNECTING_BLE 8  /* disconnecting BLE */
#define BTM_SEC_STATE_DISCONNECTING_BOTH 9 /* disconnecting BR/EDR and BLE */

  uint8_t sec_state;          /* Operating state                    */
  bool is_originator;         /* true if device is originating connection */
  bool role_master;           /* true if current mode is master     */
  uint16_t security_required; /* Security required for connection   */
  bool link_key_not_sent; /* link key notification has not been sent waiting for
                             name */
  uint8_t link_key_type;  /* Type of key used in pairing   */
  bool link_key_changed;  /* Changed link key during current connection */

#define BTM_MAX_PRE_SM4_LKEY_TYPE \
  BTM_LKEY_TYPE_REMOTE_UNIT /* the link key type used by legacy pairing */

#define BTM_SM4_UNKNOWN 0x00
#define BTM_SM4_KNOWN 0x10
#define BTM_SM4_TRUE 0x11
#define BTM_SM4_REQ_PEND 0x08 /* set this bit when getting remote features */
#define BTM_SM4_UPGRADE 0x04  /* set this bit when upgrading link key */
#define BTM_SM4_RETRY                                     \
  0x02 /* set this bit to retry on HCI_ERR_KEY_MISSING or \
          HCI_ERR_LMP_ERR_TRANS_COLLISION */
#define BTM_SM4_DD_ACP \
  0x20 /* set this bit to indicate peer initiated dedicated bonding */
#define BTM_SM4_CONN_PEND                                               \
  0x40 /* set this bit to indicate accepting acl conn; to be cleared on \
          btm_acl_created */
  uint8_t sm4;                /* BTM_SM4_TRUE, if the peer supports SM4 */
  tBTM_IO_CAP rmt_io_caps;    /* IO capability of the peer device */
  tBTM_AUTH_REQ rmt_auth_req; /* the auth_req flag as in the IO caps rsp evt */
  bool remote_supports_secure_connections;
  bool remote_features_needed; /* set to true if the local device is in */
  /* "Secure Connections Only" mode and it receives */
  /* HCI_IO_CAPABILITY_REQUEST_EVT from the peer before */
  /* it knows peer's support for Secure Connections */

  uint16_t ble_hci_handle; /* use in DUMO connection */
  uint8_t enc_key_size;    /* current link encryption key size */
  tBT_DEVICE_TYPE device_type;
  bool new_encryption_key_is_p256; /* Set to true when the newly generated LK
                                   ** is generated from P-256.
                                   ** Link encrypted with such LK can be used
                                   ** for SM over BR/EDR.
                                   */
  tBTM_BOND_TYPE bond_type; /* peering bond type */

  tBTM_SEC_BLE ble;
  tBTM_LE_CONN_PRAMS conn_params;

#define BTM_SEC_RS_NOT_PENDING 0 /* Role Switch not in progress */
#define BTM_SEC_RS_PENDING 1     /* Role Switch in progress */
#define BTM_SEC_DISC_PENDING 2   /* Disconnect is pending */
  uint8_t rs_disc_pending;

} tBTM_SEC_DEV_REC;