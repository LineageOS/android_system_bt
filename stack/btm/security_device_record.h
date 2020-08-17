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

#include "btif/include/btif_bqr.h"
#include "btm_api_types.h"
#include "btm_ble_api_types.h"
#include "btm_ble_int_types.h"
#include "hcidefs.h"
#include "osi/include/alarm.h"
#include "osi/include/list.h"
#include "rfcdefs.h"
#include "stack/acl/acl.h"

typedef char tBTM_LOC_BD_NAME[BTM_MAX_LOC_BD_NAME_LEN + 1];

/* Definitions for Server Channel Number (SCN) management
 */
#define BTM_MAX_SCN PORT_MAX_RFC_PORTS

/* Define masks for supported and exception 2.0 ACL packet types
 */
#define BTM_ACL_SUPPORTED_PKTS_MASK                                           \
  (HCI_PKT_TYPES_MASK_DM1 | HCI_PKT_TYPES_MASK_DH1 | HCI_PKT_TYPES_MASK_DM3 | \
   HCI_PKT_TYPES_MASK_DH3 | HCI_PKT_TYPES_MASK_DM5 | HCI_PKT_TYPES_MASK_DH5)

#define BTM_ACL_EXCEPTION_PKTS_MASK                            \
  (HCI_PKT_TYPES_MASK_NO_2_DH1 | HCI_PKT_TYPES_MASK_NO_3_DH1 | \
   HCI_PKT_TYPES_MASK_NO_2_DH3 | HCI_PKT_TYPES_MASK_NO_3_DH3 | \
   HCI_PKT_TYPES_MASK_NO_2_DH5 | HCI_PKT_TYPES_MASK_NO_3_DH5)

#define BTM_EPR_AVAILABLE(p)                                        \
  ((HCI_ATOMIC_ENCRYPT_SUPPORTED((p)->peer_lmp_feature_pages[0]) && \
    controller_get_interface()->supports_encryption_pause())        \
       ? true                                                       \
       : false)

#define BTM_IS_BRCM_CONTROLLER()                                 \
  (controller_get_interface()->get_bt_version()->manufacturer == \
   LMP_COMPID_BROADCOM)

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

  alarm_t* read_inq_tx_power_timer;
  tBTM_CMPL_CB*
      p_inq_tx_power_cmpl_cb; /* Callback function to be called when  */
                              /* read inq tx power function completes  */

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

/* Define the structures and constants used for inquiry
 */

/* Definitions of limits for inquiries */
#define BTM_PER_INQ_MIN_MAX_PERIOD HCI_PER_INQ_MIN_MAX_PERIOD
#define BTM_PER_INQ_MAX_MAX_PERIOD HCI_PER_INQ_MAX_MAX_PERIOD
#define BTM_PER_INQ_MIN_MIN_PERIOD HCI_PER_INQ_MIN_MIN_PERIOD
#define BTM_PER_INQ_MAX_MIN_PERIOD HCI_PER_INQ_MAX_MIN_PERIOD
#define BTM_MAX_INQUIRY_LENGTH HCI_MAX_INQUIRY_LENGTH
#define BTM_MIN_INQUIRY_LEN 0x01

#define BTM_MIN_INQ_TX_POWER (-70)
#define BTM_MAX_INQ_TX_POWER 20

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

typedef struct {
  tBTM_CMPL_CB* p_remname_cmpl_cb;

#define BTM_EXT_RMT_NAME_TIMEOUT_MS (40 * 1000) /* 40 seconds */

  alarm_t* remote_name_timer;

  uint16_t discoverable_mode;
  uint16_t connectable_mode;
  uint16_t page_scan_window;
  uint16_t page_scan_period;
  uint16_t inq_scan_window;
  uint16_t inq_scan_period;
  uint16_t inq_scan_type;
  uint16_t page_scan_type; /* current page scan type */
  tBTM_INQ_TYPE scan_type;

  RawAddress remname_bda; /* Name of bd addr for active remote name request */
#define BTM_RMT_NAME_EXT 0x1 /* Initiated through API */
  bool remname_active; /* State of a remote name request by external API */

  tBTM_CMPL_CB* p_inq_cmpl_cb;
  tBTM_INQ_RESULTS_CB* p_inq_results_cb;
  tBTM_CMPL_CB* p_inqfilter_cmpl_cb; /* Called (if not NULL) after inquiry
                                        filter completed */
  uint32_t inq_counter; /* Counter incremented each time an inquiry completes */
  /* Used for determining whether or not duplicate devices */
  /* have responded to the same inquiry */
  tINQ_BDADDR* p_bd_db;    /* Pointer to memory that holds bdaddrs */
  uint16_t num_bd_entries; /* Number of entries in database */
  uint16_t max_bd_entries; /* Maximum number of entries that can be stored */
  tINQ_DB_ENT inq_db[BTM_INQ_DB_SIZE];
  tBTM_INQ_PARMS inqparms; /* Contains the parameters for the current inquiry */
  tBTM_INQUIRY_CMPL
      inq_cmpl_info; /* Status and number of responses from the last inquiry */

  uint16_t per_min_delay; /* Current periodic minimum delay */
  uint16_t per_max_delay; /* Current periodic maximum delay */
  bool inqfilt_active;
  uint8_t pending_filt_complete_event; /* to take care of
                                          btm_event_filter_complete
                                          corresponding to */
  /* inquiry that has been cancelled*/
  uint8_t inqfilt_type; /* Contains the inquiry filter type (BD ADDR, COD, or
                           Clear) */

#define BTM_INQ_INACTIVE_STATE 0
#define BTM_INQ_CLR_FILT_STATE \
  1 /* Currently clearing the inquiry filter preceding the inquiry request */
    /* (bypassed if filtering is not used)                                  */
#define BTM_INQ_SET_FILT_STATE \
  2 /* Sets the new filter (or turns off filtering) in this state */
#define BTM_INQ_ACTIVE_STATE \
  3 /* Actual inquiry or periodic inquiry is in progress */

  uint8_t state;      /* Current state that the inquiry process is in */
  uint8_t inq_active; /* Bit Mask indicating type of inquiry is active */
  bool no_inc_ssp;    /* true, to stop inquiry on incoming SSP */
} tBTM_INQUIRY_VAR_ST;

/* The MSB of the clock offset field indicates whether the offset is valid. */
#define BTM_CLOCK_OFFSET_VALID 0x8000

/* Define the structures needed by security management
 */

typedef void(tBTM_SCO_IND_CBACK)(uint16_t sco_inx);

/* MACROs to convert from SCO packet types mask to ESCO and back */
#define BTM_SCO_PKT_TYPE_MASK \
  (HCI_PKT_TYPES_MASK_HV1 | HCI_PKT_TYPES_MASK_HV2 | HCI_PKT_TYPES_MASK_HV3)

/* Mask defining only the SCO types of an esco packet type */
#define BTM_ESCO_PKT_TYPE_MASK \
  (ESCO_PKT_TYPES_MASK_HV1 | ESCO_PKT_TYPES_MASK_HV2 | ESCO_PKT_TYPES_MASK_HV3)

#define BTM_ESCO_2_SCO(escotype) \
  ((uint16_t)(((escotype)&BTM_ESCO_PKT_TYPE_MASK) << 5))

/* Define masks for supported and exception 2.0 SCO packet types
 */
#define BTM_SCO_SUPPORTED_PKTS_MASK                    \
  (ESCO_PKT_TYPES_MASK_HV1 | ESCO_PKT_TYPES_MASK_HV2 | \
   ESCO_PKT_TYPES_MASK_HV3 | ESCO_PKT_TYPES_MASK_EV3 | \
   ESCO_PKT_TYPES_MASK_EV4 | ESCO_PKT_TYPES_MASK_EV5)

#define BTM_SCO_EXCEPTION_PKTS_MASK                              \
  (ESCO_PKT_TYPES_MASK_NO_2_EV3 | ESCO_PKT_TYPES_MASK_NO_3_EV3 | \
   ESCO_PKT_TYPES_MASK_NO_2_EV5 | ESCO_PKT_TYPES_MASK_NO_3_EV5)

/* Define the structure that contains (e)SCO data */
typedef struct {
  tBTM_ESCO_CBACK* p_esco_cback; /* Callback for eSCO events     */
  enh_esco_params_t setup;
  tBTM_ESCO_DATA data; /* Connection complete information */
  uint8_t hci_status;
} tBTM_ESCO_INFO;

/* Define the structure used for SCO Management
 */
typedef struct {
  tBTM_ESCO_INFO esco;    /* Current settings             */
  tBTM_SCO_CB* p_conn_cb; /* Callback for when connected  */
  tBTM_SCO_CB* p_disc_cb; /* Callback for when disconnect */
  uint16_t state;         /* The state of the SCO link    */
  uint16_t hci_handle;    /* HCI Handle                   */
  bool is_orig;           /* true if the originator       */
  bool rem_bd_known;      /* true if remote BD addr known */

} tSCO_CONN;

/* SCO Management control block */
typedef struct {
  tBTM_SCO_IND_CBACK* app_sco_ind_cb;
  tSCO_CONN sco_db[BTM_MAX_SCO_LINKS];
  enh_esco_params_t def_esco_parms;
  uint16_t sco_disc_reason;
  bool esco_supported;        /* true if 1.2 cntlr AND supports eSCO links */
  esco_data_path_t sco_route; /* HCI, PCM, or TEST */
} tSCO_CB;

extern void btm_set_sco_ind_cback(tBTM_SCO_IND_CBACK* sco_ind_cb);
extern void btm_accept_sco_link(uint16_t sco_inx, enh_esco_params_t* p_setup,
                                tBTM_SCO_CB* p_conn_cb, tBTM_SCO_CB* p_disc_cb);
extern void btm_reject_sco_link(uint16_t sco_inx);
extern void btm_sco_chk_pend_rolechange(uint16_t hci_handle);
extern void btm_sco_disc_chk_pend_for_modechange(uint16_t hci_handle);

/*
 * Define structure for Security Service Record.
 * A record exists for each service registered with the Security Manager
 */
#define BTM_SEC_OUT_FLAGS \
  (BTM_SEC_OUT_AUTHENTICATE | BTM_SEC_OUT_ENCRYPT | BTM_SEC_OUT_AUTHORIZE)
#define BTM_SEC_IN_FLAGS \
  (BTM_SEC_IN_AUTHENTICATE | BTM_SEC_IN_ENCRYPT | BTM_SEC_IN_AUTHORIZE)

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
  tBLE_ADDR_TYPE identity_addr_type; /* identity address type */
  RawAddress identity_addr;          /* identity address */

#define BTM_WHITE_LIST_BIT 0x01
#define BTM_RESOLVING_LIST_BIT 0x02
  uint8_t in_controller_list; /* in controller resolving list or not */
  uint8_t resolving_list_index;
#if (BLE_PRIVACY_SPT == TRUE)
  RawAddress cur_rand_addr; /* current random address */
  uint8_t active_addr_type;
#endif
#define BTM_BLE_ADDR_PSEUDO 0 /* address index device record */
#define BTM_BLE_ADDR_RRA 1    /* cur_rand_addr */
#define BTM_BLE_ADDR_STATIC 2 /* static_addr  */

  tBTM_LE_KEY_TYPE key_type; /* bit mask of valid key types in record */
  tBTM_SEC_BLE_KEYS keys;    /* LE device security info in slave rode */
} tBTM_SEC_BLE;

/* Peering bond type */
enum { BOND_TYPE_UNKNOWN, BOND_TYPE_PERSISTENT, BOND_TYPE_TEMPORARY };
typedef uint8_t tBTM_BOND_TYPE;

/*
 * Define structure for Security Device Record.
 * A record exists for each device authenticated with this device
 */
typedef struct {
  tBTM_SEC_SERV_REC* p_cur_service;
  tBTM_SEC_CALLBACK* p_callback;
  void* p_ref_data;
  uint32_t timestamp; /* Timestamp of the last connection   */
  uint32_t trusted_mask[BTM_SEC_SERVICE_ARRAY_SIZE]; /* Bitwise OR of trusted
                                                        services     */
  uint16_t hci_handle;     /* Handle to connection when exists   */
  uint16_t clock_offset;   /* Latest known clock offset          */
  RawAddress bd_addr;      /* BD_ADDR of the device              */
  DEV_CLASS dev_class;     /* DEV_CLASS of the device            */
  LinkKey link_key;        /* Device link key                    */
  uint8_t pin_code_length; /* Length of the pin_code used for paring */

#define BTM_SEC_AUTHORIZED BTM_SEC_FLAG_AUTHORIZED       /* 0x01 */
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
  bool no_smp_on_br;        /* if set to true then SMP on BR/EDR doesn't */
                            /* work, i.e. link keys crosspairing */
                            /* SC BR/EDR->SC LE doesn't happen */
  tBTM_BOND_TYPE bond_type; /* peering bond type */

  tBTM_SEC_BLE ble;
  tBTM_LE_CONN_PRAMS conn_params;

#if (BTM_DISC_DURING_RS == TRUE)
#define BTM_SEC_RS_NOT_PENDING 0 /* Role Switch not in progress */
#define BTM_SEC_RS_PENDING 1     /* Role Switch in progress */
#define BTM_SEC_DISC_PENDING 2   /* Disconnect is pending */
  uint8_t rs_disc_pending;
#endif
#define BTM_SEC_NO_LAST_SERVICE_ID 0
  uint8_t last_author_service_id; /* ID of last serviced authorized: Reset after
                                     each l2cap connection */

} tBTM_SEC_DEV_REC;
