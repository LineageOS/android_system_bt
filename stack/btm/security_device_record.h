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

#include <base/strings/stringprintf.h>
#include <cstdint>
#include <string>

#include "gd/crypto_toolbox/crypto_toolbox.h"
#include "main/shim/dumpsys.h"
#include "osi/include/alarm.h"
#include "stack/include/btm_api_types.h"
#include "types/raw_address.h"

typedef char tBTM_LOC_BD_NAME[BTM_MAX_LOC_BD_NAME_LEN + 1];

typedef struct {
  uint16_t min_conn_int;
  uint16_t max_conn_int;
  uint16_t peripheral_latency;
  uint16_t supervision_tout;

} tBTM_LE_CONN_PRAMS;

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
  uint8_t orig_service_name[BT_MAX_SERVICE_NAME_LEN + 1];
  uint8_t term_service_name[BT_MAX_SERVICE_NAME_LEN + 1];
} tBTM_SEC_SERV_REC;

/* LE Security information of device in Peripheral Role */
typedef struct {
  Octet16 irk;   /* peer diverified identity root */
  Octet16 pltk;  /* peer long term key */
  Octet16 pcsrk; /* peer SRK peer device used to secured sign local data  */

  Octet16 lltk;  /* local long term key */
  Octet16 lcsrk; /* local SRK peer device used to secured sign local data  */

  BT_OCTET8 rand;        /* random vector for LTK generation */
  uint16_t ediv;         /* LTK diversifier of this peripheral device */
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

#define BTM_ACCEPTLIST_BIT 0x01
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
  tBTM_SEC_BLE_KEYS keys;    /* LE device security info in peripheral rode */
} tBTM_SEC_BLE;

enum : uint16_t {
  BTM_SEC_AUTHENTICATED = 0x0002,
  BTM_SEC_ENCRYPTED = 0x0004,
  BTM_SEC_NAME_KNOWN = 0x0008,
  BTM_SEC_LINK_KEY_KNOWN = 0x0010,
  BTM_SEC_LINK_KEY_AUTHED = 0x0020,
  BTM_SEC_ROLE_SWITCHED = 0x0040,  // UNUSED - only cleared
  BTM_SEC_IN_USE = 0x0080,         // UNUSED - only set
  /* LE link security flag */
  /* LE link is encrypted after pairing with MITM */
  BTM_SEC_LE_AUTHENTICATED = 0x0200,
  /* LE link is encrypted */
  BTM_SEC_LE_ENCRYPTED = 0x0400,
  /* not used */
  BTM_SEC_LE_NAME_KNOWN = 0x0800,  // UNUSED
  /* bonded with peer (peer LTK and/or SRK is saved) */
  BTM_SEC_LE_LINK_KEY_KNOWN = 0x1000,
  /* pairing is done with MITM */
  BTM_SEC_LE_LINK_KEY_AUTHED = 0x2000,
  /* pairing is done with 16 digit pin */
  BTM_SEC_16_DIGIT_PIN_AUTHED = 0x4000,
};

typedef enum : uint8_t {
  BTM_SEC_STATE_IDLE = 0,
  BTM_SEC_STATE_AUTHENTICATING = 1,
  BTM_SEC_STATE_ENCRYPTING = 2,
  BTM_SEC_STATE_GETTING_NAME = 3,
  BTM_SEC_STATE_AUTHORIZING = 4,
  BTM_SEC_STATE_SWITCHING_ROLE = 5,
  /* disconnecting BR/EDR */
  BTM_SEC_STATE_DISCONNECTING = 6,
  /* delay to check for encryption to work around */
  /* controller problems */
  BTM_SEC_STATE_DELAY_FOR_ENC = 7,
  BTM_SEC_STATE_DISCONNECTING_BLE = 8,
  BTM_SEC_STATE_DISCONNECTING_BOTH = 9,
} tSECURITY_STATE;

/*
 * Define structure for Security Device Record.
 * A record exists for each device authenticated with this device
 */
typedef struct {
  /* Peering bond type */
  typedef enum : uint8_t {
    BOND_TYPE_UNKNOWN = 0,
    BOND_TYPE_PERSISTENT = 1,
    BOND_TYPE_TEMPORARY = 2
  } tBTM_BOND_TYPE;

  uint32_t required_security_flags_for_pairing;
  tBTM_SEC_CALLBACK* p_callback;
  void* p_ref_data;
  uint32_t timestamp; /* Timestamp of the last connection   */
  uint16_t hci_handle;     /* Handle to connection when exists   */
  uint16_t clock_offset;   /* Latest known clock offset          */
  RawAddress bd_addr;      /* BD_ADDR of the device              */
  DEV_CLASS dev_class;     /* DEV_CLASS of the device            */
  LinkKey link_key;        /* Device link key                    */

 private:
  friend bool BTM_SecAddDevice(const RawAddress& bd_addr, DEV_CLASS dev_class,
                               BD_NAME bd_name, uint8_t* features,
                               LinkKey* p_link_key, uint8_t key_type,
                               uint8_t pin_length);
  friend void BTM_PINCodeReply(const RawAddress& bd_addr, uint8_t res,
                               uint8_t pin_len, uint8_t* p_pin);
  friend void btm_sec_auth_complete(uint16_t handle, tHCI_STATUS status);
  friend void btm_sec_connected(const RawAddress& bda, uint16_t handle,
                                tHCI_STATUS status, uint8_t enc_mode);
  friend void btm_sec_encrypt_change(uint16_t handle, tHCI_STATUS status,
                                     uint8_t encr_enable);
  friend void btm_sec_link_key_notification(const RawAddress& p_bda,
                                            const Octet16& link_key,
                                            uint8_t key_type);
  friend tBTM_STATUS btm_sec_bond_by_transport(const RawAddress& bd_addr,
                                               tBT_TRANSPORT transport,
                                               uint8_t pin_len, uint8_t* p_pin);
  uint8_t pin_code_length; /* Length of the pin_code used for paring */

 public:
  uint16_t sec_flags; /* Current device security state      */
  bool is_device_authenticated() const {
    return sec_flags & BTM_SEC_AUTHENTICATED;
  }
  void set_device_authenticated() { sec_flags |= BTM_SEC_AUTHENTICATED; }
  void reset_device_authenticated() { sec_flags &= ~BTM_SEC_AUTHENTICATED; }

  bool is_device_encrypted() const { return sec_flags & BTM_SEC_ENCRYPTED; }
  void set_device_encrypted() { sec_flags |= BTM_SEC_ENCRYPTED; }
  void reset_device_encrypted() { sec_flags &= ~BTM_SEC_ENCRYPTED; }

  bool is_name_known() const { return sec_flags & BTM_SEC_NAME_KNOWN; }
  void set_device_known() { sec_flags |= BTM_SEC_NAME_KNOWN; }
  void reset_device_known() { sec_flags &= ~BTM_SEC_NAME_KNOWN; }

  bool is_link_key_known() const { return sec_flags & BTM_SEC_LINK_KEY_KNOWN; }
  void set_link_key_known() { sec_flags |= BTM_SEC_LINK_KEY_KNOWN; }
  void reset_link_key_known() { sec_flags &= ~BTM_SEC_LINK_KEY_KNOWN; }

  bool is_link_key_authenticated() const {
    return sec_flags & BTM_SEC_LINK_KEY_AUTHED;
  }
  void set_link_key_authenticated() { sec_flags |= BTM_SEC_LINK_KEY_AUTHED; }
  void reset_link_key_authenticated() { sec_flags &= ~BTM_SEC_LINK_KEY_AUTHED; }

  bool is_le_device_authenticated() const {
    return sec_flags & BTM_SEC_LE_AUTHENTICATED;
  }
  void set_le_device_authenticated() { sec_flags |= BTM_SEC_LE_AUTHENTICATED; }
  void reset_le_device_authenticated() {
    sec_flags &= ~BTM_SEC_LE_AUTHENTICATED;
  }

  bool is_le_device_encrypted() const {
    return sec_flags & BTM_SEC_LE_ENCRYPTED;
  }
  void set_le_device_encrypted() { sec_flags |= BTM_SEC_LE_ENCRYPTED; }
  void reset_le_device_encrypted() { sec_flags &= ~BTM_SEC_LE_ENCRYPTED; }

  bool is_le_link_key_known() const {
    return sec_flags & BTM_SEC_LE_LINK_KEY_KNOWN;
  }
  void set_le_link_key_known() { sec_flags |= BTM_SEC_LE_LINK_KEY_KNOWN; }
  void reset_le_link_key_known() { sec_flags &= ~BTM_SEC_LE_LINK_KEY_KNOWN; }

  bool is_le_link_key_authenticated() const {
    return sec_flags & BTM_SEC_LE_LINK_KEY_AUTHED;
  }
  void set_le_link_key_authenticated() {
    sec_flags |= BTM_SEC_LE_LINK_KEY_AUTHED;
  }
  void reset_le_link_key_authenticated() {
    sec_flags &= ~BTM_SEC_LE_LINK_KEY_AUTHED;
  }

  bool is_le_link_16_digit_key_authenticated() const {
    return sec_flags & BTM_SEC_16_DIGIT_PIN_AUTHED;
  }
  void set_le_link_16_digit_key_authenticated() {
    sec_flags |= BTM_SEC_16_DIGIT_PIN_AUTHED;
  }
  void reset_le_link_16_digit_key_authenticated() {
    sec_flags &= ~BTM_SEC_16_DIGIT_PIN_AUTHED;
  }

  tBTM_BD_NAME sec_bd_name; /* User friendly name of the device. (may be
                               truncated to save space in dev_rec table) */

  uint8_t sec_state;          /* Operating state                    */
  bool is_security_state_idle() const {
    return sec_state == BTM_SEC_STATE_IDLE;
  }
  bool is_security_state_authenticating() const {
    return sec_state == BTM_SEC_STATE_AUTHENTICATING;
  }
  bool is_security_state_encrypting() const {
    return sec_state == BTM_SEC_STATE_ENCRYPTING;
  }
  bool is_security_state_getting_name() const {
    return sec_state == BTM_SEC_STATE_GETTING_NAME;
  }
  bool is_security_state_authorizing() const {
    return sec_state == BTM_SEC_STATE_AUTHORIZING;
  }
  bool is_security_state_switching_role() const {
    return sec_state == BTM_SEC_STATE_SWITCHING_ROLE;
  }
  bool is_security_state_disconnecting() const {
    return sec_state == BTM_SEC_STATE_DISCONNECTING;
  }
  bool is_security_state_wait_for_encryption() const {
    return sec_state == BTM_SEC_STATE_DELAY_FOR_ENC;
  }
  bool is_security_state_ble_disconnecting() const {
    return sec_state == BTM_SEC_STATE_DISCONNECTING_BLE;
  }
  bool is_security_state_br_edr_and_ble() const {
    return sec_state == BTM_SEC_STATE_DISCONNECTING_BOTH;
  }

  bool is_originator;         /* true if device is originating connection */
  bool role_central;          /* true if current mode is central     */
  uint16_t security_required; /* Security required for connection   */
  bool link_key_not_sent; /* link key notification has not been sent waiting for
                             name */
  uint8_t link_key_type;  /* Type of key used in pairing   */

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
  friend void btm_sec_set_peer_sec_caps(uint16_t hci_handle, bool ssp_supported,
                                        bool sc_supported,
                                        bool hci_role_switch_supported);

 public:
  bool SupportsSecureConnections() const {
    return remote_supports_secure_connections;
  }

  bool remote_features_needed; /* set to true if the local device is in */
  /* "Secure Connections Only" mode and it receives */
  /* HCI_IO_CAPABILITY_REQUEST_EVT from the peer before */
  /* it knows peer's support for Secure Connections */
  bool remote_supports_hci_role_switch = false;
  bool remote_feature_received = false;

  uint16_t ble_hci_handle; /* use in DUMO connection */
  uint16_t get_ble_hci_handle() const { return ble_hci_handle; }

  uint8_t enc_key_size;    /* current link encryption key size */
  uint8_t get_encryption_key_size() const { return enc_key_size; }

  tBT_DEVICE_TYPE device_type;
  bool is_device_type_br_edr() const {
    return device_type == BT_DEVICE_TYPE_BREDR;
  }
  bool is_device_type_ble() const { return device_type == BT_DEVICE_TYPE_BLE; }
  bool is_device_type_dual_mode() const {
    return device_type == BT_DEVICE_TYPE_DUMO;
  }

  bool new_encryption_key_is_p256; /* Set to true when the newly generated LK
                                   ** is generated from P-256.
                                   ** Link encrypted with such LK can be used
                                   ** for SM over BR/EDR.
                                   */
  tBTM_BOND_TYPE bond_type; /* peering bond type */
  bool is_bond_type_unknown() const { return bond_type == BOND_TYPE_UNKNOWN; }
  bool is_bond_type_persistent() const {
    return bond_type == BOND_TYPE_PERSISTENT;
  }
  bool is_bond_type_temporary() const {
    return bond_type == BOND_TYPE_TEMPORARY;
  }

  tBTM_SEC_BLE ble;
  tBTM_LE_CONN_PRAMS conn_params;

  std::string ToString() const {
    return base::StringPrintf(
        "%s %6s name:\"%s\" supports_SC:%s", PRIVATE_ADDRESS(bd_addr),
        DeviceTypeText(device_type).c_str(), sec_bd_name,
        logbool(remote_supports_secure_connections).c_str());
  }

} tBTM_SEC_DEV_REC;
