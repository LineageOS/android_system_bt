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
#include <string>

#include "stack/include/acl_api_types.h"
#include "stack/include/bt_types.h"
#include "stack/include/btm_api_types.h"
#include "stack/include/hcidefs.h"
#include "stack/include/hcimsgs.h"
#include "types/bt_transport.h"
#include "types/raw_address.h"

enum btm_acl_encrypt_state_t {
  BTM_ACL_ENCRYPT_STATE_IDLE = 0,
  BTM_ACL_ENCRYPT_STATE_ENCRYPT_OFF = 1,
  BTM_ACL_ENCRYPT_STATE_TEMP_FUNC = 2,
  BTM_ACL_ENCRYPT_STATE_ENCRYPT_ON = 3,
};

enum btm_acl_swkey_state_t {
  BTM_ACL_SWKEY_STATE_IDLE = 0,
  BTM_ACL_SWKEY_STATE_MODE_CHANGE = 1,
  BTM_ACL_SWKEY_STATE_ENCRYPTION_OFF = 2,
  BTM_ACL_SWKEY_STATE_SWITCHING = 3,
  BTM_ACL_SWKEY_STATE_ENCRYPTION_ON = 4,
  BTM_ACL_SWKEY_STATE_IN_PROGRESS = 5,
};

/* Policy settings status */
typedef enum : uint16_t {
  HCI_DISABLE_ALL_LM_MODES = 0,
  HCI_ENABLE_CENTRAL_PERIPHERAL_SWITCH = (1u << 0),
  HCI_ENABLE_HOLD_MODE = (1u << 1),
  HCI_ENABLE_SNIFF_MODE = (1u << 2),
  HCI_ENABLE_PARK_MODE = (1u << 3),
} tLINK_POLICY;

static const char* link_policy_string[] = {
    " role_switch ",
    " hold_mode ",
    " sniff_mode ",
    " park_mode ",
};

inline std::string link_policy_text(tLINK_POLICY policy) {
  std::ostringstream os;
  os << "0x" << loghex(static_cast<uint16_t>(policy)) << " :";
  std::string s = os.str();
  for (uint16_t i = 0; i < 4; i++) {
    if (policy & (0x1 << i)) s += link_policy_string[i];
  }
  return s;
}

/* Structure returned with Role Switch information (in tBTM_CMPL_CB callback
 * function) in response to BTM_SwitchRoleToCentral call.
 */
typedef struct {
  RawAddress remote_bd_addr; /* Remote BD addr involved with the switch */
  uint8_t hci_status;        /* HCI status returned with the event */
  uint8_t role;              /* HCI_ROLE_CENTRAL or HCI_ROLE_PERIPHERAL */
} tBTM_ROLE_SWITCH_CMPL;

typedef struct {
  BD_FEATURES peer_le_features;
  bool peer_le_features_valid;
  BD_FEATURES peer_lmp_feature_pages[HCI_EXT_FEATURES_PAGE_MAX + 1];
  bool peer_lmp_feature_valid[HCI_EXT_FEATURES_PAGE_MAX + 1];

  RawAddress active_remote_addr;
  RawAddress conn_addr;
  RawAddress remote_addr;
  bool in_use;
  bool link_up_issued;
  tBT_TRANSPORT transport;
  bool is_transport_br_edr() const { return transport == BT_TRANSPORT_BR_EDR; }
  bool is_transport_ble() const { return transport == BT_TRANSPORT_LE; }
  bool is_transport_valid() const {
    return is_transport_ble() || is_transport_br_edr();
  }

  uint16_t flush_timeout_in_ticks;
  uint16_t hci_handle;
  uint16_t link_policy;
  uint16_t link_super_tout;
  uint16_t pkt_types_mask;
  tBLE_ADDR_TYPE active_remote_addr_type;
  tBLE_ADDR_TYPE conn_addr_type;
  uint8_t disconnect_reason;

 private:
  btm_acl_encrypt_state_t encrypt_state_;

 public:
  void set_encryption_off() {
    if (encrypt_state_ != BTM_ACL_ENCRYPT_STATE_ENCRYPT_OFF) {
      btsnd_hcic_set_conn_encrypt(hci_handle, false);
      encrypt_state_ = BTM_ACL_ENCRYPT_STATE_ENCRYPT_OFF;
    }
  }
  void set_encryption_on() {
    if (encrypt_state_ != BTM_ACL_ENCRYPT_STATE_ENCRYPT_ON) {
      btsnd_hcic_set_conn_encrypt(hci_handle, true);
      encrypt_state_ = BTM_ACL_ENCRYPT_STATE_ENCRYPT_ON;
    }
  }
  void set_encryption_idle() { encrypt_state_ = BTM_ACL_ENCRYPT_STATE_IDLE; }

  void set_encryption_switching() {
    encrypt_state_ = BTM_ACL_ENCRYPT_STATE_TEMP_FUNC;
  }

 public:
  bool is_encrypted = false;
  uint8_t link_role;
  uint8_t switch_role_failed_attempts;

  struct {
    uint8_t lmp_version{0};
    uint16_t lmp_subversion{0};
    uint16_t manufacturer{0};
    bool valid{false};
  } remote_version_info;

#define BTM_SEC_RS_NOT_PENDING 0 /* Role Switch not in progress */
#define BTM_SEC_RS_PENDING 1     /* Role Switch in progress */
#define BTM_SEC_DISC_PENDING 2   /* Disconnect is pending */
  uint8_t rs_disc_pending = BTM_SEC_RS_NOT_PENDING;

 private:
  uint8_t switch_role_state_;

 public:
  void reset_switch_role() { switch_role_state_ = BTM_ACL_SWKEY_STATE_IDLE; }
  void set_switch_role_changing() {
    switch_role_state_ = BTM_ACL_SWKEY_STATE_MODE_CHANGE;
  }
  void set_switch_role_encryption_off() {
    switch_role_state_ = BTM_ACL_SWKEY_STATE_ENCRYPTION_OFF;
  }
  void set_switch_role_encryption_on() {
    switch_role_state_ = BTM_ACL_SWKEY_STATE_ENCRYPTION_ON;
  }
  void set_switch_role_in_progress() {
    switch_role_state_ = BTM_ACL_SWKEY_STATE_IN_PROGRESS;
  }
  void set_switch_role_switching() {
    switch_role_state_ = BTM_ACL_SWKEY_STATE_SWITCHING;
  }

  bool is_switch_role_idle() const {
    return switch_role_state_ == BTM_ACL_SWKEY_STATE_IDLE;
  }
  bool is_switch_role_encryption_off() const {
    return switch_role_state_ == BTM_ACL_SWKEY_STATE_ENCRYPTION_OFF;
  }
  bool is_switch_role_encryption_on() const {
    return switch_role_state_ == BTM_ACL_SWKEY_STATE_ENCRYPTION_ON;
  }
  bool is_switch_role_switching() const {
    return switch_role_state_ == BTM_ACL_SWKEY_STATE_SWITCHING;
  }
  bool is_switch_role_in_progress() const {
    return switch_role_state_ == BTM_ACL_SWKEY_STATE_IN_PROGRESS;
  }
  bool is_switch_role_mode_change() const {
    return switch_role_state_ == BTM_ACL_SWKEY_STATE_MODE_CHANGE;
  }
  bool is_switch_role_switching_or_in_progress() const {
    return is_switch_role_switching() || is_switch_role_in_progress();
  }

  friend void DumpsysL2cap(int fd);

 public:
  uint8_t sca; /* Sleep clock accuracy */
} tACL_CONN;

typedef uint8_t tBTM_PM_STATE;
typedef struct {
  bool chg_ind;
  tBTM_PM_PWR_MD req_mode[BTM_MAX_PM_RECORDS + 1];
  tBTM_PM_PWR_MD set_mode;
  tBTM_PM_STATE state;
  uint16_t interval;
  uint16_t max_lat;
  uint16_t min_loc_to;
  uint16_t min_rmt_to;
} tBTM_PM_MCB;

/****************************************************
 **      ACL Management API
 ****************************************************/
typedef struct {
 private:
  friend bool BTM_IsBleConnection(uint16_t hci_handle);
  friend bool BTM_ReadPowerMode(const RawAddress& remote_bda,
                                tBTM_PM_MODE* p_mode);
  friend bool acl_is_role_switch_allowed();
  friend bool btm_pm_is_le_link(const RawAddress& remote_bda);
  friend const RawAddress acl_address_from_handle(uint16_t hci_handle);
  friend int btm_pm_find_acl_ind(const RawAddress& remote_bda);
  friend tACL_CONN* btm_bda_to_acl(const RawAddress& bda,
                                   tBT_TRANSPORT transport);
  friend tBTM_PM_MCB* acl_power_mode_from_handle(uint16_t hci_handle);
  friend tBTM_STATUS BTM_SetPowerMode(uint8_t pm_id,
                                      const RawAddress& remote_bda,
                                      const tBTM_PM_PWR_MD* p_mode);
  friend tBTM_STATUS BTM_SetSsrParams(const RawAddress& remote_bda,
                                      uint16_t max_lat, uint16_t min_rmt_to,
                                      uint16_t min_loc_to);
  friend tBTM_STATUS btm_read_power_mode_state(const RawAddress& remote_bda,
                                               tBTM_PM_STATE* pmState);
  friend uint16_t BTM_GetMaxPacketSize(const RawAddress& addr);
  friend uint16_t BTM_GetNumAclLinks(void);
  friend uint16_t acl_get_link_supervision_timeout();
  friend uint16_t acl_get_supported_packet_types();
  friend uint8_t btm_handle_to_acl_index(uint16_t hci_handle);
  friend void BTM_SetDefaultLinkSuperTout(uint16_t timeout);
  friend void BTM_acl_after_controller_started();
  friend void BTM_default_block_role_switch();
  friend void BTM_default_unblock_role_switch();
  friend void acl_initialize_power_mode(const tACL_CONN& p_acl);
  friend void acl_set_disconnect_reason(tHCI_STATUS acl_disc_reason);
  friend void btm_acl_created(const RawAddress& bda, uint16_t hci_handle,
                              uint8_t link_role, tBT_TRANSPORT transport);
  friend void btm_acl_device_down(void);
  friend void btm_acl_encrypt_change(uint16_t handle, uint8_t status,
                                     uint8_t encr_enable);
  friend void btm_acl_init(void);
  friend void btm_acl_process_sca_cmpl_pkt(uint8_t evt_len, uint8_t* p);
  friend void btm_acl_role_changed(tHCI_STATUS hci_status,
                                   const RawAddress& bd_addr, uint8_t new_role);
  friend void btm_pm_proc_cmd_status(uint8_t status);
  friend void btm_pm_proc_mode_change(uint8_t hci_status, uint16_t hci_handle,
                                      tHCI_MODE mode, uint16_t interval);
  friend void btm_pm_proc_ssr_evt(uint8_t* p, uint16_t evt_len);
  friend void btm_pm_reset(void);
  friend void btm_pm_sm_alloc(uint8_t ind);
  friend void btm_process_clk_off_comp_evt(uint16_t hci_handle,
                                           uint16_t clock_offset);
  friend void btm_read_automatic_flush_timeout_complete(uint8_t* p);
  friend void btm_read_failed_contact_counter_complete(uint8_t* p);
  friend void btm_read_link_quality_complete(uint8_t* p);
  friend void btm_read_remote_ext_features_complete(uint16_t handle,
                                                    uint8_t page_num,
                                                    uint8_t max_page,
                                                    uint8_t* features);
  friend void btm_read_remote_ext_features_failed(uint8_t status,
                                                  uint16_t handle);
  friend void btm_read_remote_features_complete(uint16_t handle,
                                                uint8_t* features);
  friend void btm_read_remote_version_complete_raw(uint8_t* p);
  friend void btm_read_rssi_complete(uint8_t* p);
  friend void btm_read_tx_power_complete(uint8_t* p, bool is_ble);
  friend void DumpsysL2cap(int fd);
  friend void DumpsysAcl(int fd);

  friend struct StackAclBtmAcl;
  friend struct StackAclBtmPm;

  tACL_CONN acl_db[MAX_L2CAP_LINKS];
  tBTM_PM_MCB pm_mode_db[MAX_L2CAP_LINKS];
  tBTM_ROLE_SWITCH_CMPL switch_role_ref_data;
  uint16_t btm_acl_pkt_types_supported;
  uint16_t btm_def_link_policy;
  uint16_t btm_def_link_super_tout;
  tHCI_STATUS acl_disc_reason;
  uint8_t pm_pend_link;

 public:
  tHCI_STATUS get_disconnect_reason() const { return acl_disc_reason; }
  void set_disconnect_reason(tHCI_STATUS reason) { acl_disc_reason = reason; }
} tACL_CB;
