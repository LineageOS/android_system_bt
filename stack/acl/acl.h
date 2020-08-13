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

#include <stdint.h>
#include "internal_include/bt_target.h"
#include "stack/include/acl_api_types.h"
#include "stack/include/bt_types.h"
#include "stack/include/hcidefs.h"
#include "types/raw_address.h"

#define BTM_MAX_SCN_ 31  // PORT_MAX_RFC_PORTS system/bt/stack/include/rfcdefs.h

/* Define the ACL Management control structure
 */
typedef struct {
  uint16_t hci_handle;
  uint16_t pkt_types_mask;
  uint16_t clock_offset;
  RawAddress remote_addr;
  DEV_CLASS remote_dc;
  BD_NAME remote_name;

  uint16_t manufacturer;
  uint16_t lmp_subversion;
  uint16_t link_super_tout;
  BD_FEATURES
  peer_lmp_feature_pages[HCI_EXT_FEATURES_PAGE_MAX + 1]; /* Peer LMP Extended
                                                            features mask table
                                                            for the device */
  uint8_t num_read_pages;
  uint8_t lmp_version;

  bool in_use;
  uint8_t link_role;
  bool link_up_issued; /* True if busy_level link up has been issued */

#define BTM_ACL_SWKEY_STATE_IDLE 0
#define BTM_ACL_SWKEY_STATE_MODE_CHANGE 1
#define BTM_ACL_SWKEY_STATE_ENCRYPTION_OFF 2
#define BTM_ACL_SWKEY_STATE_SWITCHING 3
#define BTM_ACL_SWKEY_STATE_ENCRYPTION_ON 4
#define BTM_ACL_SWKEY_STATE_IN_PROGRESS 5
  uint8_t switch_role_state;

#define BTM_MAX_SW_ROLE_FAILED_ATTEMPTS 3
  uint8_t switch_role_failed_attempts;

#define BTM_ACL_ENCRYPT_STATE_IDLE 0
#define BTM_ACL_ENCRYPT_STATE_ENCRYPT_OFF 1 /* encryption turning off */
#define BTM_ACL_ENCRYPT_STATE_TEMP_FUNC \
  2 /* temporarily off for change link key or role switch */
#define BTM_ACL_ENCRYPT_STATE_ENCRYPT_ON 3 /* encryption turning on */
  uint8_t encrypt_state;                   /* overall BTM encryption state */

  tBT_TRANSPORT transport;
  RawAddress conn_addr;   /* local device address used for this connection */
  uint8_t conn_addr_type; /* local device address type for this connection */
  RawAddress active_remote_addr;   /* remote address used on this connection */
  uint8_t active_remote_addr_type; /* local device address type for this
                                      connection */
  BD_FEATURES peer_le_features; /* Peer LE Used features mask for the device */

  uint16_t link_policy;

} tACL_CONN;

typedef uint8_t tBTM_PM_STATE;
typedef struct {
  tBTM_PM_PWR_MD req_mode[BTM_MAX_PM_RECORDS + 1]; /* the desired mode and
                                                      parameters of the
                                                      connection*/
  tBTM_PM_PWR_MD
      set_mode; /* the mode and parameters sent down to the host controller. */
  uint16_t interval; /* the interval from last mode change event. */
#if (BTM_SSR_INCLUDED == TRUE)
  uint16_t max_lat;    /* stored SSR maximum latency */
  uint16_t min_rmt_to; /* stored SSR minimum remote timeout */
  uint16_t min_loc_to; /* stored SSR minimum local timeout */
#endif
  tBTM_PM_STATE state; /* contains the current mode of the connection */
  bool chg_ind;        /* a request change indication */
} tBTM_PM_MCB;

typedef struct {
  /****************************************************
   **      ACL Management
   ****************************************************/
 private:
  friend bool BTM_IsBleConnection(uint16_t hci_handle);
  friend bool BTM_IsBleConnection(uint16_t hci_handle);
  friend const RawAddress acl_address_from_handle(uint16_t hci_handle);
  friend int btm_pm_find_acl_ind(const RawAddress& remote_bda);
  friend tACL_CONN* btm_bda_to_acl(const RawAddress& bda,
                                   tBT_TRANSPORT transport);
  friend tBTM_STATUS BTM_SetSsrParams(const RawAddress& remote_bda,
                                      uint16_t max_lat, uint16_t min_rmt_to,
                                      uint16_t min_loc_to);
  friend uint16_t BTM_GetNumAclLinks(void);
  friend uint8_t btm_handle_to_acl_index(uint16_t hci_handle);
  friend void btm_acl_created(const RawAddress& bda, DEV_CLASS dc, BD_NAME bdn,
                              uint16_t hci_handle, uint8_t link_role,
                              tBT_TRANSPORT transport);
  friend void btm_acl_device_down(void);
  friend void btm_acl_encrypt_change(uint16_t handle, uint8_t status,
                                     uint8_t encr_enable);
  friend void btm_acl_update_conn_addr(uint16_t conn_handle,
                                       const RawAddress& address);
  friend void btm_pm_proc_cmd_status(uint8_t status);
  friend void btm_pm_reset(void);
  friend void btm_process_clk_off_comp_evt(uint16_t hci_handle,
                                           uint16_t clock_offset);
  friend void btm_read_automatic_flush_timeout_complete(uint8_t* p);
  friend void btm_read_failed_contact_counter_complete(uint8_t* p);
  friend void btm_read_link_quality_complete(uint8_t* p);
  friend void btm_read_remote_ext_features_complete(uint8_t* p,
                                                    uint8_t evt_len);
  friend void btm_read_remote_ext_features_failed(uint8_t status,
                                                  uint16_t handle);
  friend void btm_read_remote_features_complete(uint8_t* p);
  friend void btm_read_remote_version_complete(uint8_t* p);
  friend void btm_read_rssi_complete(uint8_t* p);
  friend void btm_read_tx_power_complete(uint8_t* p, bool is_ble);

  friend struct StackAclBtmPm;
  friend struct StackAclBtmAcl;

  tACL_CONN acl_db[MAX_L2CAP_LINKS];

 public:
  uint8_t btm_scn[BTM_MAX_SCN_]; /* current SCNs: true if SCN is in use */
  uint16_t btm_def_link_policy;

 private:
  friend void btm_acl_init(void);
  friend void BTM_SetDefaultLinkSuperTout(uint16_t timeout);
  friend uint16_t acl_get_link_supervision_timeout();

  uint16_t btm_def_link_super_tout;

 public:
  uint8_t pm_pend_link; /* the index of acl_db, which has a pending PM cmd */

  /* Packet types supported by the local device */
  uint16_t btm_acl_pkt_types_supported;

 private:
  friend tBTM_PM_MCB* acl_power_mode_from_handle(uint16_t hci_handle);
  friend uint16_t btm_get_acl_disc_reason_code(void);
  friend uint8_t acl_get_disconnect_reason();
  friend void acl_set_disconnect_reason(uint8_t acl_disc_reason);
  friend void btm_pm_proc_mode_change(uint8_t hci_status, uint16_t hci_handle,
                                      uint8_t mode, uint16_t interval);
  friend void btm_pm_proc_ssr_evt(uint8_t* p, uint16_t evt_len);
  friend void btm_pm_sm_alloc(uint8_t ind);

  uint8_t acl_disc_reason;

 private:
  friend tBTM_PM_MCB* acl_power_mode_from_handle(uint16_t hci_handle);
  friend tBTM_STATUS BTM_ReadPowerMode(const RawAddress& remote_bda,
                                       tBTM_PM_MODE* p_mode);
  friend tBTM_STATUS BTM_SetPowerMode(uint8_t pm_id,
                                      const RawAddress& remote_bda,
                                      const tBTM_PM_PWR_MD* p_mode);
  friend tBTM_STATUS btm_read_power_mode_state(const RawAddress& remote_bda,
                                               tBTM_PM_STATE* pmState);
  friend void btm_pm_proc_mode_change(uint8_t hci_status, uint16_t hci_handle,
                                      uint8_t mode, uint16_t interval);
  friend void btm_pm_proc_ssr_evt(uint8_t* p, UNUSED_ATTR uint16_t evt_len);

  tBTM_PM_MCB pm_mode_db[MAX_L2CAP_LINKS]; /* per ACL link */
} tACL_CB;  // NEW
