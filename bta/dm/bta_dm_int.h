/******************************************************************************
 *
 *  Copyright 2003-2012 Broadcom Corporation
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
 *  This is the private interface file for the BTA device manager.
 *
 ******************************************************************************/
#ifndef BTA_DM_INT_H
#define BTA_DM_INT_H

#include <base/strings/stringprintf.h>
#include <memory>
#include <string>
#include "bt_target.h"
#include "bta/include/bta_gatt_api.h"
#include "bta/sys/bta_sys.h"
#include "main/shim/dumpsys.h"

#ifndef CASE_RETURN_TEXT
#define CASE_RETURN_TEXT(code) \
  case code:                   \
    return #code
#endif

/*****************************************************************************
 *  Constants and data types
 ****************************************************************************/

#define BTA_COPY_DEVICE_CLASS(coddst, codsrc)          \
  {                                                    \
    ((uint8_t*)(coddst))[0] = ((uint8_t*)(codsrc))[0]; \
    ((uint8_t*)(coddst))[1] = ((uint8_t*)(codsrc))[1]; \
    ((uint8_t*)(coddst))[2] = ((uint8_t*)(codsrc))[2]; \
  }

#define BTA_DM_MSG_LEN 50

#define BTA_SERVICE_ID_TO_SERVICE_MASK(id) (1 << (id))

/* DM search events */
enum {
  /* DM search API events */
  BTA_DM_API_SEARCH_EVT = BTA_SYS_EVT_START(BTA_ID_DM_SEARCH),
  BTA_DM_API_DISCOVER_EVT,
  BTA_DM_INQUIRY_CMPL_EVT,
  BTA_DM_REMT_NAME_EVT,
  BTA_DM_SDP_RESULT_EVT,
  BTA_DM_SEARCH_CMPL_EVT,
  BTA_DM_DISCOVERY_RESULT_EVT,
  BTA_DM_DISC_CLOSE_TOUT_EVT
};

/* data type for BTA_DM_API_SEARCH_EVT */
typedef struct {
  BT_HDR hdr;
  tBTA_SERVICE_MASK services;
  tBTA_DM_SEARCH_CBACK* p_cback;
} tBTA_DM_API_SEARCH;

/* data type for BTA_DM_API_DISCOVER_EVT */
typedef struct {
  BT_HDR hdr;
  RawAddress bd_addr;
  tBTA_DM_SEARCH_CBACK* p_cback;
  tBT_TRANSPORT transport;
} tBTA_DM_API_DISCOVER;

typedef struct {
  RawAddress bd_addr;
  bool accept;
  uint8_t pin_len;
  uint8_t p_pin[PIN_CODE_LEN];
} tBTA_DM_API_PIN_REPLY;

typedef struct {
  BT_HDR hdr;
  RawAddress bd_addr;
  tBTM_IO_CAP io_cap;
  tBTM_OOB_DATA oob_data;
  tBTM_AUTH_REQ auth_req;
} tBTA_DM_CI_IO_REQ;

typedef struct {
  RawAddress bd_addr;
  Octet16 c;
  Octet16 r;
  bool accept;
} tBTA_DM_CI_RMT_OOB;

/* data type for BTA_DM_REMT_NAME_EVT */
typedef struct {
  BT_HDR hdr;
  tBTA_DM_SEARCH result;
} tBTA_DM_REM_NAME;

/* data type for tBTA_DM_DISC_RESULT */
typedef struct {
  BT_HDR hdr;
  tBTA_DM_SEARCH result;
} tBTA_DM_DISC_RESULT;

/* data type for BTA_DM_INQUIRY_CMPL_EVT */
typedef struct {
  BT_HDR hdr;
  uint8_t num;
} tBTA_DM_INQUIRY_CMPL;

/* data type for BTA_DM_SDP_RESULT_EVT */
typedef struct {
  BT_HDR hdr;
  uint16_t sdp_result;
} tBTA_DM_SDP_RESULT;

typedef struct {
  RawAddress bd_addr;
  DEV_CLASS dc;
  LinkKey link_key;
  uint8_t key_type;
  bool link_key_known;
  bool dc_known;
  BD_NAME bd_name;
  uint8_t pin_length;
} tBTA_DM_API_ADD_DEVICE;

typedef struct {
  BT_HDR hdr;
  bool enable;
} tBTA_DM_API_BLE_FEATURE;

/* union of all data types */
typedef union {
  /* GKI event buffer header */
  BT_HDR hdr;

  tBTA_DM_API_SEARCH search;

  tBTA_DM_API_DISCOVER discover;

  tBTA_DM_REM_NAME rem_name;

  tBTA_DM_DISC_RESULT disc_result;

  tBTA_DM_INQUIRY_CMPL inq_cmpl;

  tBTA_DM_SDP_RESULT sdp_event;

} tBTA_DM_MSG;

#define BTA_DM_NUM_PEER_DEVICE 7

typedef enum : uint8_t {
  BTA_DM_NOT_CONNECTED = 0,
  BTA_DM_CONNECTED = 1,
  BTA_DM_UNPAIRING = 2,
} tBTA_DM_CONN_STATE;

inline std::string bta_conn_state_text(tBTA_DM_CONN_STATE state) {
  switch (state) {
    CASE_RETURN_TEXT(BTA_DM_NOT_CONNECTED);
    CASE_RETURN_TEXT(BTA_DM_CONNECTED);
    CASE_RETURN_TEXT(BTA_DM_UNPAIRING);
    default:
      return std::string("UNKNOWN");
  }
}

typedef enum : uint8_t {
  BTA_DM_DI_NONE = 0x00,      /* nothing special */
  BTA_DM_DI_SET_SNIFF = 0x01, /* set this bit if call BTM_SetPowerMode(sniff) */
  BTA_DM_DI_INT_SNIFF = 0x02, /* set this bit if call BTM_SetPowerMode(sniff) &
                                 enter sniff mode */
  BTA_DM_DI_ACP_SNIFF = 0x04, /* set this bit if peer init sniff */
  BTA_DM_DI_UNUSED = 0x08,
  BTA_DM_DI_USE_SSR = 0x10, /* set this bit if ssr is supported for this link */
  BTA_DM_DI_AV_ACTIVE = 0x20, /* set this bit if AV is active for this link */
} tBTA_DM_DEV_INFO_BITMASK;
typedef uint8_t tBTA_DM_DEV_INFO;

inline std::string device_info_text(tBTA_DM_DEV_INFO info) {
  const char* const device_info_text[] = {
      ":set_sniff", ":int_sniff", ":acp_sniff",
      ":unused",    ":use_ssr",   ":av_active",
  };

  std::string s = base::StringPrintf("0x%02x", info);
  if (info == BTA_DM_DI_NONE) return s + std::string(":none");
  for (size_t i = 0; i < sizeof(device_info_text) / sizeof(device_info_text[0]);
       i++) {
    if (info & (1u << i)) s += std::string(device_info_text[i]);
  }
  return s;
}

/* set power mode request type */
#define BTA_DM_PM_RESTART 1
#define BTA_DM_PM_NEW_REQ 2
#define BTA_DM_PM_EXECUTE 3
typedef uint8_t tBTA_DM_PM_REQ;

struct sBTA_DM_PEER_DEVICE {
  RawAddress peer_bdaddr;
  tBTA_DM_CONN_STATE conn_state;
  tBTA_PREF_ROLES pref_role;
  bool in_use;

 private:
  friend void bta_dm_acl_up(const RawAddress& bd_addr, tBT_TRANSPORT transport);
  friend void bta_dm_pm_btm_status(const RawAddress& bd_addr,
                                   tBTM_PM_STATUS status, uint16_t value,
                                   tHCI_STATUS hci_status);
  friend void bta_dm_pm_sniff(struct sBTA_DM_PEER_DEVICE* p_peer_dev,
                              uint8_t index);
  friend void bta_dm_rm_cback(tBTA_SYS_CONN_STATUS status, uint8_t id,
                              uint8_t app_id, const RawAddress& peer_addr);
  friend void handle_remote_features_complete(const RawAddress& bd_addr);
  tBTA_DM_DEV_INFO info;

 public:
  tBTA_DM_DEV_INFO Info() const { return info; }

  tBTA_DM_ENCRYPT_CBACK* p_encrypt_cback;
  tBTM_PM_STATUS prev_low; /* previous low power mode used */
  tBTA_DM_PM_ACTION pm_mode_attempted;
  tBTA_DM_PM_ACTION pm_mode_failed;
  bool remove_dev_pending;
  tBT_TRANSPORT transport;
};
typedef struct sBTA_DM_PEER_DEVICE tBTA_DM_PEER_DEVICE;

/* structure to store list of
  active connections */
typedef struct {
  tBTA_DM_PEER_DEVICE peer_device[BTA_DM_NUM_PEER_DEVICE];
  uint8_t count;
  uint8_t le_count;
} tBTA_DM_ACTIVE_LINK;

typedef struct {
  RawAddress peer_bdaddr;
  tBTA_SYS_ID id;
  uint8_t app_id;
  tBTA_SYS_CONN_STATUS state;
  bool new_request;

  std::string ToString() const {
    return base::StringPrintf(
        "peer:%s sys_name:%s app_id:%hhu state:%s new:request:%s",
        PRIVATE_ADDRESS(peer_bdaddr), BtaIdSysText(id).c_str(), app_id,
        bta_sys_conn_status_text(state).c_str(), logbool(new_request).c_str());
  }

} tBTA_DM_SRVCS;

#ifndef BTA_DM_NUM_CONN_SRVS
#define BTA_DM_NUM_CONN_SRVS 30
#endif

typedef struct {
  uint8_t count;
  tBTA_DM_SRVCS conn_srvc[BTA_DM_NUM_CONN_SRVS];

} tBTA_DM_CONNECTED_SRVCS;

typedef struct {
#define BTA_DM_PM_SNIFF_TIMER_IDX 0
#define BTA_DM_PM_PARK_TIMER_IDX 1
#define BTA_DM_PM_SUSPEND_TIMER_IDX 2
#define BTA_DM_PM_MODE_TIMER_MAX 3
  /*
   * Keep three different timers for PARK, SNIFF and SUSPEND if TBFC is
   * supported.
   */
  alarm_t* timer[BTA_DM_PM_MODE_TIMER_MAX];

  uint8_t srvc_id[BTA_DM_PM_MODE_TIMER_MAX];
  uint8_t pm_action[BTA_DM_PM_MODE_TIMER_MAX];
  uint8_t active; /* number of active timer */

  RawAddress peer_bdaddr;
  bool in_use;
} tBTA_PM_TIMER;

extern tBTA_DM_CONNECTED_SRVCS bta_dm_conn_srvcs;

#define BTA_DM_NUM_PM_TIMER 7

/* DM control block */
typedef struct {
  bool is_bta_dm_active;
  tBTA_DM_ACTIVE_LINK device_list;
  tBTA_DM_SEC_CBACK* p_sec_cback;
  tBTA_BLE_ENERGY_INFO_CBACK* p_energy_info_cback;
  uint16_t state;
  bool disabling;
  alarm_t* disable_timer;
  uint32_t wbt_sdp_handle; /* WIDCOMM Extensions SDP record handle */
  uint8_t wbt_scn;         /* WIDCOMM Extensions SCN */
  uint8_t num_central_only;
  uint8_t pm_id;
  tBTA_PM_TIMER pm_timer[BTA_DM_NUM_PM_TIMER];
  uint8_t cur_av_count;   /* current AV connecions */
  bool disable_pair_mode; /* disable pair mode or not */
  bool conn_paired_only;  /* allow connectable to paired device only or not */
  tBTA_DM_API_SEARCH search_msg;

  /* Storage for pin code request parameters */
  RawAddress pin_bd_addr;
  DEV_CLASS pin_dev_class;
  tBTA_DM_SEC_EVT pin_evt;
  tBTM_IO_CAP loc_io_caps;    /* IO Capabilities of local device */
  tBTM_IO_CAP rmt_io_caps;    /* IO Capabilities of remote device */
  tBTM_AUTH_REQ loc_auth_req; /* Authentication required for local device */
  tBTM_AUTH_REQ rmt_auth_req;
  uint32_t num_val; /* the numeric value for comparison. If just_works, do not
                       show this number to UI */
  bool just_works;  /* true, if "Just Works" association model */
#if (BTA_EIR_CANNED_UUID_LIST != TRUE)
  /* store UUID list for EIR */
  uint32_t eir_uuid[BTM_EIR_SERVICE_ARRAY_SIZE];
#if (BTA_EIR_SERVER_NUM_CUSTOM_UUID > 0)
  tBTA_CUSTOM_UUID bta_custom_uuid[BTA_EIR_SERVER_NUM_CUSTOM_UUID];
#endif

#endif

  tBTA_DM_ENCRYPT_CBACK* p_encrypt_cback;
  alarm_t* switch_delay_timer;

} tBTA_DM_CB;

/* DM search control block */
typedef struct {
  tBTA_DM_SEARCH_CBACK* p_search_cback;
  tBTM_INQ_INFO* p_btm_inq_info;
  tBTA_SERVICE_MASK services;
  tBTA_SERVICE_MASK services_to_search;
  tBTA_SERVICE_MASK services_found;
  tSDP_DISCOVERY_DB* p_sdp_db;
  uint16_t state;
  RawAddress peer_bdaddr;
  bool name_discover_done;
  BD_NAME peer_name;
  alarm_t* search_timer;
  uint8_t service_index;
  tBTA_DM_MSG* p_pending_search;
  tBTA_DM_MSG* p_pending_discovery;
  bool wait_disc;
  bool sdp_results;
  bluetooth::Uuid uuid;
  uint8_t peer_scn;
  tBT_TRANSPORT transport;
  tBTA_DM_SEARCH_CBACK* p_scan_cback;
  tGATT_IF client_if;
  uint8_t uuid_to_search;
  bool gatt_disc_active;
  uint16_t conn_id;
  alarm_t* gatt_close_timer; /* GATT channel close delay timer */
  RawAddress pending_close_bda; /* pending GATT channel remote device address */

} tBTA_DM_SEARCH_CB;

/* DI control block */
typedef struct {
  uint8_t di_num;                     /* total local DI record number */
  uint32_t di_handle[BTA_DI_NUM_MAX]; /* local DI record handle, the first one
                                         is primary record */
} tBTA_DM_DI_CB;

/* DM search state */
enum {

  BTA_DM_SEARCH_IDLE,
  BTA_DM_SEARCH_ACTIVE,
  BTA_DM_SEARCH_CANCELLING,
  BTA_DM_DISCOVER_ACTIVE

};

typedef struct {
  DEV_CLASS dev_class; /* local device class */
  uint16_t page_timeout; /* timeout for page in slots */
  uint16_t link_timeout; /* link supervision timeout in slots */
  bool avoid_scatter; /* true to avoid scatternet when av is streaming (be the
                         central) */

} tBTA_DM_CFG;

extern const uint32_t bta_service_id_to_btm_srv_id_lkup_tbl[];

typedef struct {
  uint8_t id;
  uint8_t app_id;
  uint8_t cfg;

} tBTA_DM_RM;

extern const tBTA_DM_CFG* p_bta_dm_cfg;
extern const tBTA_DM_RM* p_bta_dm_rm_cfg;

typedef struct {
  uint8_t id;
  uint8_t app_id;
  uint8_t spec_idx; /* index of spec table to use */

} tBTA_DM_PM_CFG;

typedef struct {
  tBTA_DM_PM_ACTION power_mode;
  uint16_t timeout;

} tBTA_DM_PM_ACTN;

typedef struct {
  uint8_t allow_mask; /* mask of sniff/hold/park modes to allow */
  uint8_t ssr; /* set SSR on conn open/unpark */
  tBTA_DM_PM_ACTN actn_tbl[BTA_DM_PM_NUM_EVTS][2];

} tBTA_DM_PM_SPEC;

typedef struct {
  uint16_t max_lat;
  uint16_t min_rmt_to;
  uint16_t min_loc_to;
  const char* name{nullptr};
} tBTA_DM_SSR_SPEC;

typedef struct {
  uint16_t manufacturer;
  uint16_t lmp_sub_version;
  uint8_t lmp_version;
} tBTA_DM_LMP_VER_INFO;

extern const uint16_t bta_service_id_to_uuid_lkup_tbl[];

extern const tBTA_DM_PM_CFG* p_bta_dm_pm_cfg;
extern const tBTA_DM_PM_SPEC* p_bta_dm_pm_spec;
extern const tBTM_PM_PWR_MD* p_bta_dm_pm_md;
extern tBTA_DM_SSR_SPEC* p_bta_dm_ssr_spec;

/* update dynamic BRCM Aware EIR data */
extern const tBTA_DM_EIR_CONF bta_dm_eir_cfg;
extern const tBTA_DM_EIR_CONF* p_bta_dm_eir_cfg;

/* DM control block */
extern tBTA_DM_CB bta_dm_cb;

/* DM search control block */
extern tBTA_DM_SEARCH_CB bta_dm_search_cb;

/* DI control block */
extern tBTA_DM_DI_CB bta_dm_di_cb;

extern bool bta_dm_search_sm_execute(BT_HDR* p_msg);
extern void bta_dm_search_sm_disable(void);

extern void bta_dm_enable(tBTA_DM_SEC_CBACK*);
extern void bta_dm_disable();
extern void bta_dm_init_cb(void);
extern void bta_dm_set_dev_name(const std::vector<uint8_t>&);
extern void bta_dm_set_visibility(tBTA_DM_DISC, tBTA_DM_CONN);
extern void bta_dm_set_scan_config(tBTA_DM_MSG* p_data);
extern void bta_dm_vendor_spec_command(tBTA_DM_MSG* p_data);
extern void bta_dm_bond(const RawAddress&, tBLE_ADDR_TYPE, tBT_TRANSPORT, int);
extern void bta_dm_bond_cancel(const RawAddress&);
extern void bta_dm_pin_reply(std::unique_ptr<tBTA_DM_API_PIN_REPLY> msg);
extern void bta_dm_add_device(std::unique_ptr<tBTA_DM_API_ADD_DEVICE> msg);
extern void bta_dm_remove_device(const RawAddress& bd_addr);
extern void bta_dm_close_acl(const RawAddress&, bool, tBT_TRANSPORT);

extern void bta_dm_pm_btm_status(const RawAddress&, tBTM_PM_STATUS, uint16_t,
                                 tHCI_STATUS);
extern void bta_dm_pm_timer(const RawAddress&, tBTA_DM_PM_ACTION);
extern void bta_dm_add_ampkey(tBTA_DM_MSG* p_data);

extern void bta_dm_add_blekey(const RawAddress& bd_addr,
                              tBTA_LE_KEY_VALUE blekey,
                              tBTM_LE_KEY_TYPE key_type);
extern void bta_dm_add_ble_device(const RawAddress& bd_addr,
                                  tBLE_ADDR_TYPE addr_type,
                                  tBT_DEVICE_TYPE dev_type);
extern void bta_dm_ble_passkey_reply(const RawAddress& bd_addr, bool accept,
                                     uint32_t passkey);
extern void bta_dm_ble_confirm_reply(const RawAddress&, bool);
extern void bta_dm_ble_set_conn_params(const RawAddress&, uint16_t, uint16_t,
                                       uint16_t, uint16_t);
extern void bta_dm_close_gatt_conn(tBTA_DM_MSG* p_data);
extern void bta_dm_ble_observe(bool, uint8_t, tBTA_DM_SEARCH_CBACK*);
extern void bta_dm_ble_update_conn_params(const RawAddress&, uint16_t, uint16_t,
                                          uint16_t, uint16_t, uint16_t,
                                          uint16_t);
extern void bta_dm_ble_config_local_privacy(bool);

extern void bta_dm_ble_set_data_length(const RawAddress&, uint16_t);

extern void bta_dm_ble_get_energy_info(tBTA_BLE_ENERGY_INFO_CBACK*);

extern void bta_dm_set_encryption(const RawAddress&, tBT_TRANSPORT,
                                  tBTA_DM_ENCRYPT_CBACK*, tBTM_BLE_SEC_ACT);
extern void bta_dm_confirm(const RawAddress&, bool);

extern void bta_dm_ci_rmt_oob_act(std::unique_ptr<tBTA_DM_CI_RMT_OOB> msg);

extern void bta_dm_init_pm(void);
extern void bta_dm_disable_pm(void);

extern uint8_t bta_dm_get_av_count(void);
extern void bta_dm_search_start(tBTA_DM_MSG* p_data);
extern void bta_dm_search_cancel();
extern void bta_dm_discover(tBTA_DM_MSG* p_data);
extern void bta_dm_inq_cmpl(uint8_t num);
extern void bta_dm_rmt_name(tBTA_DM_MSG* p_data);
extern void bta_dm_sdp_result(tBTA_DM_MSG* p_data);
extern void bta_dm_search_cmpl();
extern void bta_dm_free_sdp_db();
extern void bta_dm_disc_result(tBTA_DM_MSG* p_data);
extern void bta_dm_search_result(tBTA_DM_MSG* p_data);
extern void bta_dm_discovery_cmpl(tBTA_DM_MSG* p_data);
extern void bta_dm_queue_search(tBTA_DM_MSG* p_data);
extern void bta_dm_queue_disc(tBTA_DM_MSG* p_data);
extern void bta_dm_search_clear_queue();
extern void bta_dm_search_cancel_cmpl();
extern void bta_dm_search_cancel_notify();
extern void bta_dm_disc_rmt_name(tBTA_DM_MSG* p_data);
extern tBTA_DM_PEER_DEVICE* bta_dm_find_peer_device(
    const RawAddress& peer_addr);

uint8_t bta_dm_search_get_state();
void bta_dm_search_set_state(uint8_t state);

void bta_dm_eir_update_uuid(uint16_t uuid16, bool adding);
void bta_dm_eir_update_cust_uuid(const tBTA_CUSTOM_UUID &curr, bool adding);

#undef CASE_RETURN_TEXT
#endif /* BTA_DM_INT_H */
