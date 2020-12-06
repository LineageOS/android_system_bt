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
 *  This is the public interface file for the BTA system manager.
 *
 ******************************************************************************/
#ifndef BTA_SYS_H
#define BTA_SYS_H

#include "bt_common.h"
#include "bt_target.h"
#include "osi/include/alarm.h"

#include <base/logging.h>
#include <base/threading/thread.h>

/*****************************************************************************
 *  Constants and data types
 ****************************************************************************/

/* vendor specific event handler function type */
typedef bool(tBTA_SYS_VS_EVT_HDLR)(uint16_t evt, void* p);

/* event handler function type */
typedef bool(tBTA_SYS_EVT_HDLR)(BT_HDR* p_msg);

/* disable function type */
typedef void(tBTA_SYS_DISABLE)(void);

#ifndef BTA_DM_NUM_JV_ID
#define BTA_DM_NUM_JV_ID 2
#endif

/* SW sub-systems */
#define BTA_ID_SYS 0 /* system manager */
/* BLUETOOTH PART - from 0 to BTA_ID_BLUETOOTH_MAX */
#define BTA_ID_DM_SEARCH 2      /* device manager search */
#define BTA_ID_DM_SEC 3         /* device manager security */
#define BTA_ID_DG 4             /* data gateway */
#define BTA_ID_AG 5             /* audio gateway */
#define BTA_ID_OPC 6            /* object push client */
#define BTA_ID_OPS 7            /* object push server */
#define BTA_ID_FTS 8            /* file transfer server */
#define BTA_ID_CT 9             /* cordless telephony terminal */
#define BTA_ID_FTC 10           /* file transfer client */
#define BTA_ID_SS 11            /* synchronization server */
#define BTA_ID_PR 12            /* Printer client */
#define BTA_ID_BIC 13           /* Basic Imaging Client */
#define BTA_ID_PAN 14           /* Personal Area Networking */
#define BTA_ID_BIS 15           /* Basic Imaging Server */
#define BTA_ID_ACC 16           /* Advanced Camera Client */
#define BTA_ID_SC 17            /* SIM Card Access server */
#define BTA_ID_AV 18            /* Advanced audio/video */
#define BTA_ID_HD 20            /* HID Device */
#define BTA_ID_CG 21            /* Cordless Gateway */
#define BTA_ID_BP 22            /* Basic Printing Client */
#define BTA_ID_HH 23            /* Human Interface Device Host */
#define BTA_ID_PBS 24           /* Phone Book Access Server */
#define BTA_ID_PBC 25           /* Phone Book Access Client */
#define BTA_ID_JV 26            /* Java */
#define BTA_ID_HS 27            /* Headset */
#define BTA_ID_MSE 28           /* Message Server Equipment */
#define BTA_ID_MCE 29           /* Message Client Equipment */
#define BTA_ID_HL 30            /* Health Device Profile*/
#define BTA_ID_GATTC 31         /* GATT Client */
#define BTA_ID_GATTS 32         /* GATT Client */
#define BTA_ID_SDP 33           /* SDP Client */
#define BTA_ID_BLUETOOTH_MAX 34 /* last BT profile */

#define BTA_ID_MAX (44 + BTA_DM_NUM_JV_ID)

typedef uint8_t tBTA_SYS_ID;

inline std::string BtaIdSysText(tBTA_SYS_ID sys_id) {
  switch (sys_id) {
    case BTA_ID_DM_SEARCH:
      return std::string("Scanner");
    case BTA_ID_PAN:
      return std::string("PAN Personal area network");
    case BTA_ID_AV:
      return std::string("Advanced audio/video");
    case BTA_ID_HD:
      return std::string("HID Human interface device");
    case BTA_ID_GATTC:
      return std::string("GATT client");
    case BTA_ID_GATTS:
      return std::string("GATT server");
    default:
      return std::string("Unknown");
  }
}

typedef enum : uint8_t {
  BTA_SYS_CONN_OPEN = 0x00,
  BTA_SYS_CONN_CLOSE = 0x01,
  BTA_SYS_APP_OPEN = 0x02,
  BTA_SYS_APP_CLOSE = 0x03,
  BTA_SYS_SCO_OPEN = 0x04,
  BTA_SYS_SCO_CLOSE = 0x05,
  BTA_SYS_CONN_IDLE = 0x06,
  BTA_SYS_CONN_BUSY = 0x07,
  BTA_SYS_ROLE_CHANGE = 0x14, /* role change */
} tBTA_SYS_CONN_STATUS;

inline std::string bta_sys_conn_status_text(tBTA_SYS_CONN_STATUS status) {
  switch (status) {
    case BTA_SYS_CONN_OPEN:
      return std::string("BTA_SYS_CONN_OPEN");
    case BTA_SYS_CONN_CLOSE:
      return std::string("BTA_SYS_CONN_CLOSE");
    case BTA_SYS_APP_OPEN:
      return std::string("BTA_SYS_APP_OPEN");
    case BTA_SYS_APP_CLOSE:
      return std::string("BTA_SYS_APP_CLOSE");
    case BTA_SYS_SCO_OPEN:
      return std::string("BTA_SYS_SCO_OPEN");
    case BTA_SYS_SCO_CLOSE:
      return std::string("BTA_SYS_SCO_CLOSE");
    case BTA_SYS_CONN_IDLE:
      return std::string("BTA_SYS_CONN_IDLE");
    case BTA_SYS_CONN_BUSY:
      return std::string("BTA_SYS_CONN_BUSY");
    case BTA_SYS_ROLE_CHANGE:
      return std::string("BTA_SYS_ROLE_CHANGE");
    default:
      return std::string("UNKNOWN");
  }
}

/* conn callback for role / low power manager*/
typedef void(tBTA_SYS_CONN_CBACK)(tBTA_SYS_CONN_STATUS status, uint8_t id,
                                  uint8_t app_id, const RawAddress& peer_addr);

/* conn callback for role / low power manager*/
typedef void(tBTA_SYS_SSR_CFG_CBACK)(uint8_t id, uint8_t app_id,
                                     uint16_t latency, uint16_t tout);

typedef struct {
  bluetooth::Uuid custom_uuid;
  uint32_t handle;
} tBTA_CUSTOM_UUID;

#if (BTA_EIR_CANNED_UUID_LIST != TRUE)
/* eir callback for adding/removeing UUID */
typedef void(tBTA_SYS_EIR_CBACK)(uint16_t uuid16, bool adding);
typedef void(tBTA_SYS_CUST_EIR_CBACK)(const tBTA_CUSTOM_UUID &curr, bool adding);
#endif

/* registration structure */
typedef struct {
  tBTA_SYS_EVT_HDLR* evt_hdlr;
  tBTA_SYS_DISABLE* disable;
} tBTA_SYS_REG;

/*****************************************************************************
 *  Global data
 ****************************************************************************/

/* trace level */
extern uint8_t appl_trace_level;

/*****************************************************************************
 *  Macros
 ****************************************************************************/
/* Calculate start of event enumeration; id is top 8 bits of event */
#define BTA_SYS_EVT_START(id) ((id) << 8)

/*****************************************************************************
 *  Function declarations
 ****************************************************************************/
void bta_set_forward_hw_failures(bool value);
void BTA_sys_signal_hw_error();

extern void bta_sys_init(void);
extern void bta_sys_register(uint8_t id, const tBTA_SYS_REG* p_reg);
extern void bta_sys_deregister(uint8_t id);
extern bool bta_sys_is_register(uint8_t id);
extern void bta_sys_sendmsg(void* p_msg);
extern void bta_sys_sendmsg_delayed(void* p_msg, const base::TimeDelta& delay);
extern void bta_sys_start_timer(alarm_t* alarm, uint64_t interval_ms,
                                uint16_t event, uint16_t layer_specific);
extern void bta_sys_disable();

extern void bta_sys_rm_register(tBTA_SYS_CONN_CBACK* p_cback);
extern void bta_sys_pm_register(tBTA_SYS_CONN_CBACK* p_cback);

extern void bta_sys_sco_register(tBTA_SYS_CONN_CBACK* p_cback);

extern void bta_sys_conn_open(uint8_t id, uint8_t app_id,
                              const RawAddress& peer_addr);
extern void bta_sys_conn_close(uint8_t id, uint8_t app_id,
                               const RawAddress& peer_addr);
extern void bta_sys_app_open(uint8_t id, uint8_t app_id,
                             const RawAddress& peer_addr);
extern void bta_sys_app_close(uint8_t id, uint8_t app_id,
                              const RawAddress& peer_addr);
extern void bta_sys_sco_open(uint8_t id, uint8_t app_id,
                             const RawAddress& peer_addr);
extern void bta_sys_sco_close(uint8_t id, uint8_t app_id,
                              const RawAddress& peer_addr);
extern void bta_sys_sco_use(uint8_t id, uint8_t app_id,
                            const RawAddress& peer_addr);
extern void bta_sys_sco_unuse(uint8_t id, uint8_t app_id,
                              const RawAddress& peer_addr);
extern void bta_sys_idle(uint8_t id, uint8_t app_id,
                         const RawAddress& peer_addr);
extern void bta_sys_busy(uint8_t id, uint8_t app_id,
                         const RawAddress& peer_addr);

#if (BTM_SSR_INCLUDED == TRUE)
extern void bta_sys_ssr_cfg_register(tBTA_SYS_SSR_CFG_CBACK* p_cback);
extern void bta_sys_chg_ssr_config(uint8_t id, uint8_t app_id,
                                   uint16_t max_latency, uint16_t min_tout);
#endif

extern void bta_sys_role_chg_register(tBTA_SYS_CONN_CBACK* p_cback);
extern void bta_sys_notify_role_chg(const RawAddress& peer_addr,
                                    uint8_t new_role, uint8_t hci_status);
extern void bta_sys_collision_register(uint8_t bta_id,
                                       tBTA_SYS_CONN_CBACK* p_cback);
extern void bta_sys_notify_collision(const RawAddress& peer_addr);

#if (BTA_EIR_CANNED_UUID_LIST != TRUE)
extern void bta_sys_eir_register(tBTA_SYS_EIR_CBACK* p_cback);
extern void bta_sys_add_uuid(uint16_t uuid16);
extern void bta_sys_remove_uuid(uint16_t uuid16);
extern void bta_sys_cust_eir_register(tBTA_SYS_CUST_EIR_CBACK* p_cback);
extern void bta_sys_add_cust_uuid(const tBTA_CUSTOM_UUID& curr);
extern void bta_sys_remove_cust_uuid(const tBTA_CUSTOM_UUID& curr);
#else
#define bta_sys_eir_register(ut)
#define bta_sys_add_uuid(ut)
#define bta_sys_remove_uuid(ut)
#define bta_sys_cust_eir_register(ut)
#define bta_sys_add_cust_uuid(ut)
#define bta_sys_remove_cust_uuid(ut)
#endif

#endif /* BTA_SYS_H */
