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
 *  This file contains the action functions for device manager state
 *  machine.
 *
 ******************************************************************************/

#define LOG_TAG "bt_bta_dm"

#include <base/logging.h>

#include <cstdint>

#include "bta/dm/bta_dm_int.h"
#include "bta/gatt/bta_gattc_int.h"
#include "bta/include/bta_dm_ci.h"
#include "btif/include/btif_config.h"
#include "btif/include/btif_dm.h"
#include "btif/include/btif_storage.h"
#include "btif/include/stack_manager.h"
#include "device/include/controller.h"
#include "device/include/interop.h"
#include "main/shim/acl_api.h"
#include "main/shim/btm_api.h"
#include "main/shim/dumpsys.h"
#include "main/shim/shim.h"
#include "osi/include/fixed_queue.h"
#include "osi/include/log.h"
#include "osi/include/osi.h"
#include "stack/btm/btm_ble_int.h"
#include "stack/btm/btm_sec.h"
#include "stack/btm/neighbor_inquiry.h"
#include "stack/gatt/connection_manager.h"
#include "stack/include/acl_api.h"
#include "stack/include/bt_types.h"
#include "stack/include/btm_client_interface.h"
#include "stack/include/btu.h"  // do_in_main_thread
#include "types/raw_address.h"

#if (GAP_INCLUDED == TRUE)
#include "gap_api.h"
#endif

using bluetooth::Uuid;

void BTIF_dm_disable();
void BTIF_dm_enable();
void btm_ble_adv_init(void);

static void bta_dm_inq_results_cb(tBTM_INQ_RESULTS* p_inq, uint8_t* p_eir,
                                  uint16_t eir_len);
static void bta_dm_inq_cmpl_cb(void* p_result);
static void bta_dm_service_search_remname_cback(const RawAddress& bd_addr,
                                                DEV_CLASS dc, BD_NAME bd_name);
static void bta_dm_remname_cback(void* p);
static void bta_dm_find_services(const RawAddress& bd_addr);
static void bta_dm_discover_next_device(void);
static void bta_dm_sdp_callback(tSDP_STATUS sdp_status);
static uint8_t bta_dm_pin_cback(const RawAddress& bd_addr, DEV_CLASS dev_class,
                                BD_NAME bd_name, bool min_16_digit);
static uint8_t bta_dm_new_link_key_cback(const RawAddress& bd_addr,
                                         DEV_CLASS dev_class, BD_NAME bd_name,
                                         const LinkKey& key, uint8_t key_type);
static void bta_dm_authentication_complete_cback(const RawAddress& bd_addr,
                                                 DEV_CLASS dev_class,
                                                 BD_NAME bd_name,
                                                 tHCI_REASON result);
static void bta_dm_local_name_cback(void* p_name);
static void bta_dm_check_av();

void BTA_dm_update_policy(tBTA_SYS_CONN_STATUS status, uint8_t id,
                          uint8_t app_id, const RawAddress& peer_addr);

/* Extended Inquiry Response */
static tBTM_STATUS bta_dm_sp_cback(tBTM_SP_EVT event, tBTM_SP_EVT_DATA* p_data);

static void bta_dm_set_eir(char* local_name);

static void bta_dm_search_timer_cback(void* data);
static void bta_dm_disable_conn_down_timer_cback(void* data);
void bta_dm_rm_cback(tBTA_SYS_CONN_STATUS status, uint8_t id, uint8_t app_id,
                     const RawAddress& peer_addr);
static void bta_dm_adjust_roles(bool delay_role_switch);
static char* bta_dm_get_remname(void);
static void bta_dm_bond_cancel_complete_cback(tBTM_STATUS result);

static bool bta_dm_read_remote_device_name(const RawAddress& bd_addr,
                                           tBT_TRANSPORT transport);
static void bta_dm_discover_device(const RawAddress& remote_bd_addr);

static void bta_dm_disable_search_and_disc(void);

static uint8_t bta_dm_ble_smp_cback(tBTM_LE_EVT event, const RawAddress& bda,
                                    tBTM_LE_EVT_DATA* p_data);
static void bta_dm_ble_id_key_cback(uint8_t key_type,
                                    tBTM_BLE_LOCAL_KEYS* p_key);
static void bta_dm_gattc_register(void);
static void btm_dm_start_gatt_discovery(const RawAddress& bd_addr);
static void bta_dm_cancel_gatt_discovery(const RawAddress& bd_addr);
static void bta_dm_gattc_callback(tBTA_GATTC_EVT event, tBTA_GATTC* p_data);
extern tBTA_DM_CONTRL_STATE bta_dm_pm_obtain_controller_state(void);
#if (BLE_VND_INCLUDED == TRUE)
static void bta_dm_ctrl_features_rd_cmpl_cback(tHCI_STATUS result);
#endif

#ifndef BTA_DM_BLE_ADV_CHNL_MAP
#define BTA_DM_BLE_ADV_CHNL_MAP \
  (BTM_BLE_ADV_CHNL_37 | BTM_BLE_ADV_CHNL_38 | BTM_BLE_ADV_CHNL_39)
#endif

/* Disable timer interval (in milliseconds) */
#ifndef BTA_DM_DISABLE_TIMER_MS
#define BTA_DM_DISABLE_TIMER_MS (2000)
#endif

/* Disable timer retrial interval (in milliseconds) */
#ifndef BTA_DM_DISABLE_TIMER_RETRIAL_MS
#define BTA_DM_DISABLE_TIMER_RETRIAL_MS 1500
#endif

/* Disable connection down timer (in milliseconds) */
#ifndef BTA_DM_DISABLE_CONN_DOWN_TIMER_MS
#define BTA_DM_DISABLE_CONN_DOWN_TIMER_MS 1000
#endif

/* Switch delay timer (in milliseconds) */
#ifndef BTA_DM_SWITCH_DELAY_TIMER_MS
#define BTA_DM_SWITCH_DELAY_TIMER_MS 500
#endif

namespace {

// Time to wait after receiving shutdown request to delay the actual shutdown
// process. This time may be zero which invokes immediate shutdown.
#ifndef BTA_DISABLE_DELAY
constexpr uint64_t kDisableDelayTimerInMs = 0;
#else
constexpr uint64_t kDisableDelayTimerInMs =
    static_cast<uint64_t>(BTA_DISABLE_DELAY);
#endif

struct WaitForAllAclConnectionsToDrain {
  uint64_t time_to_wait_in_ms;
  unsigned long TimeToWaitInMs() const {
    return static_cast<unsigned long>(time_to_wait_in_ms);
  }
  void* AlarmCallbackData() const {
    return const_cast<void*>(static_cast<const void*>(this));
  }

  static const WaitForAllAclConnectionsToDrain* FromAlarmCallbackData(
      void* data);
  static bool IsFirstPass(const WaitForAllAclConnectionsToDrain*);
} first_pass =
    {
        .time_to_wait_in_ms = static_cast<uint64_t>(BTA_DM_DISABLE_TIMER_MS),
},
  second_pass = {
      .time_to_wait_in_ms =
          static_cast<uint64_t>(BTA_DM_DISABLE_TIMER_RETRIAL_MS),
};

bool WaitForAllAclConnectionsToDrain::IsFirstPass(
    const WaitForAllAclConnectionsToDrain* pass) {
  return pass == &first_pass;
}

const WaitForAllAclConnectionsToDrain*
WaitForAllAclConnectionsToDrain::FromAlarmCallbackData(void* data) {
  return const_cast<const WaitForAllAclConnectionsToDrain*>(
      static_cast<WaitForAllAclConnectionsToDrain*>(data));
}

}  // namespace

static void bta_dm_reset_sec_dev_pending(const RawAddress& remote_bd_addr);
static void bta_dm_remove_sec_dev_entry(const RawAddress& remote_bd_addr);
static void bta_dm_observe_results_cb(tBTM_INQ_RESULTS* p_inq, uint8_t* p_eir,
                                      uint16_t eir_len);
static void bta_dm_observe_cmpl_cb(void* p_result);
static void bta_dm_delay_role_switch_cback(void* data);
static void bta_dm_wait_for_acl_to_drain_cback(void* data);

const uint16_t bta_service_id_to_uuid_lkup_tbl[BTA_MAX_SERVICE_ID] = {
    UUID_SERVCLASS_PNP_INFORMATION,       /* Reserved */
    UUID_SERVCLASS_SERIAL_PORT,           /* BTA_SPP_SERVICE_ID */
    UUID_SERVCLASS_DIALUP_NETWORKING,     /* BTA_DUN_SERVICE_ID */
    UUID_SERVCLASS_AUDIO_SOURCE,          /* BTA_A2DP_SOURCE_SERVICE_ID */
    UUID_SERVCLASS_LAN_ACCESS_USING_PPP,  /* BTA_LAP_SERVICE_ID */
    UUID_SERVCLASS_HEADSET,               /* BTA_HSP_HS_SERVICE_ID */
    UUID_SERVCLASS_HF_HANDSFREE,          /* BTA_HFP_HS_SERVICE_ID */
    UUID_SERVCLASS_OBEX_OBJECT_PUSH,      /* BTA_OPP_SERVICE_ID */
    UUID_SERVCLASS_OBEX_FILE_TRANSFER,    /* BTA_FTP_SERVICE_ID */
    UUID_SERVCLASS_CORDLESS_TELEPHONY,    /* BTA_CTP_SERVICE_ID */
    UUID_SERVCLASS_INTERCOM,              /* BTA_ICP_SERVICE_ID */
    UUID_SERVCLASS_IRMC_SYNC,             /* BTA_SYNC_SERVICE_ID */
    UUID_SERVCLASS_DIRECT_PRINTING,       /* BTA_BPP_SERVICE_ID */
    UUID_SERVCLASS_IMAGING_RESPONDER,     /* BTA_BIP_SERVICE_ID */
    UUID_SERVCLASS_PANU,                  /* BTA_PANU_SERVICE_ID */
    UUID_SERVCLASS_NAP,                   /* BTA_NAP_SERVICE_ID */
    UUID_SERVCLASS_GN,                    /* BTA_GN_SERVICE_ID */
    UUID_SERVCLASS_SAP,                   /* BTA_SAP_SERVICE_ID */
    UUID_SERVCLASS_AUDIO_SINK,            /* BTA_A2DP_SERVICE_ID */
    UUID_SERVCLASS_AV_REMOTE_CONTROL,     /* BTA_AVRCP_SERVICE_ID */
    UUID_SERVCLASS_HUMAN_INTERFACE,       /* BTA_HID_SERVICE_ID */
    UUID_SERVCLASS_VIDEO_SINK,            /* BTA_VDP_SERVICE_ID */
    UUID_SERVCLASS_PBAP_PSE,              /* BTA_PBAP_SERVICE_ID */
    UUID_SERVCLASS_HEADSET_AUDIO_GATEWAY, /* BTA_HSP_SERVICE_ID */
    UUID_SERVCLASS_AG_HANDSFREE,          /* BTA_HFP_SERVICE_ID */
    UUID_SERVCLASS_MESSAGE_ACCESS,        /* BTA_MAP_SERVICE_ID */
    UUID_SERVCLASS_MESSAGE_NOTIFICATION,  /* BTA_MN_SERVICE_ID */
    UUID_SERVCLASS_HDP_PROFILE,           /* BTA_HDP_SERVICE_ID */
    UUID_SERVCLASS_PBAP_PCE,              /* BTA_PCE_SERVICE_ID */
    UUID_PROTOCOL_ATT                     /* BTA_GATT_SERVICE_ID */
};

/* bta security callback */
const tBTM_APPL_INFO bta_security = {
    .p_pin_callback = &bta_dm_pin_cback,
    .p_link_key_callback = &bta_dm_new_link_key_cback,
    .p_auth_complete_callback = &bta_dm_authentication_complete_cback,
    .p_bond_cancel_cmpl_callback = &bta_dm_bond_cancel_complete_cback,
    .p_sp_callback = &bta_dm_sp_cback,
    .p_le_callback = &bta_dm_ble_smp_cback,
    .p_le_key_callback = &bta_dm_ble_id_key_cback};

#define MAX_DISC_RAW_DATA_BUF (4096)
uint8_t g_disc_raw_data_buf[MAX_DISC_RAW_DATA_BUF];

extern DEV_CLASS local_device_default_class;

// Stores the local Input/Output Capabilities of the Bluetooth device.
static uint8_t btm_local_io_caps;

/** Initialises the BT device manager */
void bta_dm_enable(tBTA_DM_SEC_CBACK* p_sec_cback) {
  /* make sure security callback is saved - if no callback, do not erase the
  previous one,
  it could be an error recovery mechanism */
  if (p_sec_cback != NULL) bta_dm_cb.p_sec_cback = p_sec_cback;
  /* notify BTA DM is now active */
  bta_dm_cb.is_bta_dm_active = true;

  btm_local_io_caps = btif_storage_get_local_io_caps();
}

/*******************************************************************************
 *
 * Function         bta_dm_init_cb
 *
 * Description      Initializes the bta_dm_cb control block
 *
 *
 * Returns          void
 *
 ******************************************************************************/
void bta_dm_init_cb(void) {
  memset(&bta_dm_cb, 0, sizeof(bta_dm_cb));
  bta_dm_cb.disable_timer = alarm_new("bta_dm.disable_timer");
  bta_dm_cb.switch_delay_timer = alarm_new("bta_dm.switch_delay_timer");
  for (size_t i = 0; i < BTA_DM_NUM_PM_TIMER; i++) {
    for (size_t j = 0; j < BTA_DM_PM_MODE_TIMER_MAX; j++) {
      bta_dm_cb.pm_timer[i].timer[j] = alarm_new("bta_dm.pm_timer");
    }
  }
}

/*******************************************************************************
 *
 * Function         bta_dm_deinit_cb
 *
 * Description      De-initializes the bta_dm_cb control block
 *
 *
 * Returns          void
 *
 ******************************************************************************/
void bta_dm_deinit_cb(void) {
  /*
   * TODO: Should alarm_free() the bta_dm_cb timers during graceful
   * shutdown.
   */
  alarm_free(bta_dm_cb.disable_timer);
  alarm_free(bta_dm_cb.switch_delay_timer);
  for (size_t i = 0; i < BTA_DM_NUM_PM_TIMER; i++) {
    for (size_t j = 0; j < BTA_DM_PM_MODE_TIMER_MAX; j++) {
      alarm_free(bta_dm_cb.pm_timer[i].timer[j]);
    }
  }
  memset(&bta_dm_cb, 0, sizeof(bta_dm_cb));
}

void BTA_dm_on_hw_off() {
  BTIF_dm_disable();

  /* reinitialize the control block */
  bta_dm_deinit_cb();

  /* hw is ready, go on with BTA DM initialization */
  alarm_free(bta_dm_search_cb.search_timer);
  alarm_free(bta_dm_search_cb.gatt_close_timer);
  osi_free(bta_dm_search_cb.p_pending_search);
  fixed_queue_free(bta_dm_search_cb.pending_discovery_queue, osi_free);
  memset(&bta_dm_search_cb, 0, sizeof(bta_dm_search_cb));

  /* notify BTA DM is now unactive */
  bta_dm_cb.is_bta_dm_active = false;
}

void BTA_dm_on_hw_on() {
  DEV_CLASS dev_class;
  tBTA_DM_SEC_CBACK* temp_cback;
  uint8_t key_mask = 0;
  tBTA_BLE_LOCAL_ID_KEYS id_key;

  /* save security callback */
  temp_cback = bta_dm_cb.p_sec_cback;
  /* make sure the control block is properly initialized */
  bta_dm_init_cb();
  /* and retrieve the callback */
  bta_dm_cb.p_sec_cback = temp_cback;
  bta_dm_cb.is_bta_dm_active = true;

  /* hw is ready, go on with BTA DM initialization */
  alarm_free(bta_dm_search_cb.search_timer);
  alarm_free(bta_dm_search_cb.gatt_close_timer);
  osi_free(bta_dm_search_cb.p_pending_search);
  fixed_queue_free(bta_dm_search_cb.pending_discovery_queue, osi_free);
  memset(&bta_dm_search_cb, 0, sizeof(bta_dm_search_cb));
  /*
   * TODO: Should alarm_free() the bta_dm_search_cb timers during
   * graceful shutdown.
   */
  bta_dm_search_cb.search_timer = alarm_new("bta_dm_search.search_timer");
  bta_dm_search_cb.gatt_close_timer =
      alarm_new("bta_dm_search.gatt_close_timer");
  bta_dm_search_cb.pending_discovery_queue = fixed_queue_new(SIZE_MAX);

  memset(&bta_dm_conn_srvcs, 0, sizeof(bta_dm_conn_srvcs));
  memset(&bta_dm_di_cb, 0, sizeof(tBTA_DM_DI_CB));

  memcpy(dev_class, p_bta_dm_cfg->dev_class, sizeof(dev_class));
  if (bluetooth::shim::is_gd_security_enabled()) {
    bluetooth::shim::BTM_SetDeviceClass(dev_class);
  } else {
    BTM_SetDeviceClass(dev_class);
  }

  /* load BLE local information: ID keys, ER if available */
  Octet16 er;
  btif_dm_get_ble_local_keys(&key_mask, &er, &id_key);

  if (key_mask & BTA_BLE_LOCAL_KEY_TYPE_ER) {
    get_btm_client_interface().ble.BTM_BleLoadLocalKeys(
        BTA_BLE_LOCAL_KEY_TYPE_ER, (tBTM_BLE_LOCAL_KEYS*)&er);
  }
  if (key_mask & BTA_BLE_LOCAL_KEY_TYPE_ID) {
    get_btm_client_interface().ble.BTM_BleLoadLocalKeys(
        BTA_BLE_LOCAL_KEY_TYPE_ID, (tBTM_BLE_LOCAL_KEYS*)&id_key);
  }
  bta_dm_search_cb.conn_id = GATT_INVALID_CONN_ID;

  if (bluetooth::shim::is_gd_security_enabled()) {
    bluetooth::shim::BTM_SecRegister(&bta_security);
  } else {
    get_btm_client_interface().security.BTM_SecRegister(&bta_security);
  }

  BTM_WritePageTimeout(p_bta_dm_cfg->page_timeout);

#if (BLE_VND_INCLUDED == TRUE)
  BTM_BleReadControllerFeatures(bta_dm_ctrl_features_rd_cmpl_cback);
#else
  /* If VSC multi adv commands are available, advertising will be initialized
   * when capabilities are read. If they are not available, initialize
   * advertising here */
  btm_ble_adv_init();
#endif

  /* Earlier, we used to invoke BTM_ReadLocalAddr which was just copying the
     bd_addr
     from the control block and invoking the callback which was sending the
     DM_ENABLE_EVT.
     But then we have a few HCI commands being invoked above which were still
     in progress
     when the ENABLE_EVT was sent. So modified this to fetch the local name
     which forces
     the DM_ENABLE_EVT to be sent only after all the init steps are complete
     */
  BTM_ReadLocalDeviceNameFromController(bta_dm_local_name_cback);

  bta_sys_rm_register(bta_dm_rm_cback);

  /* initialize bluetooth low power manager */
  bta_dm_init_pm();

  bta_dm_gattc_register();
}

/** Disables the BT device manager */
void bta_dm_disable() {
  /* Set l2cap idle timeout to 0 (so BTE immediately disconnects ACL link after
   * last channel is closed) */
  L2CA_SetIdleTimeoutByBdAddr(RawAddress::kAny, 0, BT_TRANSPORT_BR_EDR);
  L2CA_SetIdleTimeoutByBdAddr(RawAddress::kAny, 0, BT_TRANSPORT_LE);

  /* disable all active subsystems */
  bta_sys_disable();

  BTM_SetDiscoverability(BTM_NON_DISCOVERABLE);
  BTM_SetConnectability(BTM_NON_CONNECTABLE);

  bta_dm_disable_pm();
  bta_dm_disable_search_and_disc();
  bta_dm_cb.disabling = true;

  connection_manager::reset(false);

  if (BTM_GetNumAclLinks() == 0) {
    // We can shut down faster if there are no ACL links
    switch (kDisableDelayTimerInMs) {
      case 0:
        LOG_DEBUG("Immediately disabling device manager");
        bta_dm_disable_conn_down_timer_cback(nullptr);
        break;
      default:
        LOG_DEBUG("Set timer to delay disable initiation:%lu ms",
                  static_cast<unsigned long>(kDisableDelayTimerInMs));
        alarm_set_on_mloop(bta_dm_cb.disable_timer, kDisableDelayTimerInMs,
                           bta_dm_disable_conn_down_timer_cback, nullptr);
    }
  } else {
    LOG_DEBUG("Set timer to wait for all ACL connections to close:%lu ms",
              first_pass.TimeToWaitInMs());
    alarm_set_on_mloop(bta_dm_cb.disable_timer, first_pass.time_to_wait_in_ms,
                       bta_dm_wait_for_acl_to_drain_cback,
                       first_pass.AlarmCallbackData());
  }
}

/*******************************************************************************
 *
 * Function         bta_dm_wait_for_all_acl_to_drain
 *
 * Description      Called if the disable timer expires
 *                  Used to close ACL connections which are still active
 *
 *
 *
 * Returns          void
 *
 ******************************************************************************/
static bool force_disconnect_all_acl_connections() {
  const bool is_force_disconnect_needed = (bta_dm_cb.device_list.count > 0);

  for (auto i = 0; i < bta_dm_cb.device_list.count; i++) {
    btm_remove_acl(bta_dm_cb.device_list.peer_device[i].peer_bdaddr,
                   bta_dm_cb.device_list.peer_device[i].transport);
  }
  return is_force_disconnect_needed;
}

static void bta_dm_wait_for_acl_to_drain_cback(void* data) {
  ASSERT(data != nullptr);
  const WaitForAllAclConnectionsToDrain* pass =
      WaitForAllAclConnectionsToDrain::FromAlarmCallbackData(data);

  if (BTM_GetNumAclLinks() &&
      WaitForAllAclConnectionsToDrain::IsFirstPass(pass)) {
    /* DISABLE_EVT still need to be sent out to avoid java layer disable timeout
     */
    if (force_disconnect_all_acl_connections()) {
      LOG_DEBUG(
          "Set timer for second pass to wait for all ACL connections to "
          "close:%lu ms ",
          second_pass.TimeToWaitInMs());
      alarm_set_on_mloop(
          bta_dm_cb.disable_timer, second_pass.time_to_wait_in_ms,
          bta_dm_wait_for_acl_to_drain_cback, second_pass.AlarmCallbackData());
    }
  } else {
    // No ACL links were up or is second pass at ACL closure
    if (bluetooth::shim::is_gd_acl_enabled()) {
      LOG_INFO("Ensuring all ACL connections have been properly flushed");
      bluetooth::shim::ACL_Shutdown();
    }

    bta_dm_cb.disabling = false;

    bta_sys_remove_uuid(UUID_SERVCLASS_PNP_INFORMATION);
    BTIF_dm_disable();
  }
}

/** Sets local device name */
void bta_dm_set_dev_name(const std::vector<uint8_t>& name) {
  BTM_SetLocalDeviceName((char*)name.data());
  bta_dm_set_eir((char*)name.data());
}

/** Sets discoverability, connectability and pairability */
bool BTA_DmSetVisibility(bt_scan_mode_t mode) {
  tBTA_DM_DISC disc_mode_param;
  tBTA_DM_CONN conn_mode_param;

  switch (mode) {
    case BT_SCAN_MODE_NONE:
      disc_mode_param = BTA_DM_NON_DISC;
      conn_mode_param = BTA_DM_NON_CONN;
      break;

    case BT_SCAN_MODE_CONNECTABLE:
      disc_mode_param = BTA_DM_NON_DISC;
      conn_mode_param = BTA_DM_CONN;
      break;

    case BT_SCAN_MODE_CONNECTABLE_DISCOVERABLE:
      disc_mode_param = BTA_DM_GENERAL_DISC;
      conn_mode_param = BTA_DM_CONN;
      break;

    default:
      return false;
  }

  BTM_SetDiscoverability(disc_mode_param);
  BTM_SetConnectability(conn_mode_param);
  return true;
}

static void bta_dm_process_remove_device_no_callback(
    const RawAddress& bd_addr) {
  /* need to remove all pending background connection before unpair */
  BTA_GATTC_CancelOpen(0, bd_addr, false);

  if (bluetooth::shim::is_gd_security_enabled()) {
    bluetooth::shim::BTM_SecDeleteDevice(bd_addr);
  } else {
    BTM_SecDeleteDevice(bd_addr);
  }

  /* remove all cached GATT information */
  BTA_GATTC_Refresh(bd_addr);
}

void bta_dm_process_remove_device(const RawAddress& bd_addr) {
  bta_dm_process_remove_device_no_callback(bd_addr);

  if (bta_dm_cb.p_sec_cback) {
    tBTA_DM_SEC sec_event;
    sec_event.link_down.bd_addr = bd_addr;
    bta_dm_cb.p_sec_cback(BTA_DM_DEV_UNPAIRED_EVT, &sec_event);
  }
}

/** Removes device, disconnects ACL link if required */
void bta_dm_remove_device(const RawAddress& bd_addr) {
  /* If ACL exists for the device in the remove_bond message*/
  bool is_bd_addr_connected =
      BTM_IsAclConnectionUp(bd_addr, BT_TRANSPORT_LE) ||
      BTM_IsAclConnectionUp(bd_addr, BT_TRANSPORT_BR_EDR);

  uint8_t other_transport = BT_TRANSPORT_INVALID;
  if (is_bd_addr_connected) {
    APPL_TRACE_DEBUG("%s: ACL Up count: %d", __func__,
                     bta_dm_cb.device_list.count);

    /* Take the link down first, and mark the device for removal when
     * disconnected */
    for (int i = 0; i < bta_dm_cb.device_list.count; i++) {
      auto& peer_device = bta_dm_cb.device_list.peer_device[i];
      if (peer_device.peer_bdaddr == bd_addr) {
        peer_device.conn_state = BTA_DM_UNPAIRING;

        /* Make sure device is not in acceptlist before we disconnect */
        GATT_CancelConnect(0, bd_addr, false);

        btm_remove_acl(bd_addr, peer_device.transport);
        APPL_TRACE_DEBUG("%s: transport: %d", __func__, peer_device.transport);

        /* save the other transport to check if device is connected on
         * other_transport */
        if (peer_device.transport == BT_TRANSPORT_LE)
          other_transport = BT_TRANSPORT_BR_EDR;
        else
          other_transport = BT_TRANSPORT_LE;

        break;
      }
    }
  }

  RawAddress other_address = bd_addr;
  RawAddress other_address2 = bd_addr;

  // If it is DUMO device and device is paired as different address, unpair that
  // device
  bool other_address_connected =
      (other_transport)
          ? BTM_ReadConnectedTransportAddress(&other_address, other_transport)
          : (BTM_ReadConnectedTransportAddress(&other_address,
                                               BT_TRANSPORT_BR_EDR) ||
             BTM_ReadConnectedTransportAddress(&other_address2,
                                               BT_TRANSPORT_LE));
  if (other_address == bd_addr) other_address = other_address2;

  if (other_address_connected) {
    /* Take the link down first, and mark the device for removal when
     * disconnected */
    for (int i = 0; i < bta_dm_cb.device_list.count; i++) {
      auto& peer_device = bta_dm_cb.device_list.peer_device[i];
      if (peer_device.peer_bdaddr == other_address &&
          peer_device.transport == other_transport) {
        peer_device.conn_state = BTA_DM_UNPAIRING;

        /* Make sure device is not in acceptlist before we disconnect */
        GATT_CancelConnect(0, bd_addr, false);

        btm_remove_acl(other_address, peer_device.transport);
        break;
      }
    }
  }

  /* Delete the device mentioned in the msg */
  if (!is_bd_addr_connected) {
    bta_dm_process_remove_device(bd_addr);
  }

  /* Delete the other paired device too */
  if (!other_address_connected && !other_address.IsEmpty()) {
    bta_dm_process_remove_device(other_address);
  }

  /* Check the length of the paired devices, and if 0 then reset IRK */
  auto paired_devices = btif_config_get_paired_devices();
  if (paired_devices.empty()) {
    LOG_INFO("Last paired device removed, resetting IRK");
    btm_ble_reset_id();
  }
}

/*******************************************************************************
 *
 * Function         bta_dm_add_device
 *
 * Description      This function adds a Link Key to an security database entry.
 *                  It is normally called during host startup to restore all
 *                  required information stored in the NVRAM.
 ******************************************************************************/
void bta_dm_add_device(std::unique_ptr<tBTA_DM_API_ADD_DEVICE> msg) {
  uint8_t* p_dc = NULL;
  LinkKey* p_lc = NULL;

  /* If not all zeros, the device class has been specified */
  if (msg->dc_known) p_dc = (uint8_t*)msg->dc;

  if (msg->link_key_known) p_lc = &msg->link_key;

  if (bluetooth::shim::is_gd_security_enabled()) {
    bluetooth::shim::BTM_SecAddDevice(msg->bd_addr, p_dc, msg->bd_name, nullptr,
                                      p_lc, msg->key_type, msg->pin_length);
  } else {
    auto add_result =
        BTM_SecAddDevice(msg->bd_addr, p_dc, msg->bd_name, nullptr, p_lc,
                         msg->key_type, msg->pin_length);
    if (!add_result) {
      LOG(ERROR) << "BTA_DM: Error adding device " << msg->bd_addr;
    }
  }
}

/** This function forces to close the connection to a remote device and
 * optionaly remove the device from security database if required. */
void bta_dm_close_acl(const RawAddress& bd_addr, bool remove_dev,
                      tBT_TRANSPORT transport) {
  uint8_t index;

  APPL_TRACE_DEBUG("bta_dm_close_acl");

  if (BTM_IsAclConnectionUp(bd_addr, transport)) {
    for (index = 0; index < bta_dm_cb.device_list.count; index++) {
      if (bta_dm_cb.device_list.peer_device[index].peer_bdaddr == bd_addr)
        break;
    }
    if (index != bta_dm_cb.device_list.count) {
      if (remove_dev)
        bta_dm_cb.device_list.peer_device[index].remove_dev_pending = true;
    } else {
      APPL_TRACE_ERROR("unknown device, remove ACL failed");
    }

    /* Make sure device is not in acceptlist before we disconnect */
    GATT_CancelConnect(0, bd_addr, false);

    /* Disconnect the ACL link */
    btm_remove_acl(bd_addr, transport);
  }
  /* if to remove the device from security database ? do it now */
  else if (remove_dev) {
    bta_dm_process_remove_device_no_callback(bd_addr);
  }
  /* otherwise, no action needed */
}

/** Bonds with peer device */
void bta_dm_bond(const RawAddress& bd_addr, tBLE_ADDR_TYPE addr_type,
                 tBT_TRANSPORT transport, int device_type) {
  tBTA_DM_SEC sec_event;
  char* p_name;

  tBTM_STATUS status =
      (bluetooth::shim::is_gd_security_enabled())
          ? bluetooth::shim::BTM_SecBond(bd_addr, addr_type, transport,
                                         device_type)
          : BTM_SecBond(bd_addr, addr_type, transport, device_type, 0, NULL);

  if (bta_dm_cb.p_sec_cback && (status != BTM_CMD_STARTED)) {
    memset(&sec_event, 0, sizeof(tBTA_DM_SEC));
    sec_event.auth_cmpl.bd_addr = bd_addr;
    p_name = (bluetooth::shim::is_gd_security_enabled())
                 ? bluetooth::shim::BTM_SecReadDevName(bd_addr)
                 : BTM_SecReadDevName(bd_addr);
    if (p_name != NULL) {
      memcpy(sec_event.auth_cmpl.bd_name, p_name, BD_NAME_LEN);
      sec_event.auth_cmpl.bd_name[BD_NAME_LEN] = 0;
    }

    /*      taken care of by memset [above]
            sec_event.auth_cmpl.key_present = false;
            sec_event.auth_cmpl.success = false;
    */
    sec_event.auth_cmpl.fail_reason = HCI_ERR_ILLEGAL_COMMAND;
    if (status == BTM_SUCCESS) {
      sec_event.auth_cmpl.success = true;
    } else {
      /* delete this device entry from Sec Dev DB */
      bta_dm_remove_sec_dev_entry(bd_addr);
    }
    bta_dm_cb.p_sec_cback(BTA_DM_AUTH_CMPL_EVT, &sec_event);
  }
}

/** Cancels bonding with a peer device */
void bta_dm_bond_cancel(const RawAddress& bd_addr) {
  tBTM_STATUS status;
  tBTA_DM_SEC sec_event;

  APPL_TRACE_EVENT(" bta_dm_bond_cancel ");

  status = (bluetooth::shim::is_gd_security_enabled())
               ? bluetooth::shim::BTM_SecBondCancel(bd_addr)
               : BTM_SecBondCancel(bd_addr);

  if (bta_dm_cb.p_sec_cback &&
      (status != BTM_CMD_STARTED && status != BTM_SUCCESS)) {
    sec_event.bond_cancel_cmpl.result = BTA_FAILURE;

    bta_dm_cb.p_sec_cback(BTA_DM_BOND_CANCEL_CMPL_EVT, &sec_event);
  }
}

/** Send the pin_reply to a request from BTM */
void bta_dm_pin_reply(std::unique_ptr<tBTA_DM_API_PIN_REPLY> msg) {
  if (msg->accept) {
    if (bluetooth::shim::is_gd_security_enabled()) {
      bluetooth::shim::BTM_PINCodeReply(msg->bd_addr, BTM_SUCCESS, msg->pin_len,
                                        msg->p_pin);
    } else {
      BTM_PINCodeReply(msg->bd_addr, BTM_SUCCESS, msg->pin_len, msg->p_pin);
    }
  } else {
    if (bluetooth::shim::is_gd_security_enabled()) {
      bluetooth::shim::BTM_PINCodeReply(msg->bd_addr, BTM_NOT_AUTHORIZED, 0,
                                        NULL);
    } else {
      BTM_PINCodeReply(msg->bd_addr, BTM_NOT_AUTHORIZED, 0, NULL);
    }
  }
}

/** Send the user confirm request reply in response to a request from BTM */
void bta_dm_confirm(const RawAddress& bd_addr, bool accept) {
  if (bluetooth::shim::is_gd_security_enabled()) {
    bluetooth::shim::BTM_ConfirmReqReply(
        accept ? BTM_SUCCESS : BTM_NOT_AUTHORIZED, bd_addr);
  } else {
    BTM_ConfirmReqReply(accept ? BTM_SUCCESS : BTM_NOT_AUTHORIZED, bd_addr);
  }
}

/** respond to the OOB data request for the remote device from BTM */
void bta_dm_ci_rmt_oob_act(std::unique_ptr<tBTA_DM_CI_RMT_OOB> msg) {
  if (bluetooth::shim::is_gd_security_enabled()) {
    bluetooth::shim::BTM_RemoteOobDataReply(
        msg->accept ? BTM_SUCCESS : BTM_NOT_AUTHORIZED, msg->bd_addr, msg->c,
        msg->r);
  } else {
    BTM_RemoteOobDataReply(msg->accept ? BTM_SUCCESS : BTM_NOT_AUTHORIZED,
                           msg->bd_addr, msg->c, msg->r);
  }
}

/*******************************************************************************
 *
 * Function         bta_dm_search_start
 *
 * Description      Starts an inquiry
 *
 *
 * Returns          void
 *
 ******************************************************************************/
void bta_dm_search_start(tBTA_DM_MSG* p_data) {
  tBTM_INQUIRY_CMPL result = {};

  bta_dm_gattc_register();

  APPL_TRACE_DEBUG("%s avoid_scatter=%d", __func__,
                   p_bta_dm_cfg->avoid_scatter);

  BTM_ClearInqDb(nullptr);
  /* save search params */
  bta_dm_search_cb.p_search_cback = p_data->search.p_cback;
  bta_dm_search_cb.services = p_data->search.services;

  result.status = BTM_StartInquiry(bta_dm_inq_results_cb, bta_dm_inq_cmpl_cb);

  APPL_TRACE_EVENT("%s status=%d", __func__, result.status);
  if (result.status != BTM_CMD_STARTED) {
    LOG(ERROR) << __func__ << ": BTM_StartInquiry returned "
               << std::to_string(result.status);
    result.num_resp = 0;
    bta_dm_inq_cmpl_cb((void*)&result);
  }
}

/*******************************************************************************
 *
 * Function         bta_dm_search_cancel
 *
 * Description      Cancels an ongoing search for devices
 *
 *
 * Returns          void
 *
 ******************************************************************************/
void bta_dm_search_cancel() {
  if (BTM_IsInquiryActive()) {
    BTM_CancelInquiry();
    bta_dm_search_cancel_notify();
    bta_dm_search_cmpl();
  }
  /* If no Service Search going on then issue cancel remote name in case it is
     active */
  else if (!bta_dm_search_cb.name_discover_done) {
    BTM_CancelRemoteDeviceName();
    bta_dm_search_cmpl();
  } else {
    bta_dm_inq_cmpl(0);
  }

  if (bta_dm_search_cb.gatt_disc_active) {
    bta_dm_cancel_gatt_discovery(bta_dm_search_cb.peer_bdaddr);
  }
}

/*******************************************************************************
 *
 * Function         bta_dm_discover
 *
 * Description      Discovers services on a remote device
 *
 *
 * Returns          void
 *
 ******************************************************************************/
void bta_dm_discover(tBTA_DM_MSG* p_data) {
  /* save the search condition */
  bta_dm_search_cb.services = BTA_ALL_SERVICE_MASK;

  bta_dm_gattc_register();

  bta_dm_search_cb.p_search_cback = p_data->discover.p_cback;
  bta_dm_search_cb.services_to_search = bta_dm_search_cb.services;
  bta_dm_search_cb.service_index = 0;
  bta_dm_search_cb.services_found = 0;
  bta_dm_search_cb.peer_name[0] = 0;
  bta_dm_search_cb.p_btm_inq_info = BTM_InqDbRead(p_data->discover.bd_addr);
  bta_dm_search_cb.transport = p_data->discover.transport;

  bta_dm_search_cb.name_discover_done = false;
  bta_dm_discover_device(p_data->discover.bd_addr);
}

/*******************************************************************************
 *
 * Function         bta_dm_disable_search_and_disc
 *
 * Description      Cancels an ongoing search or discovery for devices in case
 *                  of a Bluetooth disable
 *
 *
 * Returns          void
 *
 ******************************************************************************/
static void bta_dm_disable_search_and_disc(void) {
  if (bta_dm_search_cb.state != BTA_DM_SEARCH_IDLE) bta_dm_search_cancel();
}

/*******************************************************************************
 *
 * Function         bta_dm_read_remote_device_name
 *
 * Description      Initiate to get remote device name
 *
 * Returns          true if started to get remote name
 *
 ******************************************************************************/
static bool bta_dm_read_remote_device_name(const RawAddress& bd_addr,
                                           tBT_TRANSPORT transport) {
  tBTM_STATUS btm_status;

  APPL_TRACE_DEBUG("%s", __func__);

  bta_dm_search_cb.peer_bdaddr = bd_addr;
  bta_dm_search_cb.peer_name[0] = 0;

  btm_status =
      (bluetooth::shim::is_gd_security_enabled())
          ? bluetooth::shim::BTM_ReadRemoteDeviceName(
                bta_dm_search_cb.peer_bdaddr, bta_dm_remname_cback, transport)
          : BTM_ReadRemoteDeviceName(bta_dm_search_cb.peer_bdaddr,
                                     bta_dm_remname_cback, transport);

  if (btm_status == BTM_CMD_STARTED) {
    APPL_TRACE_DEBUG("%s: BTM_ReadRemoteDeviceName is started", __func__);

    return (true);
  } else if (btm_status == BTM_BUSY) {
    APPL_TRACE_DEBUG("%s: BTM_ReadRemoteDeviceName is busy", __func__);

    /* Remote name discovery is on going now so BTM cannot notify through
     * "bta_dm_remname_cback" */
    /* adding callback to get notified that current reading remore name done */

    if (bluetooth::shim::is_gd_security_enabled()) {
      bluetooth::shim::BTM_SecAddRmtNameNotifyCallback(
          &bta_dm_service_search_remname_cback);
    } else {
      BTM_SecAddRmtNameNotifyCallback(&bta_dm_service_search_remname_cback);
    }

    return (true);
  } else {
    APPL_TRACE_WARNING("%s: BTM_ReadRemoteDeviceName returns 0x%02X", __func__,
                       btm_status);

    return (false);
  }
}

/*******************************************************************************
 *
 * Function         bta_dm_inq_cmpl
 *
 * Description      Process the inquiry complete event from BTM
 *
 * Returns          void
 *
 ******************************************************************************/
void bta_dm_inq_cmpl(uint8_t num) {
  if (bta_dm_search_get_state() == BTA_DM_SEARCH_CANCELLING) {
    bta_dm_search_set_state(BTA_DM_SEARCH_IDLE);
    bta_dm_execute_queued_request();
    return;
  }

  if (bta_dm_search_get_state() != BTA_DM_SEARCH_ACTIVE) {
    return;
  }

  tBTA_DM_SEARCH data;

  APPL_TRACE_DEBUG("bta_dm_inq_cmpl");

  data.inq_cmpl.num_resps = num;
  bta_dm_search_cb.p_search_cback(BTA_DM_INQ_CMPL_EVT, &data);

  bta_dm_search_cb.p_btm_inq_info = BTM_InqDbFirst();
  if (bta_dm_search_cb.p_btm_inq_info != NULL) {
    /* start name and service discovery from the first device on inquiry result
     */
    bta_dm_search_cb.name_discover_done = false;
    bta_dm_search_cb.peer_name[0] = 0;
    bta_dm_discover_device(
        bta_dm_search_cb.p_btm_inq_info->results.remote_bd_addr);
  } else {
    bta_dm_search_cb.services = 0;
    bta_dm_search_cmpl();
  }
}

/*******************************************************************************
 *
 * Function         bta_dm_rmt_name
 *
 * Description      Process the remote name result from BTM
 *
 * Returns          void
 *
 ******************************************************************************/
void bta_dm_rmt_name(tBTA_DM_MSG* p_data) {
  APPL_TRACE_DEBUG("bta_dm_rmt_name");

  if (p_data->rem_name.result.disc_res.bd_name[0] &&
      bta_dm_search_cb.p_btm_inq_info) {
    bta_dm_search_cb.p_btm_inq_info->appl_knows_rem_name = true;
  }

  bta_dm_discover_device(bta_dm_search_cb.peer_bdaddr);
}

/*******************************************************************************
 *
 * Function         bta_dm_disc_rmt_name
 *
 * Description      Process the remote name result from BTM when application
 *                  wants to find the name for a bdaddr
 *
 * Returns          void
 *
 ******************************************************************************/
void bta_dm_disc_rmt_name(tBTA_DM_MSG* p_data) {
  tBTM_INQ_INFO* p_btm_inq_info;

  APPL_TRACE_DEBUG("bta_dm_disc_rmt_name");

  p_btm_inq_info = BTM_InqDbRead(p_data->rem_name.result.disc_res.bd_addr);
  if (p_btm_inq_info) {
    if (p_data->rem_name.result.disc_res.bd_name[0]) {
      p_btm_inq_info->appl_knows_rem_name = true;
    }
  }

  bta_dm_discover_device(p_data->rem_name.result.disc_res.bd_addr);
}

/*******************************************************************************
 *
 * Function         bta_dm_sdp_result
 *
 * Description      Process the discovery result from sdp
 *
 * Returns          void
 *
 ******************************************************************************/
void bta_dm_sdp_result(tBTA_DM_MSG* p_data) {
  tSDP_DISC_REC* p_sdp_rec = NULL;
  tBTA_DM_MSG* p_msg;
  bool scn_found = false;
  uint16_t service = 0xFFFF;
  tSDP_PROTOCOL_ELEM pe;

  std::vector<Uuid> uuid_list;

  if ((p_data->sdp_event.sdp_result == SDP_SUCCESS) ||
      (p_data->sdp_event.sdp_result == SDP_NO_RECS_MATCH) ||
      (p_data->sdp_event.sdp_result == SDP_DB_FULL)) {
    APPL_TRACE_DEBUG("sdp_result::0x%x", p_data->sdp_event.sdp_result);
    do {
      p_sdp_rec = NULL;
      if (bta_dm_search_cb.service_index == (BTA_USER_SERVICE_ID + 1)) {
        if (p_sdp_rec && SDP_FindProtocolListElemInRec(
                             p_sdp_rec, UUID_PROTOCOL_RFCOMM, &pe)) {
          bta_dm_search_cb.peer_scn = (uint8_t)pe.params[0];
          scn_found = true;
        }
      } else {
        service =
            bta_service_id_to_uuid_lkup_tbl[bta_dm_search_cb.service_index - 1];
        p_sdp_rec =
            SDP_FindServiceInDb(bta_dm_search_cb.p_sdp_db, service, p_sdp_rec);
      }
      /* finished with BR/EDR services, now we check the result for GATT based
       * service UUID */
      if (bta_dm_search_cb.service_index == BTA_MAX_SERVICE_ID) {
        /* all GATT based services */

        std::vector<Uuid> gatt_uuids;

        do {
          /* find a service record, report it */
          p_sdp_rec =
              SDP_FindServiceInDb(bta_dm_search_cb.p_sdp_db, 0, p_sdp_rec);
          if (p_sdp_rec) {
            Uuid service_uuid;
            if (SDP_FindServiceUUIDInRec(p_sdp_rec, &service_uuid)) {
              gatt_uuids.push_back(service_uuid);
            }
          }
        } while (p_sdp_rec);

        if (!gatt_uuids.empty()) {
          LOG_INFO("GATT services discovered using SDP");

          // send all result back to app
          tBTA_DM_SEARCH result;
          result.disc_ble_res.bd_addr = bta_dm_search_cb.peer_bdaddr;
          strlcpy((char*)result.disc_ble_res.bd_name, bta_dm_get_remname(),
                  BD_NAME_LEN + 1);

          result.disc_ble_res.services = &gatt_uuids;
          bta_dm_search_cb.p_search_cback(BTA_DM_DISC_BLE_RES_EVT, &result);
        }
      } else {
        /* SDP_DB_FULL means some records with the
           required attributes were received */
        if (((p_data->sdp_event.sdp_result == SDP_DB_FULL) &&
             bta_dm_search_cb.services != BTA_ALL_SERVICE_MASK) ||
            (p_sdp_rec != NULL)) {
          if (service != UUID_SERVCLASS_PNP_INFORMATION) {
            bta_dm_search_cb.services_found |=
                (tBTA_SERVICE_MASK)(BTA_SERVICE_ID_TO_SERVICE_MASK(
                    bta_dm_search_cb.service_index - 1));
            uint16_t tmp_svc =
                bta_service_id_to_uuid_lkup_tbl[bta_dm_search_cb.service_index -
                                                1];
            /* Add to the list of UUIDs */
            uuid_list.push_back(Uuid::From16Bit(tmp_svc));
          }
        }
      }

      if (bta_dm_search_cb.services == BTA_ALL_SERVICE_MASK &&
          bta_dm_search_cb.services_to_search == 0) {
        bta_dm_search_cb.service_index++;
      } else /* regular one service per search or PNP search */
        break;

    } while (bta_dm_search_cb.service_index <= BTA_MAX_SERVICE_ID);

    APPL_TRACE_DEBUG("%s services_found = %04x", __func__,
                     bta_dm_search_cb.services_found);

    /* Collect the 128-bit services here and put them into the list */
    if (bta_dm_search_cb.services == BTA_ALL_SERVICE_MASK) {
      p_sdp_rec = NULL;
      do {
        /* find a service record, report it */
        p_sdp_rec =
            SDP_FindServiceInDb_128bit(bta_dm_search_cb.p_sdp_db, p_sdp_rec);
        if (p_sdp_rec) {
          // SDP_FindServiceUUIDInRec_128bit is used only once, refactor?
          Uuid temp_uuid;
          if (SDP_FindServiceUUIDInRec_128bit(p_sdp_rec, &temp_uuid)) {
            uuid_list.push_back(temp_uuid);
          }
        }
      } while (p_sdp_rec);
    }
    /* if there are more services to search for */
    if (bta_dm_search_cb.services_to_search) {
      /* Free up the p_sdp_db before checking the next one */
      bta_dm_free_sdp_db();
      bta_dm_find_services(bta_dm_search_cb.peer_bdaddr);
    } else {
      /* callbacks */
      /* start next bd_addr if necessary */

      if (bluetooth::shim::is_gd_security_enabled()) {
        bluetooth::shim::BTM_SecDeleteRmtNameNotifyCallback(
            &bta_dm_service_search_remname_cback);
      } else {
        BTM_SecDeleteRmtNameNotifyCallback(
            &bta_dm_service_search_remname_cback);
      }

      p_msg = (tBTA_DM_MSG*)osi_malloc(sizeof(tBTA_DM_MSG));
      p_msg->hdr.event = BTA_DM_DISCOVERY_RESULT_EVT;
      p_msg->disc_result.result.disc_res.result = BTA_SUCCESS;
      p_msg->disc_result.result.disc_res.num_uuids = uuid_list.size();
      p_msg->disc_result.result.disc_res.p_uuid_list = NULL;
      if (uuid_list.size() > 0) {
        // TODO(jpawlowski): make p_uuid_list into vector, and just copy
        // vectors, but first get rid of bta_sys_sendmsg below.
        p_msg->disc_result.result.disc_res.p_uuid_list =
            (Uuid*)osi_malloc(uuid_list.size() * sizeof(Uuid));
        memcpy(p_msg->disc_result.result.disc_res.p_uuid_list, uuid_list.data(),
               uuid_list.size() * sizeof(Uuid));
      }
      // Copy the raw_data to the discovery result structure
      if (bta_dm_search_cb.p_sdp_db != NULL &&
          bta_dm_search_cb.p_sdp_db->raw_used != 0 &&
          bta_dm_search_cb.p_sdp_db->raw_data != NULL) {
        APPL_TRACE_DEBUG("%s raw_data used = 0x%x raw_data_ptr = 0x%x",
                         __func__, bta_dm_search_cb.p_sdp_db->raw_used,
                         bta_dm_search_cb.p_sdp_db->raw_data);

        bta_dm_search_cb.p_sdp_db->raw_data =
            NULL;  // no need to free this - it is a global assigned.
        bta_dm_search_cb.p_sdp_db->raw_used = 0;
        bta_dm_search_cb.p_sdp_db->raw_size = 0;
      } else {
        APPL_TRACE_DEBUG("%s raw data size is 0 or raw_data is null!!",
                         __func__);
      }
      /* Done with p_sdp_db. Free it */
      bta_dm_free_sdp_db();
      p_msg->disc_result.result.disc_res.services =
          bta_dm_search_cb.services_found;

      // Piggy back the SCN over result field
      if (scn_found) {
        p_msg->disc_result.result.disc_res.result =
            static_cast<tBTA_STATUS>((3 + bta_dm_search_cb.peer_scn));
        p_msg->disc_result.result.disc_res.services |= BTA_USER_SERVICE_MASK;

        APPL_TRACE_EVENT(" Piggy back the SCN over result field  SCN=%d",
                         bta_dm_search_cb.peer_scn);
      }
      p_msg->disc_result.result.disc_res.bd_addr = bta_dm_search_cb.peer_bdaddr;
      strlcpy((char*)p_msg->disc_result.result.disc_res.bd_name,
              bta_dm_get_remname(), BD_NAME_LEN + 1);

      bta_sys_sendmsg(p_msg);
    }
  } else {
    /* conn failed. No need for timer */
    if (p_data->sdp_event.sdp_result == SDP_CONN_FAILED)
      bta_dm_search_cb.wait_disc = false;

    /* not able to connect go to next device */
    if (bta_dm_search_cb.p_sdp_db)
      osi_free_and_reset((void**)&bta_dm_search_cb.p_sdp_db);

    if (bluetooth::shim::is_gd_security_enabled()) {
      bluetooth::shim::BTM_SecDeleteRmtNameNotifyCallback(
          &bta_dm_service_search_remname_cback);
    } else {
      BTM_SecDeleteRmtNameNotifyCallback(&bta_dm_service_search_remname_cback);
    }

    p_msg = (tBTA_DM_MSG*)osi_malloc(sizeof(tBTA_DM_MSG));
    p_msg->hdr.event = BTA_DM_DISCOVERY_RESULT_EVT;
    p_msg->disc_result.result.disc_res.result = BTA_FAILURE;
    p_msg->disc_result.result.disc_res.services =
        bta_dm_search_cb.services_found;
    p_msg->disc_result.result.disc_res.bd_addr = bta_dm_search_cb.peer_bdaddr;
    strlcpy((char*)p_msg->disc_result.result.disc_res.bd_name,
            bta_dm_get_remname(), BD_NAME_LEN + 1);

    bta_sys_sendmsg(p_msg);
  }
}

/*******************************************************************************
 *
 * Function         bta_dm_search_cmpl
 *
 * Description      Sends event to application
 *
 * Returns          void
 *
 ******************************************************************************/
void bta_dm_search_cmpl() {
  bta_dm_search_set_state(BTA_DM_SEARCH_IDLE);

  uint16_t conn_id = bta_dm_search_cb.conn_id;

  /* no BLE connection, i.e. Classic service discovery end */
  if (conn_id == GATT_INVALID_CONN_ID) {
    bta_dm_search_cb.p_search_cback(BTA_DM_DISC_CMPL_EVT, nullptr);
    bta_dm_execute_queued_request();
    return;
  }

  btgatt_db_element_t* db = NULL;
  int count = 0;
  BTA_GATTC_GetGattDb(conn_id, 0x0000, 0xFFFF, &db, &count);

  if (count == 0) {
    LOG_INFO("Empty GATT database - no BLE services discovered");
    bta_dm_search_cb.p_search_cback(BTA_DM_DISC_CMPL_EVT, nullptr);
    bta_dm_execute_queued_request();
    return;
  }

  std::vector<Uuid> gatt_services;

  for (int i = 0; i < count; i++) {
    // we process service entries only
    if (db[i].type == BTGATT_DB_PRIMARY_SERVICE) {
      gatt_services.push_back(db[i].uuid);
    }
  }
  osi_free(db);

  tBTA_DM_SEARCH result;
  result.disc_ble_res.services = &gatt_services;
  result.disc_ble_res.bd_addr = bta_dm_search_cb.peer_bdaddr;
  strlcpy((char*)result.disc_ble_res.bd_name, (char*)bta_dm_search_cb.peer_name,
          BD_NAME_LEN + 1);

  LOG_INFO("GATT services discovered using LE Transport");
  // send all result back to app
  bta_dm_search_cb.p_search_cback(BTA_DM_DISC_BLE_RES_EVT, &result);

  bta_dm_search_cb.p_search_cback(BTA_DM_DISC_CMPL_EVT, nullptr);

  bta_dm_execute_queued_request();
}

/*******************************************************************************
 *
 * Function         bta_dm_disc_result
 *
 * Description      Service discovery result when discovering services on a
 *                  device
 *
 * Returns          void
 *
 ******************************************************************************/
void bta_dm_disc_result(tBTA_DM_MSG* p_data) {
  APPL_TRACE_EVENT("%s", __func__);

  /* if any BR/EDR service discovery has been done, report the event */
  if ((bta_dm_search_cb.services &
       ((BTA_ALL_SERVICE_MASK | BTA_USER_SERVICE_MASK) &
        ~BTA_BLE_SERVICE_MASK)))
    bta_dm_search_cb.p_search_cback(BTA_DM_DISC_RES_EVT,
                                    &p_data->disc_result.result);

  bta_dm_search_cmpl();
}

/*******************************************************************************
 *
 * Function         bta_dm_search_result
 *
 * Description      Service discovery result while searching for devices
 *
 * Returns          void
 *
 ******************************************************************************/
void bta_dm_search_result(tBTA_DM_MSG* p_data) {
  APPL_TRACE_DEBUG("%s searching:0x%04x, result:0x%04x", __func__,
                   bta_dm_search_cb.services,
                   p_data->disc_result.result.disc_res.services);

  /* call back if application wants name discovery or found services that
   * application is searching */
  if ((!bta_dm_search_cb.services) ||
      ((bta_dm_search_cb.services) &&
       (p_data->disc_result.result.disc_res.services))) {
    bta_dm_search_cb.p_search_cback(BTA_DM_DISC_RES_EVT,
                                    &p_data->disc_result.result);
  }

  /* if searching did not initiate to create link */
  if (!bta_dm_search_cb.wait_disc) {
    /* if service searching is done with EIR, don't search next device */
    if (bta_dm_search_cb.p_btm_inq_info) bta_dm_discover_next_device();
  } else {
    /* wait until link is disconnected or timeout */
    bta_dm_search_cb.sdp_results = true;
    alarm_set_on_mloop(bta_dm_search_cb.search_timer,
                       1000 * (L2CAP_LINK_INACTIVITY_TOUT + 1),
                       bta_dm_search_timer_cback, NULL);
  }
}

/*******************************************************************************
 *
 * Function         bta_dm_search_timer_cback
 *
 * Description      Called when ACL disconnect time is over
 *
 *
 * Returns          void
 *
 ******************************************************************************/
static void bta_dm_search_timer_cback(UNUSED_ATTR void* data) {
  APPL_TRACE_EVENT("%s", __func__);
  bta_dm_search_cb.wait_disc = false;

  /* proceed with next device */
  bta_dm_discover_next_device();
}

/*******************************************************************************
 *
 * Function         bta_dm_free_sdp_db
 *
 * Description      Frees SDP data base
 *
 * Returns          void
 *
 ******************************************************************************/
void bta_dm_free_sdp_db() {
  osi_free_and_reset((void**)&bta_dm_search_cb.p_sdp_db);
}

/*******************************************************************************
 *
 * Function         bta_dm_queue_search
 *
 * Description      Queues search command
 *
 * Returns          void
 *
 ******************************************************************************/
void bta_dm_queue_search(tBTA_DM_MSG* p_data) {
  osi_free_and_reset((void**)&bta_dm_search_cb.p_pending_search);
  bta_dm_search_cb.p_pending_search =
      (tBTA_DM_MSG*)osi_malloc(sizeof(tBTA_DM_API_SEARCH));
  memcpy(bta_dm_search_cb.p_pending_search, p_data, sizeof(tBTA_DM_API_SEARCH));
}

/*******************************************************************************
 *
 * Function         bta_dm_queue_disc
 *
 * Description      Queues discovery command
 *
 * Returns          void
 *
 ******************************************************************************/
void bta_dm_queue_disc(tBTA_DM_MSG* p_data) {
  tBTA_DM_MSG* p_pending_discovery =
      (tBTA_DM_MSG*)osi_malloc(sizeof(tBTA_DM_API_DISCOVER));
  memcpy(p_pending_discovery, p_data, sizeof(tBTA_DM_API_DISCOVER));
  fixed_queue_enqueue(bta_dm_search_cb.pending_discovery_queue,
                      p_pending_discovery);
}

/*******************************************************************************
 *
 * Function         bta_dm_execute_queued_request
 *
 * Description      Executes queued request if one exists
 *
 * Returns          void
 *
 ******************************************************************************/
void bta_dm_execute_queued_request() {
  if (bta_dm_search_cb.p_pending_search) {
    // Updated queued event to search event to trigger start search
    if (bta_dm_search_cb.p_pending_search->hdr.event ==
        BTA_DM_API_QUEUE_SEARCH_EVT) {
      bta_dm_search_cb.p_pending_search->hdr.event = BTA_DM_API_SEARCH_EVT;
    }
    LOG_INFO("%s Start pending search", __func__);
    bta_sys_sendmsg(bta_dm_search_cb.p_pending_search);
    bta_dm_search_cb.p_pending_search = NULL;
  } else {
    tBTA_DM_MSG* p_pending_discovery = (tBTA_DM_MSG*)fixed_queue_try_dequeue(
        bta_dm_search_cb.pending_discovery_queue);
    if (p_pending_discovery) {
      if (p_pending_discovery->hdr.event == BTA_DM_API_QUEUE_DISCOVER_EVT) {
        p_pending_discovery->hdr.event = BTA_DM_API_DISCOVER_EVT;
      }
      LOG_INFO("%s Start pending discovery", __func__);
      bta_sys_sendmsg(p_pending_discovery);
    }
  }
}

/*******************************************************************************
 *
 * Function         bta_dm_is_search_request_queued
 *
 * Description      Checks if there is a queued search request
 *
 * Returns          bool
 *
 ******************************************************************************/
bool bta_dm_is_search_request_queued() {
  return bta_dm_search_cb.p_pending_search != NULL;
}

/*******************************************************************************
 *
 * Function         bta_dm_search_clear_queue
 *
 * Description      Clears the queue if API search cancel is called
 *
 * Returns          void
 *
 ******************************************************************************/
void bta_dm_search_clear_queue() {
  osi_free_and_reset((void**)&bta_dm_search_cb.p_pending_search);
  fixed_queue_flush(bta_dm_search_cb.pending_discovery_queue, osi_free);
}

/*******************************************************************************
 *
 * Function         bta_dm_search_cancel_notify
 *
 * Description      Notify application that search has been cancelled
 *
 * Returns          void
 *
 ******************************************************************************/
void bta_dm_search_cancel_notify() {
  if (bta_dm_search_cb.p_search_cback) {
    bta_dm_search_cb.p_search_cback(BTA_DM_SEARCH_CANCEL_CMPL_EVT, NULL);
  }
  if (!bta_dm_search_cb.name_discover_done &&
      (bta_dm_search_cb.state == BTA_DM_SEARCH_ACTIVE ||
       bta_dm_search_cb.state == BTA_DM_SEARCH_CANCELLING)) {
    BTM_CancelRemoteDeviceName();
  }
  if (bta_dm_search_cb.gatt_disc_active) {
    bta_dm_cancel_gatt_discovery(bta_dm_search_cb.peer_bdaddr);
  }
}

/*******************************************************************************
 *
 * Function         bta_dm_find_services
 *
 * Description      Starts discovery on a device
 *
 * Returns          void
 *
 ******************************************************************************/
static void bta_dm_find_services(const RawAddress& bd_addr) {
  while (bta_dm_search_cb.service_index < BTA_MAX_SERVICE_ID) {
    Uuid uuid = Uuid::kEmpty;
    if (bta_dm_search_cb.services_to_search &
        (tBTA_SERVICE_MASK)(
            BTA_SERVICE_ID_TO_SERVICE_MASK(bta_dm_search_cb.service_index))) {
      bta_dm_search_cb.p_sdp_db =
          (tSDP_DISCOVERY_DB*)osi_malloc(BTA_DM_SDP_DB_SIZE);
      APPL_TRACE_DEBUG("bta_dm_search_cb.services = %04x***********",
                       bta_dm_search_cb.services);
      /* try to search all services by search based on L2CAP UUID */
      if (bta_dm_search_cb.services == BTA_ALL_SERVICE_MASK) {
        LOG_INFO("%s services_to_search=%08x", __func__,
                 bta_dm_search_cb.services_to_search);
        if (bta_dm_search_cb.services_to_search & BTA_RES_SERVICE_MASK) {
          uuid = Uuid::From16Bit(bta_service_id_to_uuid_lkup_tbl[0]);
          bta_dm_search_cb.services_to_search &= ~BTA_RES_SERVICE_MASK;
        } else {
          uuid = Uuid::From16Bit(UUID_PROTOCOL_L2CAP);
          bta_dm_search_cb.services_to_search = 0;
        }
      } else {
        /* for LE only profile */
        if (bta_dm_search_cb.service_index == BTA_BLE_SERVICE_ID) {
          uuid = Uuid::From16Bit(
              bta_service_id_to_uuid_lkup_tbl[bta_dm_search_cb.service_index]);

          bta_dm_search_cb.services_to_search &= (tBTA_SERVICE_MASK)(~(
              BTA_SERVICE_ID_TO_SERVICE_MASK(bta_dm_search_cb.service_index)));
        } else {
          /* remove the service from services to be searched  */
          bta_dm_search_cb.services_to_search &= (tBTA_SERVICE_MASK)(~(
              BTA_SERVICE_ID_TO_SERVICE_MASK(bta_dm_search_cb.service_index)));
          uuid = Uuid::From16Bit(
              bta_service_id_to_uuid_lkup_tbl[bta_dm_search_cb.service_index]);
        }
      }

      LOG_INFO("%s search UUID = %s", __func__, uuid.ToString().c_str());
      SDP_InitDiscoveryDb(bta_dm_search_cb.p_sdp_db, BTA_DM_SDP_DB_SIZE, 1,
                          &uuid, 0, NULL);

      memset(g_disc_raw_data_buf, 0, sizeof(g_disc_raw_data_buf));
      bta_dm_search_cb.p_sdp_db->raw_data = g_disc_raw_data_buf;

      bta_dm_search_cb.p_sdp_db->raw_size = MAX_DISC_RAW_DATA_BUF;

      if (!SDP_ServiceSearchAttributeRequest(bd_addr, bta_dm_search_cb.p_sdp_db,
                                             &bta_dm_sdp_callback)) {
        /*
         * If discovery is not successful with this device, then
         * proceed with the next one.
         */
        osi_free_and_reset((void**)&bta_dm_search_cb.p_sdp_db);
        bta_dm_search_cb.service_index = BTA_MAX_SERVICE_ID;

      } else {
        bta_dm_search_cb.service_index++;
        return;
      }
    }

    bta_dm_search_cb.service_index++;
  }

  /* no more services to be discovered */
  if (bta_dm_search_cb.service_index >= BTA_MAX_SERVICE_ID) {
    tBTA_DM_MSG* p_msg = (tBTA_DM_MSG*)osi_malloc(sizeof(tBTA_DM_MSG));
    /* initialize the data structure */
    memset(&(p_msg->disc_result.result), 0, sizeof(tBTA_DM_DISC_RES));
    p_msg->hdr.event = BTA_DM_DISCOVERY_RESULT_EVT;
    p_msg->disc_result.result.disc_res.services =
        bta_dm_search_cb.services_found;
    p_msg->disc_result.result.disc_res.bd_addr = bta_dm_search_cb.peer_bdaddr;
    strlcpy((char*)p_msg->disc_result.result.disc_res.bd_name,
            bta_dm_get_remname(), BD_NAME_LEN + 1);

    bta_sys_sendmsg(p_msg);
  }
}

/*******************************************************************************
 *
 * Function         bta_dm_discover_next_device
 *
 * Description      Starts discovery on the next device in Inquiry data base
 *
 * Returns          void
 *
 ******************************************************************************/
static void bta_dm_discover_next_device(void) {
  APPL_TRACE_DEBUG("bta_dm_discover_next_device");

  /* searching next device on inquiry result */
  bta_dm_search_cb.p_btm_inq_info =
      BTM_InqDbNext(bta_dm_search_cb.p_btm_inq_info);
  if (bta_dm_search_cb.p_btm_inq_info != NULL) {
    bta_dm_search_cb.name_discover_done = false;
    bta_dm_search_cb.peer_name[0] = 0;
    bta_dm_discover_device(
        bta_dm_search_cb.p_btm_inq_info->results.remote_bd_addr);
  } else {
    tBTA_DM_MSG* p_msg = (tBTA_DM_MSG*)osi_malloc(sizeof(tBTA_DM_MSG));

    /* no devices, search complete */
    bta_dm_search_cb.services = 0;

    p_msg->hdr.event = BTA_DM_SEARCH_CMPL_EVT;
    bta_sys_sendmsg(p_msg);
  }
}

/*******************************************************************************
 *
 * Function         bta_dm_discover_device
 *
 * Description      Starts name and service discovery on the device
 *
 * Returns          void
 *
 ******************************************************************************/
static void bta_dm_discover_device(const RawAddress& remote_bd_addr) {
  tBT_TRANSPORT transport = BT_TRANSPORT_BR_EDR;
  if (bta_dm_search_cb.transport == BT_TRANSPORT_UNKNOWN) {
    tBT_DEVICE_TYPE dev_type;
    tBLE_ADDR_TYPE addr_type;

    BTM_ReadDevInfo(remote_bd_addr, &dev_type, &addr_type);
    if (dev_type == BT_DEVICE_TYPE_BLE || addr_type == BLE_ADDR_RANDOM)
      transport = BT_TRANSPORT_LE;
  } else {
    transport = bta_dm_search_cb.transport;
  }

  VLOG(1) << __func__ << " BDA: " << remote_bd_addr;

  bta_dm_search_cb.peer_bdaddr = remote_bd_addr;

  APPL_TRACE_DEBUG(
      "%s name_discover_done = %d p_btm_inq_info 0x%x state = %d, transport=%d",
      __func__, bta_dm_search_cb.name_discover_done,
      bta_dm_search_cb.p_btm_inq_info, bta_dm_search_cb.state, transport);

  if (bta_dm_search_cb.p_btm_inq_info) {
    APPL_TRACE_DEBUG("%s appl_knows_rem_name %d", __func__,
                     bta_dm_search_cb.p_btm_inq_info->appl_knows_rem_name);
  }
  if (((bta_dm_search_cb.p_btm_inq_info) &&
       (bta_dm_search_cb.p_btm_inq_info->results.device_type ==
        BT_DEVICE_TYPE_BLE) &&
       (bta_dm_search_cb.state == BTA_DM_SEARCH_ACTIVE)) ||
      (transport == BT_TRANSPORT_LE &&
       interop_match_addr(INTEROP_DISABLE_NAME_REQUEST,
                          &bta_dm_search_cb.peer_bdaddr))) {
    /* Do not perform RNR for LE devices at inquiry complete*/
    bta_dm_search_cb.name_discover_done = true;
  }
  /* if name discovery is not done and application needs remote name */
  if ((!bta_dm_search_cb.name_discover_done) &&
      ((bta_dm_search_cb.p_btm_inq_info == NULL) ||
       (bta_dm_search_cb.p_btm_inq_info &&
        (!bta_dm_search_cb.p_btm_inq_info->appl_knows_rem_name)))) {
    if (bta_dm_read_remote_device_name(bta_dm_search_cb.peer_bdaddr,
                                       transport)) {
      if (bta_dm_search_cb.state != BTA_DM_DISCOVER_ACTIVE) {
        /* Reset transport state for next discovery */
        bta_dm_search_cb.transport = BT_TRANSPORT_UNKNOWN;
      }
      return;
    }

    /* starting name discovery failed */
    bta_dm_search_cb.name_discover_done = true;
  }

  /* Reset transport state for next discovery */
  bta_dm_search_cb.transport = BT_TRANSPORT_UNKNOWN;

  /* if application wants to discover service */
  if (bta_dm_search_cb.services) {
    /* initialize variables */
    bta_dm_search_cb.service_index = 0;
    bta_dm_search_cb.services_found = 0;
    bta_dm_search_cb.services_to_search = bta_dm_search_cb.services;

    /* if seaching with EIR is not completed */
    if (bta_dm_search_cb.services_to_search) {
      /* check whether connection already exists to the device
         if connection exists, we don't have to wait for ACL
         link to go down to start search on next device */
      if (transport == BT_TRANSPORT_BR_EDR) {
        if (BTM_IsAclConnectionUp(bta_dm_search_cb.peer_bdaddr,
                                  BT_TRANSPORT_BR_EDR))
          bta_dm_search_cb.wait_disc = false;
        else
          bta_dm_search_cb.wait_disc = true;
      }
      if (bta_dm_search_cb.p_btm_inq_info) {
        APPL_TRACE_DEBUG(
            "%s p_btm_inq_info 0x%x results.device_type 0x%x "
            "services_to_search 0x%x",
            __func__, bta_dm_search_cb.p_btm_inq_info,
            bta_dm_search_cb.p_btm_inq_info->results.device_type,
            bta_dm_search_cb.services_to_search);
      }

      if (transport == BT_TRANSPORT_LE) {
        if (bta_dm_search_cb.services_to_search & BTA_BLE_SERVICE_MASK) {
          // set the raw data buffer here
          memset(g_disc_raw_data_buf, 0, sizeof(g_disc_raw_data_buf));
          /* start GATT for service discovery */
          btm_dm_start_gatt_discovery(bta_dm_search_cb.peer_bdaddr);
          return;
        }
      } else {
        bta_dm_search_cb.sdp_results = false;
        bta_dm_find_services(bta_dm_search_cb.peer_bdaddr);
        return;
      }
    }
  }

  /* name discovery and service discovery are done for this device */
  tBTA_DM_MSG* p_msg = (tBTA_DM_MSG*)osi_malloc(sizeof(tBTA_DM_MSG));
  p_msg->hdr.event = BTA_DM_DISCOVERY_RESULT_EVT;
  /* initialize the data structure */
  memset(&(p_msg->disc_result.result), 0, sizeof(tBTA_DM_DISC_RES));
  p_msg->disc_result.result.disc_res.result = BTA_SUCCESS;
  p_msg->disc_result.result.disc_res.services = bta_dm_search_cb.services_found;
  p_msg->disc_result.result.disc_res.bd_addr = bta_dm_search_cb.peer_bdaddr;
  strlcpy((char*)p_msg->disc_result.result.disc_res.bd_name,
          (char*)bta_dm_search_cb.peer_name, BD_NAME_LEN + 1);

  bta_sys_sendmsg(p_msg);
}

/*******************************************************************************
 *
 * Function         bta_dm_sdp_callback
 *
 * Description      Callback from sdp with discovery status
 *
 * Returns          void
 *
 ******************************************************************************/
static void bta_dm_sdp_callback(tSDP_STATUS sdp_status) {
  tBTA_DM_SDP_RESULT* p_msg =
      (tBTA_DM_SDP_RESULT*)osi_malloc(sizeof(tBTA_DM_SDP_RESULT));

  p_msg->hdr.event = BTA_DM_SDP_RESULT_EVT;
  p_msg->sdp_result = static_cast<uint16_t>(sdp_status);

  bta_sys_sendmsg(p_msg);
}

/*******************************************************************************
 *
 * Function         bta_dm_inq_results_cb
 *
 * Description      Inquiry results callback from BTM
 *
 * Returns          void
 *
 ******************************************************************************/
static void bta_dm_inq_results_cb(tBTM_INQ_RESULTS* p_inq, uint8_t* p_eir,
                                  uint16_t eir_len) {
  tBTA_DM_SEARCH result;
  tBTM_INQ_INFO* p_inq_info;
  uint16_t service_class;

  result.inq_res.bd_addr = p_inq->remote_bd_addr;
  memcpy(result.inq_res.dev_class, p_inq->dev_class, DEV_CLASS_LEN);
  BTM_COD_SERVICE_CLASS(service_class, p_inq->dev_class);
  result.inq_res.is_limited =
      (service_class & BTM_COD_SERVICE_LMTD_DISCOVER) ? true : false;
  result.inq_res.rssi = p_inq->rssi;

  result.inq_res.ble_addr_type = p_inq->ble_addr_type;
  result.inq_res.inq_result_type = p_inq->inq_result_type;
  result.inq_res.device_type = p_inq->device_type;
  result.inq_res.flag = p_inq->flag;

  /* application will parse EIR to find out remote device name */
  result.inq_res.p_eir = p_eir;
  result.inq_res.eir_len = eir_len;

  p_inq_info = BTM_InqDbRead(p_inq->remote_bd_addr);
  if (p_inq_info != NULL) {
    /* initialize remt_name_not_required to false so that we get the name by
     * default */
    result.inq_res.remt_name_not_required = false;
  }

  if (bta_dm_search_cb.p_search_cback)
    bta_dm_search_cb.p_search_cback(BTA_DM_INQ_RES_EVT, &result);

  if (p_inq_info) {
    /* application indicates if it knows the remote name, inside the callback
     copy that to the inquiry data base*/
    if (result.inq_res.remt_name_not_required)
      p_inq_info->appl_knows_rem_name = true;
  }
}

/*******************************************************************************
 *
 * Function         bta_dm_inq_cmpl_cb
 *
 * Description      Inquiry complete callback from BTM
 *
 * Returns          void
 *
 ******************************************************************************/
static void bta_dm_inq_cmpl_cb(void* p_result) {
  APPL_TRACE_DEBUG("%s", __func__);

  bta_dm_inq_cmpl(((tBTM_INQUIRY_CMPL*)p_result)->num_resp);
}

/*******************************************************************************
 *
 * Function         bta_dm_service_search_remname_cback
 *
 * Description      Remote name call back from BTM during service discovery
 *
 * Returns          void
 *
 ******************************************************************************/
static void bta_dm_service_search_remname_cback(const RawAddress& bd_addr,
                                                UNUSED_ATTR DEV_CLASS dc,
                                                BD_NAME bd_name) {
  tBTM_REMOTE_DEV_NAME rem_name;
  tBTM_STATUS btm_status;

  APPL_TRACE_DEBUG("%s name=<%s>", __func__, bd_name);

  /* if this is what we are looking for */
  if (bta_dm_search_cb.peer_bdaddr == bd_addr) {
    rem_name.length = strlcpy((char*)rem_name.remote_bd_name, (char*)bd_name,
                              BD_NAME_LEN + 1);
    if (rem_name.length > BD_NAME_LEN) {
      rem_name.length = BD_NAME_LEN;
    }
    rem_name.status = BTM_SUCCESS;

    bta_dm_remname_cback(&rem_name);
  } else {
    /* get name of device */
    btm_status =
        BTM_ReadRemoteDeviceName(bta_dm_search_cb.peer_bdaddr,
                                 bta_dm_remname_cback, BT_TRANSPORT_BR_EDR);
    if (btm_status == BTM_BUSY) {
      /* wait for next chance(notification of remote name discovery done) */
      APPL_TRACE_DEBUG("%s: BTM_ReadRemoteDeviceName is busy", __func__);
    } else if (btm_status != BTM_CMD_STARTED) {
      /* if failed to start getting remote name then continue */
      APPL_TRACE_WARNING("%s: BTM_ReadRemoteDeviceName returns 0x%02X",
                         __func__, btm_status);

      rem_name.length = 0;
      rem_name.remote_bd_name[0] = 0;
      rem_name.status = btm_status;
      bta_dm_remname_cback(&rem_name);
    }
  }
}

/*******************************************************************************
 *
 * Function         bta_dm_remname_cback
 *
 * Description      Remote name complete call back from BTM
 *
 * Returns          void
 *
 ******************************************************************************/
static void bta_dm_remname_cback(void* p) {
  tBTM_REMOTE_DEV_NAME* p_remote_name = (tBTM_REMOTE_DEV_NAME*)p;
  APPL_TRACE_DEBUG("bta_dm_remname_cback len = %d name=<%s>",
                   p_remote_name->length, p_remote_name->remote_bd_name);

  /* remote name discovery is done but it could be failed */
  bta_dm_search_cb.name_discover_done = true;
  strlcpy((char*)bta_dm_search_cb.peer_name,
          (char*)p_remote_name->remote_bd_name, BD_NAME_LEN + 1);

  if (bluetooth::shim::is_gd_security_enabled()) {
    bluetooth::shim::BTM_SecDeleteRmtNameNotifyCallback(
        &bta_dm_service_search_remname_cback);
  } else {
    BTM_SecDeleteRmtNameNotifyCallback(&bta_dm_service_search_remname_cback);
  }

  if (bta_dm_search_cb.transport == BT_TRANSPORT_LE) {
    GAP_BleReadPeerPrefConnParams(bta_dm_search_cb.peer_bdaddr);
  }

  tBTA_DM_REM_NAME* p_msg =
      (tBTA_DM_REM_NAME*)osi_malloc(sizeof(tBTA_DM_REM_NAME));
  p_msg->result.disc_res.bd_addr = bta_dm_search_cb.peer_bdaddr;
  strlcpy((char*)p_msg->result.disc_res.bd_name,
          (char*)p_remote_name->remote_bd_name, BD_NAME_LEN + 1);
  p_msg->hdr.event = BTA_DM_REMT_NAME_EVT;

  bta_sys_sendmsg(p_msg);
}

/*******************************************************************************
 *
 * Function         bta_dm_pinname_cback
 *
 * Description      Callback requesting pin_key
 *
 * Returns          void
 *
 ******************************************************************************/
static void bta_dm_pinname_cback(void* p_data) {
  tBTM_REMOTE_DEV_NAME* p_result = (tBTM_REMOTE_DEV_NAME*)p_data;
  tBTA_DM_SEC sec_event;
  uint32_t bytes_to_copy;
  tBTA_DM_SEC_EVT event = bta_dm_cb.pin_evt;

  if (BTA_DM_SP_CFM_REQ_EVT == event) {
    /* Retrieved saved device class and bd_addr */
    sec_event.cfm_req.bd_addr = bta_dm_cb.pin_bd_addr;
    BTA_COPY_DEVICE_CLASS(sec_event.cfm_req.dev_class, bta_dm_cb.pin_dev_class);

    if (p_result && p_result->status == BTM_SUCCESS) {
      bytes_to_copy =
          (p_result->length < BD_NAME_LEN) ? p_result->length : BD_NAME_LEN;
      memcpy(sec_event.cfm_req.bd_name, p_result->remote_bd_name,
             bytes_to_copy);
      sec_event.pin_req.bd_name[BD_NAME_LEN] = 0;
    } else /* No name found */
      sec_event.cfm_req.bd_name[0] = 0;

    sec_event.key_notif.passkey =
        bta_dm_cb.num_val; /* get PIN code numeric number */

    /* 1 additional event data fields for this event */
    sec_event.cfm_req.just_works = bta_dm_cb.just_works;
    /* retrieve the loc and rmt caps */
    sec_event.cfm_req.loc_io_caps = bta_dm_cb.loc_io_caps;
    sec_event.cfm_req.rmt_io_caps = bta_dm_cb.rmt_io_caps;
    sec_event.cfm_req.loc_auth_req = bta_dm_cb.loc_auth_req;
    sec_event.cfm_req.rmt_auth_req = bta_dm_cb.rmt_auth_req;

  } else {
    /* Retrieved saved device class and bd_addr */
    sec_event.pin_req.bd_addr = bta_dm_cb.pin_bd_addr;
    BTA_COPY_DEVICE_CLASS(sec_event.pin_req.dev_class, bta_dm_cb.pin_dev_class);

    if (p_result && p_result->status == BTM_SUCCESS) {
      bytes_to_copy = (p_result->length < BD_NAME_LEN) ? p_result->length
                                                       : (BD_NAME_LEN - 1);
      memcpy(sec_event.pin_req.bd_name, p_result->remote_bd_name,
             bytes_to_copy);
      sec_event.pin_req.bd_name[BD_NAME_LEN] = 0;
    } else /* No name found */
      sec_event.pin_req.bd_name[0] = 0;

    event = bta_dm_cb.pin_evt;
    sec_event.key_notif.passkey =
        bta_dm_cb.num_val; /* get PIN code numeric number */
  }

  if (bta_dm_cb.p_sec_cback) bta_dm_cb.p_sec_cback(event, &sec_event);
}

/*******************************************************************************
 *
 * Function         bta_dm_pin_cback
 *
 * Description      Callback requesting pin_key
 *
 * Returns          void
 *
 ******************************************************************************/
static uint8_t bta_dm_pin_cback(const RawAddress& bd_addr, DEV_CLASS dev_class,
                                BD_NAME bd_name, bool min_16_digit) {
  tBTA_DM_SEC sec_event;

  if (!bta_dm_cb.p_sec_cback) return BTM_NOT_AUTHORIZED;

  /* If the device name is not known, save bdaddr and devclass and initiate a
   * name request */
  if (bd_name[0] == 0) {
    bta_dm_cb.pin_evt = BTA_DM_PIN_REQ_EVT;
    bta_dm_cb.pin_bd_addr = bd_addr;
    BTA_COPY_DEVICE_CLASS(bta_dm_cb.pin_dev_class, dev_class);
    if ((BTM_ReadRemoteDeviceName(bd_addr, bta_dm_pinname_cback,
                                  BT_TRANSPORT_BR_EDR)) == BTM_CMD_STARTED)
      return BTM_CMD_STARTED;

    APPL_TRACE_WARNING(
        " bta_dm_pin_cback() -> Failed to start Remote Name Request  ");
  }

  sec_event.pin_req.bd_addr = bd_addr;
  BTA_COPY_DEVICE_CLASS(sec_event.pin_req.dev_class, dev_class);
  strlcpy((char*)sec_event.pin_req.bd_name, (char*)bd_name, BD_NAME_LEN + 1);
  sec_event.pin_req.min_16_digit = min_16_digit;

  bta_dm_cb.p_sec_cback(BTA_DM_PIN_REQ_EVT, &sec_event);
  return BTM_CMD_STARTED;
}

/*******************************************************************************
 *
 * Function         bta_dm_new_link_key_cback
 *
 * Description      Callback from BTM to notify new link key
 *
 * Returns          void
 *
 ******************************************************************************/
static uint8_t bta_dm_new_link_key_cback(const RawAddress& bd_addr,
                                         UNUSED_ATTR DEV_CLASS dev_class,
                                         BD_NAME bd_name, const LinkKey& key,
                                         uint8_t key_type) {
  tBTA_DM_SEC sec_event;
  tBTA_DM_AUTH_CMPL* p_auth_cmpl;
  uint8_t event;

  memset(&sec_event, 0, sizeof(tBTA_DM_SEC));

  event = BTA_DM_AUTH_CMPL_EVT;
  p_auth_cmpl = &sec_event.auth_cmpl;

  p_auth_cmpl->bd_addr = bd_addr;

  memcpy(p_auth_cmpl->bd_name, bd_name, BD_NAME_LEN);
  p_auth_cmpl->bd_name[BD_NAME_LEN] = 0;
  p_auth_cmpl->key_present = true;
  p_auth_cmpl->key_type = key_type;
  p_auth_cmpl->success = true;
  p_auth_cmpl->key = key;
  sec_event.auth_cmpl.fail_reason = HCI_SUCCESS;

  // Report the BR link key based on the BR/EDR address and type
  BTM_ReadDevInfo(bd_addr, &sec_event.auth_cmpl.dev_type,
                  &sec_event.auth_cmpl.addr_type);
  if (bta_dm_cb.p_sec_cback) bta_dm_cb.p_sec_cback(event, &sec_event);

  // Setting remove_dev_pending flag to false, where it will avoid deleting
  // the
  // security device record when the ACL connection link goes down in case of
  // reconnection.
  if (bta_dm_cb.device_list.count)
    bta_dm_reset_sec_dev_pending(p_auth_cmpl->bd_addr);

  return BTM_CMD_STARTED;
}

/*******************************************************************************
 *
 * Function         bta_dm_authentication_complete_cback
 *
 * Description      Authentication complete callback from BTM
 *
 * Returns          void
 *
 ******************************************************************************/
static void bta_dm_authentication_complete_cback(
    const RawAddress& bd_addr, UNUSED_ATTR DEV_CLASS dev_class, BD_NAME bd_name,
    tHCI_REASON reason) {
  if (reason != HCI_SUCCESS) {
    if (bta_dm_cb.p_sec_cback) {
      // Build out the security event data structure
      tBTA_DM_SEC sec_event = {
          .auth_cmpl =
              {
                  .bd_addr = bd_addr,
              },
      };
      memcpy(sec_event.auth_cmpl.bd_name, bd_name, BD_NAME_LEN);
      sec_event.auth_cmpl.bd_name[BD_NAME_LEN] = 0;

      // Report the BR link key based on the BR/EDR address and type
      BTM_ReadDevInfo(bd_addr, &sec_event.auth_cmpl.dev_type,
                      &sec_event.auth_cmpl.addr_type);
      sec_event.auth_cmpl.fail_reason = reason;

      bta_dm_cb.p_sec_cback(BTA_DM_AUTH_CMPL_EVT, &sec_event);
    }

    switch (reason) {
      case HCI_ERR_AUTH_FAILURE:
      case HCI_ERR_KEY_MISSING:
      case HCI_ERR_HOST_REJECT_SECURITY:
      case HCI_ERR_ENCRY_MODE_NOT_ACCEPTABLE:
        LOG_WARN(
            "Deleting device record as authentication failed entry:%s "
            "reason:%s",
            PRIVATE_ADDRESS(bd_addr), hci_reason_code_text(reason).c_str());
        break;

      default:
        break;
    }
  }
}

/*******************************************************************************
 *
 * Function         bta_dm_sp_cback
 *
 * Description      simple pairing callback from BTM
 *
 * Returns          void
 *
 ******************************************************************************/
static tBTM_STATUS bta_dm_sp_cback(tBTM_SP_EVT event,
                                   tBTM_SP_EVT_DATA* p_data) {
  tBTM_STATUS status = BTM_CMD_STARTED;
  tBTA_DM_SEC sec_event;
  tBTA_DM_SEC_EVT pin_evt = BTA_DM_SP_KEY_NOTIF_EVT;

  APPL_TRACE_EVENT("bta_dm_sp_cback: %d", event);
  if (!bta_dm_cb.p_sec_cback) return BTM_NOT_AUTHORIZED;

  bool sp_rmt_result = false;
  /* TODO_SP */
  switch (event) {
    case BTM_SP_IO_REQ_EVT:
      if (btm_local_io_caps != BTM_IO_CAP_NONE) {
        /* translate auth_req */
        btif_dm_set_oob_for_io_req(&p_data->io_req.oob_data);
        btif_dm_proc_io_req(&p_data->io_req.auth_req, p_data->io_req.is_orig);
      }
      APPL_TRACE_EVENT("io mitm: %d oob_data:%d", p_data->io_req.auth_req,
                       p_data->io_req.oob_data);
      break;
    case BTM_SP_IO_RSP_EVT:
      if (btm_local_io_caps != BTM_IO_CAP_NONE) {
        btif_dm_proc_io_rsp(p_data->io_rsp.bd_addr, p_data->io_rsp.io_cap,
                            p_data->io_rsp.oob_data, p_data->io_rsp.auth_req);
      }
      break;

    case BTM_SP_CFM_REQ_EVT:
      pin_evt = BTA_DM_SP_CFM_REQ_EVT;
      bta_dm_cb.just_works = sec_event.cfm_req.just_works =
          p_data->cfm_req.just_works;
      sec_event.cfm_req.loc_auth_req = p_data->cfm_req.loc_auth_req;
      sec_event.cfm_req.rmt_auth_req = p_data->cfm_req.rmt_auth_req;
      sec_event.cfm_req.loc_io_caps = p_data->cfm_req.loc_io_caps;
      sec_event.cfm_req.rmt_io_caps = p_data->cfm_req.rmt_io_caps;

      [[fallthrough]];
    /* Passkey entry mode, mobile device with output capability is very
        unlikely to receive key request, so skip this event */
    /*case BTM_SP_KEY_REQ_EVT: */
    case BTM_SP_KEY_NOTIF_EVT:
      if (btm_local_io_caps == BTM_IO_CAP_NONE &&
          BTM_SP_KEY_NOTIF_EVT == event) {
        status = BTM_NOT_AUTHORIZED;
        break;
      }

      bta_dm_cb.num_val = sec_event.key_notif.passkey =
          p_data->key_notif.passkey;

      if (BTM_SP_CFM_REQ_EVT == event) {
        /* Due to the switch case falling through below to BTM_SP_KEY_NOTIF_EVT,
           call remote name request using values from cfm_req */
        if (p_data->cfm_req.bd_name[0] == 0) {
          bta_dm_cb.pin_evt = pin_evt;
          bta_dm_cb.pin_bd_addr = p_data->cfm_req.bd_addr;
          bta_dm_cb.rmt_io_caps = sec_event.cfm_req.rmt_io_caps;
          bta_dm_cb.loc_io_caps = sec_event.cfm_req.loc_io_caps;
          bta_dm_cb.rmt_auth_req = sec_event.cfm_req.rmt_auth_req;
          bta_dm_cb.loc_auth_req = sec_event.cfm_req.loc_auth_req;

          BTA_COPY_DEVICE_CLASS(bta_dm_cb.pin_dev_class,
                                p_data->cfm_req.dev_class);
          if ((BTM_ReadRemoteDeviceName(
                  p_data->cfm_req.bd_addr, bta_dm_pinname_cback,
                  BT_TRANSPORT_BR_EDR)) == BTM_CMD_STARTED)
            return BTM_CMD_STARTED;
          APPL_TRACE_WARNING(
              " bta_dm_sp_cback() -> Failed to start Remote Name Request  ");
        } else {
          /* Due to the switch case falling through below to
             BTM_SP_KEY_NOTIF_EVT,
             copy these values into key_notif from cfm_req */
          sec_event.key_notif.bd_addr = p_data->cfm_req.bd_addr;
          BTA_COPY_DEVICE_CLASS(sec_event.key_notif.dev_class,
                                p_data->cfm_req.dev_class);
          strlcpy((char*)sec_event.key_notif.bd_name,
                  (char*)p_data->cfm_req.bd_name, BD_NAME_LEN + 1);
        }
      }

      if (BTM_SP_KEY_NOTIF_EVT == event) {
        /* If the device name is not known, save bdaddr and devclass
           and initiate a name request with values from key_notif */
        if (p_data->key_notif.bd_name[0] == 0) {
          bta_dm_cb.pin_evt = pin_evt;
          bta_dm_cb.pin_bd_addr = p_data->key_notif.bd_addr;
          BTA_COPY_DEVICE_CLASS(bta_dm_cb.pin_dev_class,
                                p_data->key_notif.dev_class);
          if ((BTM_ReadRemoteDeviceName(
                  p_data->key_notif.bd_addr, bta_dm_pinname_cback,
                  BT_TRANSPORT_BR_EDR)) == BTM_CMD_STARTED)
            return BTM_CMD_STARTED;
          APPL_TRACE_WARNING(
              " bta_dm_sp_cback() -> Failed to start Remote Name Request  ");
        } else {
          sec_event.key_notif.bd_addr = p_data->key_notif.bd_addr;
          BTA_COPY_DEVICE_CLASS(sec_event.key_notif.dev_class,
                                p_data->key_notif.dev_class);
          strlcpy((char*)sec_event.key_notif.bd_name,
                  (char*)p_data->key_notif.bd_name, BD_NAME_LEN + 1);
          sec_event.key_notif.bd_name[BD_NAME_LEN] = 0;
        }
      }

      bta_dm_cb.p_sec_cback(pin_evt, &sec_event);

      break;

    case BTM_SP_LOC_OOB_EVT:
#ifdef BTIF_DM_OOB_TEST
      btif_dm_proc_loc_oob(BT_TRANSPORT_BR_EDR,
                           (bool)(p_data->loc_oob.status == BTM_SUCCESS),
                           p_data->loc_oob.c, p_data->loc_oob.r);
#endif
      break;

    case BTM_SP_RMT_OOB_EVT: {
      Octet16 c;
      Octet16 r;
      sp_rmt_result = false;
#ifdef BTIF_DM_OOB_TEST
      sp_rmt_result = btif_dm_proc_rmt_oob(p_data->rmt_oob.bd_addr, &c, &r);
#endif
      BTIF_TRACE_DEBUG("bta_dm_ci_rmt_oob: result=%d", sp_rmt_result);
      bta_dm_ci_rmt_oob(sp_rmt_result, p_data->rmt_oob.bd_addr, c, r);
      break;
    }

    default:
      status = BTM_NOT_AUTHORIZED;
      break;
  }
  APPL_TRACE_EVENT("dm status: %d", status);
  return status;
}

/*******************************************************************************
 *
 * Function         bta_dm_local_name_cback
 *
 * Description      Callback from btm after local name is read
 *
 *
 * Returns          void
 *
 ******************************************************************************/
static void bta_dm_local_name_cback(UNUSED_ATTR void* p_name) {
  BTIF_dm_enable();
}

static void handle_role_change(const RawAddress& bd_addr, tHCI_ROLE new_role,
                               tHCI_STATUS hci_status) {
  tBTA_DM_PEER_DEVICE* p_dev = bta_dm_find_peer_device(bd_addr);
  if (!p_dev) {
    LOG_WARN(
        "Unable to find device for role change peer:%s new_role:%s "
        "hci_status:%s",
        PRIVATE_ADDRESS(bd_addr), RoleText(new_role).c_str(),
        hci_error_code_text(hci_status).c_str());
    return;
  }

  LOG_INFO(
      "Role change callback peer:%s info:0x%x new_role:%s dev count:%d "
      "hci_status:%s",
      PRIVATE_ADDRESS(bd_addr), p_dev->Info(), RoleText(new_role).c_str(),
      bta_dm_cb.device_list.count, hci_error_code_text(hci_status).c_str());

  if (p_dev->Info() & BTA_DM_DI_AV_ACTIVE) {
    bool need_policy_change = false;

    /* there's AV activity on this link */
    if (new_role == HCI_ROLE_PERIPHERAL && bta_dm_cb.device_list.count > 1 &&
        hci_status == HCI_SUCCESS) {
      /* more than one connections and the AV connection is role switched
       * to peripheral
       * switch it back to central and remove the switch policy */
      BTM_SwitchRoleToCentral(bd_addr);
      need_policy_change = true;
    } else if (p_bta_dm_cfg->avoid_scatter && (new_role == HCI_ROLE_CENTRAL)) {
      /* if the link updated to be central include AV activities, remove
       * the switch policy */
      need_policy_change = true;
    }

    if (need_policy_change) {
      BTM_block_role_switch_for(p_dev->peer_bdaddr);
    }
  } else {
    /* there's AV no activity on this link and role switch happened
     * check if AV is active
     * if so, make sure the AV link is central */
    bta_dm_check_av();
  }
  bta_sys_notify_role_chg(bd_addr, new_role, hci_status);
}

void BTA_dm_report_role_change(const RawAddress bd_addr, tHCI_ROLE new_role,
                               tHCI_STATUS hci_status) {
  do_in_main_thread(
      FROM_HERE, base::Bind(handle_role_change, bd_addr, new_role, hci_status));
}

void handle_remote_features_complete(const RawAddress& bd_addr) {
  tBTA_DM_PEER_DEVICE* p_dev = bta_dm_find_peer_device(bd_addr);
  if (!p_dev) {
    LOG_WARN("Unable to find device peer:%s", PRIVATE_ADDRESS(bd_addr));
    return;
  }

  if (controller_get_interface()->supports_sniff_subrating() &&
      acl_peer_supports_sniff_subrating(bd_addr)) {
    LOG_DEBUG("Device supports sniff subrating peer:%s",
              PRIVATE_ADDRESS(bd_addr));
    p_dev->info = BTA_DM_DI_USE_SSR;
  } else {
    LOG_DEBUG("Device does NOT support sniff subrating peer:%s",
              PRIVATE_ADDRESS(bd_addr));
  }
}

void BTA_dm_notify_remote_features_complete(const RawAddress bd_addr) {
  do_in_main_thread(FROM_HERE,
                    base::Bind(handle_remote_features_complete, bd_addr));
}

static tBTA_DM_PEER_DEVICE* allocate_device_for(const RawAddress& bd_addr,
                                                tBT_TRANSPORT transport) {
  for (uint8_t i = 0; i < bta_dm_cb.device_list.count; i++) {
    auto device = &bta_dm_cb.device_list.peer_device[i];
    if (device->peer_bdaddr == bd_addr && device->transport == transport) {
      return device;
    }
  }

  if (bta_dm_cb.device_list.count < BTA_DM_NUM_PEER_DEVICE) {
    auto device =
        &bta_dm_cb.device_list.peer_device[bta_dm_cb.device_list.count];
    device->peer_bdaddr = bd_addr;
    bta_dm_cb.device_list.count++;
    if (transport == BT_TRANSPORT_LE) {
      bta_dm_cb.device_list.le_count++;
    }
    return device;
  }
  return nullptr;
}

void bta_dm_acl_up(const RawAddress& bd_addr, tBT_TRANSPORT transport) {
  auto device = allocate_device_for(bd_addr, transport);
  if (device == nullptr) {
    LOG_WARN("Unable to allocate device resources for new connection");
    return;
  }
  device->conn_state = BTA_DM_CONNECTED;
  device->pref_role = BTA_ANY_ROLE;
  device->info = BTA_DM_DI_NONE;
  device->transport = transport;

  if (controller_get_interface()->supports_sniff_subrating() &&
      acl_peer_supports_sniff_subrating(bd_addr)) {
    // NOTE: This callback assumes upon ACL connection that
    // the read remote features has completed and is valid.
    // The only guaranteed contract for valid read remote features
    // data is when the BTA_dm_notify_remote_features_complete()
    // callback has completed.  The below assignment is kept for
    // transitional informational purposes only.
    device->info = BTA_DM_DI_USE_SSR;
  }

  if (bta_dm_cb.p_sec_cback) {
    tBTA_DM_SEC conn;
    memset(&conn, 0, sizeof(tBTA_DM_SEC));
    conn.link_up.bd_addr = bd_addr;

    bta_dm_cb.p_sec_cback(BTA_DM_LINK_UP_EVT, &conn);
    LOG_DEBUG("Executed security callback for new connection available");
  }
  bta_dm_adjust_roles(true);
}

void BTA_dm_acl_up(const RawAddress bd_addr, tBT_TRANSPORT transport) {
  do_in_main_thread(FROM_HERE, base::Bind(bta_dm_acl_up, bd_addr, transport));
}

static void bta_dm_acl_down(const RawAddress& bd_addr,
                            tBT_TRANSPORT transport) {
  bool issue_unpair_cb = false;
  bool remove_device = false;

  for (uint8_t i = 0; i < bta_dm_cb.device_list.count; i++) {
    auto device = &bta_dm_cb.device_list.peer_device[i];
    if (device->peer_bdaddr != bd_addr || device->transport != transport)
      continue;

    if (device->conn_state == BTA_DM_UNPAIRING) {
      issue_unpair_cb =
          (bluetooth::shim::is_gd_security_enabled())
              ? bluetooth::shim::BTM_SecDeleteDevice(device->peer_bdaddr)
              : BTM_SecDeleteDevice(device->peer_bdaddr);

      /* remove all cached GATT information */
      BTA_GATTC_Refresh(bd_addr);

      APPL_TRACE_DEBUG("%s: Unpairing: issue unpair CB = %d ", __func__,
                       issue_unpair_cb);
    }

    remove_device = device->remove_dev_pending;

    // Iterate to the one before the last when shrinking the list,
    // otherwise we memcpy garbage data into the record.
    // Then clear out the last item in the list since we are shrinking.
    for (; i < bta_dm_cb.device_list.count - 1; i++) {
      memcpy(&bta_dm_cb.device_list.peer_device[i],
             &bta_dm_cb.device_list.peer_device[i + 1],
             sizeof(bta_dm_cb.device_list.peer_device[i]));
    }
    if (bta_dm_cb.device_list.count > 0) {
      int clear_index = bta_dm_cb.device_list.count - 1;
      memset(&bta_dm_cb.device_list.peer_device[clear_index], 0,
             sizeof(bta_dm_cb.device_list.peer_device[clear_index]));
    }
    break;
  }
  if (bta_dm_cb.device_list.count) bta_dm_cb.device_list.count--;
  if ((transport == BT_TRANSPORT_LE) && (bta_dm_cb.device_list.le_count)) {
    bta_dm_cb.device_list.le_count--;
  }

  if ((transport == BT_TRANSPORT_BR_EDR) &&
      (bta_dm_search_cb.wait_disc && bta_dm_search_cb.peer_bdaddr == bd_addr)) {
    bta_dm_search_cb.wait_disc = false;

    if (bta_dm_search_cb.sdp_results) {
      APPL_TRACE_EVENT(" timer stopped  ");
      alarm_cancel(bta_dm_search_cb.search_timer);
      bta_dm_discover_next_device();
    }
  }

  if (bta_dm_cb.disabling) {
    if (!BTM_GetNumAclLinks()) {
      /*
       * Start a timer to make sure that the profiles
       * get the disconnect event.
       */
      alarm_set_on_mloop(bta_dm_cb.disable_timer,
                         BTA_DM_DISABLE_CONN_DOWN_TIMER_MS,
                         bta_dm_disable_conn_down_timer_cback, NULL);
    }
  }
  if (remove_device) {
    bta_dm_process_remove_device_no_callback(bd_addr);
  }

  if (bta_dm_cb.p_sec_cback) {
    tBTA_DM_SEC conn;
    memset(&conn, 0, sizeof(tBTA_DM_SEC));
    conn.link_down.bd_addr = bd_addr;

    bta_dm_cb.p_sec_cback(BTA_DM_LINK_DOWN_EVT, &conn);
    if (issue_unpair_cb) bta_dm_cb.p_sec_cback(BTA_DM_DEV_UNPAIRED_EVT, &conn);
  }

  bta_dm_adjust_roles(true);
}

void BTA_dm_acl_down(const RawAddress bd_addr, tBT_TRANSPORT transport) {
  do_in_main_thread(FROM_HERE, base::Bind(bta_dm_acl_down, bd_addr, transport));
}

/*******************************************************************************
 *
 * Function         bta_dm_check_av
 *
 * Description      This function checks if AV is active
 *                  if yes, make sure the AV link is central
 *
 ******************************************************************************/
static void bta_dm_check_av() {
  uint8_t i;
  tBTA_DM_PEER_DEVICE* p_dev;

  if (bta_dm_cb.cur_av_count) {
    LOG_INFO("av_count:%d", bta_dm_cb.cur_av_count);
    for (i = 0; i < bta_dm_cb.device_list.count; i++) {
      p_dev = &bta_dm_cb.device_list.peer_device[i];
      APPL_TRACE_WARNING("[%d]: state:%d, info:x%x", i, p_dev->conn_state,
                         p_dev->Info());
      if ((p_dev->conn_state == BTA_DM_CONNECTED) &&
          (p_dev->Info() & BTA_DM_DI_AV_ACTIVE)) {
        /* make central and take away the role switch policy */
        BTM_SwitchRoleToCentral(p_dev->peer_bdaddr);
        /* else either already central or can not switch for some reasons */
        BTM_block_role_switch_for(p_dev->peer_bdaddr);
        break;
      }
    }
  }
}

/*******************************************************************************
 *
 * Function         bta_dm_disable_conn_down_timer_cback
 *
 * Description      Sends disable event to application
 *
 *
 * Returns          void
 *
 ******************************************************************************/
static void bta_dm_disable_conn_down_timer_cback(UNUSED_ATTR void* data) {
  /* disable the power managment module */
  bta_dm_disable_pm();

  bta_dm_cb.disabling = false;
  LOG_INFO("Stack device manager shutdown completed");
  future_ready(stack_manager_get_hack_future(), FUTURE_SUCCESS);
}

/*******************************************************************************
 *
 * Function         bta_dm_rm_cback
 *
 * Description      Role management callback from sys
 *
 *
 * Returns          void
 *
 ******************************************************************************/
void bta_dm_rm_cback(tBTA_SYS_CONN_STATUS status, uint8_t id, uint8_t app_id,
                     const RawAddress& peer_addr) {
  uint8_t j;
  tBTA_PREF_ROLES role;
  tBTA_DM_PEER_DEVICE* p_dev;

  LOG_DEBUG("BTA Role management callback count:%d status:%s peer:%s",
            bta_dm_cb.cur_av_count, bta_sys_conn_status_text(status).c_str(),
            PRIVATE_ADDRESS(peer_addr));

  p_dev = bta_dm_find_peer_device(peer_addr);
  if (status == BTA_SYS_CONN_OPEN) {
    if (p_dev) {
      /* Do not set to connected if we are in the middle of unpairing. When AV
       * stream is
       * started it fakes out a SYS_CONN_OPEN to potentially trigger a role
       * switch command.
       * But this should not be done if we are in the middle of unpairing.
       */
      if (p_dev->conn_state != BTA_DM_UNPAIRING)
        p_dev->conn_state = BTA_DM_CONNECTED;

      for (j = 1; j <= p_bta_dm_rm_cfg[0].app_id; j++) {
        if (((p_bta_dm_rm_cfg[j].app_id == app_id) ||
             (p_bta_dm_rm_cfg[j].app_id == BTA_ALL_APP_ID)) &&
            (p_bta_dm_rm_cfg[j].id == id)) {
          ASSERT_LOG(p_bta_dm_rm_cfg[j].cfg <= BTA_PERIPHERAL_ROLE_ONLY,
                     "Passing illegal preferred role:0x%02x [0x%02x<=>0x%02x]",
                     p_bta_dm_rm_cfg[j].cfg, BTA_ANY_ROLE,
                     BTA_PERIPHERAL_ROLE_ONLY);
          role = static_cast<tBTA_PREF_ROLES>(p_bta_dm_rm_cfg[j].cfg);
          if (role > p_dev->pref_role) p_dev->pref_role = role;
          break;
        }
      }
    }
  }

  if (BTA_ID_AV == id) {
    if (status == BTA_SYS_CONN_BUSY) {
      if (p_dev) p_dev->info |= BTA_DM_DI_AV_ACTIVE;
      /* AV calls bta_sys_conn_open with the A2DP stream count as app_id */
      if (BTA_ID_AV == id) bta_dm_cb.cur_av_count = bta_dm_get_av_count();
    } else if (status == BTA_SYS_CONN_IDLE) {
      if (p_dev) p_dev->info &= ~BTA_DM_DI_AV_ACTIVE;

      /* get cur_av_count from connected services */
      if (BTA_ID_AV == id) bta_dm_cb.cur_av_count = bta_dm_get_av_count();
    }
  }

  /* Don't adjust roles for each busy/idle state transition to avoid
     excessive switch requests when individual profile busy/idle status
     changes */
  if ((status != BTA_SYS_CONN_BUSY) && (status != BTA_SYS_CONN_IDLE))
    bta_dm_adjust_roles(false);
}

/*******************************************************************************
 *
 * Function         bta_dm_delay_role_switch_cback
 *
 * Description      Callback from btm to delay a role switch
 *
 * Returns          void
 *
 ******************************************************************************/
static void bta_dm_delay_role_switch_cback(UNUSED_ATTR void* data) {
  APPL_TRACE_EVENT("%s: initiating Delayed RS", __func__);
  bta_dm_adjust_roles(false);
}

/*******************************************************************************
 *
 * Function         bta_dm_reset_sec_dev_pending
 *
 * Description      Setting the remove device pending status to false from
 *                  security device DB, when the link key notification
 *                  event comes.
 *
 * Returns          void
 *
 ******************************************************************************/
static void bta_dm_reset_sec_dev_pending(const RawAddress& remote_bd_addr) {
  for (size_t i = 0; i < bta_dm_cb.device_list.count; i++) {
    if (bta_dm_cb.device_list.peer_device[i].peer_bdaddr == remote_bd_addr) {
      bta_dm_cb.device_list.peer_device[i].remove_dev_pending = false;
      return;
    }
  }
}

/*******************************************************************************
 *
 * Function         bta_dm_remove_sec_dev_entry
 *
 * Description      Removes device entry from Security device DB if ACL
 connection with
 *                  remtoe device does not exist, else schedule for dev entry
 removal upon
                     ACL close
 *
 * Returns          void
 *
 ******************************************************************************/
static void bta_dm_remove_sec_dev_entry(const RawAddress& remote_bd_addr) {
  if (BTM_IsAclConnectionUp(remote_bd_addr, BT_TRANSPORT_LE) ||
      BTM_IsAclConnectionUp(remote_bd_addr, BT_TRANSPORT_BR_EDR)) {
    APPL_TRACE_DEBUG(
        "%s ACL is not down. Schedule for  Dev Removal when ACL closes",
        __func__);
    if (bluetooth::shim::is_gd_security_enabled()) {
      bluetooth::shim::BTM_SecClearSecurityFlags(remote_bd_addr);
    } else {
      BTM_SecClearSecurityFlags(remote_bd_addr);
    }
    for (int i = 0; i < bta_dm_cb.device_list.count; i++) {
      if (bta_dm_cb.device_list.peer_device[i].peer_bdaddr == remote_bd_addr) {
        bta_dm_cb.device_list.peer_device[i].remove_dev_pending = TRUE;
        break;
      }
    }
  } else {
    // remote_bd_addr comes from security record, which is removed in
    // BTM_SecDeleteDevice.
    RawAddress addr_copy = remote_bd_addr;
    bta_dm_process_remove_device_no_callback(addr_copy);
  }
}

/*******************************************************************************
 *
 * Function         bta_dm_adjust_roles
 *
 * Description      Adjust roles
 *
 *
 * Returns          void
 *
 ******************************************************************************/
static void bta_dm_adjust_roles(bool delay_role_switch) {
  uint8_t i;
  uint8_t br_count =
      bta_dm_cb.device_list.count - bta_dm_cb.device_list.le_count;
  if (br_count) {
    for (i = 0; i < bta_dm_cb.device_list.count; i++) {
      if (bta_dm_cb.device_list.peer_device[i].conn_state == BTA_DM_CONNECTED &&
          bta_dm_cb.device_list.peer_device[i].transport ==
              BT_TRANSPORT_BR_EDR) {
        if ((bta_dm_cb.device_list.peer_device[i].pref_role ==
             BTA_CENTRAL_ROLE_ONLY) ||
            (br_count > 1)) {
          /* Initiating immediate role switch with certain remote devices
            has caused issues due to role  switch colliding with link encryption
            setup and
            causing encryption (and in turn the link) to fail .  These device .
            Firmware
            versions are stored in a rejectlist and role switch with these
            devices are
            delayed to avoid the collision with link encryption setup */

          if (bta_dm_cb.device_list.peer_device[i].pref_role !=
                  BTA_PERIPHERAL_ROLE_ONLY &&
              !delay_role_switch) {
            BTM_SwitchRoleToCentral(
                bta_dm_cb.device_list.peer_device[i].peer_bdaddr);
          } else {
            alarm_set_on_mloop(bta_dm_cb.switch_delay_timer,
                               BTA_DM_SWITCH_DELAY_TIMER_MS,
                               bta_dm_delay_role_switch_cback, NULL);
          }
        }
      }
    }
  }
}

/*******************************************************************************
 *
 * Function         bta_dm_get_remname
 *
 * Description      Returns a pointer to the remote name stored in the DM
 *                  control block if it exists, or from the BTM memory.
 *
 * Returns          char * - Pointer to the remote device name
 ******************************************************************************/
static char* bta_dm_get_remname(void) {
  char* p_name = (char*)bta_dm_search_cb.peer_name;
  char* p_temp;

  /* If the name isn't already stored, try retrieving from BTM */
  if (*p_name == '\0') {
    p_temp =
        (bluetooth::shim::is_gd_security_enabled())
            ? bluetooth::shim::BTM_SecReadDevName(bta_dm_search_cb.peer_bdaddr)
            : BTM_SecReadDevName(bta_dm_search_cb.peer_bdaddr);
    if (p_temp != NULL) p_name = p_temp;
  }

  return p_name;
}

/*******************************************************************************
 *
 * Function         bta_dm_bond_cancel_complete_cback
 *
 * Description      Authentication complete callback from BTM
 *
 * Returns          void
 *
 ******************************************************************************/
static void bta_dm_bond_cancel_complete_cback(tBTM_STATUS result) {
  tBTA_DM_SEC sec_event;

  if (result == BTM_SUCCESS)
    sec_event.bond_cancel_cmpl.result = BTA_SUCCESS;
  else
    sec_event.bond_cancel_cmpl.result = BTA_FAILURE;

  if (bta_dm_cb.p_sec_cback) {
    bta_dm_cb.p_sec_cback(BTA_DM_BOND_CANCEL_CMPL_EVT, &sec_event);
  }
}

/*******************************************************************************
 *
 * Function         find_utf8_char_boundary
 *
 * Description      This function checks a UTF8 string |utf8str| starting at
 *                  |offset|, moving backwards and returns the offset of the
 *                  next valid UTF8 character boundary found.
 *
 * Returns          Offset of UTF8 character boundary
 *
 ******************************************************************************/
static size_t find_utf8_char_boundary(const char* utf8str, size_t offset) {
  CHECK(utf8str);
  CHECK(offset > 0);

  while (--offset) {
    uint8_t ch = (uint8_t)utf8str[offset];
    if ((ch & 0x80) == 0x00)  // ASCII
      return offset + 1;
    if ((ch & 0xC0) == 0xC0)  // Multi-byte sequence start
      return offset;
  }

  return 0;
}

/*******************************************************************************
 *
 * Function         bta_dm_set_eir
 *
 * Description      This function creates EIR tagged data and writes it to
 *                  controller.
 *
 * Returns          None
 *
 ******************************************************************************/
static void bta_dm_set_eir(char* local_name) {
  uint8_t* p;
  uint8_t* p_length;
#if (BTA_EIR_CANNED_UUID_LIST != TRUE)
  uint8_t* p_type;
  uint8_t max_num_uuid;
#if (BTA_EIR_SERVER_NUM_CUSTOM_UUID > 0)
  uint8_t custom_uuid_idx;
#endif  // BTA_EIR_SERVER_NUM_CUSTOM_UUID
#endif  // BTA_EIR_CANNED_UUID_LIST
#if (BTM_EIR_DEFAULT_FEC_REQUIRED == FALSE)
  uint8_t free_eir_length = HCI_EXT_INQ_RESPONSE_LEN;
#else  // BTM_EIR_DEFAULT_FEC_REQUIRED
  uint8_t free_eir_length = HCI_DM5_PACKET_SIZE;
#endif  // BTM_EIR_DEFAULT_FEC_REQUIRED
  uint8_t num_uuid;
  uint8_t data_type;
  uint8_t local_name_len;

  /* wait until complete to disable */
  if (alarm_is_scheduled(bta_dm_cb.disable_timer)) return;

#if (BTA_EIR_CANNED_UUID_LIST != TRUE)
  /* if local name is not provided, get it from controller */
  if (local_name == NULL) {
    if (BTM_ReadLocalDeviceName(&local_name) != BTM_SUCCESS) {
      APPL_TRACE_ERROR("Fail to read local device name for EIR");
    }
  }
#endif  // BTA_EIR_CANNED_UUID_LIST

  /* Allocate a buffer to hold HCI command */
  BT_HDR* p_buf = (BT_HDR*)osi_malloc(BTM_CMD_BUF_SIZE);
  p = (uint8_t*)p_buf + BTM_HCI_EIR_OFFSET;

  memset(p, 0x00, HCI_EXT_INQ_RESPONSE_LEN);

  LOG_INFO("Generating extended inquiry response packet EIR");

  if (local_name)
    local_name_len = strlen(local_name);
  else
    local_name_len = 0;

  data_type = BTM_EIR_COMPLETE_LOCAL_NAME_TYPE;
  /* if local name is longer than minimum length of shortened name */
  /* check whether it needs to be shortened or not */
  if (local_name_len > p_bta_dm_eir_cfg->bta_dm_eir_min_name_len) {
/* get number of UUID 16-bit list */
#if (BTA_EIR_CANNED_UUID_LIST == TRUE)
    num_uuid = p_bta_dm_eir_cfg->bta_dm_eir_uuid16_len / Uuid::kNumBytes16;
#else   // BTA_EIR_CANNED_UUID_LIST
    max_num_uuid = (free_eir_length - 2) / Uuid::kNumBytes16;
    data_type = BTM_GetEirSupportedServices(bta_dm_cb.eir_uuid, &p,
                                            max_num_uuid, &num_uuid);
    p = (uint8_t*)p_buf + BTM_HCI_EIR_OFFSET; /* reset p */
#endif  // BTA_EIR_CANNED_UUID_LIST

    /* if UUID doesn't fit remaing space, shorten local name */
    if (local_name_len > (free_eir_length - 4 - num_uuid * Uuid::kNumBytes16)) {
      local_name_len = find_utf8_char_boundary(
          local_name, p_bta_dm_eir_cfg->bta_dm_eir_min_name_len);
      APPL_TRACE_WARNING("%s local name is shortened (%d)", __func__,
                         local_name_len);
      data_type = BTM_EIR_SHORTENED_LOCAL_NAME_TYPE;
    } else {
      data_type = BTM_EIR_COMPLETE_LOCAL_NAME_TYPE;
    }
  }

  UINT8_TO_STREAM(p, local_name_len + 1);
  UINT8_TO_STREAM(p, data_type);

  if (local_name != NULL) {
    memcpy(p, local_name, local_name_len);
    p += local_name_len;
  }
  free_eir_length -= local_name_len + 2;

#if (BTA_EIR_CANNED_UUID_LIST == TRUE)
  /* if UUID list is provided as static data in configuration */
  if ((p_bta_dm_eir_cfg->bta_dm_eir_uuid16_len > 0) &&
      (p_bta_dm_eir_cfg->bta_dm_eir_uuid16)) {
    if (free_eir_length > Uuid::kNumBytes16 + 2) {
      free_eir_length -= 2;

      if (free_eir_length >= p_bta_dm_eir_cfg->bta_dm_eir_uuid16_len) {
        num_uuid = p_bta_dm_eir_cfg->bta_dm_eir_uuid16_len / Uuid::kNumBytes16;
        data_type = BTM_EIR_COMPLETE_16BITS_UUID_TYPE;
      } else /* not enough room for all UUIDs */
      {
        APPL_TRACE_WARNING("BTA EIR: UUID 16-bit list is truncated");
        num_uuid = free_eir_length / Uuid::kNumBytes16;
        data_type = BTM_EIR_MORE_16BITS_UUID_TYPE;
      }
      UINT8_TO_STREAM(p, num_uuid * Uuid::kNumBytes16 + 1);
      UINT8_TO_STREAM(p, data_type);
      memcpy(p, p_bta_dm_eir_cfg->bta_dm_eir_uuid16,
             num_uuid * Uuid::kNumBytes16);
      p += num_uuid * Uuid::kNumBytes16;
      free_eir_length -= num_uuid * Uuid::kNumBytes16;
    }
  }
#else /* (BTA_EIR_CANNED_UUID_LIST == TRUE) */
  /* if UUID list is dynamic */
  if (free_eir_length >= 2) {
    p_length = p++;
    p_type = p++;
    num_uuid = 0;

    max_num_uuid = (free_eir_length - 2) / Uuid::kNumBytes16;
    data_type = BTM_GetEirSupportedServices(bta_dm_cb.eir_uuid, &p,
                                            max_num_uuid, &num_uuid);

    if (data_type == BTM_EIR_MORE_16BITS_UUID_TYPE) {
      APPL_TRACE_WARNING("BTA EIR: UUID 16-bit list is truncated");
    }
#if (BTA_EIR_SERVER_NUM_CUSTOM_UUID > 0)
    else {
      for (custom_uuid_idx = 0;
           custom_uuid_idx < BTA_EIR_SERVER_NUM_CUSTOM_UUID;
           custom_uuid_idx++) {
        const Uuid& curr = bta_dm_cb.bta_custom_uuid[custom_uuid_idx].custom_uuid;
        if (curr.GetShortestRepresentationSize() == Uuid::kNumBytes16) {
          if (num_uuid < max_num_uuid) {
            UINT16_TO_STREAM(p, curr.As16Bit());
            num_uuid++;
          } else {
            data_type = BTM_EIR_MORE_16BITS_UUID_TYPE;
            APPL_TRACE_WARNING("BTA EIR: UUID 16-bit list is truncated");
            break;
          }
        }
      }
    }
#endif /* (BTA_EIR_SERVER_NUM_CUSTOM_UUID > 0) */

    UINT8_TO_STREAM(p_length, num_uuid * Uuid::kNumBytes16 + 1);
    UINT8_TO_STREAM(p_type, data_type);
    free_eir_length -= num_uuid * Uuid::kNumBytes16 + 2;
  }
#endif /* (BTA_EIR_CANNED_UUID_LIST == TRUE) */

#if (BTA_EIR_CANNED_UUID_LIST != TRUE && BTA_EIR_SERVER_NUM_CUSTOM_UUID > 0)
  /* Adding 32-bit UUID list */
  if (free_eir_length >= 2) {
    p_length = p++;
    p_type = p++;
    num_uuid = 0;
    data_type = BTM_EIR_COMPLETE_32BITS_UUID_TYPE;

    max_num_uuid = (free_eir_length - 2) / Uuid::kNumBytes32;

    for (custom_uuid_idx = 0; custom_uuid_idx < BTA_EIR_SERVER_NUM_CUSTOM_UUID;
         custom_uuid_idx++) {
      const Uuid& curr = bta_dm_cb.bta_custom_uuid[custom_uuid_idx].custom_uuid;
      if (curr.GetShortestRepresentationSize() == Uuid::kNumBytes32) {
        if (num_uuid < max_num_uuid) {
          UINT32_TO_STREAM(p, curr.As32Bit());
          num_uuid++;
        } else {
          data_type = BTM_EIR_MORE_32BITS_UUID_TYPE;
          APPL_TRACE_WARNING("BTA EIR: UUID 32-bit list is truncated");
          break;
        }
      }
    }

    UINT8_TO_STREAM(p_length, num_uuid * Uuid::kNumBytes32 + 1);
    UINT8_TO_STREAM(p_type, data_type);
    free_eir_length -= num_uuid * Uuid::kNumBytes32 + 2;
  }

  /* Adding 128-bit UUID list */
  if (free_eir_length >= 2) {
    p_length = p++;
    p_type = p++;
    num_uuid = 0;
    data_type = BTM_EIR_COMPLETE_128BITS_UUID_TYPE;

    max_num_uuid = (free_eir_length - 2) / Uuid::kNumBytes128;

    for (custom_uuid_idx = 0; custom_uuid_idx < BTA_EIR_SERVER_NUM_CUSTOM_UUID;
         custom_uuid_idx++) {
      const Uuid& curr = bta_dm_cb.bta_custom_uuid[custom_uuid_idx].custom_uuid;
      if (curr.GetShortestRepresentationSize() == Uuid::kNumBytes128) {
        if (num_uuid < max_num_uuid) {
          ARRAY16_TO_STREAM(p, curr.To128BitBE().data());
          num_uuid++;
        } else {
          data_type = BTM_EIR_MORE_128BITS_UUID_TYPE;
          APPL_TRACE_WARNING("BTA EIR: UUID 128-bit list is truncated");
          break;
        }
      }
    }

    UINT8_TO_STREAM(p_length, num_uuid * Uuid::kNumBytes128 + 1);
    UINT8_TO_STREAM(p_type, data_type);
    free_eir_length -= num_uuid * Uuid::kNumBytes128 + 2;
  }
#endif /* ( BTA_EIR_CANNED_UUID_LIST != TRUE \
          )&&(BTA_EIR_SERVER_NUM_CUSTOM_UUID > 0) */

  /* if Flags are provided in configuration */
  if ((p_bta_dm_eir_cfg->bta_dm_eir_flag_len > 0) &&
      (p_bta_dm_eir_cfg->bta_dm_eir_flags) &&
      (free_eir_length >= p_bta_dm_eir_cfg->bta_dm_eir_flag_len + 2)) {
    UINT8_TO_STREAM(p, p_bta_dm_eir_cfg->bta_dm_eir_flag_len + 1);
    UINT8_TO_STREAM(p, BTM_EIR_FLAGS_TYPE);
    memcpy(p, p_bta_dm_eir_cfg->bta_dm_eir_flags,
           p_bta_dm_eir_cfg->bta_dm_eir_flag_len);
    p += p_bta_dm_eir_cfg->bta_dm_eir_flag_len;
    free_eir_length -= p_bta_dm_eir_cfg->bta_dm_eir_flag_len + 2;
  }

  /* if Manufacturer Specific are provided in configuration */
  if ((p_bta_dm_eir_cfg->bta_dm_eir_manufac_spec_len > 0) &&
      (p_bta_dm_eir_cfg->bta_dm_eir_manufac_spec) &&
      (free_eir_length >= p_bta_dm_eir_cfg->bta_dm_eir_manufac_spec_len + 2)) {
    p_length = p;

    UINT8_TO_STREAM(p, p_bta_dm_eir_cfg->bta_dm_eir_manufac_spec_len + 1);
    UINT8_TO_STREAM(p, HCI_EIR_MANUFACTURER_SPECIFIC_TYPE);
    memcpy(p, p_bta_dm_eir_cfg->bta_dm_eir_manufac_spec,
           p_bta_dm_eir_cfg->bta_dm_eir_manufac_spec_len);
    p += p_bta_dm_eir_cfg->bta_dm_eir_manufac_spec_len;
    free_eir_length -= p_bta_dm_eir_cfg->bta_dm_eir_manufac_spec_len + 2;

  } else {
    p_length = NULL;
  }

  /* if Inquiry Tx Resp Power compiled */
  if ((p_bta_dm_eir_cfg->bta_dm_eir_inq_tx_power) && (free_eir_length >= 3)) {
    UINT8_TO_STREAM(p, 2); /* Length field */
    UINT8_TO_STREAM(p, BTM_EIR_TX_POWER_LEVEL_TYPE);
    UINT8_TO_STREAM(p, *(p_bta_dm_eir_cfg->bta_dm_eir_inq_tx_power));
    free_eir_length -= 3;
  }

  if (free_eir_length)
    UINT8_TO_STREAM(p, 0); /* terminator of significant part */

  BTM_WriteEIR(p_buf);
}

#if (BTA_EIR_CANNED_UUID_LIST != TRUE)
/*******************************************************************************
 *
 * Function         bta_dm_get_cust_uuid_index
 *
 * Description      Get index of custom uuid from list
 *                  Note, handle equals to 0 means to find a vacant
 *                  from list.
 *
 * Returns          Index of array
 *                  bta_dm_cb.bta_custom_uuid[BTA_EIR_SERVER_NUM_CUSTOM_UUID]
 *
 ******************************************************************************/
static uint8_t bta_dm_get_cust_uuid_index(uint32_t handle) {
#if (BTA_EIR_SERVER_NUM_CUSTOM_UUID > 0)
  uint8_t c_uu_idx = 0;

  while(c_uu_idx < BTA_EIR_SERVER_NUM_CUSTOM_UUID &&
      bta_dm_cb.bta_custom_uuid[c_uu_idx].handle != handle) {
    c_uu_idx++;
  }

  return c_uu_idx;
#else
  return 0;
#endif
}

/*******************************************************************************
 *
 * Function         bta_dm_update_cust_uuid
 *
 * Description      Update custom uuid with given value
 *
 * Returns          None
 *
 ******************************************************************************/
static void bta_dm_update_cust_uuid(uint8_t c_uu_idx, const Uuid& uuid, uint32_t handle) {
#if (BTA_EIR_SERVER_NUM_CUSTOM_UUID > 0)
  if (c_uu_idx < BTA_EIR_SERVER_NUM_CUSTOM_UUID) {
    tBTA_CUSTOM_UUID& curr = bta_dm_cb.bta_custom_uuid[c_uu_idx];
    curr.custom_uuid.UpdateUuid(uuid);
    curr.handle = handle;
  } else {
    APPL_TRACE_ERROR("%s invalid uuid index %d", __func__, c_uu_idx);
  }
#endif
}

/*******************************************************************************
 *
 * Function         bta_dm_eir_update_cust_uuid
 *
 * Description      This function adds or removes custom service UUID in EIR database.
 *
 * Returns          None
 *
 ******************************************************************************/
void bta_dm_eir_update_cust_uuid(const tBTA_CUSTOM_UUID& curr, bool adding) {
  APPL_TRACE_DEBUG("%s", __func__);
#if (BTA_EIR_SERVER_NUM_CUSTOM_UUID > 0)
  uint8_t c_uu_idx = 0;
  if (adding) {
    c_uu_idx = bta_dm_get_cust_uuid_index(0); /* find a vacant from uuid list */
    bta_dm_update_cust_uuid(c_uu_idx, curr.custom_uuid, curr.handle);
  } else {
    c_uu_idx = bta_dm_get_cust_uuid_index(curr.handle); /* find the uuid from uuid list */
    bta_dm_update_cust_uuid(c_uu_idx, curr.custom_uuid, 0);
  }

  /* Update EIR when UUIDs are changed */
  if (c_uu_idx <= BTA_EIR_SERVER_NUM_CUSTOM_UUID) {
    bta_dm_set_eir(NULL);
  }
#endif
}

/*******************************************************************************
 *
 * Function         bta_dm_eir_update_uuid
 *
 * Description      This function adds or removes service UUID in EIR database.
 *
 * Returns          None
 *
 ******************************************************************************/
void bta_dm_eir_update_uuid(uint16_t uuid16, bool adding) {
  /* if this UUID is not advertised in EIR */
  if (!BTM_HasEirService(p_bta_dm_eir_cfg->uuid_mask, uuid16)) return;

  if (adding) {
    LOG_INFO("EIR Adding UUID=0x%04X into extended inquiry response", uuid16);

    BTM_AddEirService(bta_dm_cb.eir_uuid, uuid16);
  } else {
    LOG_INFO("EIR Removing UUID=0x%04X from extended inquiry response", uuid16);

    BTM_RemoveEirService(bta_dm_cb.eir_uuid, uuid16);
  }

  bta_dm_set_eir(NULL);
}
#endif

/*******************************************************************************
 *
 * Function         bta_dm_encrypt_cback
 *
 * Description      link encryption complete callback.
 *
 * Returns         None
 *
 ******************************************************************************/
void bta_dm_encrypt_cback(const RawAddress* bd_addr, tBT_TRANSPORT transport,
                          UNUSED_ATTR void* p_ref_data, tBTM_STATUS result) {
  tBTA_STATUS bta_status = BTA_SUCCESS;
  tBTA_DM_ENCRYPT_CBACK* p_callback = NULL;
  uint8_t i;

  for (i = 0; i < bta_dm_cb.device_list.count; i++) {
    if (bta_dm_cb.device_list.peer_device[i].peer_bdaddr == *bd_addr &&
        bta_dm_cb.device_list.peer_device[i].conn_state == BTA_DM_CONNECTED)
      break;
  }

  if (i < bta_dm_cb.device_list.count) {
    p_callback = bta_dm_cb.device_list.peer_device[i].p_encrypt_cback;
    bta_dm_cb.device_list.peer_device[i].p_encrypt_cback = NULL;
  }

  switch (result) {
    case BTM_SUCCESS:
      break;
    case BTM_WRONG_MODE:
      bta_status = BTA_WRONG_MODE;
      break;
    case BTM_NO_RESOURCES:
      bta_status = BTA_NO_RESOURCES;
      break;
    case BTM_BUSY:
      bta_status = BTA_BUSY;
      break;
    default:
      bta_status = BTA_FAILURE;
      break;
  }

  APPL_TRACE_DEBUG("bta_dm_encrypt_cback status =%d p_callback=0x%x",
                   bta_status, p_callback);

  if (p_callback) {
    (*p_callback)(*bd_addr, transport, bta_status);
  }
}

/**This function to encrypt the link */
void bta_dm_set_encryption(const RawAddress& bd_addr, tBT_TRANSPORT transport,
                           tBTA_DM_ENCRYPT_CBACK* p_callback,
                           tBTM_BLE_SEC_ACT sec_act) {
  uint8_t i;

  APPL_TRACE_DEBUG("bta_dm_set_encryption");  // todo
  if (!p_callback) {
    APPL_TRACE_ERROR("bta_dm_set_encryption callback is not provided");
    return;
  }
  for (i = 0; i < bta_dm_cb.device_list.count; i++) {
    if (bta_dm_cb.device_list.peer_device[i].peer_bdaddr == bd_addr &&
        bta_dm_cb.device_list.peer_device[i].conn_state == BTA_DM_CONNECTED)
      break;
  }
  if (i < bta_dm_cb.device_list.count) {
    if (bta_dm_cb.device_list.peer_device[i].p_encrypt_cback) {
      APPL_TRACE_ERROR("earlier enc was not done for same device");
      (*p_callback)(bd_addr, transport, BTA_BUSY);
      return;
    }

    if (BTM_SetEncryption(bd_addr, transport, bta_dm_encrypt_cback, NULL,
                          sec_act) == BTM_CMD_STARTED) {
      bta_dm_cb.device_list.peer_device[i].p_encrypt_cback = p_callback;
    }
  }
}

bool bta_dm_check_if_only_hd_connected(const RawAddress& peer_addr) {
  APPL_TRACE_DEBUG("%s: count(%d)", __func__, bta_dm_conn_srvcs.count);

  for (uint8_t j = 0; j < bta_dm_conn_srvcs.count; j++) {
    // Check if profiles other than hid are connected
    if ((bta_dm_conn_srvcs.conn_srvc[j].id != BTA_ID_HD) &&
        bta_dm_conn_srvcs.conn_srvc[j].peer_bdaddr == peer_addr) {
      APPL_TRACE_DEBUG("%s: Another profile (id=%d) is connected", __func__,
                       bta_dm_conn_srvcs.conn_srvc[j].id);
      return false;
    }
  }

  return true;
}

/*******************************************************************************
 *
 * Function         bta_dm_observe_results_cb
 *
 * Description      Callback for BLE Observe result
 *
 *
 * Returns          void
 *
 ******************************************************************************/
static void bta_dm_observe_results_cb(tBTM_INQ_RESULTS* p_inq, uint8_t* p_eir,
                                      uint16_t eir_len) {
  tBTA_DM_SEARCH result;
  tBTM_INQ_INFO* p_inq_info;
  APPL_TRACE_DEBUG("bta_dm_observe_results_cb");

  result.inq_res.bd_addr = p_inq->remote_bd_addr;
  result.inq_res.rssi = p_inq->rssi;
  result.inq_res.ble_addr_type = p_inq->ble_addr_type;
  result.inq_res.inq_result_type = p_inq->inq_result_type;
  result.inq_res.device_type = p_inq->device_type;
  result.inq_res.flag = p_inq->flag;
  result.inq_res.ble_evt_type = p_inq->ble_evt_type;
  result.inq_res.ble_primary_phy = p_inq->ble_primary_phy;
  result.inq_res.ble_secondary_phy = p_inq->ble_secondary_phy;
  result.inq_res.ble_advertising_sid = p_inq->ble_advertising_sid;
  result.inq_res.ble_tx_power = p_inq->ble_tx_power;
  result.inq_res.ble_periodic_adv_int = p_inq->ble_periodic_adv_int;

  /* application will parse EIR to find out remote device name */
  result.inq_res.p_eir = p_eir;
  result.inq_res.eir_len = eir_len;

  p_inq_info = BTM_InqDbRead(p_inq->remote_bd_addr);
  if (p_inq_info != NULL) {
    /* initialize remt_name_not_required to false so that we get the name by
     * default */
    result.inq_res.remt_name_not_required = false;
  }

  if (bta_dm_search_cb.p_scan_cback)
    bta_dm_search_cb.p_scan_cback(BTA_DM_INQ_RES_EVT, &result);

  if (p_inq_info) {
    /* application indicates if it knows the remote name, inside the callback
     copy that to the inquiry data base*/
    if (result.inq_res.remt_name_not_required)
      p_inq_info->appl_knows_rem_name = true;
  }
}

/*******************************************************************************
 *
 * Function         bta_dm_observe_cmpl_cb
 *
 * Description      Callback for BLE Observe complete
 *
 *
 * Returns          void
 *
 ******************************************************************************/
static void bta_dm_observe_cmpl_cb(void* p_result) {
  tBTA_DM_SEARCH data;

  APPL_TRACE_DEBUG("bta_dm_observe_cmpl_cb");

  data.inq_cmpl.num_resps = ((tBTM_INQUIRY_CMPL*)p_result)->num_resp;
  if (bta_dm_search_cb.p_scan_cback) {
    bta_dm_search_cb.p_scan_cback(BTA_DM_INQ_CMPL_EVT, &data);
  }
}

static void ble_io_req(const RawAddress& bd_addr, tBTM_IO_CAP* p_io_cap,
                       tBTM_OOB_DATA* p_oob_data, tBTM_LE_AUTH_REQ* p_auth_req,
                       uint8_t* p_max_key_size, tBTM_LE_KEY_TYPE* p_init_key,
                       tBTM_LE_KEY_TYPE* p_resp_key) {
  bte_appl_cfg.ble_io_cap = btif_storage_get_local_io_caps_ble();

  /* Retrieve the properties from file system if possible */
  tBTE_APPL_CFG nv_config;
  if (btif_dm_get_smp_config(&nv_config)) bte_appl_cfg = nv_config;

  /* *p_auth_req by default is false for devices with NoInputNoOutput; true for
   * other devices. */

  if (bte_appl_cfg.ble_auth_req)
    *p_auth_req = bte_appl_cfg.ble_auth_req |
                  (bte_appl_cfg.ble_auth_req & 0x04) | ((*p_auth_req) & 0x04);

  /* if OOB is not supported, this call-out function does not need to do
   * anything
   * otherwise, look for the OOB data associated with the address and set
   * *p_oob_data accordingly.
   * If the answer can not be obtained right away,
   * set *p_oob_data to BTA_OOB_UNKNOWN and call bta_dm_ci_io_req() when the
   * answer is available.
   */

  btif_dm_set_oob_for_le_io_req(bd_addr, p_oob_data, p_auth_req);

  if (bte_appl_cfg.ble_io_cap <= 4) *p_io_cap = bte_appl_cfg.ble_io_cap;

  if (bte_appl_cfg.ble_init_key <= BTM_BLE_INITIATOR_KEY_SIZE)
    *p_init_key = bte_appl_cfg.ble_init_key;

  if (bte_appl_cfg.ble_resp_key <= BTM_BLE_RESPONDER_KEY_SIZE)
    *p_resp_key = bte_appl_cfg.ble_resp_key;

  if (bte_appl_cfg.ble_max_key_size > 7 && bte_appl_cfg.ble_max_key_size <= 16)
    *p_max_key_size = bte_appl_cfg.ble_max_key_size;
}

/*******************************************************************************
 *
 * Function         bta_dm_ble_smp_cback
 *
 * Description      Callback for BLE SMP
 *
 *
 * Returns          void
 *
 ******************************************************************************/
static uint8_t bta_dm_ble_smp_cback(tBTM_LE_EVT event, const RawAddress& bda,
                                    tBTM_LE_EVT_DATA* p_data) {
  tBTM_STATUS status = BTM_SUCCESS;
  tBTA_DM_SEC sec_event;
  char* p_name = NULL;

  if (!bta_dm_cb.p_sec_cback) return BTM_NOT_AUTHORIZED;

  memset(&sec_event, 0, sizeof(tBTA_DM_SEC));
  switch (event) {
    case BTM_LE_IO_REQ_EVT:
      ble_io_req(bda, &p_data->io_req.io_cap, &p_data->io_req.oob_data,
                 &p_data->io_req.auth_req, &p_data->io_req.max_key_size,
                 &p_data->io_req.init_keys, &p_data->io_req.resp_keys);
      APPL_TRACE_EVENT("io mitm: %d oob_data:%d", p_data->io_req.auth_req,
                       p_data->io_req.oob_data);
      break;

    case BTM_LE_CONSENT_REQ_EVT:
      sec_event.ble_req.bd_addr = bda;
      p_name = BTM_SecReadDevName(bda);
      if (p_name != NULL)
        strlcpy((char*)sec_event.ble_req.bd_name, p_name, BD_NAME_LEN);
      else
        sec_event.ble_req.bd_name[0] = 0;
      bta_dm_cb.p_sec_cback(BTA_DM_BLE_CONSENT_REQ_EVT, &sec_event);
      break;

    case BTM_LE_SEC_REQUEST_EVT:
      sec_event.ble_req.bd_addr = bda;
      p_name = (bluetooth::shim::is_gd_security_enabled())
                   ? bluetooth::shim::BTM_SecReadDevName(bda)
                   : BTM_SecReadDevName(bda);
      if (p_name != NULL)
        strlcpy((char*)sec_event.ble_req.bd_name, p_name, BD_NAME_LEN + 1);
      else
        sec_event.ble_req.bd_name[0] = 0;
      bta_dm_cb.p_sec_cback(BTA_DM_BLE_SEC_REQ_EVT, &sec_event);
      break;

    case BTM_LE_KEY_NOTIF_EVT:
      sec_event.key_notif.bd_addr = bda;
      p_name = (bluetooth::shim::is_gd_security_enabled())
                   ? bluetooth::shim::BTM_SecReadDevName(bda)
                   : BTM_SecReadDevName(bda);
      if (p_name != NULL)
        strlcpy((char*)sec_event.key_notif.bd_name, p_name, BD_NAME_LEN + 1);
      else
        sec_event.key_notif.bd_name[0] = 0;
      sec_event.key_notif.passkey = p_data->key_notif;
      bta_dm_cb.p_sec_cback(BTA_DM_BLE_PASSKEY_NOTIF_EVT, &sec_event);
      break;

    case BTM_LE_KEY_REQ_EVT:
      sec_event.ble_req.bd_addr = bda;
      bta_dm_cb.p_sec_cback(BTA_DM_BLE_PASSKEY_REQ_EVT, &sec_event);
      break;

    case BTM_LE_OOB_REQ_EVT:
      sec_event.ble_req.bd_addr = bda;
      bta_dm_cb.p_sec_cback(BTA_DM_BLE_OOB_REQ_EVT, &sec_event);
      break;

    case BTM_LE_NC_REQ_EVT:
      sec_event.key_notif.bd_addr = bda;
      strlcpy((char*)sec_event.key_notif.bd_name, bta_dm_get_remname(),
              (BD_NAME_LEN + 1));
      sec_event.key_notif.passkey = p_data->key_notif;
      bta_dm_cb.p_sec_cback(BTA_DM_BLE_NC_REQ_EVT, &sec_event);
      break;

    case BTM_LE_SC_OOB_REQ_EVT:
      sec_event.ble_req.bd_addr = bda;
      bta_dm_cb.p_sec_cback(BTA_DM_BLE_SC_OOB_REQ_EVT, &sec_event);
      break;

    case BTM_LE_SC_LOC_OOB_EVT:
      tBTA_DM_LOC_OOB_DATA local_oob_data;
      local_oob_data.local_oob_c = p_data->local_oob_data.commitment;
      local_oob_data.local_oob_r = p_data->local_oob_data.randomizer;
      sec_event.local_oob_data = local_oob_data;
      bta_dm_cb.p_sec_cback(BTA_DM_BLE_SC_CR_LOC_OOB_EVT, &sec_event);
      break;

    case BTM_LE_KEY_EVT:
      sec_event.ble_key.bd_addr = bda;
      sec_event.ble_key.key_type = p_data->key.key_type;
      sec_event.ble_key.p_key_value = p_data->key.p_key_value;
      bta_dm_cb.p_sec_cback(BTA_DM_BLE_KEY_EVT, &sec_event);
      break;

    case BTM_LE_COMPLT_EVT:
      sec_event.auth_cmpl.bd_addr = bda;
      BTM_ReadDevInfo(bda, &sec_event.auth_cmpl.dev_type,
                      &sec_event.auth_cmpl.addr_type);
      p_name = (bluetooth::shim::is_gd_security_enabled())
                   ? bluetooth::shim::BTM_SecReadDevName(bda)
                   : BTM_SecReadDevName(bda);
      if (p_name != NULL)
        strlcpy((char*)sec_event.auth_cmpl.bd_name, p_name, (BD_NAME_LEN + 1));
      else
        sec_event.auth_cmpl.bd_name[0] = 0;

      if (p_data->complt.reason != HCI_SUCCESS) {
        // TODO This is not a proper use of this type
        sec_event.auth_cmpl.fail_reason =
            static_cast<tHCI_STATUS>(BTA_DM_AUTH_CONVERT_SMP_CODE(
                (static_cast<uint8_t>(p_data->complt.reason))));

        if (btm_sec_is_a_bonded_dev(bda) &&
            p_data->complt.reason == SMP_CONN_TOUT) {
          // Bonded device failed to encrypt - to test this remove battery from
          // HID device right after connection, but before encryption is
          // established
          LOG(INFO) << __func__
                    << ": bonded device disconnected when encrypting - no "
                       "reason to unbond";
        } else {
          /* delete this device entry from Sec Dev DB */
          bta_dm_remove_sec_dev_entry(bda);
        }

      } else {
        sec_event.auth_cmpl.success = true;
        if (!p_data->complt.smp_over_br)
          GATT_ConfigServiceChangeCCC(bda, true, BT_TRANSPORT_LE);
      }

      if (bta_dm_cb.p_sec_cback) {
        // bta_dm_cb.p_sec_cback(BTA_DM_AUTH_CMPL_EVT, &sec_event);
        bta_dm_cb.p_sec_cback(BTA_DM_BLE_AUTH_CMPL_EVT, &sec_event);
      }
      break;

    default:
      status = BTM_NOT_AUTHORIZED;
      break;
  }
  return status;
}

/*******************************************************************************
 *
 * Function         bta_dm_ble_id_key_cback
 *
 * Description      Callback for BLE local ID keys
 *
 *
 * Returns          void
 *
 ******************************************************************************/
static void bta_dm_ble_id_key_cback(uint8_t key_type,
                                    tBTM_BLE_LOCAL_KEYS* p_key) {
  uint8_t evt;
  tBTA_DM_SEC dm_key;

  switch (key_type) {
    case BTM_BLE_KEY_TYPE_ID:
    case BTM_BLE_KEY_TYPE_ER:
      if (bta_dm_cb.p_sec_cback) {
        memcpy(&dm_key.ble_id_keys, p_key, sizeof(tBTM_BLE_LOCAL_KEYS));

        evt = (key_type == BTM_BLE_KEY_TYPE_ID) ? BTA_DM_BLE_LOCAL_IR_EVT
                                                : BTA_DM_BLE_LOCAL_ER_EVT;
        bta_dm_cb.p_sec_cback(evt, &dm_key);
      }
      break;

    default:
      APPL_TRACE_DEBUG("Unknown key type %d", key_type);
      break;
  }
  return;
}

/*******************************************************************************
 *
 * Function         bta_dm_add_blekey
 *
 * Description      This function adds an BLE Key to an security database entry.
 *                  This function shall only be called AFTER BTA_DmAddBleDevice
 *                  has been called.
 *                  It is normally called during host startup to restore all
 *                  required information stored in the NVRAM.
 *
 * Parameters:
 *
 ******************************************************************************/
void bta_dm_add_blekey(const RawAddress& bd_addr, tBTA_LE_KEY_VALUE blekey,
                       tBTM_LE_KEY_TYPE key_type) {
  BTM_SecAddBleKey(bd_addr, (tBTM_LE_KEY_VALUE*)&blekey, key_type);
}

/*******************************************************************************
 *
 * Function         bta_dm_add_ble_device
 *
 * Description      This function adds an BLE device to an security database
 *                  entry.
 *                  It is normally called during host startup to restore all
 *                  required information stored in the NVRAM.
 *
 * Parameters:
 *
 ******************************************************************************/
void bta_dm_add_ble_device(const RawAddress& bd_addr, tBLE_ADDR_TYPE addr_type,
                           tBT_DEVICE_TYPE dev_type) {
  BTM_SecAddBleDevice(bd_addr, dev_type, addr_type);
}

/*******************************************************************************
 *
 * Function         bta_dm_add_ble_device
 *
 * Description      This function adds an BLE device to an security database
 *                  entry.
 *                  It is normally called during host startup to restore all
 *                  required information stored in the NVRAM.
 *
 * Parameters:
 *
 ******************************************************************************/
void bta_dm_ble_passkey_reply(const RawAddress& bd_addr, bool accept,
                              uint32_t passkey) {
  BTM_BlePasskeyReply(bd_addr, accept ? BTM_SUCCESS : BTM_NOT_AUTHORIZED,
                      passkey);
}

/** This is response to SM numeric comparison request submitted to application.
 */
void bta_dm_ble_confirm_reply(const RawAddress& bd_addr, bool accept) {
  BTM_BleConfirmReply(bd_addr, accept ? BTM_SUCCESS : BTM_NOT_AUTHORIZED);
}

/** This function set the preferred connection parameters */
void bta_dm_ble_set_conn_params(const RawAddress& bd_addr,
                                uint16_t conn_int_min, uint16_t conn_int_max,
                                uint16_t peripheral_latency,
                                uint16_t supervision_tout) {
  L2CA_AdjustConnectionIntervals(&conn_int_min, &conn_int_max,
                                 BTM_BLE_CONN_INT_MIN);

  BTM_BleSetPrefConnParams(bd_addr, conn_int_min, conn_int_max,
                           peripheral_latency, supervision_tout);
}

/** This function update LE connection parameters */
void bta_dm_ble_update_conn_params(const RawAddress& bd_addr, uint16_t min_int,
                                   uint16_t max_int, uint16_t latency,
                                   uint16_t timeout, uint16_t min_ce_len,
                                   uint16_t max_ce_len) {
  L2CA_AdjustConnectionIntervals(&min_int, &max_int, BTM_BLE_CONN_INT_MIN);

  if (!L2CA_UpdateBleConnParams(bd_addr, min_int, max_int, latency, timeout,
                                min_ce_len, max_ce_len)) {
    APPL_TRACE_ERROR("Update connection parameters failed!");
  }
}

#if (BLE_PRIVACY_SPT == TRUE)
/** This function set the local device LE privacy settings. */
void bta_dm_ble_config_local_privacy(bool privacy_enable) {
  BTM_BleConfigPrivacy(privacy_enable);
}
#endif

void bta_dm_ble_observe(bool start, uint8_t duration,
                        tBTA_DM_SEARCH_CBACK* p_cback) {
  if (!start) {
    bta_dm_search_cb.p_scan_cback = NULL;
    BTM_BleObserve(false, 0, NULL, NULL);
    return;
  }

  /*Save the  callback to be called when a scan results are available */
  bta_dm_search_cb.p_scan_cback = p_cback;
  tBTM_STATUS status = BTM_BleObserve(true, duration, bta_dm_observe_results_cb,
                                      bta_dm_observe_cmpl_cb);
  if (status != BTM_CMD_STARTED) {
    tBTA_DM_SEARCH data;
    APPL_TRACE_WARNING(" %s BTM_BleObserve  failed. status %d", __func__,
                       status);
    data.inq_cmpl.num_resps = 0;
    if (bta_dm_search_cb.p_scan_cback) {
      bta_dm_search_cb.p_scan_cback(BTA_DM_INQ_CMPL_EVT, &data);
    }
  }
}

/** This function set the maximum transmission packet size */
void bta_dm_ble_set_data_length(const RawAddress& bd_addr) {
  const controller_t* controller = controller_get_interface();
  uint16_t max_len = controller->get_ble_maximum_tx_data_length();

  if (BTM_SetBleDataLength(bd_addr, max_len) != BTM_SUCCESS) {
    LOG_INFO("Unable to set ble data length:%hu", max_len);
  }
}

/*******************************************************************************
 *
 * Function         bta_ble_enable_scan_cmpl
 *
 * Description      ADV payload filtering enable / disable complete callback
 *
 *
 * Returns          None
 *
 ******************************************************************************/
static void bta_ble_energy_info_cmpl(tBTM_BLE_TX_TIME_MS tx_time,
                                     tBTM_BLE_RX_TIME_MS rx_time,
                                     tBTM_BLE_IDLE_TIME_MS idle_time,
                                     tBTM_BLE_ENERGY_USED energy_used,
                                     tHCI_STATUS status) {
  tBTA_STATUS st = (status == HCI_SUCCESS) ? BTA_SUCCESS : BTA_FAILURE;
  tBTA_DM_CONTRL_STATE ctrl_state = 0;

  if (BTA_SUCCESS == st) ctrl_state = bta_dm_pm_obtain_controller_state();

  if (bta_dm_cb.p_energy_info_cback)
    bta_dm_cb.p_energy_info_cback(tx_time, rx_time, idle_time, energy_used,
                                  ctrl_state, st);
}

/** This function obtains the energy info */
void bta_dm_ble_get_energy_info(
    tBTA_BLE_ENERGY_INFO_CBACK* p_energy_info_cback) {
  bta_dm_cb.p_energy_info_cback = p_energy_info_cback;
  tBTM_STATUS btm_status = BTM_BleGetEnergyInfo(bta_ble_energy_info_cmpl);
  if (btm_status != BTM_CMD_STARTED)
    bta_ble_energy_info_cmpl(0, 0, 0, 0, HCI_ERR_UNSPECIFIED);
}

#ifndef BTA_DM_GATT_CLOSE_DELAY_TOUT
#define BTA_DM_GATT_CLOSE_DELAY_TOUT 1000
#endif

/*******************************************************************************
 *
 * Function         bta_dm_gattc_register
 *
 * Description      Register with GATTC in DM if BLE is needed.
 *
 *
 * Returns          void
 *
 ******************************************************************************/
static void bta_dm_gattc_register(void) {
  if (bta_dm_search_cb.client_if == BTA_GATTS_INVALID_IF) {
    BTA_GATTC_AppRegister(bta_dm_gattc_callback,
                          base::Bind([](uint8_t client_id, uint8_t status) {
                            if (status == GATT_SUCCESS)
                              bta_dm_search_cb.client_if = client_id;
                            else
                              bta_dm_search_cb.client_if = BTA_GATTS_INVALID_IF;

                          }), false);
  }
}

/*******************************************************************************
 *
 * Function         bta_dm_gatt_disc_complete
 *
 * Description      This function process the GATT service search complete.
 *
 * Parameters:
 *
 ******************************************************************************/
static void bta_dm_gatt_disc_complete(uint16_t conn_id, tGATT_STATUS status) {
  APPL_TRACE_DEBUG("%s conn_id = %d", __func__, conn_id);

  tBTA_DM_MSG* p_msg = (tBTA_DM_MSG*)osi_malloc(sizeof(tBTA_DM_MSG));

  /* no more services to be discovered */
  p_msg->hdr.event = BTA_DM_DISCOVERY_RESULT_EVT;
  p_msg->disc_result.result.disc_res.result =
      (status == GATT_SUCCESS) ? BTA_SUCCESS : BTA_FAILURE;
  APPL_TRACE_DEBUG("%s service found: 0x%08x", __func__,
                   bta_dm_search_cb.services_found);
  p_msg->disc_result.result.disc_res.services = bta_dm_search_cb.services_found;
  p_msg->disc_result.result.disc_res.num_uuids = 0;
  p_msg->disc_result.result.disc_res.p_uuid_list = NULL;
  p_msg->disc_result.result.disc_res.bd_addr = bta_dm_search_cb.peer_bdaddr;
  strlcpy((char*)p_msg->disc_result.result.disc_res.bd_name,
          bta_dm_get_remname(), BD_NAME_LEN + 1);

  p_msg->disc_result.result.disc_res.device_type |= BT_DEVICE_TYPE_BLE;

  bta_sys_sendmsg(p_msg);

  if (conn_id != GATT_INVALID_CONN_ID) {
    /* start a GATT channel close delay timer */
    bta_sys_start_timer(bta_dm_search_cb.gatt_close_timer,
                        BTA_DM_GATT_CLOSE_DELAY_TOUT,
                        BTA_DM_DISC_CLOSE_TOUT_EVT, 0);
    bta_dm_search_cb.pending_close_bda = bta_dm_search_cb.peer_bdaddr;
  }
  bta_dm_search_cb.gatt_disc_active = false;
}

/*******************************************************************************
 *
 * Function         bta_dm_close_gatt_conn
 *
 * Description      This function close the GATT connection after delay
 *timeout.
 *
 * Parameters:
 *
 ******************************************************************************/
void bta_dm_close_gatt_conn(UNUSED_ATTR tBTA_DM_MSG* p_data) {
  if (bta_dm_search_cb.conn_id != GATT_INVALID_CONN_ID)
    BTA_GATTC_Close(bta_dm_search_cb.conn_id);

  bta_dm_search_cb.pending_close_bda = RawAddress::kEmpty;
  bta_dm_search_cb.conn_id = GATT_INVALID_CONN_ID;
}
/*******************************************************************************
 *
 * Function         btm_dm_start_gatt_discovery
 *
 * Description      This is GATT initiate the service search by open a GATT
 *                  connection first.
 *
 * Parameters:
 *
 ******************************************************************************/
void btm_dm_start_gatt_discovery(const RawAddress& bd_addr) {
  bta_dm_search_cb.gatt_disc_active = true;

  /* connection is already open */
  if (bta_dm_search_cb.pending_close_bda == bd_addr &&
      bta_dm_search_cb.conn_id != GATT_INVALID_CONN_ID) {
    bta_dm_search_cb.pending_close_bda = RawAddress::kEmpty;
    alarm_cancel(bta_dm_search_cb.gatt_close_timer);
    BTA_GATTC_ServiceSearchRequest(bta_dm_search_cb.conn_id, nullptr);
  } else {
    if (BTM_IsAclConnectionUp(bd_addr, BT_TRANSPORT_LE)) {
      BTA_GATTC_Open(bta_dm_search_cb.client_if, bd_addr, true, true);
    } else {
      BTA_GATTC_Open(bta_dm_search_cb.client_if, bd_addr, true, false);
    }
  }
}

/*******************************************************************************
 *
 * Function         bta_dm_cancel_gatt_discovery
 *
 * Description      This is GATT cancel the GATT service search.
 *
 * Parameters:
 *
 ******************************************************************************/
static void bta_dm_cancel_gatt_discovery(const RawAddress& bd_addr) {
  if (bta_dm_search_cb.conn_id == GATT_INVALID_CONN_ID) {
    BTA_GATTC_CancelOpen(bta_dm_search_cb.client_if, bd_addr, true);
  }

  bta_dm_gatt_disc_complete(bta_dm_search_cb.conn_id, (tGATT_STATUS)GATT_ERROR);
}

/*******************************************************************************
 *
 * Function         bta_dm_proc_open_evt
 *
 * Description      process BTA_GATTC_OPEN_EVT in DM.
 *
 * Parameters:
 *
 ******************************************************************************/
void bta_dm_proc_open_evt(tBTA_GATTC_OPEN* p_data) {
  VLOG(1) << "DM Search state= " << bta_dm_search_cb.state
          << " search_cb.peer_dbaddr:" << bta_dm_search_cb.peer_bdaddr
          << " connected_bda=" << p_data->remote_bda.address;

  APPL_TRACE_DEBUG("BTA_GATTC_OPEN_EVT conn_id = %d client_if=%d status = %d",
                   p_data->conn_id, p_data->client_if, p_data->status);

  bta_dm_search_cb.conn_id = p_data->conn_id;

  if (p_data->status == GATT_SUCCESS) {
    BTA_GATTC_ServiceSearchRequest(p_data->conn_id, nullptr);
  } else {
    bta_dm_gatt_disc_complete(GATT_INVALID_CONN_ID, p_data->status);
  }
}

/*******************************************************************************
 *
 * Function         bta_dm_gattc_callback
 *
 * Description      This is GATT client callback function used in DM.
 *
 * Parameters:
 *
 ******************************************************************************/
static void bta_dm_gattc_callback(tBTA_GATTC_EVT event, tBTA_GATTC* p_data) {
  APPL_TRACE_DEBUG("bta_dm_gattc_callback event = %d", event);

  switch (event) {
    case BTA_GATTC_OPEN_EVT:
      bta_dm_proc_open_evt(&p_data->open);
      break;

    case BTA_GATTC_SEARCH_RES_EVT:
      break;

    case BTA_GATTC_SEARCH_CMPL_EVT:
      if (bta_dm_search_cb.state != BTA_DM_SEARCH_IDLE)
        bta_dm_gatt_disc_complete(p_data->search_cmpl.conn_id,
                                  p_data->search_cmpl.status);
      break;

    case BTA_GATTC_CLOSE_EVT:
      APPL_TRACE_DEBUG("BTA_GATTC_CLOSE_EVT reason = %d", p_data->close.reason);
      /* in case of disconnect before search is completed */
      if ((bta_dm_search_cb.state != BTA_DM_SEARCH_IDLE) &&
          (bta_dm_search_cb.state != BTA_DM_SEARCH_ACTIVE) &&
          p_data->close.remote_bda == bta_dm_search_cb.peer_bdaddr) {
        bta_dm_gatt_disc_complete((uint16_t)GATT_INVALID_CONN_ID,
                                  (tGATT_STATUS)GATT_ERROR);
      }
      break;

    default:
      break;
  }
}

#if (BLE_VND_INCLUDED == TRUE)
/*******************************************************************************
 *
 * Function         bta_dm_ctrl_features_rd_cmpl_cback
 *
 * Description      callback to handle controller feature read complete
 *
 * Parameters:
 *
 ******************************************************************************/
static void bta_dm_ctrl_features_rd_cmpl_cback(tHCI_STATUS result) {
  APPL_TRACE_DEBUG("%s  status = %d ", __func__, result);
  if (result == HCI_SUCCESS) {
    if (bta_dm_cb.p_sec_cback)
      bta_dm_cb.p_sec_cback(BTA_DM_LE_FEATURES_READ, NULL);
  } else {
    APPL_TRACE_ERROR("%s Ctrl BLE feature read failed: status :%d", __func__,
                     result);
  }
}
#endif /* BLE_VND_INCLUDED */
