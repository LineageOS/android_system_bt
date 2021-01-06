/******************************************************************************
 *
 *  Copyright 2019 The Android Open Source Project
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

#include <frameworks/proto_logging/stats/enums/bluetooth/enums.pb.h>
#include <frameworks/proto_logging/stats/enums/bluetooth/hci/enums.pb.h>

#include "bt_types.h"
#include "btm_int.h"
#include "common/metrics.h"
#include "device/include/controller.h"
#include "stack/btm/btm_ble_int.h"
#include "stack/gatt/connection_manager.h"
#include "stack/include/acl_api.h"
#include "stack/include/ble_acl_interface.h"
#include "stack/include/ble_hci_link_interface.h"
#include "stack/include/hcimsgs.h"
#include "stack/include/l2cap_hci_link_interface.h"

extern tBTM_CB btm_cb;

extern void btm_ble_advertiser_notify_terminated_legacy(
    uint8_t status, uint16_t connection_handle);

extern bool btm_ble_init_pseudo_addr(tBTM_SEC_DEV_REC* p_dev_rec,
                                     const RawAddress& new_pseudo_addr);
void btm_send_hci_create_connection(
    uint16_t scan_int, uint16_t scan_win, uint8_t init_filter_policy,
    uint8_t addr_type_peer, const RawAddress& bda_peer, uint8_t addr_type_own,
    uint16_t conn_int_min, uint16_t conn_int_max, uint16_t conn_latency,
    uint16_t conn_timeout, uint16_t min_ce_len, uint16_t max_ce_len,
    uint8_t initiating_phys) {
  if (controller_get_interface()->supports_ble_extended_advertising()) {
    EXT_CONN_PHY_CFG phy_cfg[3];  // maximum three phys

    int phy_cnt =
        std::bitset<std::numeric_limits<uint8_t>::digits>(initiating_phys)
            .count();

    LOG_ASSERT(phy_cnt <= 3) << "More than three phys provided";
    // TODO(jpawlowski): tune parameters for different transports
    for (int i = 0; i < phy_cnt; i++) {
      phy_cfg[i].scan_int = scan_int;
      phy_cfg[i].scan_win = scan_win;
      phy_cfg[i].conn_int_min = conn_int_min;
      phy_cfg[i].conn_int_max = conn_int_max;
      phy_cfg[i].conn_latency = conn_latency;
      phy_cfg[i].sup_timeout = conn_timeout;
      phy_cfg[i].min_ce_len = min_ce_len;
      phy_cfg[i].max_ce_len = max_ce_len;
    }

    addr_type_peer &= ~BLE_ADDR_TYPE_ID_BIT;
    btsnd_hcic_ble_ext_create_conn(init_filter_policy, addr_type_own,
                                   addr_type_peer, bda_peer, initiating_phys,
                                   phy_cfg);
  } else {
    btsnd_hcic_ble_create_ll_conn(scan_int, scan_win, init_filter_policy,
                                  addr_type_peer, bda_peer, addr_type_own,
                                  conn_int_min, conn_int_max, conn_latency,
                                  conn_timeout, min_ce_len, max_ce_len);
  }

  btm_cb.ble_ctr_cb.set_connection_state_connecting();
  btm_ble_set_topology_mask(BTM_BLE_STATE_INIT_BIT);
}

/** LE connection complete. */
void btm_ble_create_ll_conn_complete(uint8_t status) {
  if (status == HCI_SUCCESS) return;

  LOG(WARNING) << "LE Create Connection attempt failed, status="
               << loghex(status);

  if (status == HCI_ERR_COMMAND_DISALLOWED) {
    btm_cb.ble_ctr_cb.set_connection_state_connecting();
    btm_ble_set_topology_mask(BTM_BLE_STATE_INIT_BIT);
    LOG(ERROR) << "LE Create Connection - command disallowed";
  } else {
    btm_cb.ble_ctr_cb.set_connection_state_idle();
    btm_ble_clear_topology_mask(BTM_BLE_STATE_INIT_BIT);
    btm_ble_update_mode_operation(HCI_ROLE_UNKNOWN, NULL, status);
  }
}

bool maybe_resolve_address(RawAddress* bda, tBLE_ADDR_TYPE* bda_type) {
  bool is_in_security_db = false;
  tBLE_ADDR_TYPE peer_addr_type = *bda_type;
  bool addr_is_rpa =
      (peer_addr_type == BLE_ADDR_RANDOM && BTM_BLE_IS_RESOLVE_BDA(*bda));

  /* We must translate whatever address we received into the "pseudo" address.
   * i.e. if we bonded with device that was using RPA for first connection,
   * "pseudo" address is equal to this RPA. If it later decides to use Public
   * address, or Random Static Address, we convert it into the "pseudo"
   * address here. */
  if (!addr_is_rpa || peer_addr_type & BLE_ADDR_TYPE_ID_BIT) {
    is_in_security_db = btm_identity_addr_to_random_pseudo(bda, bda_type, true);
  }

  /* possiblly receive connection complete with resolvable random while
     the device has been paired */
  if (!is_in_security_db && addr_is_rpa) {
    tBTM_SEC_DEV_REC* match_rec = btm_ble_resolve_random_addr(*bda);
    if (match_rec) {
      LOG(INFO) << __func__ << ": matched and resolved random address";
      is_in_security_db = true;
      match_rec->ble.active_addr_type = tBTM_SEC_BLE::BTM_BLE_ADDR_RRA;
      match_rec->ble.cur_rand_addr = *bda;
      if (!btm_ble_init_pseudo_addr(match_rec, *bda)) {
        /* assign the original address to be the current report address */
        *bda = match_rec->ble.pseudo_addr;
        *bda_type = match_rec->ble.ble_addr_type;
      } else {
        *bda = match_rec->bd_addr;
      }
    } else {
      LOG(INFO) << __func__ << ": unable to match and resolve random address";
    }
  }
  return is_in_security_db;
}

/** LE connection complete. */
void btm_ble_conn_complete(uint8_t* p, UNUSED_ATTR uint16_t evt_len,
                           bool enhanced) {
  RawAddress local_rpa, peer_rpa;
  uint8_t role, status;
  tBLE_ADDR_TYPE bda_type;
  uint16_t handle;
  RawAddress bda;
  uint16_t conn_interval, conn_latency, conn_timeout;

  STREAM_TO_UINT8(status, p);
  STREAM_TO_UINT16(handle, p);
  STREAM_TO_UINT8(role, p);
  STREAM_TO_UINT8(bda_type, p);
  STREAM_TO_BDADDR(bda, p);
  if (enhanced) {
    STREAM_TO_BDADDR(local_rpa, p);
    STREAM_TO_BDADDR(peer_rpa, p);
  }
  STREAM_TO_UINT16(conn_interval, p);
  STREAM_TO_UINT16(conn_latency, p);
  STREAM_TO_UINT16(conn_timeout, p);
  handle = HCID_GET_HANDLE(handle);

  uint32_t hci_ble_event =
      enhanced ? android::bluetooth::hci::BLE_EVT_ENHANCED_CONN_COMPLETE_EVT
               : android::bluetooth::hci::BLE_EVT_CONN_COMPLETE_EVT;

  if (status == HCI_SUCCESS) {
    tBLE_ADDR_TYPE peer_addr_type = bda_type;
    bool is_in_security_db = maybe_resolve_address(&bda, &bda_type);

    // Log for the HCI success case after maybe resolving Bluetooth address
    bluetooth::common::LogLinkLayerConnectionEvent(
        &bda, handle, android::bluetooth::DIRECTION_UNKNOWN,
        android::bluetooth::LINK_TYPE_ACL, android::bluetooth::hci::CMD_UNKNOWN,
        android::bluetooth::hci::EVT_BLE_META, hci_ble_event, status,
        android::bluetooth::hci::STATUS_UNKNOWN);

    tBLE_BD_ADDR address_with_type{.bda = bda, .type = bda_type};
    if (enhanced) {
      acl_ble_enhanced_connection_complete(
          address_with_type, handle, role, is_in_security_db, conn_interval,
          conn_latency, conn_timeout, local_rpa, peer_rpa, peer_addr_type);

    } else {
      acl_ble_connection_complete(address_with_type, handle, role,
                                  is_in_security_db, conn_interval,
                                  conn_latency, conn_timeout);
    }
  } else {
    bluetooth::common::LogLinkLayerConnectionEvent(
        &bda, handle, android::bluetooth::DIRECTION_UNKNOWN,
        android::bluetooth::LINK_TYPE_ACL, android::bluetooth::hci::CMD_UNKNOWN,
        android::bluetooth::hci::EVT_BLE_META, hci_ble_event, status,
        android::bluetooth::hci::STATUS_UNKNOWN);

    tBLE_BD_ADDR address_with_type{.bda = bda, .type = bda_type};
    acl_ble_connection_fail(address_with_type, handle, enhanced,
                            static_cast<tHCI_STATUS>(status));
  }
}

void btm_ble_create_conn_cancel() {
  btsnd_hcic_ble_create_conn_cancel();
  btm_cb.ble_ctr_cb.set_connection_state_cancelled();
  btm_ble_clear_topology_mask(BTM_BLE_STATE_INIT_BIT);
}

void btm_ble_create_conn_cancel_complete(uint8_t* p) {
  uint8_t status;
  STREAM_TO_UINT8(status, p);
  if (status != HCI_SUCCESS) {
    // Only log errors to prevent log spam due to acceptlist connections
    bluetooth::common::LogLinkLayerConnectionEvent(
        nullptr, bluetooth::common::kUnknownConnectionHandle,
        android::bluetooth::DIRECTION_OUTGOING,
        android::bluetooth::LINK_TYPE_ACL,
        android::bluetooth::hci::CMD_BLE_CREATE_CONN_CANCEL,
        android::bluetooth::hci::EVT_COMMAND_COMPLETE,
        android::bluetooth::hci::BLE_EVT_UNKNOWN, status,
        android::bluetooth::hci::STATUS_UNKNOWN);
  }

  if (status == HCI_ERR_COMMAND_DISALLOWED) {
    /* This is a sign that logic around keeping connection state is broken */
    LOG(ERROR)
        << "Attempt to cancel LE connection, when no connection is pending.";
    if (btm_cb.ble_ctr_cb.is_connection_state_cancelled()) {
      btm_cb.ble_ctr_cb.set_connection_state_idle();
      btm_ble_clear_topology_mask(BTM_BLE_STATE_INIT_BIT);
      btm_ble_update_mode_operation(HCI_ROLE_UNKNOWN, nullptr, status);
    }
  }
}
