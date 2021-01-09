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

#include <cstdint>

#include "osi/include/log.h"
#include "stack/btm/btm_ble_int.h"
#include "stack/btm/btm_dev.h"
#include "stack/btm/btm_sec.h"
#include "stack/gatt/connection_manager.h"
#include "stack/include/acl_api.h"
#include "stack/include/bt_types.h"
#include "stack/include/hcidefs.h"
#include "stack/include/l2cap_hci_link_interface.h"

extern tBTM_CB btm_cb;

void btm_ble_advertiser_notify_terminated_legacy(uint8_t status,
                                                 uint16_t connection_handle);
void btm_ble_increment_link_topology_mask(uint8_t link_role);

bool maybe_resolve_address(RawAddress* bda, tBLE_ADDR_TYPE* bda_type);

static bool acl_ble_common_connection(const tBLE_BD_ADDR& address_with_type,
                                      uint16_t handle, uint8_t role,
                                      bool is_in_security_db,
                                      uint16_t conn_interval,
                                      uint16_t conn_latency,
                                      uint16_t conn_timeout) {
  if (role == HCI_ROLE_CENTRAL) {
    btm_cb.ble_ctr_cb.set_connection_state_idle();
    btm_ble_clear_topology_mask(BTM_BLE_STATE_INIT_BIT);
  }

  // Inform any applications that a connection has completed.
  connection_manager::on_connection_complete(address_with_type.bda);

  // Allocate or update the security device record for this device
  btm_ble_connected(address_with_type.bda, handle, HCI_ENCRYPT_MODE_DISABLED,
                    role, address_with_type.type, is_in_security_db);

  // Update the link topology information for our device
  btm_ble_increment_link_topology_mask(role);

  // Inform l2cap of a potential connection.
  if (!l2cble_conn_comp(handle, role, address_with_type.bda,
                        address_with_type.type, conn_interval, conn_latency,
                        conn_timeout)) {
    btm_sec_disconnect(handle, HCI_ERR_NO_CONNECTION);
    LOG_WARN("Unable to complete l2cap connection");
    return false;
  }

  btm_ble_disable_resolving_list(BTM_BLE_RL_INIT, true);

  /* Tell BTM Acl management about the link */
  btm_acl_created(address_with_type.bda, handle, role, BT_TRANSPORT_LE);

  return true;
}

void acl_ble_connection_complete(const tBLE_BD_ADDR& address_with_type,
                                 uint16_t handle, uint8_t role, bool match,
                                 uint16_t conn_interval, uint16_t conn_latency,
                                 uint16_t conn_timeout) {
  if (!acl_ble_common_connection(address_with_type, handle, role, match,
                                 conn_interval, conn_latency, conn_timeout)) {
    LOG_WARN("Unable to create non enhanced ble acl connection");
    return;
  }

  btm_ble_update_mode_operation(role, &address_with_type.bda, HCI_SUCCESS);

  if (role == HCI_ROLE_PERIPHERAL)
    btm_ble_advertiser_notify_terminated_legacy(HCI_SUCCESS, handle);
}

void acl_ble_enhanced_connection_complete(
    const tBLE_BD_ADDR& address_with_type, uint16_t handle, uint8_t role,
    bool match, uint16_t conn_interval, uint16_t conn_latency,
    uint16_t conn_timeout, const RawAddress& local_rpa,
    const RawAddress& peer_rpa, uint8_t peer_addr_type) {
  if (!acl_ble_common_connection(address_with_type, handle, role, match,
                                 conn_interval, conn_latency, conn_timeout)) {
    LOG_WARN("Unable to create enhanced ble acl connection");
    return;
  }

  btm_ble_refresh_local_resolvable_private_addr(address_with_type.bda,
                                                local_rpa);

  if (peer_addr_type & BLE_ADDR_TYPE_ID_BIT)
    btm_ble_refresh_peer_resolvable_private_addr(
        address_with_type.bda, peer_rpa, tBTM_SEC_BLE::BTM_BLE_ADDR_RRA);
  btm_ble_update_mode_operation(role, &address_with_type.bda, HCI_SUCCESS);

  if (role == HCI_ROLE_PERIPHERAL)
    btm_ble_advertiser_notify_terminated_legacy(HCI_SUCCESS, handle);
}

static bool maybe_resolve_received_address(
    const tBLE_BD_ADDR& address_with_type,
    tBLE_BD_ADDR* resolved_address_with_type) {
  ASSERT(resolved_address_with_type != nullptr);

  *resolved_address_with_type = address_with_type;
  return maybe_resolve_address(&resolved_address_with_type->bda,
                               &resolved_address_with_type->type);
}

void acl_ble_enhanced_connection_complete_from_shim(
    const tBLE_BD_ADDR& address_with_type, uint16_t handle, uint8_t role,
    uint16_t conn_interval, uint16_t conn_latency, uint16_t conn_timeout,
    const RawAddress& local_rpa, const RawAddress& peer_rpa,
    uint8_t peer_addr_type) {
  tBLE_BD_ADDR resolved_address_with_type;
  const bool is_in_security_db = maybe_resolve_received_address(
      address_with_type, &resolved_address_with_type);

  acl_ble_enhanced_connection_complete(resolved_address_with_type, handle, role,
                                       is_in_security_db, conn_interval,
                                       conn_latency, conn_timeout, local_rpa,
                                       peer_rpa, peer_addr_type);

  // The legacy stack continues the LE connection after the read remote version
  // complete has been received.
  l2cble_notify_le_connection(address_with_type.bda);
  l2cble_use_preferred_conn_params(address_with_type.bda);
}

void acl_ble_connection_fail(const tBLE_BD_ADDR& address_with_type,
                             uint16_t handle, bool enhanced,
                             tHCI_STATUS status) {
  if (status != HCI_ERR_ADVERTISING_TIMEOUT) {
    btm_cb.ble_ctr_cb.set_connection_state_idle();
    btm_ble_clear_topology_mask(BTM_BLE_STATE_INIT_BIT);
    btm_ble_disable_resolving_list(BTM_BLE_RL_INIT, true);
  } else {
    btm_cb.ble_ctr_cb.inq_var.adv_mode = BTM_BLE_ADV_DISABLE;
    btm_ble_disable_resolving_list(BTM_BLE_RL_ADV, true);
  }
  btm_ble_update_mode_operation(HCI_ROLE_UNKNOWN, &address_with_type.bda,
                                status);
}

void gatt_notify_conn_update(const RawAddress& remote, uint16_t interval,
                             uint16_t latency, uint16_t timeout,
                             tHCI_STATUS status);
void acl_ble_update_event_received(tHCI_STATUS status, uint16_t handle,
                                   uint16_t interval, uint16_t latency,
                                   uint16_t timeout) {
  l2cble_process_conn_update_evt(handle, status, interval, latency, timeout);

  tBTM_SEC_DEV_REC* p_dev_rec = btm_find_dev_by_handle(handle);

  if (!p_dev_rec) return;

  gatt_notify_conn_update(p_dev_rec->ble.pseudo_addr, interval, latency,
                          timeout, status);
}
