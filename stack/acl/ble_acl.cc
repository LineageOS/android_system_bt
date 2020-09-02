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

#include "stack/btm/btm_ble_int.h"
#include "stack/gatt/connection_manager.h"
#include "stack/include/acl_api.h"
#include "stack/include/bt_types.h"
#include "stack/include/hcidefs.h"
#include "stack/include/l2cap_hci_link_interface.h"

void btm_ble_advertiser_notify_terminated_legacy(uint8_t status,
                                                 uint16_t connection_handle);

void acl_ble_connection_complete(const tBLE_BD_ADDR& address_with_type,
                                 uint16_t handle, uint8_t role, bool match,
                                 uint16_t conn_interval, uint16_t conn_latency,
                                 uint16_t conn_timeout) {
  connection_manager::on_connection_complete(address_with_type.bda);
  btm_ble_connected(address_with_type.bda, handle, HCI_ENCRYPT_MODE_DISABLED,
                    role, address_with_type.type, match);

  l2cble_conn_comp(handle, role, address_with_type.bda, address_with_type.type,
                   conn_interval, conn_latency, conn_timeout);

  btm_ble_update_mode_operation(role, &address_with_type.bda, HCI_SUCCESS);

  if (role == HCI_ROLE_SLAVE)
    btm_ble_advertiser_notify_terminated_legacy(HCI_SUCCESS, handle);
}

void acl_ble_enhanced_connection_complete(
    const tBLE_BD_ADDR& address_with_type, uint16_t handle, uint8_t role,
    bool match, uint16_t conn_interval, uint16_t conn_latency,
    uint16_t conn_timeout, const RawAddress& local_rpa,
    const RawAddress& peer_rpa, uint8_t peer_addr_type) {
  connection_manager::on_connection_complete(address_with_type.bda);
  btm_ble_connected(address_with_type.bda, handle, HCI_ENCRYPT_MODE_DISABLED,
                    role, address_with_type.type, match);

  l2cble_conn_comp(handle, role, address_with_type.bda, address_with_type.type,
                   conn_interval, conn_latency, conn_timeout);

  btm_ble_refresh_local_resolvable_private_addr(address_with_type.bda,
                                                local_rpa);

  if (peer_addr_type & BLE_ADDR_TYPE_ID_BIT)
    btm_ble_refresh_peer_resolvable_private_addr(
        address_with_type.bda, peer_rpa, tBTM_SEC_BLE::BTM_BLE_ADDR_RRA);
  btm_ble_update_mode_operation(role, &address_with_type.bda, HCI_SUCCESS);

  if (role == HCI_ROLE_SLAVE)
    btm_ble_advertiser_notify_terminated_legacy(HCI_SUCCESS, handle);
}

void acl_ble_connection_fail(const tBLE_BD_ADDR& address_with_type,
                             uint16_t handle, bool enhanced, uint8_t status) {
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
