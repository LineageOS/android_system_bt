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

/*
 * Generated mock file from original source file
 *   Functions generated:6
 */

#include <map>
#include <string>

extern std::map<std::string, int> mock_function_count_map;

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

#ifndef UNUSED_ATTR
#define UNUSED_ATTR
#endif

void acl_ble_connection_complete(const tBLE_BD_ADDR& address_with_type,
                                 uint16_t handle, uint8_t role, bool match,
                                 uint16_t conn_interval, uint16_t conn_latency,
                                 uint16_t conn_timeout) {
  mock_function_count_map[__func__]++;
}
void acl_ble_connection_fail(const tBLE_BD_ADDR& address_with_type,
                             uint16_t handle, bool enhanced,
                             tHCI_STATUS status) {
  mock_function_count_map[__func__]++;
}
void acl_ble_enhanced_connection_complete(
    const tBLE_BD_ADDR& address_with_type, uint16_t handle, tHCI_ROLE role,
    bool match, uint16_t conn_interval, uint16_t conn_latency,
    uint16_t conn_timeout, const RawAddress& local_rpa,
    const RawAddress& peer_rpa, uint8_t peer_addr_type) {
  mock_function_count_map[__func__]++;
}
void acl_ble_enhanced_connection_complete_from_shim(
    const tBLE_BD_ADDR& address_with_type, uint16_t handle, tHCI_ROLE role,
    uint16_t conn_interval, uint16_t conn_latency, uint16_t conn_timeout,
    const RawAddress& local_rpa, const RawAddress& peer_rpa,
    uint8_t peer_addr_type) {
  mock_function_count_map[__func__]++;
}
void gatt_notify_conn_update(const RawAddress& remote, uint16_t interval,
                             uint16_t latency, uint16_t timeout,
                             tHCI_STATUS status);
void acl_ble_update_event_received(tHCI_STATUS status, uint16_t handle,
                                   uint16_t interval, uint16_t latency,
                                   uint16_t timeout) {
  mock_function_count_map[__func__]++;
}
