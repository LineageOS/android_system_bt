/*
 * Copyright 2021 The Android Open Source Project
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
 *   Functions generated:30
 */

#include <map>
#include <string>

extern std::map<std::string, int> mock_function_count_map;

#include <base/bind.h>
#include <ios>
#include <list>
#include <memory>
#include <vector>
#include "bt_target.h"
#include "bta/gatt/bta_gattc_int.h"
#include "device/include/controller.h"
#include "stack/include/btu.h"
#include "types/bluetooth/uuid.h"
#include "types/bt_transport.h"

#ifndef UNUSED_ATTR
#define UNUSED_ATTR
#endif

void BTA_GATTC_Disable(void) { mock_function_count_map[__func__]++; }
const gatt::Characteristic* BTA_GATTC_GetCharacteristic(uint16_t conn_id,
                                                        uint16_t handle) {
  mock_function_count_map[__func__]++;
  return nullptr;
}
const gatt::Characteristic* BTA_GATTC_GetOwningCharacteristic(uint16_t conn_id,
                                                              uint16_t handle) {
  mock_function_count_map[__func__]++;
  return nullptr;
}
const gatt::Descriptor* BTA_GATTC_GetDescriptor(uint16_t conn_id,
                                                uint16_t handle) {
  mock_function_count_map[__func__]++;
  return nullptr;
}
const gatt::Service* BTA_GATTC_GetOwningService(uint16_t conn_id,
                                                uint16_t handle) {
  mock_function_count_map[__func__]++;
  return nullptr;
}
const std::list<gatt::Service>* BTA_GATTC_GetServices(uint16_t conn_id) {
  mock_function_count_map[__func__]++;
  return nullptr;
}
tGATT_STATUS BTA_GATTC_DeregisterForNotifications(tGATT_IF client_if,
                                                  const RawAddress& bda,
                                                  uint16_t handle) {
  mock_function_count_map[__func__]++;
  return GATT_SUCCESS;
}
tGATT_STATUS BTA_GATTC_RegisterForNotifications(tGATT_IF client_if,
                                                const RawAddress& bda,
                                                uint16_t handle) {
  mock_function_count_map[__func__]++;
  return GATT_SUCCESS;
}
void BTA_GATTC_AppDeregister(tGATT_IF client_if) {
  mock_function_count_map[__func__]++;
}
void BTA_GATTC_AppRegister(tBTA_GATTC_CBACK* p_client_cb,
                           BtaAppRegisterCallback cb, bool eatt_support) {
  mock_function_count_map[__func__]++;
}
void BTA_GATTC_CancelOpen(tGATT_IF client_if, const RawAddress& remote_bda,
                          bool is_direct) {
  mock_function_count_map[__func__]++;
}
void BTA_GATTC_Close(uint16_t conn_id) { mock_function_count_map[__func__]++; }
void BTA_GATTC_ConfigureMTU(uint16_t conn_id, uint16_t mtu) {
  mock_function_count_map[__func__]++;
}
void BTA_GATTC_ConfigureMTU(uint16_t conn_id, uint16_t mtu,
                            GATT_CONFIGURE_MTU_OP_CB callback, void* cb_data) {
  mock_function_count_map[__func__]++;
}
void BTA_GATTC_DiscoverServiceByUuid(uint16_t conn_id,
                                     const bluetooth::Uuid& srvc_uuid) {
  mock_function_count_map[__func__]++;
}
void BTA_GATTC_ExecuteWrite(uint16_t conn_id, bool is_execute) {
  mock_function_count_map[__func__]++;
}
void BTA_GATTC_GetGattDb(uint16_t conn_id, uint16_t start_handle,
                         uint16_t end_handle, btgatt_db_element_t** db,
                         int* count) {
  mock_function_count_map[__func__]++;
}
void BTA_GATTC_Open(tGATT_IF client_if, const RawAddress& remote_bda,
                    bool is_direct, bool opportunistic) {
  mock_function_count_map[__func__]++;
}
void BTA_GATTC_Open(tGATT_IF client_if, const RawAddress& remote_bda,
                    bool is_direct, tBT_TRANSPORT transport, bool opportunistic,
                    uint8_t initiating_phys) {
  mock_function_count_map[__func__]++;
}
void BTA_GATTC_PrepareWrite(uint16_t conn_id, uint16_t handle, uint16_t offset,
                            std::vector<uint8_t> value, tGATT_AUTH_REQ auth_req,
                            GATT_WRITE_OP_CB callback, void* cb_data) {
  mock_function_count_map[__func__]++;
}
void BTA_GATTC_ReadCharDescr(uint16_t conn_id, uint16_t handle,
                             tGATT_AUTH_REQ auth_req, GATT_READ_OP_CB callback,
                             void* cb_data) {
  mock_function_count_map[__func__]++;
}
void BTA_GATTC_ReadCharacteristic(uint16_t conn_id, uint16_t handle,
                                  tGATT_AUTH_REQ auth_req,
                                  GATT_READ_OP_CB callback, void* cb_data) {
  mock_function_count_map[__func__]++;
}
void BTA_GATTC_ReadMultiple(uint16_t conn_id, tBTA_GATTC_MULTI* p_read_multi,
                            tGATT_AUTH_REQ auth_req) {
  mock_function_count_map[__func__]++;
}
void BTA_GATTC_ReadUsingCharUuid(uint16_t conn_id, const bluetooth::Uuid& uuid,
                                 uint16_t s_handle, uint16_t e_handle,
                                 tGATT_AUTH_REQ auth_req,
                                 GATT_READ_OP_CB callback, void* cb_data) {
  mock_function_count_map[__func__]++;
}
void BTA_GATTC_Refresh(const RawAddress& remote_bda) {
  mock_function_count_map[__func__]++;
}
void BTA_GATTC_SendIndConfirm(uint16_t conn_id, uint16_t cid) {
  mock_function_count_map[__func__]++;
}
void BTA_GATTC_ServiceSearchRequest(uint16_t conn_id,
                                    const bluetooth::Uuid* p_srvc_uuid) {
  mock_function_count_map[__func__]++;
}
void BTA_GATTC_WriteCharDescr(uint16_t conn_id, uint16_t handle,
                              std::vector<uint8_t> value,
                              tGATT_AUTH_REQ auth_req,
                              GATT_WRITE_OP_CB callback, void* cb_data) {
  mock_function_count_map[__func__]++;
}
void BTA_GATTC_WriteCharValue(uint16_t conn_id, uint16_t handle,
                              tGATT_WRITE_TYPE write_type,
                              std::vector<uint8_t> value,
                              tGATT_AUTH_REQ auth_req,
                              GATT_WRITE_OP_CB callback, void* cb_data) {
  mock_function_count_map[__func__]++;
}
