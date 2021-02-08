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
 *   Functions generated:27
 */

#include <cstdint>
#include <map>
#include <string>

#include "stack/gatt/gatt_int.h"
#include "stack/include/gatt_api.h"
#include "types/bluetooth/uuid.h"
#include "types/bt_transport.h"
#include "types/raw_address.h"

using namespace bluetooth;

extern std::map<std::string, int> mock_function_count_map;
tGATT_HDL_LIST_ELEM elem;  // gatt_add_an_item_to_list

#ifndef UNUSED_ATTR
#define UNUSED_ATTR
#endif

bool GATTS_DeleteService(tGATT_IF gatt_if, Uuid* p_svc_uuid,
                         uint16_t svc_inst) {
  mock_function_count_map[__func__]++;
  return false;
}
bool GATTS_NVRegister(tGATT_APPL_INFO* p_cb_info) {
  mock_function_count_map[__func__]++;
  return false;
}
bool GATT_CancelConnect(tGATT_IF gatt_if, const RawAddress& bd_addr,
                        bool is_direct) {
  mock_function_count_map[__func__]++;
  return false;
}
bool GATT_Connect(tGATT_IF gatt_if, const RawAddress& bd_addr, bool is_direct,
                  tBT_TRANSPORT transport, bool opportunistic) {
  mock_function_count_map[__func__]++;
  return false;
}
bool GATT_Connect(tGATT_IF gatt_if, const RawAddress& bd_addr, bool is_direct,
                  tBT_TRANSPORT transport, bool opportunistic,
                  uint8_t initiating_phys) {
  mock_function_count_map[__func__]++;
  return false;
}
bool GATT_GetConnIdIfConnected(tGATT_IF gatt_if, const RawAddress& bd_addr,
                               uint16_t* p_conn_id, tBT_TRANSPORT transport) {
  mock_function_count_map[__func__]++;
  return false;
}
bool GATT_GetConnectionInfor(uint16_t conn_id, tGATT_IF* p_gatt_if,
                             RawAddress& bd_addr, tBT_TRANSPORT* p_transport) {
  mock_function_count_map[__func__]++;
  return false;
}
bool is_active_service(const Uuid& app_uuid128, Uuid* p_svc_uuid,
                       uint16_t start_handle) {
  mock_function_count_map[__func__]++;
  return false;
}
tGATT_HDL_LIST_ELEM& gatt_add_an_item_to_list(uint16_t s_handle) {
  mock_function_count_map[__func__]++;
  return elem;
}
tGATT_IF GATT_Register(const Uuid& app_uuid128, tGATT_CBACK* p_cb_info,
                       bool eatt_support) {
  mock_function_count_map[__func__]++;
  return 0;
}
tGATT_STATUS GATTC_ConfigureMTU(uint16_t conn_id, uint16_t mtu) {
  mock_function_count_map[__func__]++;
  return GATT_SUCCESS;
}
tGATT_STATUS GATTC_Discover(uint16_t conn_id, tGATT_DISC_TYPE disc_type,
                            uint16_t start_handle, uint16_t end_handle) {
  mock_function_count_map[__func__]++;
  return GATT_SUCCESS;
}
tGATT_STATUS GATTC_Discover(uint16_t conn_id, tGATT_DISC_TYPE disc_type,
                            uint16_t start_handle, uint16_t end_handle,
                            const Uuid& uuid) {
  mock_function_count_map[__func__]++;
  return GATT_SUCCESS;
}
tGATT_STATUS GATTC_ExecuteWrite(uint16_t conn_id, bool is_execute) {
  mock_function_count_map[__func__]++;
  return GATT_SUCCESS;
}
tGATT_STATUS GATTC_Read(uint16_t conn_id, tGATT_READ_TYPE type,
                        tGATT_READ_PARAM* p_read) {
  mock_function_count_map[__func__]++;
  return GATT_SUCCESS;
}
tGATT_STATUS GATTC_SendHandleValueConfirm(uint16_t conn_id, uint16_t cid) {
  mock_function_count_map[__func__]++;
  return GATT_SUCCESS;
}
tGATT_STATUS GATTC_Write(uint16_t conn_id, tGATT_WRITE_TYPE type,
                         tGATT_VALUE* p_write) {
  mock_function_count_map[__func__]++;
  return GATT_SUCCESS;
}
tGATT_STATUS GATTS_AddService(tGATT_IF gatt_if, btgatt_db_element_t* service,
                              int count) {
  mock_function_count_map[__func__]++;
  return GATT_SUCCESS;
}
tGATT_STATUS GATTS_HandleValueIndication(uint16_t conn_id, uint16_t attr_handle,
                                         uint16_t val_len, uint8_t* p_val) {
  mock_function_count_map[__func__]++;
  return GATT_SUCCESS;
}
tGATT_STATUS GATTS_HandleValueNotification(uint16_t conn_id,
                                           uint16_t attr_handle,
                                           uint16_t val_len, uint8_t* p_val) {
  mock_function_count_map[__func__]++;
  return GATT_SUCCESS;
}
tGATT_STATUS GATTS_SendRsp(uint16_t conn_id, uint32_t trans_id,
                           tGATT_STATUS status, tGATTS_RSP* p_msg) {
  mock_function_count_map[__func__]++;
  return GATT_SUCCESS;
}
tGATT_STATUS GATT_Disconnect(uint16_t conn_id) {
  mock_function_count_map[__func__]++;
  return GATT_SUCCESS;
}
void GATTS_AddHandleRange(tGATTS_HNDL_RANGE* p_hndl_range) {
  mock_function_count_map[__func__]++;
}
void GATTS_StopService(uint16_t service_handle) {
  mock_function_count_map[__func__]++;
}
void GATT_Deregister(tGATT_IF gatt_if) { mock_function_count_map[__func__]++; }
void GATT_SetIdleTimeout(const RawAddress& bd_addr, uint16_t idle_tout,
                         tBT_TRANSPORT transport) {
  mock_function_count_map[__func__]++;
}
void GATT_StartIf(tGATT_IF gatt_if) { mock_function_count_map[__func__]++; }
