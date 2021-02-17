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
 *   Functions generated:14
 */

#include <cstdint>
#include <map>
#include <string>

extern std::map<std::string, int> mock_function_count_map;

#include "stack/gatt/gatt_int.h"
#include "types/bt_transport.h"
#include "types/raw_address.h"

#ifndef UNUSED_ATTR
#define UNUSED_ATTR
#endif

uint16_t gatt_profile_find_conn_id_by_bd_addr(const RawAddress& remote_bda) {
  mock_function_count_map[__func__]++;
  return 0;
}
bool gatt_profile_get_eatt_support(
    const RawAddress& remote_bda,
    base::OnceCallback<void(const RawAddress&, bool)> cb) {
  mock_function_count_map[__func__]++;
  return false;
}
bool gatt_sr_is_cl_change_aware(tGATT_TCB& tcb) {
  mock_function_count_map[__func__]++;
  return false;
}
tGATT_PROFILE_CLCB* gatt_profile_clcb_alloc(uint16_t conn_id,
                                            const RawAddress& bda,
                                            tBT_TRANSPORT tranport) {
  mock_function_count_map[__func__]++;
  return nullptr;
}
tGATT_STATUS proc_read_req(uint16_t conn_id, tGATTS_REQ_TYPE,
                           tGATT_READ_REQ* p_data, tGATTS_RSP* p_rsp) {
  mock_function_count_map[__func__]++;
  return GATT_SUCCESS;
}
tGATT_STATUS proc_write_req(uint16_t conn_id, tGATTS_REQ_TYPE,
                            tGATT_WRITE_REQ* p_data) {
  mock_function_count_map[__func__]++;
  return GATT_SUCCESS;
}
tGATT_STATUS read_attr_value(uint16_t conn_id, uint16_t handle,
                             tGATT_VALUE* p_value, bool is_long) {
  mock_function_count_map[__func__]++;
  return GATT_SUCCESS;
}
void GATT_ConfigServiceChangeCCC(const RawAddress& remote_bda, bool enable,
                                 tBT_TRANSPORT transport) {
  mock_function_count_map[__func__]++;
}
void gatt_profile_clcb_dealloc(tGATT_PROFILE_CLCB* p_clcb) {
  mock_function_count_map[__func__]++;
}
void gatt_profile_db_init(void) { mock_function_count_map[__func__]++; }
void gatt_sr_init_cl_status(tGATT_TCB& tcb) {
  mock_function_count_map[__func__]++;
}
void gatt_sr_update_cl_status(tGATT_TCB& tcb, bool chg_aware) {
  mock_function_count_map[__func__]++;
}
