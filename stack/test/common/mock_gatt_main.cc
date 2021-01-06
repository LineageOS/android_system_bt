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
 *   Functions generated:23
 */

#include <map>
#include <string>

extern std::map<std::string, int> mock_function_count_map;

#include "bt_common.h"
#include "bt_target.h"
#include "btm_ble_int.h"
#include "device/include/interop.h"
#include "l2c_api.h"
#include "osi/include/osi.h"
#include "stack/btm/btm_dev.h"
#include "stack/btm/btm_sec.h"
#include "stack/gatt/gatt_int.h"
#include "stack/include/l2cap_acl_interface.h"

#ifndef UNUSED_ATTR
#define UNUSED_ATTR
#endif

bool gatt_act_connect(tGATT_REG* p_reg, const RawAddress& bd_addr,
                      tBT_TRANSPORT transport, int8_t initiating_phys) {
  mock_function_count_map[__func__]++;
  return false;
}
bool gatt_connect(const RawAddress& rem_bda, tGATT_TCB* p_tcb,
                  tBT_TRANSPORT transport, uint8_t initiating_phys,
                  tGATT_IF gatt_if) {
  mock_function_count_map[__func__]++;
  return false;
}
bool gatt_disconnect(tGATT_TCB* p_tcb) {
  mock_function_count_map[__func__]++;
  return false;
}
bool gatt_update_app_hold_link_status(tGATT_IF gatt_if, tGATT_TCB* p_tcb,
                                      bool is_add) {
  mock_function_count_map[__func__]++;
  return false;
}
tGATT_CH_STATE gatt_get_ch_state(tGATT_TCB* p_tcb) {
  mock_function_count_map[__func__]++;
  return GATT_CH_CLOSE;
}
void gatt_add_a_bonded_dev_for_srv_chg(const RawAddress& bda) {
  mock_function_count_map[__func__]++;
}
void gatt_chk_srv_chg(tGATTS_SRV_CHG* p_srv_chg_clt) {
  mock_function_count_map[__func__]++;
}
void gatt_data_process(tGATT_TCB& tcb, uint16_t cid, BT_HDR* p_buf) {
  mock_function_count_map[__func__]++;
}
void gatt_find_in_device_record(const RawAddress& bd_addr,
                                tBLE_BD_ADDR* address_with_type) {
  mock_function_count_map[__func__]++;
}
void gatt_free(void) { mock_function_count_map[__func__]++; }
void gatt_init(void) { mock_function_count_map[__func__]++; }
void gatt_init_srv_chg(void) { mock_function_count_map[__func__]++; }
void gatt_l2cif_config_cfm_cback(uint16_t lcid, uint16_t initiator,
                                 tL2CAP_CFG_INFO* p_cfg) {
  mock_function_count_map[__func__]++;
}
void gatt_l2cif_config_ind_cback(uint16_t lcid, tL2CAP_CFG_INFO* p_cfg) {
  mock_function_count_map[__func__]++;
}
void gatt_l2cif_disconnect_ind_cback(uint16_t lcid, bool ack_needed) {
  mock_function_count_map[__func__]++;
}
void gatt_notify_conn_update(const RawAddress&, uint16_t interval,
                             uint16_t latency, uint16_t timeout,
                             tHCI_STATUS status) {
  mock_function_count_map[__func__]++;
}
void gatt_notify_phy_updated(tGATT_STATUS status, uint16_t handle,
                             uint8_t tx_phy, uint8_t rx_phy) {
  mock_function_count_map[__func__]++;
}
void gatt_proc_srv_chg(void) { mock_function_count_map[__func__]++; }
void gatt_send_srv_chg_ind(const RawAddress& peer_bda) {
  mock_function_count_map[__func__]++;
}
void gatt_set_ch_state(tGATT_TCB* p_tcb, tGATT_CH_STATE ch_state) {
  mock_function_count_map[__func__]++;
}
void gatt_update_app_use_link_flag(tGATT_IF gatt_if, tGATT_TCB* p_tcb,
                                   bool is_add, bool check_acl_link) {
  mock_function_count_map[__func__]++;
}
