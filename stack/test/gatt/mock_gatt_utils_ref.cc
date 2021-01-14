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

#include "stack/gatt/gatt_int.h"
#include "utils/include/bt_utils.h"

/** stack/btm/btm_ble.cc*/
uint8_t btm_ble_read_sec_key_size(const RawAddress& bd_addr) { return 0; }
bool BTM_GetSecurityFlagsByTransport(const RawAddress& bd_addr,
                                     uint8_t* p_sec_flags,
                                     tBT_TRANSPORT transport) {
  return false;
}

/** stack/btu/btu_task.cc, indirect reference, gatt_utils.cc -> libosi */
bluetooth::common::MessageLoopThread* get_main_thread() { return nullptr; }

/** stack/gatt/connection_manager.cc */
namespace connection_manager {
bool background_connect_remove(uint8_t app_id, const RawAddress& address) {
  return false;
}
bool direct_connect_remove(uint8_t app_id, const RawAddress& address) {
  return false;
}
}  // namespace connection_manager

/** stack/gatt/att_protocol.cc */
BT_HDR* attp_build_sr_msg(tGATT_TCB& tcb, uint8_t op_code,
                          tGATT_SR_MSG* p_msg) {
  return nullptr;
}
tGATT_STATUS attp_send_cl_confirmation_msg(tGATT_TCB& tcb, uint16_t cid) {
  return GATT_SUCCESS;
}
tGATT_STATUS attp_send_cl_msg(tGATT_TCB& tcb, tGATT_CLCB* p_clcb,
                              uint8_t op_code, tGATT_CL_MSG* p_msg) {
  return GATT_SUCCESS;
}
tGATT_STATUS attp_send_sr_msg(tGATT_TCB& tcb, uint16_t cid, BT_HDR* p_msg) {
  return GATT_SUCCESS;
}

/** stack/gatt/gatt_attr.cc */
void gatt_sr_init_cl_status(tGATT_TCB& tcb) {}

/** stack/gatt/gatt_cl.cc */
void gatt_act_discovery(tGATT_CLCB* p_clcb) {}

/** stack/gatt/gatt_main.cc */
void gatt_update_app_use_link_flag(tGATT_IF gatt_if, tGATT_TCB* p_tcb,
                                   bool is_add, bool check_acl_link) {}
void gatts_proc_srv_chg_ind_ack(tGATT_TCB) {}
bool gatt_disconnect(tGATT_TCB* p_tcb) { return false; }
tGATT_CH_STATE gatt_get_ch_state(tGATT_TCB* p_tcb) { return GATT_CH_CLOSE; }
void gatt_set_ch_state(tGATT_TCB* p_tcb, tGATT_CH_STATE ch_state) {}

/** stack/gatt/gatt_sr.cc */
uint32_t gatt_sr_enqueue_cmd(tGATT_TCB& tcb, uint16_t cid, uint8_t op_code,
                             uint16_t handle) { return 0x0000; }
void gatt_dequeue_sr_cmd(tGATT_TCB& tcb, uint16_t cid) {}


/** stack/l2cap/l2c_ble.cc */
void l2cble_set_fixed_channel_tx_data_length(const RawAddress& remote_bda,
                                             uint16_t fix_cid,
                                             uint16_t tx_mtu) {}
void L2CA_SetLeFixedChannelTxDataLength(const RawAddress& remote_bda,
                                        uint16_t fix_cid,
                                        uint16_t tx_mtu) {}
/** stack/sdp/sdp_db.cc */
bool SDP_AddAttribute(uint32_t handle, uint16_t attr_id, uint8_t attr_type,
                      uint32_t attr_len, uint8_t* p_val) {
  return false;
}
bool SDP_AddProtocolList(uint32_t handle, uint16_t num_elem,
                         tSDP_PROTOCOL_ELEM* p_elem_list) {
  return false;
}
bool SDP_AddServiceClassIdList(uint32_t handle, uint16_t num_services,
                               uint16_t* p_service_uuids) {
  return false;
}
bool SDP_AddUuidSequence(uint32_t handle, uint16_t attr_id, uint16_t num_uuids,
                         uint16_t* p_uuids) {
  return false;
}
uint32_t SDP_CreateRecord(void) { return 0; }

