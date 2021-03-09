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
 *   Functions generated:127
 */

#include <cstdint>
#include <map>
#include <string>

extern std::map<std::string, int> mock_function_count_map;

#include "stack/acl/acl.h"
#include "stack/include/acl_api.h"
#include "stack/include/hci_error_code.h"
#include "types/bt_transport.h"
#include "types/raw_address.h"

#ifndef UNUSED_ATTR
#define UNUSED_ATTR
#endif

bool IsEprAvailable(const tACL_CONN& p_acl) {
  mock_function_count_map[__func__]++;
  return false;
}
bool ACL_SupportTransparentSynchronousData(const RawAddress& bd_addr) {
  mock_function_count_map[__func__]++;
  return false;
}
bool BTM_BLE_IS_RESOLVE_BDA(const RawAddress& x) {
  mock_function_count_map[__func__]++;
  return false;
}
bool BTM_IsAclConnectionUp(const RawAddress& remote_bda,
                           tBT_TRANSPORT transport) {
  mock_function_count_map[__func__]++;
  return false;
}
bool BTM_IsAclConnectionUpAndHandleValid(const RawAddress& remote_bda,
                                         tBT_TRANSPORT transport) {
  mock_function_count_map[__func__]++;
  return false;
}
bool BTM_IsAclConnectionUpFromHandle(uint16_t hci_handle) {
  mock_function_count_map[__func__]++;
  return false;
}
bool BTM_IsBleConnection(uint16_t hci_handle) {
  mock_function_count_map[__func__]++;
  return false;
}
bool BTM_ReadRemoteConnectionAddr(const RawAddress& pseudo_addr,
                                  RawAddress& conn_addr,
                                  tBLE_ADDR_TYPE* p_addr_type) {
  mock_function_count_map[__func__]++;
  return false;
}
bool BTM_ReadRemoteVersion(const RawAddress& addr, uint8_t* lmp_version,
                           uint16_t* manufacturer, uint16_t* lmp_sub_version) {
  mock_function_count_map[__func__]++;
  return false;
}
bool acl_create_le_connection(const RawAddress& bd_addr) {
  mock_function_count_map[__func__]++;
  return false;
}
bool acl_create_le_connection_with_id(uint8_t id, const RawAddress& bd_addr) {
  mock_function_count_map[__func__]++;
  return false;
}
bool acl_is_role_switch_allowed() {
  mock_function_count_map[__func__]++;
  return false;
}
bool acl_is_switch_role_idle(const RawAddress& bd_addr,
                             tBT_TRANSPORT transport) {
  mock_function_count_map[__func__]++;
  return false;
}
bool acl_peer_supports_ble_2m_phy(uint16_t hci_handle) {
  mock_function_count_map[__func__]++;
  return false;
}
bool acl_peer_supports_ble_coded_phy(uint16_t hci_handle) {
  mock_function_count_map[__func__]++;
  return false;
}
bool acl_peer_supports_ble_connection_parameters_request(
    const RawAddress& remote_bda) {
  mock_function_count_map[__func__]++;
  return false;
}
bool acl_peer_supports_ble_packet_extension(uint16_t hci_handle) {
  mock_function_count_map[__func__]++;
  return false;
}
bool acl_peer_supports_sniff_subrating(const RawAddress& remote_bda) {
  mock_function_count_map[__func__]++;
  return false;
}
bool acl_refresh_remote_address(const RawAddress& identity_address,
                                tBLE_ADDR_TYPE identity_address_type,
                                const RawAddress& bda, tBLE_ADDR_TYPE rra_type,
                                const RawAddress& rpa) {
  mock_function_count_map[__func__]++;
  return false;
}
bool acl_set_peer_le_features_from_handle(uint16_t hci_handle,
                                          const uint8_t* p) {
  mock_function_count_map[__func__]++;
  return false;
}
bool sco_peer_supports_esco_2m_phy(const RawAddress& remote_bda) {
  mock_function_count_map[__func__]++;
  return false;
}
bool sco_peer_supports_esco_3m_phy(const RawAddress& remote_bda) {
  mock_function_count_map[__func__]++;
  return false;
}
const RawAddress acl_address_from_handle(uint16_t handle) {
  mock_function_count_map[__func__]++;
  return RawAddress::kEmpty;
}
void acl_send_data_packet_br_edr([[maybe_unused]] const RawAddress& bd_addr,
                                 BT_HDR* p_buf) {
  mock_function_count_map[__func__]++;
}
void acl_create_classic_connection(const RawAddress& bd_addr,
                                   bool there_are_high_priority_channels,
                                   bool is_bonding) {
  mock_function_count_map[__func__]++;
}
tACL_CONN* acl_get_connection_from_address(const RawAddress& bd_addr,
                                           tBT_TRANSPORT transport) {
  mock_function_count_map[__func__]++;
  return nullptr;
}
tACL_CONN* acl_get_connection_from_handle(uint16_t handle) {
  mock_function_count_map[__func__]++;
  return nullptr;
}
tBTM_STATUS BTM_GetLinkSuperTout(const RawAddress& remote_bda,
                                 uint16_t* p_timeout) {
  mock_function_count_map[__func__]++;
  return BTM_SUCCESS;
}
tBTM_STATUS BTM_GetRole(const RawAddress& remote_bd_addr, uint8_t* p_role) {
  mock_function_count_map[__func__]++;
  return BTM_SUCCESS;
}
tBTM_STATUS BTM_ReadFailedContactCounter(const RawAddress& remote_bda,
                                         tBTM_CMPL_CB* p_cb) {
  mock_function_count_map[__func__]++;
  return BTM_SUCCESS;
}
tBTM_STATUS BTM_ReadRSSI(const RawAddress& remote_bda, tBTM_CMPL_CB* p_cb) {
  mock_function_count_map[__func__]++;
  return BTM_SUCCESS;
}
tBTM_STATUS BTM_ReadTxPower(const RawAddress& remote_bda,
                            tBT_TRANSPORT transport, tBTM_CMPL_CB* p_cb) {
  mock_function_count_map[__func__]++;
  return BTM_SUCCESS;
}
tBTM_STATUS BTM_SetLinkSuperTout(const RawAddress& remote_bda,
                                 uint16_t timeout) {
  mock_function_count_map[__func__]++;
  return BTM_SUCCESS;
}
tBTM_STATUS BTM_SwitchRoleToCentral(const RawAddress& remote_bd_addr) {
  mock_function_count_map[__func__]++;
  return BTM_SUCCESS;
}
tBTM_STATUS btm_remove_acl(const RawAddress& bd_addr, tBT_TRANSPORT transport) {
  mock_function_count_map[__func__]++;
  return BTM_SUCCESS;
}
uint16_t BTM_GetHCIConnHandle(const RawAddress& remote_bda,
                              tBT_TRANSPORT transport) {
  mock_function_count_map[__func__]++;
  return 0;
}
uint16_t BTM_GetMaxPacketSize(const RawAddress& addr) {
  mock_function_count_map[__func__]++;
  return 0;
}
uint16_t mock_stack_acl_num_links = 0;
uint16_t BTM_GetNumAclLinks(void) {
  mock_function_count_map[__func__]++;
  return mock_stack_acl_num_links;
}
uint16_t acl_get_supported_packet_types() {
  mock_function_count_map[__func__]++;
  return 0;
}
uint16_t btm_get_acl_disc_reason_code(void) {
  mock_function_count_map[__func__]++;
  return 0;
}
uint8_t BTM_SetTraceLevel(uint8_t new_level) {
  mock_function_count_map[__func__]++;
  return 0;
}
uint8_t acl_link_role_from_handle(uint16_t handle) {
  mock_function_count_map[__func__]++;
  return 0;
}
uint8_t btm_handle_to_acl_index(uint16_t hci_handle) {
  mock_function_count_map[__func__]++;
  return 0;
}
uint8_t* BTM_ReadRemoteFeatures(const RawAddress& addr) {
  mock_function_count_map[__func__]++;
  return nullptr;
}
void ACL_RegisterClient(struct acl_client_callback_s* callbacks) {
  mock_function_count_map[__func__]++;
}
void ACL_UnregisterClient(struct acl_client_callback_s* callbacks) {
  mock_function_count_map[__func__]++;
}
void BTM_ReadConnectionAddr(const RawAddress& remote_bda,
                            RawAddress& local_conn_addr,
                            tBLE_ADDR_TYPE* p_addr_type) {
  mock_function_count_map[__func__]++;
}
void BTM_acl_after_controller_started(const controller_t* controller) {
  mock_function_count_map[__func__]++;
}
void BTM_block_role_switch_for(const RawAddress& peer_addr) {
  mock_function_count_map[__func__]++;
}
void BTM_block_sniff_mode_for(const RawAddress& peer_addr) {
  mock_function_count_map[__func__]++;
}
void BTM_default_block_role_switch() { mock_function_count_map[__func__]++; }
void BTM_default_unblock_role_switch() { mock_function_count_map[__func__]++; }
void BTM_unblock_role_switch_for(const RawAddress& peer_addr) {
  mock_function_count_map[__func__]++;
}
void BTM_unblock_sniff_mode_for(const RawAddress& peer_addr) {
  mock_function_count_map[__func__]++;
}
void acl_accept_connection_request(const RawAddress& bd_addr, uint8_t role) {
  mock_function_count_map[__func__]++;
}
void acl_disconnect_after_role_switch(uint16_t conn_handle,
                                      tHCI_STATUS reason) {
  mock_function_count_map[__func__]++;
}
void acl_disconnect_from_handle(uint16_t handle, tHCI_STATUS reason) {
  mock_function_count_map[__func__]++;
}
void acl_link_segments_xmitted(BT_HDR* p_msg) {
  mock_function_count_map[__func__]++;
}
void acl_packets_completed(uint16_t handle, uint16_t credits) {
  mock_function_count_map[__func__]++;
}
void acl_process_extended_features(uint16_t handle, uint8_t current_page_number,
                                   uint8_t max_page_number, uint64_t features) {
  mock_function_count_map[__func__]++;
}
void acl_process_num_completed_pkts(uint8_t* p, uint8_t evt_len) {
  mock_function_count_map[__func__]++;
}
void acl_rcv_acl_data(BT_HDR* p_msg) { mock_function_count_map[__func__]++; }
void acl_reject_connection_request(const RawAddress& bd_addr, uint8_t reason) {
  mock_function_count_map[__func__]++;
}
void acl_send_data_packet_ble(const RawAddress& bd_addr, BT_HDR* p_buf) {
  mock_function_count_map[__func__]++;
}
void acl_set_disconnect_reason(tHCI_STATUS acl_disc_reason) {
  mock_function_count_map[__func__]++;
}
void acl_write_automatic_flush_timeout(const RawAddress& bd_addr,
                                       uint16_t flush_timeout_in_ticks) {
  mock_function_count_map[__func__]++;
}
void btm_acl_chk_peer_pkt_type_support(tACL_CONN* p, uint16_t* p_pkt_type) {
  mock_function_count_map[__func__]++;
}
void btm_acl_connected(const RawAddress& bda, uint16_t handle,
                       tHCI_STATUS status, uint8_t enc_mode) {
  mock_function_count_map[__func__]++;
}
void btm_acl_connection_request(const RawAddress& bda, uint8_t* dc) {
  mock_function_count_map[__func__]++;
}
void btm_acl_created(const RawAddress& bda, uint16_t hci_handle,
                     uint8_t link_role, tBT_TRANSPORT transport) {
  mock_function_count_map[__func__]++;
}
void btm_acl_device_down(void) { mock_function_count_map[__func__]++; }
void btm_acl_disconnected(tHCI_STATUS status, uint16_t handle,
                          tHCI_REASON reason) {
  mock_function_count_map[__func__]++;
}
void btm_acl_encrypt_change(uint16_t handle, uint8_t status,
                            uint8_t encr_enable) {
  mock_function_count_map[__func__]++;
}
void btm_acl_notif_conn_collision(const RawAddress& bda) {
  mock_function_count_map[__func__]++;
}
void btm_acl_paging(BT_HDR* p, const RawAddress& bda) {
  mock_function_count_map[__func__]++;
}
void btm_acl_process_sca_cmpl_pkt(uint8_t len, uint8_t* data) {
  mock_function_count_map[__func__]++;
}
void btm_acl_removed(uint16_t handle) { mock_function_count_map[__func__]++; }
void btm_acl_reset_paging(void) { mock_function_count_map[__func__]++; }
void btm_acl_resubmit_page(void) { mock_function_count_map[__func__]++; }
void btm_acl_role_changed(tHCI_STATUS hci_status, const RawAddress& bd_addr,
                          uint8_t new_role) {
  mock_function_count_map[__func__]++;
}
void btm_acl_set_paging(bool value) { mock_function_count_map[__func__]++; }
void btm_acl_update_conn_addr(uint16_t handle, const RawAddress& address) {
  mock_function_count_map[__func__]++;
}
void btm_acl_update_inquiry_status(uint8_t status) {
  mock_function_count_map[__func__]++;
}
void btm_ble_refresh_local_resolvable_private_addr(
    const RawAddress& pseudo_addr, const RawAddress& local_rpa) {
  mock_function_count_map[__func__]++;
}
void btm_cont_rswitch_from_handle(uint16_t hci_handle) {
  mock_function_count_map[__func__]++;
}
void btm_establish_continue_from_address(const RawAddress& bda,
                                         tBT_TRANSPORT transport) {
  mock_function_count_map[__func__]++;
}
void btm_process_remote_ext_features(tACL_CONN* p_acl_cb,
                                     uint8_t num_read_pages) {
  mock_function_count_map[__func__]++;
}
void btm_process_remote_version_complete(uint8_t status, uint16_t handle,
                                         uint8_t lmp_version,
                                         uint16_t manufacturer,
                                         uint16_t lmp_subversion) {
  mock_function_count_map[__func__]++;
}
void btm_read_automatic_flush_timeout_complete(uint8_t* p) {
  mock_function_count_map[__func__]++;
}
void btm_read_failed_contact_counter_complete(uint8_t* p) {
  mock_function_count_map[__func__]++;
}
void btm_read_failed_contact_counter_timeout(UNUSED_ATTR void* data) {
  mock_function_count_map[__func__]++;
}
void btm_read_link_quality_complete(uint8_t* p) {
  mock_function_count_map[__func__]++;
}
void btm_read_link_quality_timeout(UNUSED_ATTR void* data) {
  mock_function_count_map[__func__]++;
}
void btm_read_remote_ext_features(uint16_t handle, uint8_t page_number) {
  mock_function_count_map[__func__]++;
}
void btm_read_remote_ext_features_complete(uint16_t handle, uint8_t page_num,
                                           uint8_t max_page,
                                           uint8_t* features) {
  mock_function_count_map[__func__]++;
}
void btm_read_remote_ext_features_complete_raw(uint8_t* p, uint8_t evt_len) {
  mock_function_count_map[__func__]++;
}
void btm_read_remote_ext_features_failed(uint8_t status, uint16_t handle) {
  mock_function_count_map[__func__]++;
}
void btm_read_remote_features_complete(uint16_t handle, uint8_t* features) {
  mock_function_count_map[__func__]++;
}
void btm_read_remote_features_complete_raw(uint8_t* p) {
  mock_function_count_map[__func__]++;
}
void btm_read_remote_version_complete(tHCI_STATUS status, uint16_t handle,
                                      uint8_t lmp_version,
                                      uint16_t manufacturer,
                                      uint16_t lmp_subversion) {
  mock_function_count_map[__func__]++;
}
void btm_read_remote_version_complete_raw(uint8_t* p) {
  mock_function_count_map[__func__]++;
}
void btm_read_rssi_complete(uint8_t* p) { mock_function_count_map[__func__]++; }
void btm_read_rssi_timeout(UNUSED_ATTR void* data) {
  mock_function_count_map[__func__]++;
}
void btm_read_tx_power_complete(uint8_t* p, bool is_ble) {
  mock_function_count_map[__func__]++;
}
void btm_read_tx_power_timeout(UNUSED_ATTR void* data) {
  mock_function_count_map[__func__]++;
}
void btm_rejectlist_role_change_device(const RawAddress& bd_addr,
                                       uint8_t hci_status) {
  mock_function_count_map[__func__]++;
}
void btm_set_link_policy(tACL_CONN* conn, tLINK_POLICY policy) {
  mock_function_count_map[__func__]++;
}
void btm_set_packet_types_from_address(const RawAddress& bd_addr,
                                       tBT_TRANSPORT transport,
                                       uint16_t pkt_types) {
  mock_function_count_map[__func__]++;
}
void hci_btm_set_link_supervision_timeout(tACL_CONN& link, uint16_t timeout) {
  mock_function_count_map[__func__]++;
}
void on_acl_br_edr_connected(const RawAddress& bda, uint16_t handle,
                             uint8_t enc_mode) {
  mock_function_count_map[__func__]++;
}
void on_acl_br_edr_failed(const RawAddress& bda, tHCI_STATUS status) {
  mock_function_count_map[__func__]++;
}
