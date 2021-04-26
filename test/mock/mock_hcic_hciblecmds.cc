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
 */

#include <map>
#include <string>

extern std::map<std::string, int> mock_function_count_map;
#define UNUSED_ATTR

#include <base/bind.h>
#include <stddef.h>
#include <string.h>
#include "bt_common.h"
#include "bt_target.h"
#include "btu.h"
#include "hcidefs.h"
#include "hcimsgs.h"
void btsnd_hci_ble_add_device_to_periodic_advertiser_list(
    uint8_t adv_addr_type, const RawAddress& adv_addr, uint8_t adv_sid,
    base::OnceCallback<void(uint8_t*, uint16_t)> cb) {
  mock_function_count_map[__func__]++;
}
void btsnd_hci_ble_clear_periodic_advertiser_list(
    base::OnceCallback<void(uint8_t*, uint16_t)> cb) {
  mock_function_count_map[__func__]++;
}
void btsnd_hci_ble_read_periodic_advertiser_list_size(
    base::OnceCallback<void(uint8_t*, uint16_t)> cb) {
  mock_function_count_map[__func__]++;
}
void btsnd_hci_ble_remove_device_from_periodic_advertiser_list(
    uint8_t adv_addr_type, const RawAddress& adv_addr, uint8_t adv_sid,
    base::OnceCallback<void(uint8_t*, uint16_t)> cb) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_accept_cis_req(uint16_t conn_handle) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_big_create_sync(uint8_t big_handle, uint16_t sync_handle,
                                uint8_t enc, std::array<uint8_t, 16> bcst_code,
                                uint8_t mse, uint16_t big_sync_timeout,
                                std::vector<uint8_t> bis) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_big_term_sync(uint8_t big_handle,
                              base::OnceCallback<void(uint8_t*, uint16_t)> cb) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_ble_add_acceptlist(
    uint8_t addr_type, const RawAddress& bda,
    base::OnceCallback<void(uint8_t*, uint16_t)> cb) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_ble_add_device_resolving_list(uint8_t addr_type_peer,
                                              const RawAddress& bda_peer,
                                              const Octet16& irk_peer,
                                              const Octet16& irk_local) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_ble_clear_acceptlist(
    base::OnceCallback<void(uint8_t*, uint16_t)> cb) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_ble_clear_resolving_list(void) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_ble_create_conn_cancel(void) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_ble_create_ll_conn(
    uint16_t scan_int, uint16_t scan_win, uint8_t init_filter_policy,
    uint8_t addr_type_peer, const RawAddress& bda_peer, uint8_t addr_type_own,
    uint16_t conn_int_min, uint16_t conn_int_max, uint16_t conn_latency,
    uint16_t conn_timeout, uint16_t min_ce_len, uint16_t max_ce_len) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_ble_encrypt(uint8_t* key, uint8_t key_len, uint8_t* plain_text,
                            uint8_t pt_len, void* p_cmd_cplt_cback) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_ble_enh_rx_test(uint8_t rx_chan, uint8_t phy,
                                uint8_t mod_index) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_ble_enh_tx_test(uint8_t tx_chan, uint8_t data_len,
                                uint8_t payload, uint8_t phy) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_ble_ext_create_conn(uint8_t init_filter_policy,
                                    uint8_t addr_type_own,
                                    uint8_t addr_type_peer,
                                    const RawAddress& bda_peer,
                                    uint8_t initiating_phys,
                                    EXT_CONN_PHY_CFG* phy_cfg) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_ble_ltk_req_neg_reply(uint16_t handle) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_ble_ltk_req_reply(uint16_t handle, const Octet16& ltk) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_ble_periodic_advertising_create_sync(
    uint8_t options, uint8_t adv_sid, uint8_t adv_addr_type,
    const RawAddress& adv_addr, uint16_t skip_num, uint16_t sync_timeout,
    uint8_t sync_cte_type) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_ble_periodic_advertising_create_sync_cancel(
    base::OnceCallback<void(uint8_t*, uint16_t)> cb) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_ble_periodic_advertising_set_info_transfer(
    uint16_t conn_handle, uint16_t service_data, uint8_t adv_handle,
    base::OnceCallback<void(uint8_t*, uint16_t)> cb) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_ble_periodic_advertising_sync_transfer(
    uint16_t conn_handle, uint16_t service_data, uint16_t sync_handle,
    base::OnceCallback<void(uint8_t*, uint16_t)> cb) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_ble_periodic_advertising_terminate_sync(
    uint16_t sync_handle, base::OnceCallback<void(uint8_t*, uint16_t)> cb) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_ble_rand(base::Callback<void(BT_OCTET8)> cb) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_ble_read_adv_chnl_tx_power(void) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_ble_read_chnl_map(uint16_t handle) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_ble_read_host_supported(void) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_ble_read_remote_feat(uint16_t handle) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_ble_read_resolvable_addr_local(uint8_t addr_type_peer,
                                               const RawAddress& bda_peer) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_ble_read_resolvable_addr_peer(uint8_t addr_type_peer,
                                              const RawAddress& bda_peer) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_ble_receiver_test(uint8_t rx_freq) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_ble_remove_from_acceptlist(
    uint8_t addr_type, const RawAddress& bda,
    base::OnceCallback<void(uint8_t*, uint16_t)> cb) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_ble_rm_device_resolving_list(uint8_t addr_type_peer,
                                             const RawAddress& bda_peer) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_ble_set_addr_resolution_enable(uint8_t addr_resolution_enable) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_ble_set_adv_data(uint8_t data_len, uint8_t* p_data) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_ble_set_adv_enable(uint8_t adv_enable) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_ble_set_data_length(uint16_t conn_handle, uint16_t tx_octets,
                                    uint16_t tx_time) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_ble_set_default_periodic_advertising_sync_transfer_params(
    uint16_t conn_handle, uint8_t mode, uint16_t skip, uint16_t sync_timeout,
    uint8_t cte_type, base::OnceCallback<void(uint8_t*, uint16_t)> cb) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_ble_set_extended_scan_enable(uint8_t enable,
                                             uint8_t filter_duplicates,
                                             uint16_t duration,
                                             uint16_t period) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_ble_set_extended_scan_params(uint8_t own_address_type,
                                             uint8_t scanning_filter_policy,
                                             uint8_t scanning_phys,
                                             scanning_phy_cfg* phy_cfg) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_ble_set_host_chnl_class(
    uint8_t chnl_map[HCIC_BLE_CHNL_MAP_SIZE]) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_ble_set_local_used_feat(uint8_t feat_set[8]) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_ble_set_periodic_advertising_receive_enable(
    uint16_t sync_handle, bool enable,
    base::OnceCallback<void(uint8_t*, uint16_t)> cb) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_ble_set_periodic_advertising_sync_transfer_params(
    uint16_t conn_handle, uint8_t mode, uint16_t skip, uint16_t sync_timeout,
    uint8_t cte_type, base::OnceCallback<void(uint8_t*, uint16_t)> cb) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_ble_set_privacy_mode(uint8_t addr_type_peer,
                                     const RawAddress& bda_peer,
                                     uint8_t privacy_type) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_ble_set_rand_priv_addr_timeout(uint16_t rpa_timout) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_ble_set_random_addr(const RawAddress& random_bda) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_ble_set_scan_enable(uint8_t scan_enable, uint8_t duplicate) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_ble_set_scan_params(uint8_t scan_type, uint16_t scan_int,
                                    uint16_t scan_win, uint8_t addr_type_own,
                                    uint8_t scan_filter_policy) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_ble_set_scan_rsp_data(uint8_t data_len, uint8_t* p_scan_rsp) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_ble_start_enc(uint16_t handle,
                              uint8_t rand[HCIC_BLE_RAND_DI_SIZE],
                              uint16_t ediv, const Octet16& ltk) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_ble_test_end(void) { mock_function_count_map[__func__]++; }
void btsnd_hcic_ble_transmitter_test(uint8_t tx_freq, uint8_t test_data_len,
                                     uint8_t payload) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_ble_upd_ll_conn_params(uint16_t handle, uint16_t conn_int_min,
                                       uint16_t conn_int_max,
                                       uint16_t conn_latency,
                                       uint16_t conn_timeout,
                                       uint16_t min_ce_len,
                                       uint16_t max_ce_len) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_ble_write_adv_params(uint16_t adv_int_min, uint16_t adv_int_max,
                                     uint8_t adv_type, uint8_t addr_type_own,
                                     uint8_t addr_type_dir,
                                     const RawAddress& direct_bda,
                                     uint8_t channel_map,
                                     uint8_t adv_filter_policy) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_create_big(uint8_t big_handle, uint8_t adv_handle,
                           uint8_t num_bis, uint32_t sdu_itv,
                           uint16_t max_sdu_size, uint16_t transport_latency,
                           uint8_t rtn, uint8_t phy, uint8_t packing,
                           uint8_t framing, uint8_t enc,
                           std::array<uint8_t, 16> bcst_code) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_create_cis(uint8_t num_cis, const EXT_CIS_CREATE_CFG* cis_cfg,
                           base::OnceCallback<void(uint8_t*, uint16_t)> cb) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_read_iso_tx_sync(
    uint16_t iso_handle, base::OnceCallback<void(uint8_t*, uint16_t)> cb) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_rej_cis_req(uint16_t conn_handle, uint8_t reason,
                            base::OnceCallback<void(uint8_t*, uint16_t)> cb) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_remove_cig(uint8_t cig_id,
                           base::OnceCallback<void(uint8_t*, uint16_t)> cb) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_remove_iso_data_path(
    uint16_t iso_handle, uint8_t data_path_dir,
    base::OnceCallback<void(uint8_t*, uint16_t)> cb) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_read_iso_link_quality(
    uint16_t iso_handle, base::OnceCallback<void(uint8_t*, uint16_t)> cb) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_req_peer_sca(uint16_t conn_handle) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_set_cig_params(
    uint8_t cig_id, uint32_t sdu_itv_mtos, uint32_t sdu_itv_stom, uint8_t sca,
    uint8_t packing, uint8_t framing, uint16_t max_trans_lat_stom,
    uint16_t max_trans_lat_mtos, uint8_t cis_cnt, const EXT_CIS_CFG* cis_cfg,
    base::OnceCallback<void(uint8_t*, uint16_t)> cb) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_setup_iso_data_path(
    uint16_t iso_handle, uint8_t data_path_dir, uint8_t data_path_id,
    uint8_t codec_id_format, uint16_t codec_id_company,
    uint16_t codec_id_vendor, uint32_t controller_delay,
    std::vector<uint8_t> codec_conf,
    base::OnceCallback<void(uint8_t*, uint16_t)> cb) {
  mock_function_count_map[__func__]++;
}
void btsnd_hcic_term_big(uint8_t big_handle, uint8_t reason) {
  mock_function_count_map[__func__]++;
}
