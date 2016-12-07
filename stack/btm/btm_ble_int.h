/******************************************************************************
 *
 *  Copyright (C) 1999-2012 Broadcom Corporation
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at:
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 ******************************************************************************/

/******************************************************************************
 *
 *  this file contains the main Bluetooth Manager (BTM) internal
 *  definitions.
 *
 ******************************************************************************/

#ifndef BTM_BLE_INT_H
#define BTM_BLE_INT_H

#include "bt_target.h"
#include "bt_common.h"
#include "hcidefs.h"
#include "btm_ble_api.h"
#include "btm_int.h"
#include "btm_int_types.h"

#if BLE_INCLUDED == TRUE && SMP_INCLUDED == TRUE
#include "smp_api.h"
#endif

#include "btm_ble_int_types.h"

#ifdef __cplusplus
extern "C" {
#endif

extern void btm_ble_adv_raddr_timer_timeout(void *data);
extern void btm_ble_refresh_raddr_timer_timeout(void *data);
extern void btm_ble_process_adv_pkt (UINT8 len, UINT8 *p);
extern void btm_ble_proc_scan_rsp_rpt (UINT8 *p);
extern tBTM_STATUS btm_ble_read_remote_name(BD_ADDR remote_bda, tBTM_INQ_INFO *p_cur, tBTM_CMPL_CB *p_cb);
extern BOOLEAN btm_ble_cancel_remote_name(BD_ADDR remote_bda);

extern tBTM_STATUS btm_ble_set_discoverability(UINT16 combined_mode);
extern tBTM_STATUS btm_ble_set_connectability(UINT16 combined_mode);
extern tBTM_STATUS btm_ble_start_inquiry (UINT8 mode, UINT8   duration);
extern void btm_ble_stop_scan(void);
extern void btm_clear_all_pending_le_entry(void);

extern void btm_ble_stop_scan();
extern BOOLEAN btm_ble_send_extended_scan_params(UINT8 scan_type, UINT32 scan_int,
                                                 UINT32 scan_win, UINT8 addr_type_own,
                                                 UINT8 scan_filter_policy);
extern void btm_ble_stop_inquiry(void);
extern void btm_ble_init (void);
extern void btm_ble_connected (UINT8 *bda, UINT16 handle, UINT8 enc_mode, UINT8 role, tBLE_ADDR_TYPE addr_type, BOOLEAN addr_matched);
extern void btm_ble_read_remote_features_complete(UINT8 *p);
extern void btm_ble_write_adv_enable_complete(UINT8 * p);
extern void btm_ble_conn_complete(UINT8 *p, UINT16 evt_len, BOOLEAN enhanced);
extern void btm_read_ble_local_supported_states_complete(UINT8 *p, UINT16 evt_len);
extern tBTM_BLE_CONN_ST btm_ble_get_conn_st(void);
extern void btm_ble_set_conn_st(tBTM_BLE_CONN_ST new_st);
extern UINT8 *btm_ble_build_adv_data(tBTM_BLE_AD_MASK *p_data_mask, UINT8 **p_dst,
                                     tBTM_BLE_ADV_DATA *p_data);
extern tBTM_STATUS btm_ble_start_adv(void);
extern tBTM_STATUS btm_ble_stop_adv(void);
extern tBTM_STATUS btm_ble_start_scan(void);
extern void btm_ble_create_ll_conn_complete (UINT8 status);

/* LE security function from btm_sec.c */
#if SMP_INCLUDED == TRUE
extern void btm_ble_link_sec_check(BD_ADDR bd_addr, tBTM_LE_AUTH_REQ auth_req, tBTM_BLE_SEC_REQ_ACT *p_sec_req_act);
extern void btm_ble_ltk_request_reply(BD_ADDR bda,  BOOLEAN use_stk, BT_OCTET16 stk);
extern UINT8 btm_proc_smp_cback(tSMP_EVT event, BD_ADDR bd_addr, tSMP_EVT_DATA *p_data);
extern tBTM_STATUS btm_ble_set_encryption (BD_ADDR bd_addr, tBTM_BLE_SEC_ACT sec_act, UINT8 link_role);
extern void btm_ble_ltk_request(UINT16 handle, UINT8 rand[8], UINT16 ediv);
extern tBTM_STATUS btm_ble_start_encrypt(BD_ADDR bda, BOOLEAN use_stk, BT_OCTET16 stk);
extern void btm_ble_link_encrypted(BD_ADDR bd_addr, UINT8 encr_enable);
#endif

/* LE device management functions */
extern void btm_ble_reset_id( void );

/* security related functions */
extern void btm_ble_increment_sign_ctr(BD_ADDR bd_addr, BOOLEAN is_local );
extern BOOLEAN btm_get_local_div (BD_ADDR bd_addr, UINT16 *p_div);
extern BOOLEAN btm_ble_get_enc_key_type(BD_ADDR bd_addr, UINT8 *p_key_types);

extern void btm_ble_test_command_complete(UINT8 *p);
extern void btm_ble_rand_enc_complete (UINT8 *p, UINT16 op_code, tBTM_RAND_ENC_CB *p_enc_cplt_cback);

extern void btm_sec_save_le_key(BD_ADDR bd_addr, tBTM_LE_KEY_TYPE key_type, tBTM_LE_KEY_VALUE *p_keys, BOOLEAN pass_to_application);
extern void btm_ble_update_sec_key_size(BD_ADDR bd_addr, UINT8 enc_key_size);
extern UINT8 btm_ble_read_sec_key_size(BD_ADDR bd_addr);

/* white list function */
extern BOOLEAN btm_update_dev_to_white_list(BOOLEAN to_add, BD_ADDR bd_addr);
extern void btm_update_scanner_filter_policy(tBTM_BLE_SFP scan_policy);
extern void btm_update_adv_filter_policy(tBTM_BLE_AFP adv_policy);
extern void btm_ble_clear_white_list (void);
extern void btm_read_white_list_size_complete(UINT8 *p, UINT16 evt_len);
extern void btm_ble_add_2_white_list_complete(UINT8 status);
extern void btm_ble_remove_from_white_list_complete(UINT8 *p, UINT16 evt_len);
extern void btm_ble_clear_white_list_complete(UINT8 *p, UINT16 evt_len);
extern void btm_ble_white_list_init(UINT8 white_list_size);

/* background connection function */
extern BOOLEAN btm_ble_suspend_bg_conn(void);
extern BOOLEAN btm_ble_resume_bg_conn(void);
extern void btm_ble_initiate_select_conn(BD_ADDR bda);
extern BOOLEAN btm_ble_start_auto_conn(BOOLEAN start);
extern BOOLEAN btm_ble_start_select_conn(BOOLEAN start,tBTM_BLE_SEL_CBACK   *p_select_cback);
extern BOOLEAN btm_ble_renew_bg_conn_params(BOOLEAN add, BD_ADDR bd_addr);
extern void btm_write_dir_conn_wl(BD_ADDR target_addr);
extern void btm_ble_update_mode_operation(UINT8 link_role, BD_ADDR bda, UINT8 status);
extern BOOLEAN btm_execute_wl_dev_operation(void);
extern void btm_ble_update_link_topology_mask(UINT8 role, BOOLEAN increase);

/* direct connection utility */
extern BOOLEAN btm_send_pending_direct_conn(void);
extern void btm_ble_enqueue_direct_conn_req(void *p_param);
extern void btm_ble_dequeue_direct_conn_req(BD_ADDR rem_bda);

/* BLE address management */
extern void btm_gen_resolvable_private_addr (void *p_cmd_cplt_cback);
extern void btm_gen_non_resolvable_private_addr (tBTM_BLE_ADDR_CBACK *p_cback, void *p);
extern tBTM_SEC_DEV_REC* btm_ble_resolve_random_addr(BD_ADDR random_bda);
extern void btm_gen_resolve_paddr_low(tBTM_RAND_ENC *p);

/*  privacy function */
#if (defined BLE_PRIVACY_SPT && BLE_PRIVACY_SPT == TRUE)
/* BLE address mapping with CS feature */
extern BOOLEAN btm_identity_addr_to_random_pseudo(BD_ADDR bd_addr, UINT8 *p_addr_type, BOOLEAN refresh);
extern BOOLEAN btm_random_pseudo_to_identity_addr(BD_ADDR random_pseudo, UINT8 *p_static_addr_type);
extern void btm_ble_refresh_peer_resolvable_private_addr(BD_ADDR pseudo_bda, BD_ADDR rra, UINT8 rra_type);
extern void btm_ble_refresh_local_resolvable_private_addr(BD_ADDR pseudo_addr, BD_ADDR local_rpa);
extern void btm_ble_read_resolving_list_entry_complete(UINT8 *p, UINT16 evt_len) ;
extern void btm_ble_remove_resolving_list_entry_complete(UINT8 *p, UINT16 evt_len);
extern void btm_ble_add_resolving_list_entry_complete(UINT8 *p, UINT16 evt_len);
extern void btm_ble_clear_resolving_list_complete(UINT8 *p, UINT16 evt_len);
extern void btm_read_ble_resolving_list_size_complete (UINT8 *p, UINT16 evt_len);
extern void btm_ble_enable_resolving_list(UINT8);
extern BOOLEAN btm_ble_disable_resolving_list(UINT8 rl_mask, BOOLEAN to_resume);
extern void btm_ble_enable_resolving_list_for_platform (UINT8 rl_mask);
extern void btm_ble_resolving_list_init(UINT8 max_irk_list_sz);
extern void btm_ble_resolving_list_cleanup(void);
#endif

extern void btm_ble_multi_adv_configure_rpa (tBTM_BLE_MULTI_ADV_INST *p_inst);
extern void btm_ble_multi_adv_init(void);
extern void* btm_ble_multi_adv_get_ref(UINT8 inst_id);
extern void btm_ble_multi_adv_cleanup(void);
extern void btm_ble_multi_adv_reenable(UINT8 inst_id);
extern void btm_ble_multi_adv_enb_privacy(BOOLEAN enable);
extern char btm_ble_map_adv_tx_power(int tx_power_index);
extern void btm_ble_batchscan_init(void);
extern void btm_ble_batchscan_cleanup(void);
extern void btm_ble_adv_filter_init(void);
extern void btm_ble_adv_filter_cleanup(void);
extern BOOLEAN btm_ble_topology_check(tBTM_BLE_STATE_MASK request);
extern BOOLEAN btm_ble_clear_topology_mask(tBTM_BLE_STATE_MASK request_state);
extern BOOLEAN btm_ble_set_topology_mask(tBTM_BLE_STATE_MASK request_state);

#if BTM_BLE_CONFORMANCE_TESTING == TRUE
extern void btm_ble_set_no_disc_if_pair_fail (BOOLEAN disble_disc);
extern void btm_ble_set_test_mac_value (BOOLEAN enable, UINT8 *p_test_mac_val);
extern void btm_ble_set_test_local_sign_cntr_value(BOOLEAN enable, UINT32 test_local_sign_cntr);
extern void btm_set_random_address(BD_ADDR random_bda);
extern void btm_ble_set_keep_rfu_in_auth_req(BOOLEAN keep_rfu);
#endif


#ifdef __cplusplus
}
#endif

#endif
