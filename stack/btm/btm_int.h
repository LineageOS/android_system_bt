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
#ifndef BTM_INT_H
#define BTM_INT_H

#include "bt_target.h"
#include "bt_common.h"
#include "hcidefs.h"

#include "rfcdefs.h"
#include "osi/include/alarm.h"
#include "osi/include/list.h"
#include "osi/include/fixed_queue.h"

#include "btm_api.h"

#if (BLE_INCLUDED == TRUE)
#include "btm_ble_int.h"
#if (SMP_INCLUDED == TRUE)
#include "smp_api.h"
#endif
#endif

#include "btm_int_types.h"

#ifdef __cplusplus
extern "C"
{
#endif

#if BTM_DYNAMIC_MEMORY == FALSE
extern tBTM_CB  btm_cb;
#else
extern tBTM_CB *btm_cb_ptr;
#define btm_cb (*btm_cb_ptr)
#endif

/* Internal functions provided by btm_main.c
********************************************
*/
extern void         btm_init (void);

/* Internal functions provided by btm_inq.c
*******************************************
*/
extern tBTM_STATUS  btm_initiate_rem_name(BD_ADDR remote_bda,
                                          tBTM_INQ_INFO *p_cur,
                                          UINT8 origin, period_ms_t timeout_ms,
                                          tBTM_CMPL_CB *p_cb);

extern void         btm_process_remote_name (BD_ADDR bda, BD_NAME name, UINT16 evt_len,
                                             UINT8 hci_status);
extern void         btm_inq_rmt_name_failed(void);
extern void         btm_inq_remote_name_timer_timeout(void *data);

/* Inquiry related functions */
extern void         btm_clr_inq_db (BD_ADDR p_bda);
extern void         btm_inq_db_init (void);
extern void         btm_process_inq_results (UINT8 *p, UINT8 inq_res_mode);
extern void         btm_process_inq_complete (UINT8 status, UINT8 mode);
extern void         btm_process_cancel_complete(UINT8 status, UINT8 mode);
extern void         btm_event_filter_complete (UINT8 *p);
extern void         btm_inq_stop_on_ssp(void);
extern void         btm_inq_clear_ssp(void);
extern tINQ_DB_ENT *btm_inq_db_find (const BD_ADDR p_bda);
extern BOOLEAN      btm_inq_find_bdaddr (BD_ADDR p_bda);

extern BOOLEAN btm_lookup_eir(BD_ADDR_PTR p_rem_addr);

/* Internal functions provided by btm_acl.c
********************************************
*/
extern void         btm_acl_init (void);
extern void         btm_acl_created (BD_ADDR bda, DEV_CLASS dc, BD_NAME bdn,
                                     UINT16 hci_handle, UINT8 link_role, tBT_TRANSPORT transport);
extern void         btm_acl_removed (BD_ADDR bda, tBT_TRANSPORT transport);
extern void         btm_acl_device_down (void);
extern void         btm_acl_update_busy_level (tBTM_BLI_EVENT event);

extern void         btm_cont_rswitch (tACL_CONN *p,
                                      tBTM_SEC_DEV_REC *p_dev_rec,
                                      UINT8 hci_status);

extern UINT8        btm_handle_to_acl_index (UINT16 hci_handle);
extern void         btm_read_link_policy_complete (UINT8 *p);

extern void         btm_read_rssi_timeout(void *data);
extern void         btm_read_rssi_complete(UINT8 *p);

extern void         btm_read_tx_power_timeout(void *data);
extern void         btm_read_tx_power_complete(UINT8 *p, BOOLEAN is_ble);

extern void         btm_read_link_quality_timeout(void *data);
extern void         btm_read_link_quality_complete(UINT8 *p);

extern tBTM_STATUS  btm_set_packet_types (tACL_CONN *p, UINT16 pkt_types);
extern void         btm_process_clk_off_comp_evt (UINT16 hci_handle, UINT16 clock_offset);
extern void         btm_acl_role_changed (UINT8 hci_status, BD_ADDR bd_addr, UINT8 new_role);
extern void         btm_blacklist_role_change_device (BD_ADDR bd_addr, UINT8 hci_status);
extern void         btm_acl_encrypt_change (UINT16 handle, UINT8 status, UINT8 encr_enable);
extern UINT16       btm_get_acl_disc_reason_code (void);
extern tBTM_STATUS  btm_remove_acl (BD_ADDR bd_addr, tBT_TRANSPORT transport);
extern void         btm_read_remote_features_complete (UINT8 *p);
extern void         btm_read_remote_ext_features_complete (UINT8 *p, UINT8 evt_len);
extern void         btm_read_remote_ext_features_failed (UINT8 status, UINT16 handle);
extern void         btm_read_remote_version_complete (UINT8 *p);
extern void         btm_establish_continue (tACL_CONN *p_acl_cb);

extern void         btm_acl_chk_peer_pkt_type_support (tACL_CONN *p, UINT16 *p_pkt_type);
/* Read maximum data packet that can be sent over current connection */
extern UINT16 btm_get_max_packet_size (BD_ADDR addr);
extern tACL_CONN *btm_bda_to_acl (const BD_ADDR bda, tBT_TRANSPORT transport);
extern BOOLEAN    btm_acl_notif_conn_collision (BD_ADDR bda);

extern void btm_pm_reset(void);
extern void btm_pm_sm_alloc(UINT8 ind);
extern void btm_pm_proc_cmd_status(UINT8 status);
extern void btm_pm_proc_mode_change (UINT8 hci_status, UINT16 hci_handle, UINT8 mode,
                                     UINT16 interval);
extern void btm_pm_proc_ssr_evt (UINT8 *p, UINT16 evt_len);
extern tBTM_STATUS btm_read_power_mode_state (BD_ADDR remote_bda,
                                                      tBTM_PM_STATE *pmState);
#if BTM_SCO_INCLUDED == TRUE
extern void btm_sco_chk_pend_unpark (UINT8 hci_status, UINT16 hci_handle);
#else
#define btm_sco_chk_pend_unpark(hci_status, hci_handle)
#endif /* BTM_SCO_INCLUDED */

extern void btm_qos_setup_timeout(void *data);
extern void btm_qos_setup_complete(UINT8 status, UINT16 handle,
                                   FLOW_SPEC *p_flow);


/* Internal functions provided by btm_sco.c
********************************************
*/
extern void btm_sco_init (void);
extern void btm_sco_connected (UINT8 hci_status, BD_ADDR bda, UINT16 hci_handle,
                               tBTM_ESCO_DATA *p_esco_data);
extern void btm_esco_proc_conn_chg (UINT8 status, UINT16 handle, UINT8 tx_interval,
                                    UINT8 retrans_window, UINT16 rx_pkt_len,
                                    UINT16 tx_pkt_len);
extern void btm_sco_conn_req (BD_ADDR bda,  DEV_CLASS dev_class, UINT8 link_type);
extern void btm_sco_removed (UINT16 hci_handle, UINT8 reason);
extern void btm_sco_acl_removed (BD_ADDR bda);
extern void btm_route_sco_data (BT_HDR *p_msg);
extern BOOLEAN btm_is_sco_active (UINT16 handle);
extern void btm_remove_sco_links (BD_ADDR bda);
extern BOOLEAN btm_is_sco_active_by_bdaddr (BD_ADDR remote_bda);

extern tBTM_SCO_TYPE btm_read_def_esco_mode (tBTM_ESCO_PARAMS *p_parms);
extern UINT16  btm_find_scb_by_handle (UINT16 handle);
extern void btm_sco_flush_sco_data(UINT16 sco_inx);

/* Internal functions provided by btm_devctl.c
**********************************************
*/
extern void btm_dev_init(void);
extern void btm_read_local_name_timeout(void *data);
extern void btm_read_local_name_complete(UINT8 *p, UINT16 evt_len);

#if (BLE_INCLUDED == TRUE)
extern void btm_ble_add_2_white_list_complete(UINT8 status);
extern void btm_ble_remove_from_white_list_complete(UINT8 *p, UINT16 evt_len);
extern void btm_ble_clear_white_list_complete(UINT8 *p, UINT16 evt_len);
extern BOOLEAN btm_ble_addr_resolvable(BD_ADDR rpa, tBTM_SEC_DEV_REC *p_dev_rec);
extern tBTM_STATUS btm_ble_read_resolving_list_entry(tBTM_SEC_DEV_REC *p_dev_rec);
extern BOOLEAN btm_ble_resolving_list_load_dev(tBTM_SEC_DEV_REC *p_dev_rec);
extern void btm_ble_resolving_list_remove_dev(tBTM_SEC_DEV_REC *p_dev_rec);
#endif  /* BLE_INCLUDED */

/* HCI event handler */
#if HCI_RAW_CMD_INCLUDED == TRUE
extern void btm_hci_event(UINT8 *p, UINT8 event_code, UINT8 param_len);
#endif
/* Vendor Specific Command complete evt handler */
extern void btm_vsc_complete (UINT8 *p, UINT16 cc_opcode, UINT16 evt_len,
                              tBTM_CMPL_CB *p_vsc_cplt_cback);
extern void btm_inq_db_reset (void);
extern void btm_vendor_specific_evt (UINT8 *p, UINT8 evt_len);
extern void btm_delete_stored_link_key_complete (UINT8 *p);
extern void btm_report_device_status (tBTM_DEV_STATUS status);


/* Internal functions provided by btm_dev.c
**********************************************
*/
extern BOOLEAN btm_dev_support_switch (BD_ADDR bd_addr);

extern tBTM_SEC_DEV_REC  *btm_sec_allocate_dev_rec(void);
extern tBTM_SEC_DEV_REC  *btm_sec_alloc_dev (BD_ADDR bd_addr);
extern void               btm_sec_free_dev (tBTM_SEC_DEV_REC *p_dev_rec);
extern tBTM_SEC_DEV_REC  *btm_find_dev (const BD_ADDR bd_addr);
extern tBTM_SEC_DEV_REC  *btm_find_or_alloc_dev (BD_ADDR bd_addr);
extern tBTM_SEC_DEV_REC  *btm_find_dev_by_handle (UINT16 handle);
extern tBTM_BOND_TYPE     btm_get_bond_type_dev(BD_ADDR bd_addr);
extern BOOLEAN            btm_set_bond_type_dev(BD_ADDR bd_addr,
                                                tBTM_BOND_TYPE bond_type);

/* Internal functions provided by btm_sec.c
**********************************************
*/
extern BOOLEAN btm_dev_support_switch (BD_ADDR bd_addr);
extern tBTM_STATUS  btm_sec_l2cap_access_req (BD_ADDR bd_addr, UINT16 psm,
                                       UINT16 handle, CONNECTION_TYPE conn_type,
                                       tBTM_SEC_CALLBACK *p_callback, void *p_ref_data);
extern tBTM_STATUS  btm_sec_mx_access_request (BD_ADDR bd_addr, UINT16 psm, BOOLEAN is_originator,
                                        UINT32 mx_proto_id, UINT32 mx_chan_id,
                                        tBTM_SEC_CALLBACK *p_callback, void *p_ref_data);

extern  tBTM_STATUS btm_sec_execute_procedure (tBTM_SEC_DEV_REC *p_dev_rec);
extern void  btm_sec_conn_req (UINT8 *bda, UINT8 *dc);
extern void btm_create_conn_cancel_complete (UINT8 *p);

extern void  btm_read_inq_tx_power_timeout(void *data);
extern void  btm_read_inq_tx_power_complete(UINT8 *p);

extern void  btm_sec_init (UINT8 sec_mode);
extern void  btm_sec_dev_reset (void);
extern void  btm_sec_abort_access_req (BD_ADDR bd_addr);
extern void  btm_sec_auth_complete (UINT16 handle, UINT8 status);
extern void  btm_sec_encrypt_change (UINT16 handle, UINT8 status, UINT8 encr_enable);
extern void  btm_sec_connected (UINT8 *bda, UINT16 handle, UINT8 status, UINT8 enc_mode);
extern tBTM_STATUS btm_sec_disconnect (UINT16 handle, UINT8 reason);
extern void  btm_sec_disconnected (UINT16 handle, UINT8 reason);
extern void  btm_sec_rmt_name_request_complete (UINT8 *bd_addr, UINT8 *bd_name, UINT8 status);
extern void  btm_sec_rmt_host_support_feat_evt (UINT8 *p);
extern void  btm_io_capabilities_req (UINT8 *p);
extern void  btm_io_capabilities_rsp (UINT8 *p);
extern void  btm_proc_sp_req_evt (tBTM_SP_EVT event, UINT8 *p);
extern void  btm_keypress_notif_evt (UINT8 *p);
extern void  btm_simple_pair_complete (UINT8 *p);
extern void  btm_sec_link_key_notification (UINT8 *p_bda, UINT8 *p_link_key, UINT8 key_type);
extern void  btm_sec_link_key_request (UINT8 *p_bda);
extern void  btm_sec_pin_code_request (UINT8 *p_bda);
extern void  btm_sec_update_clock_offset (UINT16 handle, UINT16 clock_offset);
extern void  btm_sec_dev_rec_cback_event (tBTM_SEC_DEV_REC *p_dev_rec, UINT8 res, BOOLEAN is_le_trasnport);
extern void btm_sec_set_peer_sec_caps (tACL_CONN *p_acl_cb, tBTM_SEC_DEV_REC *p_dev_rec);

#if BLE_INCLUDED == TRUE
extern void  btm_sec_clear_ble_keys (tBTM_SEC_DEV_REC  *p_dev_rec);
extern BOOLEAN btm_sec_is_a_bonded_dev (BD_ADDR bda);
extern void btm_consolidate_dev(tBTM_SEC_DEV_REC *p_target_rec);
extern BOOLEAN btm_sec_is_le_capable_dev (BD_ADDR bda);
extern BOOLEAN btm_ble_init_pseudo_addr (tBTM_SEC_DEV_REC *p_dev_rec, BD_ADDR new_pseudo_addr);
extern tBTM_SEC_SERV_REC *btm_sec_find_first_serv (CONNECTION_TYPE conn_type, UINT16 psm);
extern BOOLEAN btm_ble_start_sec_check(BD_ADDR bd_addr, UINT16 psm, BOOLEAN is_originator,
                            tBTM_SEC_CALLBACK *p_callback, void *p_ref_data);
#endif /* BLE_INCLUDED */

extern tINQ_DB_ENT *btm_inq_db_new (BD_ADDR p_bda);

extern void  btm_rem_oob_req (UINT8 *p);
extern void  btm_read_local_oob_complete (UINT8 *p);

extern void  btm_acl_resubmit_page (void);
extern void  btm_acl_reset_paging (void);
extern void  btm_acl_paging (BT_HDR *p, BD_ADDR dest);
extern UINT8 btm_sec_clr_service_by_psm (UINT16 psm);
extern void  btm_sec_clr_temp_auth_service (BD_ADDR bda);

#ifdef __cplusplus
}
#endif

#endif
