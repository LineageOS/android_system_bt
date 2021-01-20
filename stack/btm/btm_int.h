/******************************************************************************
 *
 *  Copyright 1999-2012 Broadcom Corporation
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

#include "bt_common.h"
#include "bt_target.h"
#include "hcidefs.h"

#include "osi/include/alarm.h"
#include "osi/include/fixed_queue.h"
#include "osi/include/list.h"
#include "rfcdefs.h"

#include "btm_api.h"
#include "device/include/esco_parameters.h"

#include "btm_ble_int.h"
#include "btm_int_types.h"
#include "l2cdefs.h"
#include "smp_api.h"

extern tBTM_CB btm_cb;

/* Internal functions provided by btm_main.cc
 *******************************************
*/
extern void btm_init(void);
extern void btm_free(void);

/* Internal functions provided by btm_inq.cc
 ******************************************
*/
extern void btm_process_remote_name(const RawAddress* bda, BD_NAME name,
                                    uint16_t evt_len, uint8_t hci_status);
extern void btm_inq_remote_name_timer_timeout(void* data);

/* Inquiry related functions */
extern void btm_inq_db_init(void);
extern void btm_process_inq_results(uint8_t* p, uint8_t hci_evt_len,
                                    uint8_t inq_res_mode);
extern void btm_process_inq_complete(uint8_t status, uint8_t mode);
extern void btm_process_cancel_complete(uint8_t status, uint8_t mode);
extern void btm_inq_stop_on_ssp(void);
extern void btm_inq_clear_ssp(void);
extern tINQ_DB_ENT* btm_inq_db_find(const RawAddress& p_bda);
extern bool btm_inq_find_bdaddr(const RawAddress& p_bda);

/* Internal functions provided by btm_acl.cc
 *******************************************
*/
extern void btm_acl_device_down(void);
extern void btm_acl_set_paging(bool value);
extern void btm_acl_update_inquiry_status(uint8_t state);

extern uint8_t btm_handle_to_acl_index(uint16_t hci_handle);

extern uint16_t btm_get_acl_disc_reason_code(void);

extern tBTM_STATUS btm_remove_acl(const RawAddress& bd_addr,
                                  tBT_TRANSPORT transport);

extern void btm_pm_reset(void);

extern void btm_acl_process_sca_cmpl_pkt(uint8_t len, uint8_t* data);

/* Internal functions provided by btm_sco.cc
 *******************************************
*/
extern void btm_sco_init(void);
extern void btm_sco_acl_removed(const RawAddress* bda);
extern void btm_route_sco_data(BT_HDR* p_msg);

/* Internal functions provided by btm_devctl.cc
 *********************************************
*/
extern void btm_dev_init(void);

extern void btm_ble_create_conn_cancel_complete(uint8_t* p);

/* Vendor Specific Command complete evt handler */
extern void btm_vsc_complete(uint8_t* p, uint16_t cc_opcode, uint16_t evt_len,
                             tBTM_VSC_CMPL_CB* p_vsc_cplt_cback);
extern void btm_inq_db_reset(void);
extern void btm_vendor_specific_evt(uint8_t* p, uint8_t evt_len);
extern void btm_delete_stored_link_key_complete(uint8_t* p);
extern tBTM_STATUS BTM_BT_Quality_Report_VSE_Register(
    bool is_register, tBTM_BT_QUALITY_REPORT_RECEIVER* p_bqr_report_receiver);

/* Internal functions provided by btm_dev.cc
 *********************************************
*/
extern void wipe_secrets_and_remove(tBTM_SEC_DEV_REC* p_dev_rec);

/* Internal functions provided by btm_sec.cc
 *********************************************
*/
extern bool btm_ble_init_pseudo_addr(tBTM_SEC_DEV_REC* p_dev_rec,
                                     const RawAddress& new_pseudo_addr);
extern tL2CAP_LE_RESULT_CODE btm_ble_start_sec_check(
    const RawAddress& bd_addr, uint16_t psm, bool is_originator,
    tBTM_SEC_CALLBACK* p_callback, void* p_ref_data);

extern tINQ_DB_ENT* btm_inq_db_new(const RawAddress& p_bda);
extern void btm_acl_resubmit_page(void);
extern void btm_acl_paging(BT_HDR* p, const RawAddress& dest);

#endif
