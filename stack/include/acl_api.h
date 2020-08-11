/* Copyright 2020 The Android Open Source Project
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

#pragma once

#include <cstdint>

#include "stack/acl/acl.h"
#include "stack/btm/btm_int_types.h"
#include "stack/include/acl_api_types.h"
#include "stack/include/bt_types.h"
#include "stack/include/btm_status.h"
#include "types/raw_address.h"

// Note: From stack/include/btm_api.h

/*****************************************************************************
 *  ACL CHANNEL MANAGEMENT FUNCTIONS
 ****************************************************************************/
void BTM_unblock_sniff_mode_for(const RawAddress& peer_addr);
void BTM_block_sniff_mode_for(const RawAddress& peer_addr);
void BTM_unblock_role_switch_for(const RawAddress& peer_addr);
void BTM_block_role_switch_for(const RawAddress& peer_addr);

void BTM_default_unblock_role_switch();
void BTM_default_block_role_switch();

void BTM_acl_after_controller_started();

/*******************************************************************************
 *
 * Function         BTM_SetDefaultLinkSuperTout
 *
 * Description      Set the default value for HCI "Write Link Supervision
 *                  Timeout" command to use when an ACL link is created.
 *
 * Returns          void
 *
 ******************************************************************************/
void BTM_SetDefaultLinkSuperTout(uint16_t timeout);

/*******************************************************************************
 *
 * Function         BTM_SetLinkSuperTout
 *
 * Description      Create and send HCI "Write Link Supervision Timeout" command
 *
 * Returns          BTM_CMD_STARTED if successfully initiated, otherwise error
 *
 ******************************************************************************/
tBTM_STATUS BTM_SetLinkSuperTout(const RawAddress& remote_bda,
                                 uint16_t timeout);
/*******************************************************************************
 *
 * Function         BTM_GetLinkSuperTout
 *
 * Description      Read the link supervision timeout value of the connection
 *
 * Returns          status of the operation
 *
 ******************************************************************************/
tBTM_STATUS BTM_GetLinkSuperTout(const RawAddress& remote_bda,
                                 uint16_t* p_timeout);

/*******************************************************************************
 *
 * Function         BTM_IsAclConnectionUp
 *
 * Description      This function is called to check if an ACL connection exists
 *                  to a specific remote BD Address.
 *
 * Returns          true if connection is up, else false.
 *
 ******************************************************************************/
bool BTM_IsAclConnectionUp(const RawAddress& remote_bda,
                           tBT_TRANSPORT transport);

/*******************************************************************************
 *
 * Function         BTM_GetRole
 *
 * Description      This function is called to get the role of the local device
 *                  for the ACL connection with the specified remote device
 *
 * Returns          BTM_SUCCESS if connection exists.
 *                  BTM_UNKNOWN_ADDR if no active link with bd addr specified
 *
 ******************************************************************************/
tBTM_STATUS BTM_GetRole(const RawAddress& remote_bd_addr, uint8_t* p_role);

/*******************************************************************************
 *
 * Function         BTM_SwitchRole
 *
 * Description      This function is called to switch role between master and
 *                  slave.  If role is already set it will do nothing.
 *
 * Returns          BTM_SUCCESS if already in specified role.
 *                  BTM_CMD_STARTED if command issued to controller.
 *                  BTM_NO_RESOURCES if memory couldn't be allocated to issue
 *                                   the command
 *                  BTM_UNKNOWN_ADDR if no active link with bd addr specified
 *                  BTM_MODE_UNSUPPORTED if the local device does not support
 *                                       role switching
 *
 ******************************************************************************/
tBTM_STATUS BTM_SwitchRole(const RawAddress& remote_bd_addr, uint8_t new_role);

/*******************************************************************************
 *
 * Function         BTM_ReadRSSI
 *
 * Description      This function is called to read the link policy settings.
 *                  The address of link policy results are returned in the
 *                  callback. (tBTM_RSSI_RESULT)
 *
 * Returns          BTM_CMD_STARTED if command issued to controller.
 *                  BTM_NO_RESOURCES if memory couldn't be allocated to issue
 *                                   the command
 *                  BTM_UNKNOWN_ADDR if no active link with bd addr specified
 *                  BTM_BUSY if command is already in progress
 *
 ******************************************************************************/
tBTM_STATUS BTM_ReadRSSI(const RawAddress& remote_bda, tBTM_CMPL_CB* p_cb);

/*******************************************************************************
 *
 * Function         BTM_ReadFailedContactCounter
 *
 * Description      This function is called to read the failed contact counter.
 *                  The result is returned in the callback.
 *                  (tBTM_FAILED_CONTACT_COUNTER_RESULT)
 *
 * Returns          BTM_CMD_STARTED if command issued to controller.
 *                  BTM_NO_RESOURCES if memory couldn't be allocated to issue
 *                                   the command
 *                  BTM_UNKNOWN_ADDR if no active link with bd addr specified
 *                  BTM_BUSY if command is already in progress
 *
 ******************************************************************************/
tBTM_STATUS BTM_ReadFailedContactCounter(const RawAddress& remote_bda,
                                         tBTM_CMPL_CB* p_cb);

/*******************************************************************************
 *
 * Function         BTM_ReadAutomaticFlushTimeout
 *
 * Description      This function is called to read the automatic flush timeout.
 *                  The result is returned in the callback.
 *                  (tBTM_AUTOMATIC_FLUSH_TIMEOUT_RESULT)
 *
 * Returns          BTM_CMD_STARTED if command issued to controller.
 *                  BTM_NO_RESOURCES if memory couldn't be allocated to issue
 *                                   the command
 *                  BTM_UNKNOWN_ADDR if no active link with bd addr specified
 *                  BTM_BUSY if command is already in progress
 *
 ******************************************************************************/
tBTM_STATUS BTM_ReadAutomaticFlushTimeout(const RawAddress& remote_bda,
                                          tBTM_CMPL_CB* p_cb);

/*******************************************************************************
 *
 * Function         BTM_ReadTxPower
 *
 * Description      This function is called to read the current connection
 *                  TX power of the connection. The TX power level results
 *                  are returned in the callback.
 *                  (tBTM_RSSI_RESULT)
 *
 * Returns          BTM_CMD_STARTED if command issued to controller.
 *                  BTM_NO_RESOURCES if memory couldn't be allocated to issue
 *                                   the command
 *                  BTM_UNKNOWN_ADDR if no active link with bd addr specified
 *                  BTM_BUSY if command is already in progress
 *
 ******************************************************************************/
tBTM_STATUS BTM_ReadTxPower(const RawAddress& remote_bda,
                            tBT_TRANSPORT transport, tBTM_CMPL_CB* p_cb);

/*******************************************************************************
 *
 * Function         BTM_GetNumAclLinks
 *
 * Description      This function is called to count the number of
 *                  ACL links that are active.
 *
 * Returns          uint16_t Number of active ACL links
 *
 ******************************************************************************/
uint16_t BTM_GetNumAclLinks(void);

/*******************************************************************************
 *
 * Function         btm_acl_role_changed
 *
 * Description      This function is called whan a link's master/slave role
 *                  change event or command status event (with error) is
 *                  received. It updates the link control block, and calls the
 *                  registered callback with status and role (if registered).
 *
 * Returns          void
 *
 ******************************************************************************/
void btm_acl_role_changed(uint8_t hci_status, const RawAddress* bd_addr,
                          uint8_t new_role);

void btm_set_packet_types_from_address(const RawAddress& bda,
                                       tBT_TRANSPORT transport,
                                       uint16_t pkt_types);

bool lmp_version_below(const RawAddress& bda, uint8_t version);

bool acl_is_role_master(const RawAddress& remote_bda, tBT_TRANSPORT transport);

#define BLE_RESOLVE_ADDR_MASK 0xc0
#define BLE_RESOLVE_ADDR_MSB 0x40

bool BTM_BLE_IS_RESOLVE_BDA(const RawAddress& x);

bool acl_refresh_remote_address(const tBTM_SEC_DEV_REC* p_dev_rec,
                                const RawAddress& remote_bda,
                                tBT_TRANSPORT transport, uint8_t rra_type,
                                const RawAddress& rpa);
