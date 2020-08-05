/*
 *  Copyright 2020 The Android Open Source Project
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
 */

#pragma once

#include "bt_common.h"

// This header contains functions for HCI-LinkManagement to invoke

extern void l2c_link_process_num_completed_pkts(uint8_t* p, uint8_t evt_len);

extern bool l2c_link_hci_conn_comp(uint8_t status, uint16_t handle,
                                   const RawAddress& p_bda);

extern bool l2c_link_hci_disc_comp(uint16_t handle, uint8_t reason);

extern void l2c_link_role_changed(const RawAddress* bd_addr, uint8_t new_role,
                                  uint8_t hci_status);

extern void l2c_pin_code_request(const RawAddress& bd_addr);

extern void l2cble_process_conn_update_evt(uint16_t handle, uint8_t status,
                                           uint16_t interval, uint16_t latency,
                                           uint16_t timeout);

extern void l2cble_process_data_length_change_event(uint16_t handle,
                                                    uint16_t tx_data_len,
                                                    uint16_t rx_data_len);

#if (BLE_LLT_INCLUDED == TRUE)
extern void l2cble_process_rc_param_request_evt(uint16_t handle,
                                                uint16_t int_min,
                                                uint16_t int_max,
                                                uint16_t latency,
                                                uint16_t timeout);
#endif
