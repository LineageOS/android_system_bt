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

// This header contains functions for HCI-ble to invoke
void btm_ble_conn_complete(uint8_t* p, UNUSED_ATTR uint16_t evt_len,
                           bool enhanced);
void btm_ble_process_adv_pkt(uint8_t len, uint8_t* p);
void btm_ble_process_ext_adv_pkt(uint8_t len, uint8_t* p);
void btm_ble_process_phy_update_pkt(uint8_t len, uint8_t* p);
void btm_ble_read_remote_features_complete(uint8_t* p);
void btm_le_on_advertising_set_terminated(uint8_t* p, uint16_t length);
