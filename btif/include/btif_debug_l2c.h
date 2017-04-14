/******************************************************************************
 *
 *  Copyright (C) 2016 Google Inc.
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

#pragma once

#include <stdint.h>

#include <hardware/bluetooth.h>

// Captures a BLE connection parameter update request (Section 4.20 of
// Bluetooth Core V4.2 specification):
//
// |min_interval| and |max_interval| define the minimum and maximum values for
// the connection event interval (in units of 1.25ms and should be in the
// [6, 3200] range).
// |slave_latency_param| is the slave latency parameter for the connection in
// number of connection events (unitless and should be less than 500).
// |timeout_multiplier| is the connection timeout parameter (in units of 10ms
// and should be in the [10, 3200] range).
void btif_debug_ble_connection_update_request(bt_bdaddr_t bda,
    uint16_t min_interval, uint16_t max_interval, uint16_t slave_latency_param,
    uint16_t timeout_multiplier);

// Captures a BLE connection parameter update response ((Section 4.21 of
// Bluetooth Core V4.2 specification):
//
// |interval| defines the minimum and maximum values for the
// connection event interval (in units of 1.25ms and should be in the
// [6, 3200] range).
// |slave_latency_param| is the slave latency parameter for the connection in
// number of connection events (unitless and should be less than 500).
// |timeout_multiplier| is the connection timeout parameter (in units of 10ms
// and should be in the [10, 3200] range).
void btif_debug_ble_connection_update_response(bt_bdaddr_t bda, uint8_t status,
    uint16_t interval, uint16_t slave_latency_param,
    uint16_t timeout_multiplier);

// Dumps captured L2C information.
void btif_debug_l2c_dump(int fd);
