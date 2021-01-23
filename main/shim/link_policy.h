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

#pragma once

#include <cstdint>
#include "stack/acl/acl.h"
#include "stack/include/btm_api_types.h"  // tBTM_PM_PWR_MD
#include "types/raw_address.h"

namespace bluetooth {
namespace shim {

bool RegisterLinkPolicyClient(tBTM_PM_STATUS_CBACK* p_cb);
bool UnregisterLinkPolicyClient(tBTM_PM_STATUS_CBACK* p_cb);

bool SetHoldMode(uint16_t handle, uint16_t max_interval, uint16_t min_interval);
bool SetSniffMode(uint16_t handle, uint16_t max_interval, uint16_t min_interval,
                  uint16_t attempt, uint16_t timeout);
bool ExitSniffMode(uint16_t handle);
bool SetSniffSubrating(uint16_t handle, uint16_t maximum_latency,
                       uint16_t minimum_remote_timeout,
                       uint16_t minimum_local_timeout);

tBTM_STATUS BTM_SetPowerMode(uint16_t handle, const tBTM_PM_PWR_MD& mode);
void btm_pm_on_mode_change(tHCI_STATUS status, uint16_t handle,
                           tHCI_MODE current_mode, uint16_t interval);

tBTM_STATUS BTM_SetSsrParams(uint16_t handle, uint16_t max_lat,
                             uint16_t min_rmt_to, uint16_t min_loc_to);
void btm_pm_on_sniff_subrating(tHCI_STATUS status, uint16_t handle,
                               uint16_t maximum_transmit_latency,
                               uint16_t maximum_receive_latency,
                               uint16_t minimum_remote_timeout,
                               uint16_t minimum_local_timeout);
}  // namespace shim
}  // namespace bluetooth
