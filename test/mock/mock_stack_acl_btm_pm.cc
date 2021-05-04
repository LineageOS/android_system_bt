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
 *   Functions generated:17
 */

#include <map>
#include <string>

extern std::map<std::string, int> mock_function_count_map;

#include <base/strings/stringprintf.h>
#include <cstdint>
#include <unordered_map>
#include "bt_target.h"
#include "device/include/controller.h"
#include "device/include/interop.h"
#include "main/shim/dumpsys.h"
#include "main/shim/link_policy.h"
#include "main/shim/shim.h"
#include "osi/include/log.h"
#include "stack/btm/btm_int_types.h"
#include "stack/include/btm_api.h"
#include "stack/include/btm_api_types.h"
#include "stack/include/btm_status.h"
#include "types/raw_address.h"

#ifndef UNUSED_ATTR
#define UNUSED_ATTR
#endif

bool BTM_ReadPowerMode(const RawAddress& remote_bda, tBTM_PM_MODE* p_mode) {
  mock_function_count_map[__func__]++;
  return false;
}
bool BTM_SetLinkPolicyActiveMode(const RawAddress& remote_bda) {
  mock_function_count_map[__func__]++;
  return false;
}
tBTM_CONTRL_STATE BTM_PM_ReadControllerState(void) {
  mock_function_count_map[__func__]++;
  return 0;
}
tBTM_STATUS BTM_PmRegister(uint8_t mask, uint8_t* p_pm_id,
                           tBTM_PM_STATUS_CBACK* p_cb) {
  mock_function_count_map[__func__]++;
  return BTM_SUCCESS;
}
tBTM_STATUS BTM_SetPowerMode(uint8_t pm_id, const RawAddress& remote_bda,
                             const tBTM_PM_PWR_MD* p_mode) {
  mock_function_count_map[__func__]++;
  return BTM_SUCCESS;
}
tBTM_STATUS BTM_SetSsrParams(const RawAddress& remote_bda, uint16_t max_lat,
                             uint16_t min_rmt_to, uint16_t min_loc_to) {
  mock_function_count_map[__func__]++;
  return BTM_SUCCESS;
}
void BTM_PM_OnConnected(uint16_t handle, const RawAddress& remote_bda) {
  mock_function_count_map[__func__]++;
}
void BTM_PM_OnDisconnected(uint16_t handle) {
  mock_function_count_map[__func__]++;
}
void btm_pm_on_mode_change(tHCI_STATUS status, uint16_t handle,
                           tHCI_MODE current_mode, uint16_t interval) {
  mock_function_count_map[__func__]++;
}
void btm_pm_on_sniff_subrating(tHCI_STATUS status, uint16_t handle,
                               uint16_t maximum_transmit_latency,
                               uint16_t maximum_receive_latency,
                               uint16_t minimum_remote_timeout,
                               uint16_t minimum_local_timeout) {
  mock_function_count_map[__func__]++;
}
void btm_pm_proc_cmd_status(tHCI_STATUS status) {
  mock_function_count_map[__func__]++;
}
void btm_pm_proc_mode_change(tHCI_STATUS hci_status, uint16_t hci_handle,
                             tHCI_MODE hci_mode, uint16_t interval) {
  mock_function_count_map[__func__]++;
}
void btm_pm_proc_ssr_evt(uint8_t* p, UNUSED_ATTR uint16_t evt_len) {
  mock_function_count_map[__func__]++;
}
void btm_pm_reset(void) { mock_function_count_map[__func__]++; }
void process_ssr_event(tHCI_STATUS status, uint16_t handle,
                       UNUSED_ATTR uint16_t max_tx_lat, uint16_t max_rx_lat) {
  mock_function_count_map[__func__]++;
}
