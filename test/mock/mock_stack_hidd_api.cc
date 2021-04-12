/*
 * Copyright 2021 The Android Open Source Project
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
 *   Functions generated:16
 */

#include <map>
#include <string>

extern std::map<std::string, int> mock_function_count_map;

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "bt_types.h"
#include "btm_api.h"
#include "btu.h"
#include "hidd_api.h"
#include "hiddefs.h"
#include "stack/btm/btm_sec.h"
#include "stack/hid/hidd_int.h"

#ifndef UNUSED_ATTR
#define UNUSED_ATTR
#endif

tHID_STATUS HID_DevAddRecord(uint32_t handle, char* p_name, char* p_description,
                             char* p_provider, uint16_t subclass,
                             uint16_t desc_len, uint8_t* p_desc_data) {
  mock_function_count_map[__func__]++;
  return HID_SUCCESS;
}
tHID_STATUS HID_DevConnect(void) {
  mock_function_count_map[__func__]++;
  return HID_SUCCESS;
}
tHID_STATUS HID_DevDeregister(void) {
  mock_function_count_map[__func__]++;
  return HID_SUCCESS;
}
tHID_STATUS HID_DevDisconnect(void) {
  mock_function_count_map[__func__]++;
  return HID_SUCCESS;
}
tHID_STATUS HID_DevGetDevice(RawAddress* addr) {
  mock_function_count_map[__func__]++;
  return HID_SUCCESS;
}
tHID_STATUS HID_DevPlugDevice(const RawAddress& addr) {
  mock_function_count_map[__func__]++;
  return HID_SUCCESS;
}
tHID_STATUS HID_DevRegister(tHID_DEV_HOST_CALLBACK* host_cback) {
  mock_function_count_map[__func__]++;
  return HID_SUCCESS;
}
tHID_STATUS HID_DevReportError(uint8_t error) {
  mock_function_count_map[__func__]++;
  return HID_SUCCESS;
}
tHID_STATUS HID_DevSendReport(uint8_t channel, uint8_t type, uint8_t id,
                              uint16_t len, uint8_t* p_data) {
  mock_function_count_map[__func__]++;
  return HID_SUCCESS;
}
tHID_STATUS HID_DevSetIncomingPolicy(bool allow) {
  mock_function_count_map[__func__]++;
  return HID_SUCCESS;
}
tHID_STATUS HID_DevSetIncomingQos(uint8_t service_type, uint32_t token_rate,
                                  uint32_t token_bucket_size,
                                  uint32_t peak_bandwidth, uint32_t latency,
                                  uint32_t delay_variation) {
  mock_function_count_map[__func__]++;
  return HID_SUCCESS;
}
tHID_STATUS HID_DevSetOutgoingQos(uint8_t service_type, uint32_t token_rate,
                                  uint32_t token_bucket_size,
                                  uint32_t peak_bandwidth, uint32_t latency,
                                  uint32_t delay_variation) {
  mock_function_count_map[__func__]++;
  return HID_SUCCESS;
}
tHID_STATUS HID_DevUnplugDevice(const RawAddress& addr) {
  mock_function_count_map[__func__]++;
  return HID_SUCCESS;
}
tHID_STATUS HID_DevVirtualCableUnplug(void) {
  mock_function_count_map[__func__]++;
  return HID_SUCCESS;
}
uint8_t HID_DevSetTraceLevel(uint8_t new_level) {
  mock_function_count_map[__func__]++;
  return 0;
}
void HID_DevInit(void) { mock_function_count_map[__func__]++; }
