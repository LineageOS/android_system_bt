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
 *   Functions generated:12
 */

#include <map>
#include <string>

extern std::map<std::string, int> mock_function_count_map;

#include <map>
#include <vector>
#include "bta/vc/devices.h"
#include "stack/btm/btm_sec.h"

using namespace bluetooth::vc::internal;

#ifndef UNUSED_ATTR
#define UNUSED_ATTR
#endif

bool VolumeControlDevice::EnableEncryption(tBTM_SEC_CALLBACK* callback) {
  mock_function_count_map[__func__]++;
  return false;
}
bool VolumeControlDevice::EnqueueInitialRequests(
    tGATT_IF gatt_if, GATT_READ_OP_CB chrc_read_cb,
    GATT_WRITE_OP_CB cccd_write_cb) {
  mock_function_count_map[__func__]++;
  return false;
}
bool VolumeControlDevice::IsEncryptionEnabled() {
  mock_function_count_map[__func__]++;
  return false;
}
bool VolumeControlDevice::UpdateHandles(void) {
  mock_function_count_map[__func__]++;
  return false;
}
bool VolumeControlDevice::VerifyReady(uint16_t handle) {
  mock_function_count_map[__func__]++;
  return false;
}
bool VolumeControlDevice::set_volume_control_service_handles(
    const gatt::Service& service) {
  mock_function_count_map[__func__]++;
  return false;
}
bool VolumeControlDevice::subscribe_for_notifications(tGATT_IF gatt_if,
                                                      uint16_t handle,
                                                      uint16_t ccc_handle,
                                                      GATT_WRITE_OP_CB cb) {
  mock_function_count_map[__func__]++;
  return false;
}
uint16_t VolumeControlDevice::find_ccc_handle(uint16_t chrc_handle) {
  mock_function_count_map[__func__]++;
  return 0;
}
void VolumeControlDevice::ControlPointOperation(uint8_t opcode,
                                                const std::vector<uint8_t>* arg,
                                                GATT_WRITE_OP_CB cb,
                                                void* cb_data) {
  mock_function_count_map[__func__]++;
}
void VolumeControlDevice::Disconnect(tGATT_IF gatt_if) {
  mock_function_count_map[__func__]++;
}
void VolumeControlDevice::EnqueueRemainingRequests(
    tGATT_IF gatt_if, GATT_READ_OP_CB chrc_read_cb,
    GATT_WRITE_OP_CB cccd_write_cb) {
  mock_function_count_map[__func__]++;
}
void VolumeControlDevice::ResetHandles(void) {
  mock_function_count_map[__func__]++;
}
