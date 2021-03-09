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
 *   Functions generated:27
 */

#include <map>
#include <string>

extern std::map<std::string, int> mock_function_count_map;

#include <base/at_exit.h>
#include <base/bind.h>
#include <base/threading/platform_thread.h>
#include <signal.h>
#include <sys/types.h>
#include <cstdint>
#include "bt_target.h"
#include "btif/include/btif_av.h"
#include "btif/include/btif_common.h"
#include "btif/include/btif_config.h"
#include "btif/include/btif_dm.h"
#include "btif/include/btif_pan.h"
#include "btif/include/btif_profile_queue.h"
#include "btif/include/btif_sock.h"
#include "btif/include/btif_storage.h"
#include "btif/include/stack_manager.h"
#include "common/message_loop_thread.h"
#include "device/include/controller.h"
#include "osi/include/future.h"
#include "osi/include/log.h"
#include "osi/include/properties.h"
#include "stack/include/a2dp_api.h"
#include "stack/include/btm_api.h"
#include "stack/include/btm_ble_api.h"
#include "types/bluetooth/uuid.h"

#ifndef UNUSED_ATTR
#define UNUSED_ATTR
#endif

bool btif_is_dut_mode() {
  mock_function_count_map[__func__]++;
  return false;
}
bool is_on_jni_thread() {
  mock_function_count_map[__func__]++;
  return false;
}
bt_property_t* property_deep_copy(const bt_property_t* prop) {
  mock_function_count_map[__func__]++;
  return nullptr;
}
bt_status_t btif_cleanup_bluetooth() {
  mock_function_count_map[__func__]++;
  return BT_STATUS_SUCCESS;
}
bt_status_t btif_init_bluetooth() {
  mock_function_count_map[__func__]++;
  return BT_STATUS_SUCCESS;
}
bt_status_t btif_set_dynamic_audio_buffer_size(int codec, int size) {
  mock_function_count_map[__func__]++;
  return BT_STATUS_SUCCESS;
}
bt_status_t btif_transfer_context(tBTIF_CBACK* p_cback, uint16_t event,
                                  char* p_params, int param_len,
                                  tBTIF_COPY_CBACK* p_copy_cback) {
  mock_function_count_map[__func__]++;
  return BT_STATUS_SUCCESS;
}
bt_status_t do_in_jni_thread(base::OnceClosure task) {
  mock_function_count_map[__func__]++;
  return BT_STATUS_SUCCESS;
}
bt_status_t do_in_jni_thread(const base::Location& from_here,
                             base::OnceClosure task) {
  mock_function_count_map[__func__]++;
  return BT_STATUS_SUCCESS;
}
btbase::AbstractMessageLoop* get_jni_message_loop() {
  mock_function_count_map[__func__]++;
  return nullptr;
}
int btif_is_enabled(void) {
  mock_function_count_map[__func__]++;
  return 0;
}
tBTA_SERVICE_MASK btif_get_enabled_services_mask(void) {
  mock_function_count_map[__func__]++;
  return 0;
}
void DynamicAudiobufferSizeCompleteCallback(tBTM_VSC_CMPL* p_vsc_cmpl_params) {
  mock_function_count_map[__func__]++;
}
void btif_adapter_properties_evt(bt_status_t status, uint32_t num_props,
                                 bt_property_t* p_props) {
  mock_function_count_map[__func__]++;
}
void btif_disable_service(tBTA_SERVICE_ID service_id) {
  mock_function_count_map[__func__]++;
}
void btif_dut_mode_configure(uint8_t enable) {
  mock_function_count_map[__func__]++;
}
void btif_dut_mode_send(uint16_t opcode, uint8_t* buf, uint8_t len) {
  mock_function_count_map[__func__]++;
}
void btif_enable_bluetooth_evt() { mock_function_count_map[__func__]++; }
void btif_enable_service(tBTA_SERVICE_ID service_id) {
  mock_function_count_map[__func__]++;
}
void btif_get_adapter_properties(void) { mock_function_count_map[__func__]++; }
void btif_get_adapter_property(bt_property_type_t type) {
  mock_function_count_map[__func__]++;
}
void btif_get_remote_device_properties(RawAddress remote_addr) {
  mock_function_count_map[__func__]++;
}
void btif_get_remote_device_property(RawAddress remote_addr,
                                     bt_property_type_t type) {
  mock_function_count_map[__func__]++;
}
void btif_init_ok() { mock_function_count_map[__func__]++; }
void btif_remote_properties_evt(bt_status_t status, RawAddress* remote_addr,
                                uint32_t num_props, bt_property_t* p_props) {
  mock_function_count_map[__func__]++;
}
void btif_set_adapter_property(bt_property_t* property) {
  mock_function_count_map[__func__]++;
}
void btif_set_remote_device_property(RawAddress* remote_addr,
                                     bt_property_t* property) {
  mock_function_count_map[__func__]++;
}
