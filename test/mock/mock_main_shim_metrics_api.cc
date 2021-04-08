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

#include <cstdint>
#include <map>
#include <string>

extern std::map<std::string, int> mock_function_count_map;

#include "gd/common/metrics.h"
#include "main/shim/metrics_api.h"
#include "types/raw_address.h"

#ifndef UNUSED_ATTR
#define UNUSED_ATTR
#endif

void bluetooth::shim::LogMetricA2dpAudioOverrunEvent(
    const RawAddress& raw_address, uint64_t encoding_interval_millis,
    int num_dropped_buffers, int num_dropped_encoded_frames,
    int num_dropped_encoded_bytes) {
  mock_function_count_map[__func__]++;
}
void bluetooth::shim::LogMetricA2dpAudioUnderrunEvent(
    const RawAddress& raw_address, uint64_t encoding_interval_millis,
    int num_missing_pcm_bytes) {
  mock_function_count_map[__func__]++;
}
void bluetooth::shim::LogMetricA2dpPlaybackEvent(const RawAddress& raw_address,
                                                 int playback_state,
                                                 int audio_coding_mode) {
  mock_function_count_map[__func__]++;
}
void bluetooth::shim::LogMetricClassicPairingEvent(
    const RawAddress& raw_address, uint16_t handle, uint32_t hci_cmd,
    uint16_t hci_event, uint16_t cmd_status, uint16_t reason_code,
    int64_t event_value) {
  mock_function_count_map[__func__]++;
}
void bluetooth::shim::LogMetricManufacturerInfo(
    const RawAddress& raw_address,
    android::bluetooth::DeviceInfoSrcEnum source_type,
    const std::string& source_name, const std::string& manufacturer,
    const std::string& model, const std::string& hardware_version,
    const std::string& software_version) {
  mock_function_count_map[__func__]++;
}
void bluetooth::shim::LogMetricReadFailedContactCounterResult(
    const RawAddress& raw_address, uint16_t handle, uint32_t cmd_status,
    int32_t failed_contact_counter) {
  mock_function_count_map[__func__]++;
}
void bluetooth::shim::LogMetricReadRssiResult(const RawAddress& raw_address,
                                              uint16_t handle,
                                              uint32_t cmd_status,
                                              int8_t rssi) {
  mock_function_count_map[__func__]++;
}
void bluetooth::shim::LogMetricReadTxPowerLevelResult(
    const RawAddress& raw_address, uint16_t handle, uint32_t cmd_status,
    int32_t transmit_power_level) {
  mock_function_count_map[__func__]++;
}
void bluetooth::shim::LogMetricSdpAttribute(const RawAddress& raw_address,
                                            uint16_t protocol_uuid,
                                            uint16_t attribute_id,
                                            size_t attribute_size,
                                            const char* attribute_value) {
  mock_function_count_map[__func__]++;
}
void bluetooth::shim::LogMetricSmpPairingEvent(
    const RawAddress& raw_address, uint8_t smp_cmd,
    android::bluetooth::DirectionEnum direction, uint8_t smp_fail_reason) {
  mock_function_count_map[__func__]++;
}
void bluetooth::shim::LogMetricSocketConnectionState(
    const RawAddress& raw_address, int port, int type,
    android::bluetooth::SocketConnectionstateEnum connection_state,
    int64_t tx_bytes, int64_t rx_bytes, int uid, int server_port,
    android::bluetooth::SocketRoleEnum socket_role) {
  mock_function_count_map[__func__]++;
}
