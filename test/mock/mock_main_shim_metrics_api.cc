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
 *
 *  mockcify.pl ver 0.2
 */

#include <cstdint>
#include <functional>
#include <map>
#include <string>

extern std::map<std::string, int> mock_function_count_map;

// Original included files, if any
// NOTE: Since this is a mock file with mock definitions some number of
//       include files may not be required.  The include-what-you-use
//       still applies, but crafting proper inclusion is out of scope
//       for this effort.  This compilation unit may compile as-is, or
//       may need attention to prune the inclusion set.
#include "gd/hci/address.h"
#include "gd/os/metrics.h"
#include "main/shim/helpers.h"
#include "main/shim/metrics_api.h"
#include "types/raw_address.h"

// Mock include file to share data between tests and mock
#include "test/mock/mock_main_shim_metrics_api.h"

// Mocked compile conditionals, if any
#ifndef UNUSED_ATTR
#define UNUSED_ATTR
#endif

// Mocked internal structures, if any

namespace test {
namespace mock {
namespace main_shim_metrics_api {

// Function state capture and return values, if needed
struct LogMetricLinkLayerConnectionEvent LogMetricLinkLayerConnectionEvent;
struct LogMetricA2dpAudioUnderrunEvent LogMetricA2dpAudioUnderrunEvent;
struct LogMetricA2dpAudioOverrunEvent LogMetricA2dpAudioOverrunEvent;
struct LogMetricA2dpPlaybackEvent LogMetricA2dpPlaybackEvent;
struct LogMetricReadRssiResult LogMetricReadRssiResult;
struct LogMetricReadFailedContactCounterResult
    LogMetricReadFailedContactCounterResult;
struct LogMetricReadTxPowerLevelResult LogMetricReadTxPowerLevelResult;
struct LogMetricSmpPairingEvent LogMetricSmpPairingEvent;
struct LogMetricClassicPairingEvent LogMetricClassicPairingEvent;
struct LogMetricSdpAttribute LogMetricSdpAttribute;
struct LogMetricSocketConnectionState LogMetricSocketConnectionState;
struct LogMetricManufacturerInfo LogMetricManufacturerInfo;

}  // namespace main_shim_metrics_api
}  // namespace mock
}  // namespace test

// Mocked functions, if any
void bluetooth::shim::LogMetricLinkLayerConnectionEvent(
    const RawAddress* raw_address, uint32_t connection_handle,
    android::bluetooth::DirectionEnum direction, uint16_t link_type,
    uint32_t hci_cmd, uint16_t hci_event, uint16_t hci_ble_event,
    uint16_t cmd_status, uint16_t reason_code) {
  mock_function_count_map[__func__]++;
  test::mock::main_shim_metrics_api::LogMetricLinkLayerConnectionEvent(
      raw_address, connection_handle, direction, link_type, hci_cmd, hci_event,
      hci_ble_event, cmd_status, reason_code);
}
void bluetooth::shim::LogMetricA2dpAudioUnderrunEvent(
    const RawAddress& raw_address, uint64_t encoding_interval_millis,
    int num_missing_pcm_bytes) {
  mock_function_count_map[__func__]++;
  test::mock::main_shim_metrics_api::LogMetricA2dpAudioUnderrunEvent(
      raw_address, encoding_interval_millis, num_missing_pcm_bytes);
}
void bluetooth::shim::LogMetricA2dpAudioOverrunEvent(
    const RawAddress& raw_address, uint64_t encoding_interval_millis,
    int num_dropped_buffers, int num_dropped_encoded_frames,
    int num_dropped_encoded_bytes) {
  mock_function_count_map[__func__]++;
  test::mock::main_shim_metrics_api::LogMetricA2dpAudioOverrunEvent(
      raw_address, encoding_interval_millis, num_dropped_buffers,
      num_dropped_encoded_frames, num_dropped_encoded_bytes);
}
void bluetooth::shim::LogMetricA2dpPlaybackEvent(const RawAddress& raw_address,
                                                 int playback_state,
                                                 int audio_coding_mode) {
  mock_function_count_map[__func__]++;
  test::mock::main_shim_metrics_api::LogMetricA2dpPlaybackEvent(
      raw_address, playback_state, audio_coding_mode);
}
void bluetooth::shim::LogMetricReadRssiResult(const RawAddress& raw_address,
                                              uint16_t handle,
                                              uint32_t cmd_status,
                                              int8_t rssi) {
  mock_function_count_map[__func__]++;
  test::mock::main_shim_metrics_api::LogMetricReadRssiResult(
      raw_address, handle, cmd_status, rssi);
}
void bluetooth::shim::LogMetricReadFailedContactCounterResult(
    const RawAddress& raw_address, uint16_t handle, uint32_t cmd_status,
    int32_t failed_contact_counter) {
  mock_function_count_map[__func__]++;
  test::mock::main_shim_metrics_api::LogMetricReadFailedContactCounterResult(
      raw_address, handle, cmd_status, failed_contact_counter);
}
void bluetooth::shim::LogMetricReadTxPowerLevelResult(
    const RawAddress& raw_address, uint16_t handle, uint32_t cmd_status,
    int32_t transmit_power_level) {
  mock_function_count_map[__func__]++;
  test::mock::main_shim_metrics_api::LogMetricReadTxPowerLevelResult(
      raw_address, handle, cmd_status, transmit_power_level);
}
void bluetooth::shim::LogMetricSmpPairingEvent(
    const RawAddress& raw_address, uint8_t smp_cmd,
    android::bluetooth::DirectionEnum direction, uint8_t smp_fail_reason) {
  mock_function_count_map[__func__]++;
  test::mock::main_shim_metrics_api::LogMetricSmpPairingEvent(
      raw_address, smp_cmd, direction, smp_fail_reason);
}
void bluetooth::shim::LogMetricClassicPairingEvent(
    const RawAddress& raw_address, uint16_t handle, uint32_t hci_cmd,
    uint16_t hci_event, uint16_t cmd_status, uint16_t reason_code,
    int64_t event_value) {
  mock_function_count_map[__func__]++;
  test::mock::main_shim_metrics_api::LogMetricClassicPairingEvent(
      raw_address, handle, hci_cmd, hci_event, cmd_status, reason_code,
      event_value);
}
void bluetooth::shim::LogMetricSdpAttribute(const RawAddress& raw_address,
                                            uint16_t protocol_uuid,
                                            uint16_t attribute_id,
                                            size_t attribute_size,
                                            const char* attribute_value) {
  mock_function_count_map[__func__]++;
  test::mock::main_shim_metrics_api::LogMetricSdpAttribute(
      raw_address, protocol_uuid, attribute_id, attribute_size,
      attribute_value);
}
void bluetooth::shim::LogMetricSocketConnectionState(
    const RawAddress& raw_address, int port, int type,
    android::bluetooth::SocketConnectionstateEnum connection_state,
    int64_t tx_bytes, int64_t rx_bytes, int uid, int server_port,
    android::bluetooth::SocketRoleEnum socket_role) {
  mock_function_count_map[__func__]++;
  test::mock::main_shim_metrics_api::LogMetricSocketConnectionState(
      raw_address, port, type, connection_state, tx_bytes, rx_bytes, uid,
      server_port, socket_role);
}
void bluetooth::shim::LogMetricManufacturerInfo(
    const RawAddress& raw_address,
    android::bluetooth::DeviceInfoSrcEnum source_type,
    const std::string& source_name, const std::string& manufacturer,
    const std::string& model, const std::string& hardware_version,
    const std::string& software_version) {
  mock_function_count_map[__func__]++;
  test::mock::main_shim_metrics_api::LogMetricManufacturerInfo(
      raw_address, source_type, source_name, manufacturer, model,
      hardware_version, software_version);
}

// END mockcify generation
