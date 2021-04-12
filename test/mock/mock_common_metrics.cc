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
 *   Functions generated:36
 */

#include <map>
#include <string>

extern std::map<std::string, int> mock_function_count_map;

#include "common/metrics.h"

#if 0
#include <base/base64.h>
#include <base/logging.h>
#include <include/hardware/bt_av.h>
#include <statslog.h>
#include <unistd.h>
#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <memory>
#include <mutex>
#include "address_obfuscator.h"
#include "bluetooth/metrics/bluetooth.pb.h"
#include "leaky_bonded_queue.h"
#include "metric_id_allocator.h"
#include "osi/include/osi.h"
#include "stack/include/btm_api_types.h"
#include "time_util.h"
#endif

#ifndef UNUSED_ATTR
#define UNUSED_ATTR
#endif

namespace bluetooth {
namespace common {

void A2dpSessionMetrics::Update(const A2dpSessionMetrics& metrics) {
  mock_function_count_map[__func__]++;
}

struct BluetoothMetricsLogger::impl {
  int mock{123};
};

BluetoothMetricsLogger::BluetoothMetricsLogger() {}
void BluetoothMetricsLogger::Build() { mock_function_count_map[__func__]++; }
void BluetoothMetricsLogger::CutoffSession() {
  mock_function_count_map[__func__]++;
}
void BluetoothMetricsLogger::LogA2dpSession(
    const A2dpSessionMetrics& a2dp_session_metrics) {
  mock_function_count_map[__func__]++;
}
void BluetoothMetricsLogger::LogBluetoothSessionDeviceInfo(
    uint32_t device_class, device_type_t device_type) {
  mock_function_count_map[__func__]++;
}
void BluetoothMetricsLogger::LogBluetoothSessionEnd(
    disconnect_reason_t disconnect_reason, uint64_t timestamp_ms) {
  mock_function_count_map[__func__]++;
}
void BluetoothMetricsLogger::LogBluetoothSessionStart(
    connection_tech_t connection_tech_type, uint64_t timestamp_ms) {
  mock_function_count_map[__func__]++;
}
void BluetoothMetricsLogger::LogHeadsetProfileRfcConnection(
    tBTA_SERVICE_ID service_id) {
  mock_function_count_map[__func__]++;
}
void BluetoothMetricsLogger::LogPairEvent(uint32_t disconnect_reason,
                                          uint64_t timestamp_ms,
                                          uint32_t device_class,
                                          device_type_t device_type) {
  mock_function_count_map[__func__]++;
}
void BluetoothMetricsLogger::LogScanEvent(bool start,
                                          const std::string& initator,
                                          scan_tech_t type, uint32_t results,
                                          uint64_t timestamp_ms) {
  mock_function_count_map[__func__]++;
}
void BluetoothMetricsLogger::LogWakeEvent(wake_event_type_t type,
                                          const std::string& requestor,
                                          const std::string& name,
                                          uint64_t timestamp_ms) {
  mock_function_count_map[__func__]++;
}
void BluetoothMetricsLogger::Reset() { mock_function_count_map[__func__]++; }
void BluetoothMetricsLogger::ResetLog() { mock_function_count_map[__func__]++; }
void BluetoothMetricsLogger::ResetSession() {
  mock_function_count_map[__func__]++;
}
void BluetoothMetricsLogger::WriteBase64(int fd) {
  mock_function_count_map[__func__]++;
}
void BluetoothMetricsLogger::WriteBase64String(std::string* serialized) {
  mock_function_count_map[__func__]++;
}
void BluetoothMetricsLogger::WriteString(std::string* serialized) {
  mock_function_count_map[__func__]++;
}
void LogA2dpAudioOverrunEvent(const RawAddress& address,
                              uint64_t encoding_interval_millis,
                              int num_dropped_buffers,
                              int num_dropped_encoded_frames,
                              int num_dropped_encoded_bytes) {
  mock_function_count_map[__func__]++;
}
void LogA2dpAudioUnderrunEvent(const RawAddress& address,
                               uint64_t encoding_interval_millis,
                               int num_missing_pcm_bytes) {
  mock_function_count_map[__func__]++;
}
void LogA2dpPlaybackEvent(const RawAddress& address, int playback_state,
                          int audio_coding_mode) {
  mock_function_count_map[__func__]++;
}
void LogBluetoothHalCrashReason(const RawAddress& address, uint32_t error_code,
                                uint32_t vendor_error_code) {
  mock_function_count_map[__func__]++;
}
void LogClassicPairingEvent(const RawAddress& address, uint16_t handle,
                            uint32_t hci_cmd, uint16_t hci_event,
                            uint16_t cmd_status, uint16_t reason_code,
                            int64_t event_value) {
  mock_function_count_map[__func__]++;
}
void LogHciTimeoutEvent(uint32_t hci_cmd) {
  mock_function_count_map[__func__]++;
}
void LogLinkLayerConnectionEvent(const RawAddress* address,
                                 uint32_t connection_handle,
                                 android::bluetooth::DirectionEnum direction,
                                 uint16_t link_type, uint32_t hci_cmd,
                                 uint16_t hci_event, uint16_t hci_ble_event,
                                 uint16_t cmd_status, uint16_t reason_code) {
  mock_function_count_map[__func__]++;
}
void LogManufacturerInfo(const RawAddress& address,
                         android::bluetooth::DeviceInfoSrcEnum source_type,
                         const std::string& source_name,
                         const std::string& manufacturer,
                         const std::string& model,
                         const std::string& hardware_version,
                         const std::string& software_version) {
  mock_function_count_map[__func__]++;
}
void LogReadFailedContactCounterResult(const RawAddress& address,
                                       uint16_t handle, uint32_t cmd_status,
                                       int32_t failed_contact_counter) {
  mock_function_count_map[__func__]++;
}
void LogReadRssiResult(const RawAddress& address, uint16_t handle,
                       uint32_t cmd_status, int8_t rssi) {
  mock_function_count_map[__func__]++;
}
void LogReadTxPowerLevelResult(const RawAddress& address, uint16_t handle,
                               uint32_t cmd_status,
                               int32_t transmit_power_level) {
  mock_function_count_map[__func__]++;
}
void LogRemoteVersionInfo(uint16_t handle, uint8_t status, uint8_t version,
                          uint16_t manufacturer_name, uint16_t subversion) {
  mock_function_count_map[__func__]++;
}
void LogSdpAttribute(const RawAddress& address, uint16_t protocol_uuid,
                     uint16_t attribute_id, size_t attribute_size,
                     const char* attribute_value) {
  mock_function_count_map[__func__]++;
}
void LogSmpPairingEvent(const RawAddress& address, uint8_t smp_cmd,
                        android::bluetooth::DirectionEnum direction,
                        uint8_t smp_fail_reason) {
  mock_function_count_map[__func__]++;
}
void LogSocketConnectionState(
    const RawAddress& address, int port, int type,
    android::bluetooth::SocketConnectionstateEnum connection_state,
    int64_t tx_bytes, int64_t rx_bytes, int uid, int server_port,
    android::bluetooth::SocketRoleEnum socket_role) {
  mock_function_count_map[__func__]++;
}

}  // namespace common
}  // namespace bluetooth
