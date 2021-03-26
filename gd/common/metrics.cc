/******************************************************************************
 *
 *  Copyright 2021 Google, Inc.
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

#define LOG_TAG "BluetoothMetrics"

#include <statslog.h>

#include "common/metric_id_manager.h"
#include "common/strings.h"
#include "metrics.h"
#include "os/log.h"

namespace bluetooth {

namespace common {

using bluetooth::hci::Address;

/**
 * nullptr and size 0 represent missing value for obfuscated_id
 */
static const android::util::BytesField byteField(nullptr, 0);

void LogMetricLinkLayerConnectionEvent(
    const Address* address,
    uint32_t connection_handle,
    android::bluetooth::DirectionEnum direction,
    uint16_t link_type,
    uint32_t hci_cmd,
    uint16_t hci_event,
    uint16_t hci_ble_event,
    uint16_t cmd_status,
    uint16_t reason_code) {
  int metric_id = 0;
  if (address != nullptr) {
    metric_id = MetricIdManager::GetInstance().AllocateId(*address);
  }
  int ret = android::util::stats_write(
      android::util::BLUETOOTH_LINK_LAYER_CONNECTION_EVENT,
      byteField,
      connection_handle,
      direction,
      link_type,
      hci_cmd,
      hci_event,
      hci_ble_event,
      cmd_status,
      reason_code,
      metric_id);
  if (ret < 0) {
    LOG_WARN(
        "Failed to log status %s , reason %s, from cmd %s, event %s,  ble_event %s, for %s, handle %d, type %s, "
        "error %d",
        ToHexString(cmd_status).c_str(),
        ToHexString(reason_code).c_str(),
        ToHexString(hci_cmd).c_str(),
        ToHexString(hci_event).c_str(),
        ToHexString(hci_ble_event).c_str(),
        address ? address->ToString().c_str() : "(NULL)",
        connection_handle,
        ToHexString(link_type).c_str(),
        ret);
  }
}

void LogMetricHciTimeoutEvent(uint32_t hci_cmd) {
  int ret = android::util::stats_write(android::util::BLUETOOTH_HCI_TIMEOUT_REPORTED, static_cast<int64_t>(hci_cmd));
  if (ret < 0) {
    LOG_WARN("Failed for opcode %s, error %d", ToHexString(hci_cmd).c_str(), ret);
  }
}

void LogMetricRemoteVersionInfo(
    uint16_t handle, uint8_t status, uint8_t version, uint16_t manufacturer_name, uint16_t subversion) {
  int ret = android::util::stats_write(
      android::util::BLUETOOTH_REMOTE_VERSION_INFO_REPORTED, handle, status, version, manufacturer_name, subversion);
  if (ret < 0) {
    LOG_WARN(
        "Failed for handle %d, status %s, version %s, manufacturer_name %s, subversion %s, error %d",
        handle,
        ToHexString(status).c_str(),
        ToHexString(version).c_str(),
        ToHexString(manufacturer_name).c_str(),
        ToHexString(subversion).c_str(),
        ret);
  }
}

void LogMetricA2dpAudioUnderrunEvent(
    const Address& address, uint64_t encoding_interval_millis, int num_missing_pcm_bytes) {
  int metric_id = 0;
  if (!address.IsEmpty()) {
    metric_id = MetricIdManager::GetInstance().AllocateId(address);
  }
  int64_t encoding_interval_nanos = encoding_interval_millis * 1000000;
  int ret = android::util::stats_write(
      android::util::BLUETOOTH_A2DP_AUDIO_UNDERRUN_REPORTED,
      byteField,
      encoding_interval_nanos,
      num_missing_pcm_bytes,
      metric_id);
  if (ret < 0) {
    LOG_WARN(
        "Failed for %s, encoding_interval_nanos %s, num_missing_pcm_bytes %d, error %d",
        address.ToString().c_str(),
        std::to_string(encoding_interval_nanos).c_str(),
        num_missing_pcm_bytes,
        ret);
  }
}

void LogMetricA2dpAudioOverrunEvent(
    const Address& address,
    uint64_t encoding_interval_millis,
    int num_dropped_buffers,
    int num_dropped_encoded_frames,
    int num_dropped_encoded_bytes) {
  int metric_id = 0;
  if (!address.IsEmpty()) {
    metric_id = MetricIdManager::GetInstance().AllocateId(address);
  }

  int64_t encoding_interval_nanos = encoding_interval_millis * 1000000;
  int ret = android::util::stats_write(
      android::util::BLUETOOTH_A2DP_AUDIO_OVERRUN_REPORTED,
      byteField,
      encoding_interval_nanos,
      num_dropped_buffers,
      num_dropped_encoded_frames,
      num_dropped_encoded_bytes,
      metric_id);
  if (ret < 0) {
    LOG_WARN(
        "Failed to log for %s, encoding_interval_nanos %s, num_dropped_buffers %d, "
        "num_dropped_encoded_frames %d, num_dropped_encoded_bytes %d, error %d",
        address.ToString().c_str(),
        std::to_string(encoding_interval_nanos).c_str(),
        num_dropped_buffers,
        num_dropped_encoded_frames,
        num_dropped_encoded_bytes,
        ret);
  }
}

void LogMetricReadRssiResult(const Address& address, uint16_t handle, uint32_t cmd_status, int8_t rssi) {
  int metric_id = 0;
  if (!address.IsEmpty()) {
    metric_id = MetricIdManager::GetInstance().AllocateId(address);
  }
  int ret = android::util::stats_write(
      android::util::BLUETOOTH_DEVICE_RSSI_REPORTED, byteField, handle, cmd_status, rssi, metric_id);
  if (ret < 0) {
    LOG_WARN(
        "Failed for %s, handle %d, status %s, rssi %d dBm, error %d",
        address.ToString().c_str(),
        handle,
        ToHexString(cmd_status).c_str(),
        rssi,
        ret);
  }
}

void LogMetricReadFailedContactCounterResult(
    const Address& address, uint16_t handle, uint32_t cmd_status, int32_t failed_contact_counter) {
  int metric_id = 0;
  if (!address.IsEmpty()) {
    metric_id = MetricIdManager::GetInstance().AllocateId(address);
  }
  int ret = android::util::stats_write(
      android::util::BLUETOOTH_DEVICE_FAILED_CONTACT_COUNTER_REPORTED,
      byteField,
      handle,
      cmd_status,
      failed_contact_counter,
      metric_id);
  if (ret < 0) {
    LOG_WARN(
        "Failed for %s, handle %d, status %s, failed_contact_counter %d packets, error %d",
        address.ToString().c_str(),
        handle,
        ToHexString(cmd_status).c_str(),
        failed_contact_counter,
        ret);
  }
}

void LogMetricReadTxPowerLevelResult(
    const Address& address, uint16_t handle, uint32_t cmd_status, int32_t transmit_power_level) {
  int metric_id = 0;
  if (!address.IsEmpty()) {
    metric_id = MetricIdManager::GetInstance().AllocateId(address);
  }
  int ret = android::util::stats_write(
      android::util::BLUETOOTH_DEVICE_TX_POWER_LEVEL_REPORTED,
      byteField,
      handle,
      cmd_status,
      transmit_power_level,
      metric_id);
  if (ret < 0) {
    LOG_WARN(
        "Failed for %s, handle %d, status %s, transmit_power_level %d packets, error %d",
        address.ToString().c_str(),
        handle,
        ToHexString(cmd_status).c_str(),
        transmit_power_level,
        ret);
  }
}

void LogMetricSmpPairingEvent(
    const Address& address, uint8_t smp_cmd, android::bluetooth::DirectionEnum direction, uint8_t smp_fail_reason) {
  int metric_id = 0;
  if (!address.IsEmpty()) {
    metric_id = MetricIdManager::GetInstance().AllocateId(address);
  }
  int ret = android::util::stats_write(
      android::util::BLUETOOTH_SMP_PAIRING_EVENT_REPORTED, byteField, smp_cmd, direction, smp_fail_reason, metric_id);
  if (ret < 0) {
    LOG_WARN(
        "Failed for %s, smp_cmd %s, direction %d, smp_fail_reason %s, error %d",
        address.ToString().c_str(),
        ToHexString(smp_cmd).c_str(),
        direction,
        ToHexString(smp_fail_reason).c_str(),
        ret);
  }
}

void LogMetricClassicPairingEvent(
    const Address& address,
    uint16_t handle,
    uint32_t hci_cmd,
    uint16_t hci_event,
    uint16_t cmd_status,
    uint16_t reason_code,
    int64_t event_value) {
  int metric_id = 0;
  if (!address.IsEmpty()) {
    metric_id = MetricIdManager::GetInstance().AllocateId(address);
  }
  int ret = android::util::stats_write(
      android::util::BLUETOOTH_CLASSIC_PAIRING_EVENT_REPORTED,
      byteField,
      handle,
      hci_cmd,
      hci_event,
      cmd_status,
      reason_code,
      event_value,
      metric_id);
  if (ret < 0) {
    LOG_WARN(
        "Failed for %s, handle %d, hci_cmd %s, hci_event %s, cmd_status %s, "
        "reason %s, event_value %s, error %d",
        address.ToString().c_str(),
        handle,
        ToHexString(hci_cmd).c_str(),
        ToHexString(hci_event).c_str(),
        ToHexString(cmd_status).c_str(),
        ToHexString(reason_code).c_str(),
        std::to_string(event_value).c_str(),
        ret);
  }
}

void LogMetricSdpAttribute(
    const Address& address,
    uint16_t protocol_uuid,
    uint16_t attribute_id,
    size_t attribute_size,
    const char* attribute_value) {
  int metric_id = 0;
  if (!address.IsEmpty()) {
    metric_id = MetricIdManager::GetInstance().AllocateId(address);
  }
  android::util::BytesField attribute_field(attribute_value, attribute_size);
  int ret = android::util::stats_write(
      android::util::BLUETOOTH_SDP_ATTRIBUTE_REPORTED,
      byteField,
      protocol_uuid,
      attribute_id,
      attribute_field,
      metric_id);
  if (ret < 0) {
    LOG_WARN(
        "Failed for %s, protocol_uuid %s, attribute_id %s, error %d",
        address.ToString().c_str(),
        ToHexString(protocol_uuid).c_str(),
        ToHexString(attribute_id).c_str(),
        ret);
  }
}

void LogMetricSocketConnectionState(
    const Address& address,
    int port,
    int type,
    android::bluetooth::SocketConnectionstateEnum connection_state,
    int64_t tx_bytes,
    int64_t rx_bytes,
    int uid,
    int server_port,
    android::bluetooth::SocketRoleEnum socket_role) {
  int metric_id = 0;
  if (!address.IsEmpty()) {
    metric_id = MetricIdManager::GetInstance().AllocateId(address);
  }
  int ret = android::util::stats_write(
      android::util::BLUETOOTH_SOCKET_CONNECTION_STATE_CHANGED,
      byteField,
      port,
      type,
      connection_state,
      tx_bytes,
      rx_bytes,
      uid,
      server_port,
      socket_role,
      metric_id);
  if (ret < 0) {
    LOG_WARN(
        "Failed for %s, port %d, type %d, state %d, tx_bytes %s, rx_bytes %s, uid %d, server_port %d, "
        "socket_role %d, error %d",
        address.ToString().c_str(),
        port,
        type,
        connection_state,
        std::to_string(tx_bytes).c_str(),
        std::to_string(rx_bytes).c_str(),
        uid,
        server_port,
        socket_role,
        ret);
  }
}

void LogMetricManufacturerInfo(
    const Address& address,
    android::bluetooth::DeviceInfoSrcEnum source_type,
    const std::string& source_name,
    const std::string& manufacturer,
    const std::string& model,
    const std::string& hardware_version,
    const std::string& software_version) {
  int metric_id = 0;
  if (!address.IsEmpty()) {
    metric_id = MetricIdManager::GetInstance().AllocateId(address);
  }
  int ret = android::util::stats_write(
      android::util::BLUETOOTH_DEVICE_INFO_REPORTED,
      byteField,
      source_type,
      source_name.c_str(),
      manufacturer.c_str(),
      model.c_str(),
      hardware_version.c_str(),
      software_version.c_str(),
      metric_id);
  if (ret < 0) {
    LOG_WARN(
        "Failed for %s, source_type %d, source_name %s, manufacturer %s, model %s, hardware_version %s, "
        "software_version %s, error %d",
        address.ToString().c_str(),
        source_type,
        source_name.c_str(),
        manufacturer.c_str(),
        model.c_str(),
        hardware_version.c_str(),
        software_version.c_str(),
        ret);
  }
}

}  // namespace common

}  // namespace bluetooth
