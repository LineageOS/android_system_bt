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

#include <frameworks/proto_logging/stats/enums/bluetooth/enums.pb.h>
#include <frameworks/proto_logging/stats/enums/bluetooth/hci/enums.pb.h>

#include "btif/include/btif_metrics_logging.h"
#include "common/metric_id_allocator.h"
#include "common/metrics.h"
#include "main/shim/metrics_api.h"
#include "main/shim/shim.h"
#include "types/raw_address.h"

void log_a2dp_audio_underrun_event(const RawAddress& address,
                                   uint64_t encoding_interval_millis,
                                   int num_missing_pcm_bytes) {
  if (bluetooth::shim::is_any_gd_enabled()) {
    bluetooth::shim::LogMetricA2dpAudioUnderrunEvent(
        address, encoding_interval_millis, num_missing_pcm_bytes);
  } else {
    bluetooth::common::LogA2dpAudioUnderrunEvent(
        address, encoding_interval_millis, num_missing_pcm_bytes);
  }
}

void log_a2dp_audio_overrun_event(const RawAddress& address,
                                  uint64_t encoding_interval_millis,
                                  int num_dropped_buffers,
                                  int num_dropped_encoded_frames,
                                  int num_dropped_encoded_bytes) {
  if (bluetooth::shim::is_any_gd_enabled()) {
    bluetooth::shim::LogMetricA2dpAudioOverrunEvent(
        address, encoding_interval_millis, num_dropped_buffers,
        num_dropped_encoded_frames, num_dropped_encoded_bytes);
  } else {
    bluetooth::common::LogA2dpAudioOverrunEvent(
        address, encoding_interval_millis, num_dropped_buffers,
        num_dropped_encoded_frames, num_dropped_encoded_bytes);
  }
}

void log_a2dp_playback_event(const RawAddress& address, int playback_state,
                             int audio_coding_mode) {
  if (bluetooth::shim::is_any_gd_enabled()) {
    bluetooth::shim::LogMetricA2dpPlaybackEvent(address, playback_state,
                                                audio_coding_mode);
  } else {
    bluetooth::common::LogA2dpPlaybackEvent(address, playback_state,
                                            audio_coding_mode);
  }
}

void log_read_rssi_result(const RawAddress& address, uint16_t handle,
                          uint32_t cmd_status, int8_t rssi) {
  if (bluetooth::shim::is_any_gd_enabled()) {
    bluetooth::shim::LogMetricReadRssiResult(address, handle, cmd_status, rssi);
  } else {
    bluetooth::common::LogReadRssiResult(address, handle, cmd_status, rssi);
  }
}

void log_read_failed_contact_counter_result(const RawAddress& address,
                                            uint16_t handle,
                                            uint32_t cmd_status,
                                            int32_t failed_contact_counter) {
  if (bluetooth::shim::is_any_gd_enabled()) {
    bluetooth::shim::LogMetricReadFailedContactCounterResult(
        address, handle, cmd_status, failed_contact_counter);
  } else {
    bluetooth::common::LogReadFailedContactCounterResult(
        address, handle, cmd_status, failed_contact_counter);
  }
}

void log_read_tx_power_level_result(const RawAddress& address, uint16_t handle,
                                    uint32_t cmd_status,
                                    int32_t transmit_power_level) {
  if (bluetooth::shim::is_any_gd_enabled()) {
    bluetooth::shim::LogMetricReadTxPowerLevelResult(
        address, handle, cmd_status, transmit_power_level);
  } else {
    bluetooth::common::LogReadTxPowerLevelResult(address, handle, cmd_status,
                                                 transmit_power_level);
  }
}

void log_socket_connection_state(
    const RawAddress& address, int port, int type,
    android::bluetooth::SocketConnectionstateEnum connection_state,
    int64_t tx_bytes, int64_t rx_bytes, int uid, int server_port,
    android::bluetooth::SocketRoleEnum socket_role) {
  if (bluetooth::shim::is_any_gd_enabled()) {
    bluetooth::shim::LogMetricSocketConnectionState(
        address, port, type, connection_state, tx_bytes, rx_bytes, uid,
        server_port, socket_role);
  } else {
    bluetooth::common::LogSocketConnectionState(
        address, port, type, connection_state, tx_bytes, rx_bytes, uid,
        server_port, socket_role);
  }
}

bool init_metric_id_allocator(
    const std::unordered_map<RawAddress, int>& paired_device_map,
    bluetooth::shim::CallbackLegacy save_device_callback,
    bluetooth::shim::CallbackLegacy forget_device_callback) {
  if (bluetooth::shim::is_any_gd_enabled()) {
    return bluetooth::shim::InitMetricIdAllocator(
        paired_device_map, std::move(save_device_callback),
        std::move(forget_device_callback));
  }
  return bluetooth::common::MetricIdAllocator::GetInstance().Init(
      paired_device_map, std::move(save_device_callback),
      std::move(forget_device_callback));
}

bool close_metric_id_allocator() {
  if (bluetooth::shim::is_any_gd_enabled()) {
    return bluetooth::shim::CloseMetricIdAllocator();
  }
  return bluetooth::common::MetricIdAllocator::GetInstance().Close();
}

int allocate_metric_id_from_metric_id_allocator(const RawAddress& address) {
  if (bluetooth::shim::is_any_gd_enabled()) {
    return bluetooth::shim::AllocateIdFromMetricIdAllocator(address);
  }
  return bluetooth::common::MetricIdAllocator::GetInstance().AllocateId(
      address);
}

int save_metric_id_from_metric_id_allocator(const RawAddress& address) {
  if (bluetooth::shim::is_any_gd_enabled()) {
    return bluetooth::shim::SaveDeviceOnMetricIdAllocator(address);
  }
  return bluetooth::common::MetricIdAllocator::GetInstance().SaveDevice(
      address);
}

void forget_device_from_metric_id_allocator(const RawAddress& address) {
  if (bluetooth::shim::is_any_gd_enabled()) {
    bluetooth::shim::ForgetDeviceFromMetricIdAllocator(address);
  } else {
    bluetooth::common::MetricIdAllocator::GetInstance().ForgetDevice(address);
  }
}

bool is_valid_id_from_metric_id_allocator(const int id) {
  if (bluetooth::shim::is_any_gd_enabled()) {
    return bluetooth::shim::IsValidIdFromMetricIdAllocator(id);
  }
  return bluetooth::common::MetricIdAllocator::IsValidId(id);
}
