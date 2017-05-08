/******************************************************************************
 *
 *  Copyright (C) 2016 Google, Inc.
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

#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif
// Typedefs to hide protobuf definition to the rest of stack

typedef enum {
  DEVICE_TYPE_UNKNOWN,
  DEVICE_TYPE_BREDR,
  DEVICE_TYPE_LE,
  DEVICE_TYPE_DUMO,
} device_type_t;

typedef enum {
  WAKE_EVENT_UNKNOWN,
  WAKE_EVENT_ACQUIRED,
  WAKE_EVENT_RELEASED,
} wake_event_type_t;

typedef enum {
  SCAN_TYPE_UNKNOWN,
  SCAN_TECH_TYPE_LE,
  SCAN_TECH_TYPE_BREDR,
  SCAN_TECH_TYPE_BOTH,
} scan_tech_t;

typedef enum {
  CONNECTION_TECHNOLOGY_TYPE_UNKNOWN,
  CONNECTION_TECHNOLOGY_TYPE_LE,
  CONNECTION_TECHNOLOGY_TYPE_BREDR,
} connection_tech_t;

typedef enum {
  DISCONNECT_REASON_UNKNOWN,
  DISCONNECT_REASON_METRICS_DUMP,
  DISCONNECT_REASON_NEXT_START_WITHOUT_END_PREVIOUS,
} disconnect_reason_t;

typedef struct {
  int64_t audio_duration_ms;
  int32_t media_timer_min_ms;
  int32_t media_timer_max_ms;
  int32_t media_timer_avg_ms;
  int64_t total_scheduling_count;
  int32_t buffer_overruns_max_count;
  int32_t buffer_overruns_total;
  float buffer_underruns_average;
  int32_t buffer_underruns_count;
} A2dpSessionMetrics_t;

void metrics_log_pair_event(uint32_t disconnect_reason, uint64_t timestamp_ms,
                    uint32_t device_class, device_type_t device_type);

void metrics_log_wake_event(wake_event_type_t type, const char* requestor,
                    const char* name, uint64_t timestamp_ms);

void metrics_log_scan_event(bool start, const char* initator, scan_tech_t type,
                    uint32_t results, uint64_t timestamp_ms);

void metrics_log_bluetooth_session_start(connection_tech_t connection_tech_type,
                                uint64_t timestamp_ms);

void metrics_log_bluetooth_session_end(disconnect_reason_t disconnect_reason,
  uint64_t timestamp_ms);

void metrics_log_bluetooth_session_device_info(uint32_t device_class,
                                     device_type_t device_type);

void metrics_log_a2dp_session(A2dpSessionMetrics_t* metrics);

void metrics_write_base64(int fd, bool clear);

#ifdef __cplusplus
}
#endif
