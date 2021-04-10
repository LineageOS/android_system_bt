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

#define LOG_TAG "BtStopWatch"

#include "common/stop_watch.h"

#include <iomanip>
#include <sstream>
#include <utility>

#include "common/init_flags.h"
#include "os/log.h"

namespace bluetooth {
namespace common {

static const int LOG_BUFFER_LENGTH = 10;
static std::array<std::string, LOG_BUFFER_LENGTH> stopwatch_logs;
static int current_buffer_index;

void StopWatch::RecordLog(std::string log) {
  if (current_buffer_index >= LOG_BUFFER_LENGTH) {
    current_buffer_index = 0;
  }
  stopwatch_logs[current_buffer_index] = std::move(log);
  current_buffer_index++;
}

void StopWatch::DumpStopWatchLog() {
  LOG_INFO("=====================================");
  LOG_INFO("bluetooth stopwatch log history:");
  for (int i = 0; i < LOG_BUFFER_LENGTH; i++) {
    if (current_buffer_index >= LOG_BUFFER_LENGTH) {
      current_buffer_index = 0;
    }
    if (stopwatch_logs[current_buffer_index].empty()) {
      break;
    }
    LOG_DEBUG("%s", stopwatch_logs[current_buffer_index].c_str());
    current_buffer_index++;
  }
  LOG_INFO("=====================================");
}

StopWatch::StopWatch(std::string text)
    : text_(std::move(text)), start_time_(std::chrono::high_resolution_clock::now()) {
  std::stringstream ss;
  auto now = std::chrono::system_clock::now();
  auto millis = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;
  auto now_time_t = std::chrono::system_clock::to_time_t(now);
  ss << std::put_time(std::localtime(&now_time_t), "%Y-%m-%d %H:%M:%S");
  ss << '.' << std::setfill('0') << std::setw(3) << millis.count();
  start_timestamp_ = ss.str();

  RecordLog(start_timestamp_ + ": " + text_);
}

StopWatch::~StopWatch() {
  RecordLog(
      start_timestamp_ + ": " + text_ + ": took " +
      std::to_string(static_cast<size_t>(
          std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::high_resolution_clock::now() - start_time_)
              .count())) +
      " us");
}

}  // namespace common
}  // namespace bluetooth
