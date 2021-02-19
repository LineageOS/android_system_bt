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

#include "os/log.h"

namespace bluetooth {
namespace common {

StopWatch::StopWatch(std::string text)
    : text_(std::move(text)), start_time_(std::chrono::high_resolution_clock::now()) {
  std::stringstream ss;
  auto now = std::chrono::system_clock::now();
  auto millis = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;
  auto now_time_t = std::chrono::system_clock::to_time_t(now);
  ss << std::put_time(std::localtime(&now_time_t), "%Y-%m-%d %H:%M:%S");
  ss << '.' << std::setfill('0') << std::setw(3) << millis.count();
  start_timestamp_ = ss.str();
  LOG_DEBUG(" %s: %s:", start_timestamp_.c_str(), text_.c_str());
}

StopWatch::~StopWatch() {
  LOG_DEBUG(
      "%s: %s: took %zu us",
      start_timestamp_.c_str(),
      text_.c_str(),
      static_cast<size_t>(
          std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::high_resolution_clock::now() - start_time_)
              .count()));
}

}  // namespace common
}  // namespace bluetooth