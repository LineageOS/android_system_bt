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
 *   Functions generated:4
 */

#include <map>
#include <string>

extern std::map<std::string, int> mock_function_count_map;

#include <base/logging.h>
#include <iomanip>
#include <sstream>
#include <utility>
#include "common/stop_watch_legacy.h"
#include "osi/include/log.h"

#ifndef UNUSED_ATTR
#define UNUSED_ATTR
#endif

namespace bluetooth {
namespace common {

StopWatchLegacy::StopWatchLegacy(std::string text)
    : text_(std::move(text)),
      timestamp_(std::chrono::system_clock::now()),
      start_timestamp_(std::chrono::high_resolution_clock::now()) {
  mock_function_count_map[__func__]++;
}
StopWatchLegacy::~StopWatchLegacy() { mock_function_count_map[__func__]++; }
void StopWatchLegacy::DumpStopWatchLog() {
  mock_function_count_map[__func__]++;
}
void StopWatchLegacy::RecordLog(StopWatchLog log) {
  mock_function_count_map[__func__]++;
}

}  // namespace common
}  // namespace bluetooth
