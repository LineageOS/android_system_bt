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

#pragma once

#include <chrono>
#include <string>

namespace bluetooth {
namespace common {

class StopWatchLegacy {
 public:
  static void DumpStopWatchLog(void);
  StopWatchLegacy(std::string text);
  ~StopWatchLegacy();

 private:
  std::string text_;
  std::chrono::time_point<std::chrono::high_resolution_clock> start_time_;
  std::string start_timestamp_;
  void RecordLog(std::string log);
};

}  // namespace common
}  // namespace bluetooth
