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
#include <cstdint>

namespace bluetooth {
namespace activity_attribution {

class WakelockProcessor {
 public:
  WakelockProcessor();

  uint32_t OnWakelockReleased();
  void OnWakelockAcquired();

 private:
  std::chrono::time_point<std::chrono::system_clock> wakelock_acquired_time_;
  uint8_t wakelock_net_count_;
};

}  // namespace activity_attribution
}  // namespace bluetooth
