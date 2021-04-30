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

#include "btaa/wakelock_processor.h"

#include "os/log.h"

namespace bluetooth {
namespace activity_attribution {

static const int kWakelockMaxDurationMs(10000);

WakelockProcessor::WakelockProcessor() {
  wakelock_net_count_ = 0;
  wakelock_acquired_time_ = {};
}

uint32_t WakelockProcessor::OnWakelockReleased() {
  auto cur_time = std::chrono::system_clock::now();
  uint32_t wakelock_duration_ms = 0;

  if (wakelock_net_count_ == 0) {
    LOG_INFO("Release a never acquired wakelock, ignored.");
  } else {
    wakelock_net_count_--;
    if (wakelock_net_count_ == 0) {
      wakelock_duration_ms = static_cast<uint32_t>(
          std::chrono::duration_cast<std::chrono::milliseconds>(cur_time - wakelock_acquired_time_).count());
      wakelock_acquired_time_ = {};
    }
  }

  return wakelock_duration_ms;
}

void WakelockProcessor::OnWakelockAcquired() {
  auto cur_time = std::chrono::system_clock::now();

  if (wakelock_net_count_ == 0) {
    if (wakelock_acquired_time_.time_since_epoch().count()) {
      LOG_INFO("Previous wakelock acquired time is not consumed, dropped.");
    }
    wakelock_acquired_time_ = cur_time;
  } else if (cur_time - wakelock_acquired_time_ > std::chrono::milliseconds(kWakelockMaxDurationMs)) {
    LOG_INFO("Wakelock held for too long, likely we missed a release notification. Resetting wakelock stats.");
    wakelock_net_count_ = 0;
    wakelock_acquired_time_ = cur_time;
  }

  wakelock_net_count_++;
}

}  // namespace activity_attribution
}  // namespace bluetooth
