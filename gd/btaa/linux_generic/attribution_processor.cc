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

#include "btaa/attribution_processor.h"

#include "os/log.h"

namespace bluetooth {
namespace activity_attribution {

void AttributionProcessor::OnWakelockReleased(uint32_t duration_ms) {}

void AttributionProcessor::OnWakeup() {
  if (wakeup_) {
    LOG_INFO("Previous wakeup notification is not consumed.");
  }
  wakeup_ = true;
}

}  // namespace activity_attribution
}  // namespace bluetooth
