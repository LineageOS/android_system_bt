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

#include "btaa/activity_attribution.h"

// TODO: Implement for Linux.
namespace bluetooth {
namespace activity_attribution {

const ModuleFactory ActivityAttribution::Factory = ModuleFactory([]() { return new ActivityAttribution(); });

struct ActivityAttribution::impl {
  impl(ActivityAttribution* module) {}

  void on_hci_packet(hal::HciPacket packet, hal::SnoopLogger::PacketType type, uint16_t length) {}

  void register_callback(ActivityAttributionCallback* callback) {}
};

void ActivityAttribution::Capture(const hal::HciPacket& packet, hal::SnoopLogger::PacketType type) {}

void ActivityAttribution::RegisterActivityAttributionCallback(ActivityAttributionCallback* callback) {}

std::string ActivityAttribution::ToString() const {
  return "Btaa Module";
}

void ActivityAttribution::ListDependencies(ModuleList* list) {}

void ActivityAttribution::Start() {}

void ActivityAttribution::Stop() {}

}  // namespace activity_attribution
}  // namespace bluetooth
