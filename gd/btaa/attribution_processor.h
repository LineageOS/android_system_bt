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

#include <cstdint>
#include <unordered_map>

#include "hci_processor.h"

namespace bluetooth {
namespace activity_attribution {

static constexpr size_t kWakeupAggregatorSize = 200;

struct AddressActivityKey {
  hci::Address address;
  Activity activity;

  bool operator==(const AddressActivityKey& other) const {
    return (address == other.address && activity == other.activity);
  }
};

struct AddressActivityKeyHasher {
  std::size_t operator()(const AddressActivityKey& key) const {
    return (
        (std::hash<std::string>()(key.address.ToString()) ^
         (std::hash<unsigned char>()(static_cast<unsigned char>(key.activity)))));
  }
};

struct WakeupDescriptor {
  Activity activity_;
  const hci::Address address_;
  WakeupDescriptor(Activity activity, const hci::Address address) : activity_(activity), address_(address) {}
  virtual ~WakeupDescriptor() {}
};

class AttributionProcessor {
 public:
  void OnBtaaPackets(std::vector<BtaaHciPacket> btaa_packets);
  void OnWakelockReleased(uint32_t duration_ms);
  void OnWakeup();
  void Dump(
      std::promise<flatbuffers::Offset<ActivityAttributionData>> promise, flatbuffers::FlatBufferBuilder* fb_builder);

  using ClockType = std::chrono::time_point<std::chrono::system_clock>;
  using NowFunc = ClockType (*)();

  // by default, we use the std::chrono::system_clock::now implementation to
  // get the current timestamp
  AttributionProcessor() : now_func_(std::chrono::system_clock::now) {}
  // in other cases, we may need to use different implementation
  // e.g., for testing purposes
  AttributionProcessor(NowFunc func) : now_func_(func) {}

 private:
  // this function is added for testing support in
  // OnWakelockReleased
  NowFunc now_func_ = std::chrono::system_clock::now;
  bool wakeup_ = false;
  std::unordered_map<AddressActivityKey, BtaaAggregationEntry, AddressActivityKeyHasher> btaa_aggregator_;
  std::unordered_map<AddressActivityKey, BtaaAggregationEntry, AddressActivityKeyHasher> wakelock_duration_aggregator_;
  common::TimestampedCircularBuffer<WakeupDescriptor> wakeup_aggregator_ =
      common::TimestampedCircularBuffer<WakeupDescriptor>(kWakeupAggregatorSize);
  const char* ActivityToString(Activity activity);
};

}  // namespace activity_attribution
}  // namespace bluetooth
