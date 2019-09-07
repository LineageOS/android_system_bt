/*
 * Copyright 2019 The Android Open Source Project
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

#include "packets/link_layer/link_layer_packet_view.h"
#include "packets/packet_view.h"

namespace test_vendor_lib {
namespace packets {

class LeConnectView : public PacketView<true> {
 public:
  LeConnectView(const LeConnectView&) = default;
  virtual ~LeConnectView() = default;

  static LeConnectView GetLeConnect(const LinkLayerPacketView& view) {
    CHECK(view.GetType() == Link::PacketType::LE_CONNECT);
    return LeConnectView(view.GetPayload());
  }

  uint16_t GetLeConnectionIntervalMin() {
    return begin().extract<uint16_t>();
  }

  uint16_t GetLeConnectionIntervalMax() {
    return (begin() + 2).extract<uint16_t>();
  }

  uint16_t GetLeConnectionLatency() {
    return (begin() + 4).extract<uint16_t>();
  }

  uint16_t GetLeConnectionSupervisionTimeout() {
    return (begin() + 6).extract<uint16_t>();
  }

  uint8_t GetAddressType() {
    return (begin() + 8).extract<uint8_t>();
  }

 private:
  LeConnectView() = delete;
  LeConnectView(const PacketView<true>& view) : PacketView(view) {}
};

}  // namespace packets
}  // namespace test_vendor_lib
