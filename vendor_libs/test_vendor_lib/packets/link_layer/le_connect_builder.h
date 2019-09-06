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
#include <memory>

#include "packets/packet_builder.h"

namespace test_vendor_lib {
namespace packets {

class LeConnectBuilder : public PacketBuilder<true> {
 public:
  virtual ~LeConnectBuilder() = default;

  static std::unique_ptr<LeConnectBuilder> Create(uint16_t le_connection_interval_min,
                                                  uint16_t le_connection_interval_max, uint16_t le_connection_latency,
                                                  uint16_t le_connection_supervision_timeout,
                                                  uint8_t peer_address_type) {
    return std::unique_ptr<LeConnectBuilder>(
        new LeConnectBuilder(le_connection_interval_min, le_connection_interval_max, le_connection_latency,
                             le_connection_supervision_timeout, peer_address_type));
  }

  virtual size_t size() const override {
    return sizeof(le_connection_interval_min_) + sizeof(le_connection_interval_max_) + sizeof(le_connection_latency_) +
           sizeof(le_connection_supervision_timeout_) + sizeof(peer_address_type_);
  }

 protected:
  virtual void Serialize(std::back_insert_iterator<std::vector<uint8_t>> it) const override {
    insert(le_connection_interval_min_, it);
    insert(le_connection_interval_max_, it);
    insert(le_connection_latency_, it);
    insert(le_connection_supervision_timeout_, it);
    insert(peer_address_type_, it);
  }

 private:
  explicit LeConnectBuilder(uint16_t le_connection_interval_min, uint16_t le_connection_interval_max,
                            uint16_t le_connection_latency, uint16_t le_connection_supervision_timeout,
                            uint8_t peer_address_type)
      : le_connection_interval_min_(le_connection_interval_min),
        le_connection_interval_max_(le_connection_interval_max), le_connection_latency_(le_connection_latency),
        le_connection_supervision_timeout_(le_connection_supervision_timeout), peer_address_type_(peer_address_type)

  {}
  uint16_t le_connection_interval_min_;
  uint16_t le_connection_interval_max_;
  uint16_t le_connection_latency_;
  uint16_t le_connection_supervision_timeout_;
  uint8_t peer_address_type_;
};

}  // namespace packets
}  // namespace test_vendor_lib
