/******************************************************************************
 *
 *  Copyright (C) 2017 Google, Inc.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at:
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 ******************************************************************************/
#pragma once

#include <cstdint>
#include <iterator>
#include <memory>
#include <vector>

#include "base/macros.h"
#include "l2cap_sdu.h"

namespace test_vendor_lib {

const int kSduHeaderLength = 4;

class L2capPacket {
 public:
  // Returns an assembled L2cap object if successful, nullptr if failure.
  static std::unique_ptr<L2capPacket> assemble(
      const std::vector<L2capSdu>& sdu_packet);

  // Construct a vector of just the L2CAP payload. This essentially
  // will remove the L2CAP header from the private member variable.
  // TODO: Remove this in favor of custom iterators.
  std::vector<uint8_t> get_l2cap_payload() const;

  uint16_t get_l2cap_cid() const;

 private:
  L2capPacket() = default;

  // Entire L2CAP packet: length, CID, and payload in that order.
  std::vector<uint8_t> l2cap_packet_;

  // Returns an iterator to the beginning of the L2CAP payload on success.
  auto get_l2cap_payload_begin() const {
    return std::next(l2cap_packet_.begin(), kSduHeaderLength);
  }

  DISALLOW_COPY_AND_ASSIGN(L2capPacket);
};  // L2capPacket

}  // namespace test_vendor_lib
