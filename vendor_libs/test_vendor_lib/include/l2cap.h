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

class L2cap {
 public:
  // Returns an assembled L2cap object if successful, nullptr if failure.
  static std::unique_ptr<L2cap> assemble(
      const std::vector<L2capSdu>& sdu_packet);

  // Construct a vector of just the L2CAP payload. This essentially
  // will remove the L2CAP header from the private member variable.
  std::vector<uint8_t> get_l2cap_payload() const;

  uint16_t get_l2cap_cid() const;

 private:
  L2cap() = default;

  // Entire L2CAP packet: length, CID, and payload in that order.
  std::vector<uint8_t> l2cap_packet_;

  // Returns an iterator to the beginning of the L2CAP payload on success.
  auto get_l2cap_payload_begin() const {
    return std::next(l2cap_packet_.begin(), kSduHeaderLength);
  }

  // Returns true if the SDU control sequence for Segmentation and
  // Reassembly is 00b, false otherwise.
  static bool check_if_only_sdu(const uint8_t bytes);

  // Returns true if the SDU control sequence for Segmentation and
  // Reassembly is 01b, false otherwise.
  static bool check_if_starting_sdu(const uint8_t bytes);

  // Returns true if the SDU control sequence for Segmentation and
  // Reasembly is 10b, false otherwise.
  static bool check_if_ending_sdu(const uint8_t bytes);

  DISALLOW_COPY_AND_ASSIGN(L2cap);
};  // L2cap

}  // namespace test_vendor_lib
