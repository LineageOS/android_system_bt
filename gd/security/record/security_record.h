/*
 *
 *  Copyright 2019 The Android Open Source Project
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
 */

#pragma once

#include <memory>
#include <utility>

#include "crypto_toolbox/crypto_toolbox.h"
#include "hci/address_with_type.h"

namespace bluetooth {
namespace security {
namespace record {

enum BondState {
  /* CreateBond was called, or remote send Pairing Request */
  PAIRING,
  /* Link key has been exchanged, but not stored */
  PAIRED,
  /* Link Keys are stored persistently */
  BONDED
};

class SecurityRecord {
 public:
  explicit SecurityRecord(hci::AddressWithType address) : pseudo_address_(address), state_(PAIRING) {}

  SecurityRecord& operator=(const SecurityRecord& other) = default;

  /**
   * Returns true if Link Keys are stored persistently
   */
  bool IsBonded() {
    return state_ == BONDED;
  }

  /* Link key has been exchanged, but not stored */
  bool IsPaired() {
    return state_ == PAIRED;
  }

  void SetLinkKey(std::array<uint8_t, 16> link_key, hci::KeyType key_type) {
    link_key_ = link_key;
    key_type_ = key_type;
  }

  std::array<uint8_t, 16> GetLinkKey() {
    return link_key_;
  }

  hci::KeyType GetKeyType() {
    return key_type_;
  }

  hci::AddressWithType GetPseudoAddress() {
    return pseudo_address_;
  }

 private:
  /* First address we have ever seen this device with, that we used to create bond */
  hci::AddressWithType pseudo_address_;

  BondState state_;
  std::array<uint8_t, 16> link_key_ = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  hci::KeyType key_type_ = hci::KeyType::DEBUG_COMBINATION;

 public:
  /* Identity Address */
  std::optional<hci::AddressWithType> identity_address_;

  std::optional<crypto_toolbox::Octet16> ltk;
  std::optional<uint16_t> ediv;
  std::optional<std::array<uint8_t, 8>> rand;
  std::optional<crypto_toolbox::Octet16> irk;
  std::optional<crypto_toolbox::Octet16> signature_key;
};

}  // namespace record
}  // namespace security
}  // namespace bluetooth
