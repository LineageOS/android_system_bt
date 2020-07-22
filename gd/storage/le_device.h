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

#include <optional>
#include <string>

#include "hci/hci_packets.h"
#include "storage/config_cache.h"
#include "storage/config_cache_helper.h"
#include "storage/device.h"

namespace bluetooth {
namespace storage {

class LeDevice {
 public:
  LeDevice(ConfigCache* config, std::string section);

  // for move
  LeDevice(LeDevice&& other) noexcept = default;
  LeDevice& operator=(LeDevice&& other) noexcept = default;

  // for copy
  LeDevice(const LeDevice& other) noexcept = default;
  LeDevice& operator=(const LeDevice& other) noexcept = default;

  // operators
  bool operator==(const LeDevice& other) const {
    return config_ == other.config_ && section_ == other.section_;
  }
  bool operator!=(const LeDevice& other) const {
    return !(*this == other);
  }
  bool operator<(const LeDevice& other) const {
    return config_ < other.config_ && section_ < other.section_;
  }
  bool operator>(const LeDevice& rhs) const {
    return (rhs < *this);
  }
  bool operator<=(const LeDevice& rhs) const {
    return !(*this > rhs);
  }
  bool operator>=(const LeDevice& rhs) const {
    return !(*this < rhs);
  }

  // Get the parent device
  Device Parent();

  // For logging purpose only, you can't get a LeDevice object from parsing a std::string
  std::string ToLogString();

 private:
  ConfigCache* config_;
  std::string section_;
  friend std::hash<LeDevice>;

 public:
  // Get LE address type of the key address
  GENERATE_PROPERTY_GETTER_SETTER_REMOVER(AddressType, hci::AddressType, "AddrType");
  GENERATE_PROPERTY_GETTER_SETTER_REMOVER(IdentityAddress, hci::Address, "LeIdentityAddr");
  GENERATE_PROPERTY_GETTER_SETTER_REMOVER(LegacyPseudoAddress, hci::AddressType, "LeLegacyPseudoAddr");
};

}  // namespace storage
}  // namespace bluetooth

namespace std {
template <>
struct hash<bluetooth::storage::LeDevice> {
  std::size_t operator()(const bluetooth::storage::LeDevice& val) const noexcept {
    std::size_t pointer_hash = std::hash<bluetooth::storage::ConfigCache*>{}(val.config_);
    std::size_t addr_hash = std::hash<std::string>{}(val.section_);
    return addr_hash ^ (pointer_hash << 1);
  }
};
}  // namespace std