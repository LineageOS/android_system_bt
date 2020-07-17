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

#include <array>
#include <cstdint>
#include <initializer_list>
#include <optional>
#include <string>

#include "storage/serializable.h"

namespace bluetooth {
namespace hci {

class LinkKey final : public storage::Serializable<LinkKey> {
 public:
  LinkKey() = default;
  LinkKey(const uint8_t (&d)[16]);
  LinkKey(std::initializer_list<uint8_t> l);

  static constexpr size_t kLength = 16;
  std::array<uint8_t, kLength> link_key = {};

  uint8_t* data() {
    return link_key.data();
  }

  const uint8_t* data() const {
    return link_key.data();
  }

  // operators
  bool operator<(const LinkKey& rhs) const {
    return link_key < rhs.link_key;
  }
  bool operator==(const LinkKey& rhs) const {
    return link_key == rhs.link_key;
  }
  bool operator>(const LinkKey& rhs) const {
    return (rhs < *this);
  }
  bool operator<=(const LinkKey& rhs) const {
    return !(*this > rhs);
  }
  bool operator>=(const LinkKey& rhs) const {
    return !(*this < rhs);
  }
  bool operator!=(const LinkKey& rhs) const {
    return !(*this == rhs);
  }

  // storage::Serializable methods
  std::string ToString() const override;
  static std::optional<LinkKey> FromString(const std::string& from);
  std::string ToLegacyConfigString() const override;
  static std::optional<LinkKey> FromLegacyConfigString(const std::string& from);

  // Example key from Bluetooth spec, do not use in real device!
  static const LinkKey kExample;
};

}  // namespace hci
}  // namespace bluetooth