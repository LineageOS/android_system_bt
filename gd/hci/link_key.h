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

#include "storage/serializable.h"

namespace bluetooth {
namespace hci {

class LinkKey final : public storage::Serializable<LinkKey> {
 public:
  LinkKey() = default;
  explicit LinkKey(const uint8_t (&data)[16]);

  static constexpr unsigned int kLength = 16;
  uint8_t link_key[kLength] = {};

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