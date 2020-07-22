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

#include "hci/link_key.h"
#include "common/strings.h"

namespace bluetooth {
namespace hci {

const LinkKey LinkKey::kExample{
    {0x4C, 0x68, 0x38, 0x41, 0x39, 0xf5, 0x74, 0xd8, 0x36, 0xbc, 0xf3, 0x4e, 0x9d, 0xfb, 0x01, 0xbf}};

LinkKey::LinkKey(const uint8_t (&d)[kLength]) {
  std::copy(d, d + kLength, data());
}

LinkKey::LinkKey(std::initializer_list<uint8_t> l) {
  std::copy(l.begin(), std::min(l.begin() + kLength, l.end()), data());
}

std::string LinkKey::ToString() const {
  std::vector<uint8_t> vec(link_key.begin(), link_key.end());
  return common::ToHexString(vec);
}

std::optional<LinkKey> LinkKey::FromString(const std::string& from) {
  if (from.length() != (kLength * 2)) {
    return std::nullopt;
  }
  auto vec = common::FromHexString(from);
  if (!vec) {
    return std::nullopt;
  }
  LinkKey new_link_key = {};
  std::copy(vec->data(), vec->data() + vec->size(), new_link_key.data());
  return new_link_key;
}

std::string LinkKey::ToLegacyConfigString() const {
  return ToString();
}

std::optional<LinkKey> LinkKey::FromLegacyConfigString(const std::string& from) {
  return FromString(from);
}

}  // namespace hci
}  // namespace bluetooth
