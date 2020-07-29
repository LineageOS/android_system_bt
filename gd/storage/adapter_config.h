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

#include <string>

#include "common/byte_array.h"
#include "hci/address.h"
#include "storage/config_cache.h"
#include "storage/device.h"

namespace bluetooth {
namespace storage {

class AdapterConfig {
 public:
  AdapterConfig(ConfigCache* config, ConfigCache* memory_only_config, std::string section);

  // for move
  AdapterConfig(AdapterConfig&& other) noexcept = default;
  AdapterConfig& operator=(AdapterConfig&& other) noexcept = default;

  // for copy
  AdapterConfig(const AdapterConfig& other) noexcept = default;
  AdapterConfig& operator=(const AdapterConfig& other) noexcept = default;

  // operators
  bool operator==(const AdapterConfig& other) const {
    return config_ == other.config_ && memory_only_config_ == other.memory_only_config_ && section_ == other.section_;
  }
  bool operator!=(const AdapterConfig& other) const {
    return !(*this == other);
  }
  bool operator<(const AdapterConfig& other) const {
    return config_ < other.config_ && memory_only_config_ < other.memory_only_config_ && section_ < other.section_;
  }
  bool operator>(const AdapterConfig& rhs) const {
    return (rhs < *this);
  }
  bool operator<=(const AdapterConfig& rhs) const {
    return !(*this > rhs);
  }
  bool operator>=(const AdapterConfig& rhs) const {
    return !(*this < rhs);
  }

 private:
  ConfigCache* config_;
  ConfigCache* memory_only_config_;
  std::string section_;

 public:
  GENERATE_PROPERTY_GETTER_SETTER_REMOVER(Address, hci::Address, "Address");
  GENERATE_PROPERTY_GETTER_SETTER_REMOVER(LeIdentityResolvingKey, common::ByteArray<16>, "LE_LOCAL_KEY_IRK");
  GENERATE_PROPERTY_GETTER_SETTER_REMOVER(LegacyScanMode, hci::LegacyScanMode, "ScanMode");
  GENERATE_PROPERTY_GETTER_SETTER_REMOVER(DiscoveryTimeoutSeconds, int, "DiscoveryTimeout");
};

}  // namespace storage
}  // namespace bluetooth