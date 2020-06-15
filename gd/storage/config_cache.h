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

#include <list>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_set>
#include <utility>
#include <vector>

#include "common/list_map.h"
#include "common/lru_cache.h"
#include "hci/address.h"
#include "os/utils.h"

namespace bluetooth {
namespace storage {

class Mutation;

// A memory operated section-key-value structured config
//
// This class is thread safe
class ConfigCache {
 public:
  explicit ConfigCache(size_t temp_device_capacity);
  virtual ~ConfigCache() = default;

  // no copy
  DISALLOW_COPY_AND_ASSIGN(ConfigCache);

  // can move
  ConfigCache(ConfigCache&& other) noexcept;
  ConfigCache& operator=(ConfigCache&& other) noexcept;

  // comparison operators
  bool operator==(const ConfigCache& rhs) const {
    return information_sections_ == rhs.information_sections_ && persistent_devices_ == rhs.persistent_devices_ &&
           temporary_devices_ == rhs.temporary_devices_;
  }
  bool operator!=(const ConfigCache& rhs) const {
    return !(*this == rhs);
  }

  // observers
  virtual bool HasSection(const std::string& section) const;
  virtual bool HasProperty(const std::string& section, const std::string& property) const;
  // Get property, return std::nullopt if section or property does not exist
  virtual std::optional<std::string> GetProperty(const std::string& section, const std::string& property) const;
  // Returns a copy of persistent device MAC addresses
  virtual std::vector<std::string> GetPersistentDevices() const;

  // modifiers
  // Commit all mutation entries in sequence while holding the config mutex
  virtual void Commit(Mutation& mutation);
  virtual void SetProperty(std::string section, std::string property, std::string value);
  virtual bool RemoveSection(const std::string& section);
  virtual bool RemoveProperty(const std::string& section, const std::string& property);
  // TODO: have a systematic way of doing this instead of specialized methods
  // Remove devices with "Restricted" property
  virtual void RemoveRestricted();
  // remove all content in this config cache, restore it to the state after the explicit constructor
  virtual void Clear();

  // static methods
  // Check if section is formatted as a MAC address
  static bool IsDeviceSection(const std::string& section);
  // Check if property represent one of those link keys used for paired devices
  static bool IsLinkKeyProperty(const std::string& property);

  // constants
  static constexpr std::string_view kDefaultSectionName = "Global";

 private:
  mutable std::recursive_mutex mutex_;
  // Common section that does not relate to remote device, will be written to disk
  common::ListMap<std::string, common::ListMap<std::string, std::string>> information_sections_;
  // Information about persistent devices, normally paired, will be written to disk
  common::ListMap<std::string, common::ListMap<std::string, std::string>> persistent_devices_;
  // Information about temporary devices, normally unpaired, will not be written to disk, will be evicted automatically
  // if capacity exceeds given value during initialization
  common::LruCache<std::string, common::ListMap<std::string, std::string>> temporary_devices_;
};

}  // namespace storage
}  // namespace bluetooth
