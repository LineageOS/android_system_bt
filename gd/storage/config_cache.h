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

#include <functional>
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

  // comparison operators, callback doesn't count
  bool operator==(const ConfigCache& rhs) const;
  bool operator!=(const ConfigCache& rhs) const;

  // observers
  virtual bool HasSection(const std::string& section) const;
  virtual bool HasProperty(const std::string& section, const std::string& property) const;
  // Get property, return std::nullopt if section or property does not exist
  virtual std::optional<std::string> GetProperty(const std::string& section, const std::string& property) const;
  // Returns a copy of persistent device MAC addresses
  virtual std::vector<std::string> GetPersistentDevices() const;
  // Serialize to legacy config format
  virtual std::string SerializeToLegacyFormat() const;

  // modifiers
  // Commit all mutation entries in sequence while holding the config mutex
  virtual void Commit(Mutation& mutation);
  virtual void SetProperty(std::string section, std::string property, std::string value);
  virtual bool RemoveSection(const std::string& section);
  virtual bool RemoveProperty(const std::string& section, const std::string& property);
  // TODO: have a systematic way of doing this instead of specialized methods
  // Remove sections with |property| set
  virtual void RemoveSectionWithProperty(const std::string& property);
  // remove all content in this config cache, restore it to the state after the explicit constructor
  virtual void Clear();
  // Set a callback to notify interested party that a persistent config change has just happened
  virtual void SetPersistentConfigChangedCallback(std::function<void()> persistent_config_changed_callback);

  // static methods
  // Check if section is formatted as a MAC address
  static bool IsDeviceSection(const std::string& section);
  // Check if property represent one of those link keys used for paired devices
  static bool IsLinkKeyProperty(const std::string& property);

  // constants
  static const std::string kDefaultSectionName;

 private:
  mutable std::recursive_mutex mutex_;
  // A callback to notify interested party that a persistent config change has just happened, empty by default
  std::function<void()> persistent_config_changed_callback_;
  // Common section that does not relate to remote device, will be written to disk
  common::ListMap<std::string, common::ListMap<std::string, std::string>> information_sections_;
  // Information about persistent devices, normally paired, will be written to disk
  common::ListMap<std::string, common::ListMap<std::string, std::string>> persistent_devices_;
  // Information about temporary devices, normally unpaired, will not be written to disk, will be evicted automatically
  // if capacity exceeds given value during initialization
  common::LruCache<std::string, common::ListMap<std::string, std::string>> temporary_devices_;

  // Convenience method to check if the callback is valid before calling it
  inline void PersistentConfigChangedCallback() const {
    if (persistent_config_changed_callback_) {
      persistent_config_changed_callback_();
    }
  }
};

}  // namespace storage
}  // namespace bluetooth
