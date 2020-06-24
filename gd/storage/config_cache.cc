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

#include "storage/config_cache.h"

#include <ios>
#include <sstream>
#include <utility>

#include "storage/mutation.h"

namespace {

bool TrimAfterNewLine(std::string& value) {
  std::string value_no_newline;
  size_t newline_position = value.find_first_of('\n');
  if (newline_position != std::string::npos) {
    value.erase(newline_position);
    return true;
  }
  return false;
}

}  // namespace

namespace bluetooth {
namespace storage {

const std::unordered_set<std::string_view> kLinkKeyPropertyNames = {
    "LinkKey", "LE_KEY_PENC", "LE_KEY_PID", "LE_KEY_PCSRK", "LE_KEY_LENC", "LE_KEY_LCSRK"};

const std::string ConfigCache::kDefaultSectionName = "Global";

ConfigCache::ConfigCache(size_t temp_device_capacity)
    : information_sections_(), persistent_devices_(), temporary_devices_(temp_device_capacity) {}

void ConfigCache::SetPersistentConfigChangedCallback(std::function<void()> persistent_config_changed_callback) {
  std::lock_guard<std::recursive_mutex> lock(mutex_);
  persistent_config_changed_callback_ = std::move(persistent_config_changed_callback);
}

ConfigCache::ConfigCache(ConfigCache&& other) noexcept
    : persistent_config_changed_callback_(std::move(other.persistent_config_changed_callback_)),
      information_sections_(std::move(other.information_sections_)),
      persistent_devices_(std::move(other.persistent_devices_)),
      temporary_devices_(std::move(other.temporary_devices_)) {
  // std::function will be in a valid but unspecified state after std::move(), hence resetting it
  other.persistent_config_changed_callback_ = {};
}

ConfigCache& ConfigCache::operator=(ConfigCache&& other) noexcept {
  if (&other == this) {
    return *this;
  }
  std::lock_guard<std::recursive_mutex> my_lock(mutex_);
  std::lock_guard<std::recursive_mutex> others_lock(other.mutex_);
  persistent_config_changed_callback_.swap(other.persistent_config_changed_callback_);
  other.persistent_config_changed_callback_ = {};
  information_sections_ = std::move(other.information_sections_);
  persistent_devices_ = std::move(other.persistent_devices_);
  temporary_devices_ = std::move(other.temporary_devices_);
  return *this;
}

bool ConfigCache::operator==(const ConfigCache& rhs) const {
  std::lock_guard<std::recursive_mutex> my_lock(mutex_);
  std::lock_guard<std::recursive_mutex> others_lock(rhs.mutex_);
  return information_sections_ == rhs.information_sections_ && persistent_devices_ == rhs.persistent_devices_ &&
         temporary_devices_ == rhs.temporary_devices_;
}

bool ConfigCache::operator!=(const ConfigCache& rhs) const {
  return !(*this == rhs);
}

void ConfigCache::Clear() {
  std::lock_guard<std::recursive_mutex> lock(mutex_);
  if (information_sections_.size() > 0) {
    information_sections_.clear();
    PersistentConfigChangedCallback();
  }
  if (persistent_devices_.size() > 0) {
    persistent_devices_.clear();
    PersistentConfigChangedCallback();
  }
  if (temporary_devices_.size() > 0) {
    temporary_devices_.clear();
  }
}

bool ConfigCache::HasSection(const std::string& section) const {
  std::lock_guard<std::recursive_mutex> lock(mutex_);
  return information_sections_.contains(section) || persistent_devices_.contains(section) ||
         temporary_devices_.contains(section);
}

bool ConfigCache::HasProperty(const std::string& section, const std::string& property) const {
  std::lock_guard<std::recursive_mutex> lock(mutex_);
  auto section_iter = information_sections_.find(section);
  if (section_iter != information_sections_.end()) {
    return section_iter->second.find(property) != section_iter->second.end();
  }
  section_iter = persistent_devices_.find(section);
  if (section_iter != persistent_devices_.end()) {
    return section_iter->second.find(property) != section_iter->second.end();
  }
  section_iter = temporary_devices_.find(section);
  if (section_iter != temporary_devices_.end()) {
    return section_iter->second.find(property) != section_iter->second.end();
  }
  return false;
}

std::optional<std::string> ConfigCache::GetProperty(const std::string& section, const std::string& property) const {
  std::lock_guard<std::recursive_mutex> lock(mutex_);
  auto section_iter = information_sections_.find(section);
  if (section_iter != information_sections_.end()) {
    auto property_iter = section_iter->second.find(property);
    if (property_iter != section_iter->second.end()) {
      return property_iter->second;
    }
  }
  section_iter = persistent_devices_.find(section);
  if (section_iter != persistent_devices_.end()) {
    auto property_iter = section_iter->second.find(property);
    if (property_iter != section_iter->second.end()) {
      return property_iter->second;
    }
  }
  section_iter = temporary_devices_.find(section);
  if (section_iter != temporary_devices_.end()) {
    auto property_iter = section_iter->second.find(property);
    if (property_iter != section_iter->second.end()) {
      return property_iter->second;
    }
  }
  return std::nullopt;
}

void ConfigCache::SetProperty(std::string section, std::string property, std::string value) {
  std::lock_guard<std::recursive_mutex> lock(mutex_);
  if (TrimAfterNewLine(section) || TrimAfterNewLine(property) || TrimAfterNewLine(value)) {
    android_errorWriteLog(0x534e4554, "70808273");
  }
  ASSERT_LOG(!section.empty(), "Empty section name not allowed");
  ASSERT_LOG(!property.empty(), "Empty property name not allowed");
  if (!IsDeviceSection(section)) {
    auto section_iter = information_sections_.find(section);
    if (section_iter == information_sections_.end()) {
      section_iter = information_sections_.try_emplace_back(section, common::ListMap<std::string, std::string>{}).first;
    }
    section_iter->second.insert_or_assign(property, std::move(value));
    PersistentConfigChangedCallback();
    return;
  }
  auto section_iter = persistent_devices_.find(section);
  if (section_iter == persistent_devices_.end() && IsLinkKeyProperty(property)) {
    // move paired devices or create new paired device when a link key is set
    auto section_properties = temporary_devices_.extract(section);
    if (section_properties) {
      section_iter = persistent_devices_.try_emplace_back(section, std::move(section_properties->second)).first;
    } else {
      section_iter = persistent_devices_.try_emplace_back(section, common::ListMap<std::string, std::string>{}).first;
    }
  }
  if (section_iter != persistent_devices_.end()) {
    section_iter->second.insert_or_assign(property, std::move(value));
    PersistentConfigChangedCallback();
    return;
  }
  section_iter = temporary_devices_.find(section);
  if (section_iter == temporary_devices_.end()) {
    auto triple = temporary_devices_.try_emplace(section, common::ListMap<std::string, std::string>{});
    section_iter = std::get<0>(triple);
  }
  section_iter->second.insert_or_assign(property, std::move(value));
}

bool ConfigCache::RemoveSection(const std::string& section) {
  std::lock_guard<std::recursive_mutex> lock(mutex_);
  // sections are unique among all three maps, hence removing from one of them is enough
  if (information_sections_.extract(section) || persistent_devices_.extract(section)) {
    PersistentConfigChangedCallback();
    return true;
  } else {
    return temporary_devices_.extract(section).has_value();
  }
}

bool ConfigCache::RemoveProperty(const std::string& section, const std::string& property) {
  std::lock_guard<std::recursive_mutex> lock(mutex_);
  auto section_iter = information_sections_.find(section);
  if (section_iter != information_sections_.end()) {
    return section_iter->second.extract(property).has_value();
  }
  section_iter = persistent_devices_.find(section);
  if (section_iter != persistent_devices_.end()) {
    auto value = section_iter->second.extract(property);
    if (value && IsLinkKeyProperty(property)) {
      // move unpaired device
      auto section_properties = persistent_devices_.extract(section);
      temporary_devices_.insert_or_assign(section, std::move(section_properties->second));
    }
    if (value.has_value()) {
      PersistentConfigChangedCallback();
      return true;
    } else {
      return false;
    }
  }
  section_iter = temporary_devices_.find(section);
  if (section_iter != temporary_devices_.end()) {
    return section_iter->second.extract(property).has_value();
  }
  return false;
}

bool ConfigCache::IsDeviceSection(const std::string& section) {
  return hci::Address::IsValidAddress(section);
}

bool ConfigCache::IsLinkKeyProperty(const std::string& property) {
  return kLinkKeyPropertyNames.find(property) != kLinkKeyPropertyNames.end();
}

void ConfigCache::RemoveSectionWithProperty(const std::string& property) {
  std::lock_guard<std::recursive_mutex> lock(mutex_);
  size_t num_persistent_removed = 0;
  for (auto* config_section : {&information_sections_, &persistent_devices_}) {
    for (auto it = config_section->begin(); it != config_section->end();) {
      if (it->second.contains(property)) {
        LOG_DEBUG("Removing persistent section %s with property %s", it->first.c_str(), property.c_str());
        it = config_section->erase(it);
        num_persistent_removed++;
        continue;
      }
      it++;
    }
  }
  for (auto it = temporary_devices_.begin(); it != temporary_devices_.end();) {
    if (it->second.contains(property)) {
      LOG_DEBUG("Removing temporary section %s with property %s", it->first.c_str(), property.c_str());
      it = temporary_devices_.erase(it);
      continue;
    }
    it++;
  }
  if (num_persistent_removed > 0) {
    PersistentConfigChangedCallback();
  }
}

std::vector<std::string> ConfigCache::GetPersistentDevices() const {
  std::lock_guard<std::recursive_mutex> lock(mutex_);
  std::vector<std::string> paired_devices;
  paired_devices.reserve(persistent_devices_.size());
  for (const auto& elem : persistent_devices_) {
    paired_devices.emplace_back(elem.first);
  }
  return paired_devices;
}

void ConfigCache::Commit(Mutation& mutation) {
  std::lock_guard<std::recursive_mutex> lock(mutex_);
  auto& entries = mutation.entries_;
  while (!entries.empty()) {
    auto entry = std::move(entries.front());
    entries.pop();
    if (entry.is_add) {
      SetProperty(std::move(entry.section), std::move(entry.property), std::move(entry.value));
    } else {
      if (entry.value.empty()) {
        RemoveSection(entry.section);
      } else {
        RemoveProperty(entry.section, entry.property);
      }
    }
  }
}

std::string ConfigCache::SerializeToLegacyFormat() const {
  std::lock_guard<std::recursive_mutex> lock(mutex_);
  std::stringstream serialized;
  for (const auto* config_section : {&information_sections_, &persistent_devices_}) {
    for (const auto& section : *config_section) {
      serialized << "[" << section.first << "]" << std::endl;
      for (const auto& property : section.second) {
        serialized << property.first << " = " << property.second << std::endl;
      }
      serialized << std::endl;
    }
  }
  return serialized.str();
}

}  // namespace storage
}  // namespace bluetooth