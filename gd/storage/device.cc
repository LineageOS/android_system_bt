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

#include "storage/device.h"

#include <limits>

#include "os/log.h"
#include "storage/classic_device.h"
#include "storage/config_cache_helper.h"
#include "storage/le_device.h"

namespace bluetooth {
namespace storage {

using hci::DeviceType;

namespace {
const std::string kDeviceTypeKey = "DevType";
// TODO(siyuanh): also defined in storage/le_device.cc
const std::string kLeIdentityAddressKey = "LeIdentityAddr";

std::string GetConfigSection(
    ConfigCache* config, hci::Address key_address, Device::ConfigKeyAddressType key_address_type) {
  ASSERT_LOG(config != nullptr, "config cannot be null");
  ASSERT_LOG(!key_address.IsEmpty(), "key_address cannot be empty");
  // assume lower case
  auto key_address_string = key_address.ToString();
  switch (key_address_type) {
    case Device::ConfigKeyAddressType::LEGACY_KEY_ADDRESS:
    case Device::ConfigKeyAddressType::CLASSIC_ADDRESS:
      return key_address_string;
    case Device::ConfigKeyAddressType::LE_IDENTITY_ADDRESS:
      for (const auto& section_and_property : config->GetSectionNamesWithProperty(kLeIdentityAddressKey)) {
        if (section_and_property.property == key_address_string) {
          return section_and_property.section;
        }
      }
      return key_address_string;
    default:
      LOG_ALWAYS_FATAL("Unknown key_address_type %d", static_cast<int>(key_address_type));
      return "";
  }
}

}  // namespace

Device::Device(ConfigCache* config, hci::Address key_address, ConfigKeyAddressType key_address_type)
    : Device(config, GetConfigSection(config, key_address, key_address_type)) {}

Device::Device(ConfigCache* config, std::string section) : config_(config), section_(section) {}

bool Device::Exists() {
  return config_->HasSection(section_);
}

MutationEntry Device::RemoveFromConfig() {
  return MutationEntry::Remove(section_);
}

LeDevice Device::Le() {
  auto device_type = GetDeviceType();
  ASSERT(device_type);
  ASSERT(device_type == DeviceType::LE || device_type == DeviceType::DUAL);
  return LeDevice(config_, section_);
}

ClassicDevice Device::Classic() {
  auto device_type = GetDeviceType();
  ASSERT(device_type);
  ASSERT(device_type == DeviceType::BR_EDR || device_type == DeviceType::DUAL);
  return ClassicDevice(config_, section_);
}

}  // namespace storage
}  // namespace bluetooth