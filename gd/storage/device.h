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
#include <limits>
#include <optional>
#include <string>
#include <type_traits>
#include <utility>

#include "hci/address.h"
#include "hci/address_with_type.h"
#include "hci/class_of_device.h"
#include "hci/enum_helper.h"
#include "storage/config_cache.h"
#include "storage/config_cache_helper.h"
#include "storage/mutation_entry.h"
#include "storage/serializable.h"

namespace bluetooth {
namespace storage {

class LeDevice;
class ClassicDevice;

// Make sure our macro is used
#ifdef GENERATE_PROPERTY_GETTER_SETTER_REMOVER
static_assert(false, "GENERATE_PROPERTY_GETTER_SETTER_REMOVER() must be uniquely defined once in this file");
#endif

#define GENERATE_PROPERTY_GETTER_SETTER_REMOVER(NAME, RETURN_TYPE, PROPERTY_KEY) \
 public:                                                                         \
  std::optional<RETURN_TYPE> Get##NAME() const {                                 \
    return ConfigCacheHelper(*config_).Get<RETURN_TYPE>(section_, PROPERTY_KEY); \
  }                                                                              \
  MutationEntry Set##NAME(const RETURN_TYPE& value) {                            \
    return MutationEntry::Set<RETURN_TYPE>(section_, PROPERTY_KEY, value);       \
  }                                                                              \
  MutationEntry Remove##NAME() {                                                 \
    return MutationEntry::Remove(section_, PROPERTY_KEY);                        \
  }

// A think wrapper of device in ConfigCache, allowing easy access to various predefined properties of a Bluetooth device
//
// Device, LeDevice, and Classic device objects are fully copyable, comparable hashable
//
// A newly created device does not have any DeviceType information and user can only read or write the values in this
// common Device abstraction layer.
//
// As soon as a user determines the type of device, they should call SetDeviceType() to assign device to a type
// After that, Classic() or Le() will return interfaces that allows access to deeper layer properties
class Device {
 public:
  enum ConfigKeyAddressType { LEGACY_KEY_ADDRESS, CLASSIC_ADDRESS, LE_IDENTITY_ADDRESS, LE_LEGACY_PSEUDO_ADDRESS };

  Device(ConfigCache* config, hci::Address key_address, ConfigKeyAddressType key_address_type);
  Device(ConfigCache* config, std::string section);

  // for move
  Device(Device&& other) noexcept = default;
  Device& operator=(Device&& other) noexcept = default;

  // for copy
  Device(const Device& other) noexcept = default;
  Device& operator=(const Device& other) noexcept = default;

  // operators
  bool operator==(const Device& other) const {
    return config_ == other.config_ && section_ == other.section_;
  }
  bool operator!=(const Device& other) const {
    return !(*this == other);
  }
  bool operator<(const Device& other) const {
    return config_ < other.config_ && section_ < other.section_;
  }
  bool operator>(const Device& rhs) const {
    return (rhs < *this);
  }
  bool operator<=(const Device& rhs) const {
    return !(*this > rhs);
  }
  bool operator>=(const Device& rhs) const {
    return !(*this < rhs);
  }

  // A newly created Device object may not be backed by any properties in the ConfigCache, where Exists() will return
  // false. As soon as a property value is added to the device. Exists() will become true.
  bool Exists();

  // Remove device and all its properties from config
  MutationEntry RemoveFromConfig();

  // Only works when GetDeviceType() returns BR_EDR or DUAL, will crash otherwise
  // For first time use, please SetDeviceType() to the right value
  ClassicDevice Classic();

  // Only works when GetDeviceType() returns LE or DUAL, will crash otherwise
  // For first time use, please SetDeviceType() to the right value
  LeDevice Le();

  // For logging purpose only, you can't get a Device object from parsing a std::string
  std::string ToLogString();

 private:
  ConfigCache* config_;
  std::string section_;
  friend std::hash<Device>;

 public:
  // Macro generate getters, setters and removers
  GENERATE_PROPERTY_GETTER_SETTER_REMOVER(Name, std::string, "Name");
  GENERATE_PROPERTY_GETTER_SETTER_REMOVER(ClassOfDevice, hci::ClassOfDevice, "DevClass");
  GENERATE_PROPERTY_GETTER_SETTER_REMOVER(DeviceType, hci::DeviceType, "DevType");
  GENERATE_PROPERTY_GETTER_SETTER_REMOVER(ManufacturerCode, uint16_t, "Manufacturer");
  GENERATE_PROPERTY_GETTER_SETTER_REMOVER(LmpVersion, uint8_t, "LmpVer");
  GENERATE_PROPERTY_GETTER_SETTER_REMOVER(LmpSubVersion, uint16_t, "LmpSubVer");
  GENERATE_PROPERTY_GETTER_SETTER_REMOVER(MetricsId, int, "MetricsId");
  GENERATE_PROPERTY_GETTER_SETTER_REMOVER(PinLength, int, "PinLength");
  // unix timestamp in seconds from epoch
  GENERATE_PROPERTY_GETTER_SETTER_REMOVER(CreationUnixTimestamp, int, "DevClass");
};

}  // namespace storage
}  // namespace bluetooth

namespace std {
template <>
struct hash<bluetooth::storage::Device> {
  std::size_t operator()(const bluetooth::storage::Device& val) const noexcept {
    std::size_t pointer_hash = std::hash<bluetooth::storage::ConfigCache*>{}(val.config_);
    std::size_t addr_hash = std::hash<std::string>{}(val.section_);
    return addr_hash ^ (pointer_hash << 1);
  }
};
}  // namespace std