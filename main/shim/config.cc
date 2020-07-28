/*
 * Copyright 2019 The Android Open Source Project
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

#define LOG_TAG "bt_shim_storage"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <memory>

#include "gd/os/log.h"
#include "gd/storage/config_cache_helper.h"
#include "gd/storage/storage_module.h"
#include "main/shim/config.h"
#include "main/shim/entry.h"

using ::bluetooth::shim::GetStorage;
using ::bluetooth::storage::ConfigCacheHelper;

namespace bluetooth {
namespace shim {

bool BtifConfigInterface::HasSection(const std::string& section) {
  return GetStorage()->GetConfigCache()->HasSection(section);
}

bool BtifConfigInterface::HasProperty(const std::string& section,
                                      const std::string& property) {
  return GetStorage()->GetConfigCache()->HasProperty(section, property);
}

bool BtifConfigInterface::GetInt(const std::string& section,
                                 const std::string& property, int* value) {
  ASSERT(value != nullptr);
  auto ret = ConfigCacheHelper::FromConfigCache(*GetStorage()->GetConfigCache())
                 .GetInt(section, property);
  if (ret) {
    *value = *ret;
  }
  return ret.has_value();
}

bool BtifConfigInterface::SetInt(const std::string& section,
                                 const std::string& property, int value) {
  ConfigCacheHelper::FromConfigCache(*GetStorage()->GetConfigCache())
      .SetInt(section, property, value);
  return true;
}

bool BtifConfigInterface::GetUint64(const std::string& section,
                                    const std::string& property,
                                    uint64_t* value) {
  ASSERT(value != nullptr);
  auto ret = ConfigCacheHelper::FromConfigCache(*GetStorage()->GetConfigCache())
                 .GetUint64(section, property);
  if (ret) {
    *value = *ret;
  }
  return ret.has_value();
}

bool BtifConfigInterface::SetUint64(const std::string& section,
                                    const std::string& property,
                                    uint64_t value) {
  ConfigCacheHelper::FromConfigCache(*GetStorage()->GetConfigCache())
      .SetUint64(section, property, value);
  return true;
}

bool BtifConfigInterface::GetStr(const std::string& section,
                                 const std::string& property, char* value,
                                 int* size_bytes) {
  ASSERT(value != nullptr);
  ASSERT(size_bytes != nullptr);
  auto str = GetStorage()->GetConfigCache()->GetProperty(section, property);
  if (!str) {
    return false;
  }
  if (*size_bytes == 0) {
    return true;
  }
  // std::string::copy does not null-terminate resultant string by default
  // avoided using strlcpy to prevent extra dependency
  *size_bytes = str->copy(value, (*size_bytes - 1));
  value[*size_bytes] = '\0';
  *size_bytes += 1;
  return true;
}

std::optional<std::string> BtifConfigInterface::GetStr(
    const std::string& section, const std::string& property) {
  return GetStorage()->GetConfigCache()->GetProperty(section, property);
}

bool BtifConfigInterface::SetStr(const std::string& section,
                                 const std::string& property,
                                 const std::string& value) {
  GetStorage()->GetConfigCache()->SetProperty(section, property, value);
  return true;
}

// TODO: implement encrypted read
bool BtifConfigInterface::GetBin(const std::string& section,
                                 const std::string& property, uint8_t* value,
                                 size_t* length) {
  ASSERT(value != nullptr);
  ASSERT(length != nullptr);
  auto value_vec =
      ConfigCacheHelper::FromConfigCache(*GetStorage()->GetConfigCache())
          .GetBin(section, property);
  if (!value_vec) {
    return false;
  }
  *length = std::min(value_vec->size(), *length);
  std::memcpy(value, value_vec->data(), *length);
  return true;
}
size_t BtifConfigInterface::GetBinLength(const std::string& section,
                                         const std::string& property) {
  auto value_vec =
      ConfigCacheHelper::FromConfigCache(*GetStorage()->GetConfigCache())
          .GetBin(section, property);
  if (!value_vec) {
    return 0;
  }
  return value_vec->size();
}
bool BtifConfigInterface::SetBin(const std::string& section,
                                 const std::string& property,
                                 const uint8_t* value, size_t length) {
  ASSERT(value != nullptr);
  std::vector<uint8_t> value_vec(value, value + length);
  ConfigCacheHelper::FromConfigCache(*GetStorage()->GetConfigCache())
      .SetBin(section, property, value_vec);
  return true;
}
bool BtifConfigInterface::RemoveProperty(const std::string& section,
                                         const std::string& property) {
  return GetStorage()->GetConfigCache()->RemoveProperty(section, property);
}

std::vector<std::string> BtifConfigInterface::GetPersistentDevices() {
  return GetStorage()->GetConfigCache()->GetPersistentSections();
}

void BtifConfigInterface::Save() { GetStorage()->SaveDelayed(); }

void BtifConfigInterface::Flush() { GetStorage()->SaveImmediately(); }

void BtifConfigInterface::Clear() { GetStorage()->GetConfigCache()->Clear(); }

}  // namespace shim
}  // namespace bluetooth
