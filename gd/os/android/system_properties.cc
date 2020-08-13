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

#include "os/system_properties.h"

#include <cutils/properties.h>

#include <array>

#include "os/log.h"

namespace bluetooth {
namespace os {

std::optional<std::string> GetSystemProperty(const std::string& property) {
  std::array<char, PROPERTY_VALUE_MAX> value_array{0};
  auto value_len = property_get(property.c_str(), value_array.data(), nullptr);
  if (value_len <= 0) {
    return std::nullopt;
  }
  return std::string(value_array.data(), value_len);
}

bool SetSystemProperty(const std::string& property, const std::string& value) {
  if (value.size() >= PROPERTY_VALUE_MAX) {
    LOG_ERROR("Property value's maximum size is %d, but %zu chars were given", PROPERTY_VALUE_MAX - 1, value.size());
    return false;
  }
  auto ret = property_set(property.c_str(), value.c_str());
  if (ret != 0) {
    LOG_ERROR("Set property %s failed with error code %d", property.c_str(), ret);
    return false;
  }
  return true;
}

}  // namespace os
}  // namespace bluetooth