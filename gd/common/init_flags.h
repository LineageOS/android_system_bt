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

#pragma once

#include <stdexcept>
#include <string>
#include <unordered_map>

#include "src/init_flags.rs.h"

namespace bluetooth {
namespace common {

class InitFlags final {
 public:
  static void Load(const char** flags);

  inline static bool IsDebugLoggingEnabledForTag(const std::string& tag) {
    auto tag_setting = logging_debug_explicit_tag_settings.find(tag);
    if (tag_setting != logging_debug_explicit_tag_settings.end()) {
      return tag_setting->second;
    }
    return logging_debug_enabled_for_all;
  }

  inline static bool IsDebugLoggingEnabledForAll() {
    return logging_debug_enabled_for_all;
  }

  static void SetAllForTesting();

 private:
  static void SetAll(bool value);
  static bool logging_debug_enabled_for_all;
  // save both log allow list and block list in the map to save hashing time
  static std::unordered_map<std::string, bool> logging_debug_explicit_tag_settings;
};

}  // namespace common
}  // namespace bluetooth
