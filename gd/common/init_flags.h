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

#include <string>
#include <unordered_map>

namespace bluetooth {
namespace common {

class InitFlags final {
 public:
  static void Load(const char** flags);

  static bool GdAdvertisingEnabled() {
    return gd_advertising_enabled;
  }

  static bool GdSecurityEnabled() {
    return gd_security_enabled;
  }

  static bool GdAclEnabled() {
    return gd_acl_enabled;
  }

  static bool GdHciEnabled() {
    return gd_hci_enabled;
  }

  static bool GdControllerEnabled() {
    return gd_controller_enabled;
  }

  static bool GdL2capEnabled() {
    return gd_l2cap_enabled;
  }

  static bool GdCoreEnabled() {
    return gd_core_enabled;
  }

  static bool GattRobustCachingEnabled() {
    return gatt_robust_caching_enabled;
  }

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

  static bool BtaaHciLogEnabled() {
    return btaa_hci_log_enabled;
  }

  static void SetAllForTesting();

 private:
  static void SetAll(bool value);
  static bool gd_advertising_enabled;
  static bool gd_security_enabled;
  static bool gd_acl_enabled;
  static bool gd_hci_enabled;
  static bool gd_controller_enabled;
  static bool gd_l2cap_enabled;
  static bool gd_core_enabled;
  static bool gatt_robust_caching_enabled;
  static bool logging_debug_enabled_for_all;
  // save both log allow list and block list in the map to save hashing time
  static std::unordered_map<std::string, bool> logging_debug_explicit_tag_settings;
  static bool btaa_hci_log_enabled;
};

}  // namespace common
}  // namespace bluetooth
