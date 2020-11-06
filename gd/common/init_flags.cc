/******************************************************************************
 *
 *  Copyright 2019 The Android Open Source Project
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at:
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 ******************************************************************************/

#include "init_flags.h"

#include <string>

#include "common/strings.h"
#include "os/log.h"

namespace bluetooth {
namespace common {

bool InitFlags::btaa_hci_log_enabled = false;
bool InitFlags::gd_core_enabled = false;
bool InitFlags::gd_advertising_enabled = false;
bool InitFlags::gd_security_enabled = false;
bool InitFlags::gd_acl_enabled = false;
bool InitFlags::gd_l2cap_enabled = false;
bool InitFlags::gd_hci_enabled = false;
bool InitFlags::gd_controller_enabled = false;
bool InitFlags::gatt_robust_caching_enabled = false;
bool InitFlags::logging_debug_enabled_for_all = false;
std::unordered_map<std::string, bool> InitFlags::logging_debug_explicit_tag_settings = {};

bool ParseBoolFlag(const std::vector<std::string>& flag_pair, const std::string& flag, bool* variable) {
  if (flag != flag_pair[0]) {
    return false;
  }
  auto value = BoolFromString(flag_pair[1]);
  if (!value) {
    return false;
  }
  *variable = *value;
  return true;
}

void InitFlags::Load(const char** flags) {
  SetAll(false);
  while (flags != nullptr && *flags != nullptr) {
    std::string flag_element = *flags;
    auto flag_pair = StringSplit(flag_element, "=", 2);
    if (flag_pair.size() != 2) {
      LOG_ERROR("Bad flag %s, must be in <FLAG>=<VALUE> format", flag_element.c_str());
      flags++;
      continue;
    }

    ParseBoolFlag(flag_pair, "INIT_gd_core", &gd_core_enabled);
    ParseBoolFlag(flag_pair, "INIT_gd_advertising", &gd_advertising_enabled);
    ParseBoolFlag(flag_pair, "INIT_gd_security", &gd_security_enabled);
    ParseBoolFlag(flag_pair, "INIT_gd_acl", &gd_acl_enabled);
    ParseBoolFlag(flag_pair, "INIT_gd_l2cap", &gd_l2cap_enabled);
    ParseBoolFlag(flag_pair, "INIT_gd_hci", &gd_hci_enabled);
    ParseBoolFlag(flag_pair, "INIT_gd_controller", &gd_controller_enabled);
    ParseBoolFlag(flag_pair, "INIT_gatt_robust_caching", &gatt_robust_caching_enabled);
    ParseBoolFlag(flag_pair, "INIT_logging_debug_enabled_for_all", &logging_debug_enabled_for_all);
    ParseBoolFlag(flag_pair, "INIT_btaa_hci", &btaa_hci_log_enabled);
    if ("INIT_logging_debug_enabled_for_tags" == flag_pair[0]) {
      auto tags = StringSplit(flag_pair[1], ",");
      for (const auto& tag : tags) {
        auto setting = logging_debug_explicit_tag_settings.find(tag);
        if (setting == logging_debug_explicit_tag_settings.end()) {
          logging_debug_explicit_tag_settings.insert_or_assign(tag, true);
        }
      }
    }
    if ("INIT_logging_debug_disabled_for_tags" == flag_pair[0]) {
      auto tags = StringSplit(flag_pair[1], ",");
      for (const auto& tag : tags) {
        logging_debug_explicit_tag_settings.insert_or_assign(tag, false);
      }
    }
    flags++;
  }

  if (gd_core_enabled && !gd_security_enabled) {
    gd_security_enabled = true;
  }
  if (gd_security_enabled && !gd_acl_enabled) {
    gd_acl_enabled = true;
  }
  if (gd_acl_enabled && !gd_controller_enabled) {
    gd_controller_enabled = true;
  }
  if (gd_l2cap_enabled) {
    gd_acl_enabled = false;
    gd_hci_enabled = true;
  }
  if (gd_controller_enabled && !gd_hci_enabled) {
    gd_hci_enabled = true;
  }

  std::vector<std::string> logging_debug_enabled_tags;
  std::vector<std::string> logging_debug_disabled_tags;
  for (const auto& tag_setting : logging_debug_explicit_tag_settings) {
    if (tag_setting.second) {
      logging_debug_enabled_tags.emplace_back(tag_setting.first);
    } else {
      logging_debug_disabled_tags.emplace_back(tag_setting.first);
    }
  }

  LOG_INFO(
      "Flags loaded: gd_advertising_enabled=%s, gd_security_enabled=%s, gd_acl_enabled=%s, gd_hci_enabled=%s, "
      "gd_controller_enabled=%s, gd_core_enabled=%s, logging_debug_enabled_for_all=%s, "
      "logging_debug_enabled_tags=%s, logging_debug_disabled_tags=%s, btaa_hci_log_enabled=%s",
      ToString(gd_advertising_enabled).c_str(),
      ToString(gd_security_enabled).c_str(),
      ToString(gd_acl_enabled).c_str(),
      ToString(gd_hci_enabled).c_str(),
      ToString(gd_controller_enabled).c_str(),
      ToString(gd_core_enabled).c_str(),
      ToString(logging_debug_enabled_for_all).c_str(),
      StringJoin(logging_debug_enabled_tags, ",").c_str(),
      StringJoin(logging_debug_disabled_tags, ",").c_str(),
      ToString(btaa_hci_log_enabled).c_str());
}

void InitFlags::SetAll(bool value) {
  gd_core_enabled = value;
  gd_advertising_enabled = value;
  gd_acl_enabled = value;
  gd_security_enabled = value;
  gd_controller_enabled = value;
  gd_hci_enabled = value;
  gatt_robust_caching_enabled = value;
  logging_debug_enabled_for_all = value;
  logging_debug_explicit_tag_settings.clear();
}

void InitFlags::SetAllForTesting() {
  SetAll(true);
}

}  // namespace common
}  // namespace bluetooth
