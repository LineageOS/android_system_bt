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
      flags++;
      continue;
    }

    ParseBoolFlag(flag_pair, "INIT_logging_debug_enabled_for_all", &logging_debug_enabled_for_all);
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

  std::vector<std::string> logging_debug_enabled_tags;
  std::vector<std::string> logging_debug_disabled_tags;
  for (const auto& tag_setting : logging_debug_explicit_tag_settings) {
    if (tag_setting.second) {
      logging_debug_enabled_tags.emplace_back(tag_setting.first);
    } else {
      logging_debug_disabled_tags.emplace_back(tag_setting.first);
    }
  }

  rust::Vec<rust::String> rusted_flags = rust::Vec<rust::String>();
  while (flags != nullptr && *flags != nullptr) {
    rusted_flags.push_back(rust::String(*flags));
    flags++;
  }
  init_flags::load(std::move(rusted_flags));
}

void InitFlags::SetAll(bool value) {
  logging_debug_enabled_for_all = value;
  logging_debug_explicit_tag_settings.clear();
}

void InitFlags::SetAllForTesting() {
  init_flags::set_all_for_testing();
  SetAll(true);
}

}  // namespace common
}  // namespace bluetooth
