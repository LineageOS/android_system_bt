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

#include <string>

namespace bluetooth {
namespace storage {

class MutationEntry {
 public:
  static MutationEntry Set(std::string section_param, std::string property_param, std::string value_param) {
    return MutationEntry(true, std::move(section_param), std::move(property_param), std::move(value_param));
  }

  static MutationEntry Remove(std::string section_param) {
    return MutationEntry(false, std::move(section_param));
  }

  static MutationEntry Remove(std::string section_param, std::string property_param) {
    return MutationEntry(false, std::move(section_param), std::move(property_param));
  }

 private:
  friend class ConfigCache;

  MutationEntry(
      bool is_add_param, std::string section_param, std::string property_param = "", std::string value_param = "");

  bool is_add;
  std::string section;
  std::string property;
  std::string value;
};

}  // namespace storage
}  // namespace bluetooth