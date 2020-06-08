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

#include "storage/mutation_entry.h"

#include "os/log.h"

namespace bluetooth {
namespace storage {

MutationEntry::MutationEntry(
    bool is_add_param, std::string section_param, std::string property_param, std::string value_param)
    : is_add(is_add_param),
      section(std::move(section_param)),
      property(std::move(property_param)),
      value(std::move(value_param)) {
  ASSERT_LOG(!section.empty(), "section cannot be empty any time");
  if (is_add) {
    ASSERT_LOG(!property.empty(), "property cannot be empty when is_add is true");
    ASSERT_LOG(!value.empty(), "value cannot be empty when is_add is true");
  }
}

}  // namespace storage
}  // namespace bluetooth