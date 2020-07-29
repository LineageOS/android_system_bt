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

#include "storage/adapter_config.h"

namespace bluetooth {
namespace storage {

AdapterConfig::AdapterConfig(ConfigCache* config, ConfigCache* memory_only_config, std::string section)
    : config_(config), memory_only_config_(memory_only_config), section_(std::move(section)) {}

}  // namespace storage
}  // namespace bluetooth