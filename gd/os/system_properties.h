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

#include <optional>
#include <string>

namespace bluetooth {
namespace os {

// Get |property| keyed system property from supported platform, return std::nullopt if the property does not exist
// or if the platform does not support system property
std::optional<std::string> GetSystemProperty(const std::string& property);

// Set |property| keyed system property to |value|, return true if the set was successful and false if the set failed
// Replace existing value if property already exists
bool SetSystemProperty(const std::string& property, const std::string& value);

// Clear system properties for host only
void ClearSystemPropertiesForHost();

}  // namespace os
}  // namespace bluetooth