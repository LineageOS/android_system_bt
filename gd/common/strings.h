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
#include <vector>

namespace bluetooth {
namespace common {

// Convert value into a hex decimal formatted string in lower case
std::string ToHexString(const std::vector<uint8_t>& value);

// Parse |str| into a std::vector<uint8_t>, |str| must contains only hex decimal
std::optional<std::vector<uint8_t>> FromHexString(const std::string& str);

// Remove whitespace from both ends of the |str|, returning a copy
std::string StringTrim(std::string str);

// Split |str| into at most |max_token| tokens delimited by |delim|, unlimited tokens when |max_token| is 0
std::vector<std::string> StringSplit(const std::string& str, const std::string& delim, size_t max_token = 0);

}  // namespace common
}  // namespace bluetooth