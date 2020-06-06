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

#include "common/strings.h"

#include <charconv>
#include <functional>
#include <iomanip>
#include <sstream>
#include <system_error>

#include "os/log.h"

namespace {

struct IsSpace : std::unary_function<std::string::value_type, bool> {
  bool operator()(std::string::value_type v) {
    return isspace(static_cast<int>(v));
  }
};

struct IsHexDigit : std::unary_function<std::string::value_type, bool> {
  bool operator()(std::string::value_type v) {
    return isxdigit(static_cast<int>(v));
  }
};

}  // namespace

namespace bluetooth {
namespace common {

std::string ToHexString(const std::vector<uint8_t>& value) {
  std::stringstream ss;
  for (const auto& byte : value) {
    ss << std::hex << std::setw(2) << std::setfill('0') << +byte;
  }
  return ss.str();
}

std::optional<std::vector<uint8_t>> FromHexString(const std::string& str) {
  if (str.size() % 2 != 0) {
    LOG_DEBUG("str size is not divisible by 2, size is %zu", str.size());
    return std::nullopt;
  }
  if (std::find_if_not(str.begin(), str.end(), IsHexDigit{}) != str.end()) {
    LOG_DEBUG("value contains none hex digit");
    return std::nullopt;
  }
  std::vector<uint8_t> value;
  value.reserve(str.size() / 2);
  for (size_t i = 0; i < str.size(); i += 2) {
    uint8_t v = 0;
    auto ret = std::from_chars(str.c_str() + i, str.c_str() + i + 2, v, 16);
    if (std::make_error_code(ret.ec)) {
      LOG_DEBUG("failed to parse hex char at index %zu", i);
      return std::nullopt;
    }
    value.push_back(v);
  }
  return value;
}

std::string StringTrim(std::string str) {
  str.erase(str.begin(), std::find_if_not(str.begin(), str.end(), IsSpace{}));
  str.erase(std::find_if_not(str.rbegin(), str.rend(), IsSpace{}).base(), str.end());
  return str;
}

std::vector<std::string> StringSplit(const std::string& str, const std::string& delim, size_t max_token) {
  ASSERT_LOG(!delim.empty(), "delim cannot be empty");
  std::vector<std::string> tokens;
  // Use std::string::find and std::string::substr to avoid copying str into a stringstream
  std::string::size_type starting_index = 0;
  auto index_of_delim = str.find(delim);
  while ((max_token == 0 || tokens.size() < (max_token - 1)) && index_of_delim != std::string::npos) {
    tokens.push_back(str.substr(starting_index, index_of_delim - starting_index));
    starting_index = index_of_delim + delim.size();
    index_of_delim = str.find(delim, starting_index);
  }
  // Append last item to the vector if there are anything left
  if (starting_index < (str.size() + 1)) {
    tokens.push_back(str.substr(starting_index));
  }
  return tokens;
}

}  // namespace common
}  // namespace bluetooth