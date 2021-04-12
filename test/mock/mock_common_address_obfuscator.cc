/*
 * Copyright 2021 The Android Open Source Project
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

/*
 * Generated mock file from original source file
 *   Functions generated:4
 */

#include <map>
#include <string>

extern std::map<std::string, int> mock_function_count_map;

#include <base/logging.h>
#include <openssl/hmac.h>
#include <algorithm>
#include "bt_trace.h"
#include "common/address_obfuscator.h"

#ifndef UNUSED_ATTR
#define UNUSED_ATTR
#endif

namespace bluetooth {
namespace common {

bool AddressObfuscator::IsInitialized() {
  mock_function_count_map[__func__]++;
  return false;
}
bool AddressObfuscator::IsSaltValid(const Octet32& salt_256bit) {
  mock_function_count_map[__func__]++;
  return false;
}
std::string AddressObfuscator::Obfuscate(const RawAddress& address) {
  mock_function_count_map[__func__]++;
  return 0;
}
void AddressObfuscator::Initialize(const Octet32& salt_256bit) {
  mock_function_count_map[__func__]++;
  salt_256bit_ = salt_256bit;
}

}  // namespace common
}  // namespace bluetooth
