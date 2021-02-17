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
 *   Functions generated:1
 */

#include <map>
#include <string>

extern std::map<std::string, int> mock_function_count_map;

#include "stack/crypto_toolbox/aes.h"
#include "stack/crypto_toolbox/crypto_toolbox.h"

#ifndef UNUSED_ATTR
#define UNUSED_ATTR
#endif

namespace crypto_toolbox {
Octet16 aes_cmac(const Octet16& key, const uint8_t* input, uint16_t length) {
  mock_function_count_map[__func__]++;
  Octet16 octet16;
  return octet16;
}
}  // namespace crypto_toolbox
