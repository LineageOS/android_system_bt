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
 *   Functions generated:8
 *
 *  mockcify.pl ver 0.2
 */

#include <cstdint>
#include <functional>
#include <map>
#include <string>

extern std::map<std::string, int> mock_function_count_map;

// Mock include file to share data between tests and mock
#include "test/mock/mock_stack_crypto_toolbox.h"

// Mocked compile conditionals, if any
#ifndef UNUSED_ATTR
#define UNUSED_ATTR
#endif

// Mocked internal structures, if any

namespace test {
namespace mock {
namespace stack_crypto_toolbox {

// Function state capture and return values, if needed
struct h6 h6;
struct h7 h7;
struct f4 f4;
struct f5 f5;
struct f6 f6;
struct g2 g2;
struct ltk_to_link_key ltk_to_link_key;
struct link_key_to_ltk link_key_to_ltk;

}  // namespace stack_crypto_toolbox
}  // namespace mock
}  // namespace test

// Mocked functions, if any
Octet16 h6(const Octet16& w, std::array<uint8_t, 4> keyid) {
  mock_function_count_map[__func__]++;
  return test::mock::stack_crypto_toolbox::h6(w, keyid);
}
Octet16 h7(const Octet16& salt, const Octet16& w) {
  mock_function_count_map[__func__]++;
  return test::mock::stack_crypto_toolbox::h7(salt, w);
}
Octet16 f4(const uint8_t* u, const uint8_t* v, const Octet16& x, uint8_t z) {
  mock_function_count_map[__func__]++;
  return test::mock::stack_crypto_toolbox::f4(u, v, x, z);
}
void f5(const uint8_t* w, const Octet16& n1, const Octet16& n2, uint8_t* a1,
        uint8_t* a2, Octet16* mac_key, Octet16* ltk) {
  mock_function_count_map[__func__]++;
  test::mock::stack_crypto_toolbox::f5(w, n1, n2, a1, a2, mac_key, ltk);
}
Octet16 f6(const Octet16& w, const Octet16& n1, const Octet16& n2,
           const Octet16& r, uint8_t* iocap, uint8_t* a1, uint8_t* a2) {
  mock_function_count_map[__func__]++;
  return test::mock::stack_crypto_toolbox::f6(w, n1, n2, r, iocap, a1, a2);
}
uint32_t g2(const uint8_t* u, const uint8_t* v, const Octet16& x,
            const Octet16& y) {
  mock_function_count_map[__func__]++;
  return test::mock::stack_crypto_toolbox::g2(u, v, x, y);
}
Octet16 ltk_to_link_key(const Octet16& ltk, bool use_h7) {
  mock_function_count_map[__func__]++;
  return test::mock::stack_crypto_toolbox::ltk_to_link_key(ltk, use_h7);
}
Octet16 link_key_to_ltk(const Octet16& link_key, bool use_h7) {
  mock_function_count_map[__func__]++;
  return test::mock::stack_crypto_toolbox::link_key_to_ltk(link_key, use_h7);
}

// END mockcify generation
