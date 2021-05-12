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

// Original included files, if any
// NOTE: Since this is a mock file with mock definitions some number of
//       include files may not be required.  The include-what-you-use
//       still applies, but crafting proper inclusion is out of scope
//       for this effort.  This compilation unit may compile as-is, or
//       may need attention to prune the inclusion set.
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <algorithm>
#include "stack/crypto_toolbox/aes.h"
#include "stack/crypto_toolbox/crypto_toolbox.h"

// Mocked compile conditionals, if any
#ifndef UNUSED_ATTR
#define UNUSED_ATTR
#endif

namespace test {
namespace mock {
namespace stack_crypto_toolbox {

// Shared state between mocked functions and tests
// Name: h6
// Params: const Octet16& w, std::array<uint8_t, 4> keyid
// Returns: Octet16
struct h6 {
  Octet16 octet16;
  std::function<Octet16(const Octet16& w, std::array<uint8_t, 4> keyid)> body{
      [this](const Octet16& w, std::array<uint8_t, 4> keyid) {
        return octet16;
      }};
  Octet16 operator()(const Octet16& w, std::array<uint8_t, 4> keyid) {
    return body(w, keyid);
  };
};
extern struct h6 h6;
// Name: h7
// Params: const Octet16& salt, const Octet16& w
// Returns: Octet16
struct h7 {
  Octet16 octet16;
  std::function<Octet16(const Octet16& salt, const Octet16& w)> body{
      [this](const Octet16& salt, const Octet16& w) { return octet16; }};
  Octet16 operator()(const Octet16& salt, const Octet16& w) {
    return body(salt, w);
  };
};
extern struct h7 h7;
// Name: f4
// Params: const uint8_t* u, const uint8_t* v, const Octet16& x, uint8_t z
// Returns: Octet16
struct f4 {
  Octet16 octet16;
  std::function<Octet16(const uint8_t* u, const uint8_t* v, const Octet16& x,
                        uint8_t z)>
      body{[this](const uint8_t* u, const uint8_t* v, const Octet16& x,
                  uint8_t z) { return octet16; }};
  Octet16 operator()(const uint8_t* u, const uint8_t* v, const Octet16& x,
                     uint8_t z) {
    return body(u, v, x, z);
  };
};
extern struct f4 f4;
// Name: f5
// Params: const uint8_t* w, const Octet16& n1, const Octet16& n2, uint8_t* a1,
// uint8_t* a2, Octet16* mac_key, Octet16* ltk Returns: void
struct f5 {
  std::function<void(const uint8_t* w, const Octet16& n1, const Octet16& n2,
                     uint8_t* a1, uint8_t* a2, Octet16* mac_key, Octet16* ltk)>
      body{[](const uint8_t* w, const Octet16& n1, const Octet16& n2,
              uint8_t* a1, uint8_t* a2, Octet16* mac_key, Octet16* ltk) {}};
  void operator()(const uint8_t* w, const Octet16& n1, const Octet16& n2,
                  uint8_t* a1, uint8_t* a2, Octet16* mac_key, Octet16* ltk) {
    body(w, n1, n2, a1, a2, mac_key, ltk);
  };
};
extern struct f5 f5;
// Name: f6
// Params: const Octet16& w, const Octet16& n1, const Octet16& n2, const
// Octet16& r, uint8_t* iocap, uint8_t* a1, uint8_t* a2 Returns: Octet16
struct f6 {
  Octet16 octet16;
  std::function<Octet16(const Octet16& w, const Octet16& n1, const Octet16& n2,
                        const Octet16& r, uint8_t* iocap, uint8_t* a1,
                        uint8_t* a2)>
      body{[this](const Octet16& w, const Octet16& n1, const Octet16& n2,
                  const Octet16& r, uint8_t* iocap, uint8_t* a1,
                  uint8_t* a2) { return octet16; }};
  Octet16 operator()(const Octet16& w, const Octet16& n1, const Octet16& n2,
                     const Octet16& r, uint8_t* iocap, uint8_t* a1,
                     uint8_t* a2) {
    return body(w, n1, n2, r, iocap, a1, a2);
  };
};
extern struct f6 f6;
// Name: g2
// Params: const uint8_t* u, const uint8_t* v, const Octet16& x, const Octet16&
// y Returns: uint32_t
struct g2 {
  std::function<uint32_t(const uint8_t* u, const uint8_t* v, const Octet16& x,
                         const Octet16& y)>
      body{[](const uint8_t* u, const uint8_t* v, const Octet16& x,
              const Octet16& y) { return 0; }};
  uint32_t operator()(const uint8_t* u, const uint8_t* v, const Octet16& x,
                      const Octet16& y) {
    return body(u, v, x, y);
  };
};
extern struct g2 g2;
// Name: ltk_to_link_key
// Params: const Octet16& ltk, bool use_h7
// Returns: Octet16
struct ltk_to_link_key {
  Octet16 octet16;
  std::function<Octet16(const Octet16& ltk, bool use_h7)> body{
      [this](const Octet16& ltk, bool use_h7) { return octet16; }};
  Octet16 operator()(const Octet16& ltk, bool use_h7) {
    return body(ltk, use_h7);
  };
};
extern struct ltk_to_link_key ltk_to_link_key;
// Name: link_key_to_ltk
// Params: const Octet16& link_key, bool use_h7
// Returns: Octet16
struct link_key_to_ltk {
  Octet16 octet16;
  std::function<Octet16(const Octet16& link_key, bool use_h7)> body{
      [this](const Octet16& link_key, bool use_h7) { return octet16; }};
  Octet16 operator()(const Octet16& link_key, bool use_h7) {
    return body(link_key, use_h7);
  };
};
extern struct link_key_to_ltk link_key_to_ltk;

}  // namespace stack_crypto_toolbox
}  // namespace mock
}  // namespace test

// END mockcify generation
