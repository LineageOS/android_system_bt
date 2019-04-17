/*
 * Copyright 2019 The Android Open Source Project
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

#include <cstdint>

namespace bluetooth {
namespace l2cap {

// Frame Check Sequence from the L2CAP spec.
class Fcs {
 public:
  static void Initialize(Fcs& s);

  static void AddByte(Fcs& s, uint8_t byte);

  static uint16_t GetChecksum(const Fcs& s);

 private:
  uint16_t crc;
};

}  // namespace l2cap
}  // namespace bluetooth
