/******************************************************************************
 *
 *  Copyright 2019 The Android Open Source Project
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at:
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 ******************************************************************************/

#pragma once

#include <stdint.h>
#include <optional>
#include <string>

#include "packet/bit_inserter.h"
#include "packet/iterator.h"

namespace bluetooth {
namespace packet {
namespace parser {
namespace test {

class Variable final {
 public:
  std::string data;

  Variable() = default;
  Variable(const Variable&) = default;
  Variable(const std::string& str);

  static void Serialize(const Variable& v, BitInserter& bi);

  static size_t Size(const Variable& v) {
    return v.size();
  }

  size_t size() const;

  static Iterator<true> Parse(std::vector<Variable>& vec, Iterator<true> it);
};

}  // namespace test
}  // namespace parser
}  // namespace packet
}  // namespace bluetooth
