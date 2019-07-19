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

#include <array>

#include "packet/bit_inserter.h"
#include "packet/iterator.h"

namespace bluetooth {
namespace packet {
// Checks a custom type has all the necessary static functions with the correct signatures.
template <typename T>
class CustomTypeChecker {
 public:
  template <class C, void (*)(const C&, BitInserter&)>
  struct SerializeChecker {};

  template <class C, size_t (*)(const C&)>
  struct SizeChecker {};

  template <class C, Iterator<true> (*)(std::vector<C>& vec, Iterator<true> it)>
  struct ParseChecker {};

  template <class C, Iterator<false> (*)(std::vector<C>& vec, Iterator<false> it)>
  struct ParseCheckerBigEndian {};

  template <class C>
  static int Test(SerializeChecker<C, &C::Serialize>*, SizeChecker<C, &C::Size>*, ParseChecker<C, &C::Parse>*);

  template <class C>
  static int Test(SerializeChecker<C, &C::Serialize>*, SizeChecker<C, &C::Size>*, ParseCheckerBigEndian<C, &C::Parse>*);

  template <class C>
  static char Test(...);

  static constexpr bool value = (sizeof(Test<T>(0, 0, 0)) == sizeof(int));
};
}  // namespace packet
}  // namespace bluetooth
