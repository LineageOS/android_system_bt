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

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <memory>

namespace testing {

using bluetooth::common::FromHexString;
using bluetooth::common::StringSplit;
using bluetooth::common::StringTrim;
using bluetooth::common::ToHexString;

TEST(StringsTest, trim_string_test) {
  EXPECT_EQ(StringTrim("  aa bb"), "aa bb");
  EXPECT_EQ(StringTrim("aa bb "), "aa bb");
  EXPECT_EQ(StringTrim("  aa bb "), "aa bb");
  EXPECT_EQ(StringTrim("  aa bb \n"), "aa bb");
  EXPECT_EQ(StringTrim("  \raa bb\t \n"), "aa bb");
}

TEST(StringsTest, split_string_test) {
  EXPECT_THAT(StringSplit("", ","), ElementsAre(""));
  EXPECT_THAT(StringSplit("1,2,3", ","), ElementsAre("1", "2", "3"));
  EXPECT_THAT(StringSplit("1,2,3", "!"), ElementsAre("1,2,3"));
  EXPECT_THAT(StringSplit("1,2,3", ",", 2), ElementsAre("1", "2,3"));
  EXPECT_THAT(StringSplit("a,b,", ","), ElementsAre("a", "b", ""));
  EXPECT_THAT(StringSplit("ab,", ",", 2), ElementsAre("ab", ""));
  EXPECT_THAT(StringSplit("ab,,", ",", 2), ElementsAre("ab", ","));
  EXPECT_THAT(StringSplit("ab,,", ",", 1), ElementsAre("ab,,"));
  EXPECT_THAT(StringSplit("1,,2,,3", ",,"), ElementsAre("1", "2", "3"));
  EXPECT_THAT(StringSplit("1,,2,,3,,", ",,"), ElementsAre("1", "2", "3", ""));
  EXPECT_THAT(StringSplit("1,,2,,3,,", ",,", 2), ElementsAre("1", "2,,3,,"));
  EXPECT_THAT(StringSplit("1", ",,", 2), ElementsAre("1"));
  EXPECT_DEATH({ StringSplit("1,2,3", ""); }, "delim cannot be empty");
}

TEST(StringsTest, to_hex_string_test) {
  // normal
  EXPECT_THAT(ToHexString({0x12, 0x34, 0x56, 0xab}), Eq("123456ab"));
  // empty
  EXPECT_THAT(ToHexString({}), Eq(""));
  // unary
  EXPECT_THAT(ToHexString({0x12}), Eq("12"));
  // half
  EXPECT_THAT(ToHexString({0x6, 0x5, 0x56, 0xb}), Eq("0605560b"));
}

TEST(StringsTest, from_hex_string_test) {
  // normal
  EXPECT_THAT(FromHexString("aabbccdd1122"), Optional(ElementsAre(0xaa, 0xbb, 0xcc, 0xdd, 0x11, 0x22)));
  // empty
  EXPECT_THAT(FromHexString(""), Optional(IsEmpty()));
  // unary
  EXPECT_THAT(FromHexString("aa"), Optional(ElementsAre(0xaa)));
  // half
  EXPECT_THAT(FromHexString("0605560b"), Optional(ElementsAre(0x6, 0x5, 0x56, 0xb)));
  // upper case letter
  EXPECT_THAT(FromHexString("AABBCC"), Optional(ElementsAre(0xaa, 0xbb, 0xcc)));
  // upper and lower case letter mixed
  EXPECT_THAT(FromHexString("aAbbCC"), Optional(ElementsAre(0xaa, 0xbb, 0xcc)));
  // Error: odd length
  EXPECT_FALSE(FromHexString("0605560"));
  // Error: non hex char
  EXPECT_FALSE(FromHexString("060u560b"));
}

}  // namespace testing