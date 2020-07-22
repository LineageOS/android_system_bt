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

#include "common/byte_array.h"

#include <gtest/gtest.h>

#include "os/log.h"

using bluetooth::common::ByteArray;

static const char* test_bytes = "4c68384139f574d836bcf34e9dfb01bf\0";
static uint8_t test_data[16] = {
    0x4c, 0x68, 0x38, 0x41, 0x39, 0xf5, 0x74, 0xd8, 0x36, 0xbc, 0xf3, 0x4e, 0x9d, 0xfb, 0x01, 0xbf};
static uint8_t data[16] = {
    0x4c, 0x87, 0x49, 0xe1, 0x2e, 0x55, 0x0f, 0x7f, 0x60, 0x8b, 0x4f, 0x96, 0xd7, 0xc5, 0xbc, 0x2a};

TEST(ByteArrayTest, test_constructor_array) {
  ByteArray<16> byte_array(data);

  for (int i = 0; i < ByteArray<16>::kLength; i++) {
    ASSERT_EQ(data[i], byte_array.bytes[i]);
  }
}

TEST(ByteArrayTest, test_from_str) {
  auto byte_array = ByteArray<16>::FromString(test_bytes);
  ASSERT_TRUE(byte_array);

  for (int i = 0; i < ByteArray<16>::kLength; i++) {
    ASSERT_EQ(test_data[i], byte_array->bytes[i]);
  }
}

TEST(ByteArrayTest, test_to_str) {
  ByteArray<16> byte_array = {
      {0x4C, 0x68, 0x38, 0x41, 0x39, 0xf5, 0x74, 0xd8, 0x36, 0xbc, 0xf3, 0x4e, 0x9d, 0xfb, 0x01, 0xbf}};
  std::string str = byte_array.ToString();
  ASSERT_STREQ(str.c_str(), test_bytes);
}