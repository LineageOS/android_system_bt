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

#include <limits>
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "storage/config_cache_helper.h"

namespace testing {

using bluetooth::storage::ConfigCache;
using bluetooth::storage::ConfigCacheHelper;

TEST(ConfigCacheHelperTest, set_get_bool_test) {
  ConfigCache config(100);
  // true
  ConfigCacheHelper(config).SetBool("A", "B", true);
  EXPECT_EQ(*config.GetProperty("A", "B"), "true");
  auto res = ConfigCacheHelper(config).GetBool("A", "B");
  EXPECT_TRUE(res);
  EXPECT_TRUE(*res);
  // false
  ConfigCacheHelper(config).SetBool("A", "B", false);
  EXPECT_EQ(*config.GetProperty("A", "B"), "false");
  res = ConfigCacheHelper(config).GetBool("A", "B");
  EXPECT_TRUE(res);
  EXPECT_FALSE(*res);
}

TEST(ConfigCacheHelperTest, set_get_uint64_test) {
  ConfigCache config(100);
  // small
  ConfigCacheHelper(config).SetUint64("A", "B", 123);
  EXPECT_EQ(*config.GetProperty("A", "B"), "123");
  EXPECT_EQ(*ConfigCacheHelper(config).GetUint64("A", "B"), uint64_t(123));
  // big
  uint64_t num = std::numeric_limits<int>::max();
  num = num * 10;
  ConfigCacheHelper(config).SetUint64("A", "B", num);
  EXPECT_EQ(*config.GetProperty("A", "B"), std::to_string(std::numeric_limits<int>::max()) + "0");
  EXPECT_EQ(*ConfigCacheHelper(config).GetUint64("A", "B"), num);
  // zero
  ConfigCacheHelper(config).SetUint64("A", "B", 0);
  EXPECT_EQ(*config.GetProperty("A", "B"), "0");
  EXPECT_EQ(*ConfigCacheHelper(config).GetUint64("A", "B"), 0);
}

TEST(ConfigCacheHelperTest, set_get_int_test) {
  ConfigCache config(100);
  // positive
  ConfigCacheHelper(config).SetInt("A", "B", 123);
  EXPECT_EQ(*config.GetProperty("A", "B"), "123");
  EXPECT_EQ(*ConfigCacheHelper(config).GetInt("A", "B"), int(123));
  // negative
  ConfigCacheHelper(config).SetInt("A", "B", -123);
  EXPECT_EQ(*config.GetProperty("A", "B"), "-123");
  EXPECT_EQ(*ConfigCacheHelper(config).GetInt("A", "B"), int(-123));
  // zero
  ConfigCacheHelper(config).SetInt("A", "B", 0);
  EXPECT_EQ(*config.GetProperty("A", "B"), "0");
  EXPECT_EQ(*ConfigCacheHelper(config).GetInt("A", "B"), int(0));
}

TEST(ConfigCacheHelperTest, set_get_bin_test) {
  ConfigCache config(100);
  // empty
  std::vector<uint8_t> data;
  ConfigCacheHelper(config).SetBin("A", "B", data);
  EXPECT_EQ(*config.GetProperty("A", "B"), "");
  EXPECT_THAT(*ConfigCacheHelper(config).GetBin("A", "B"), ContainerEq(data));
  // non-empty
  std::vector<uint8_t> data2 = {0xAB, 0x5D, 0x42};
  ConfigCacheHelper(config).SetBin("A", "B", data2);
  EXPECT_EQ(*config.GetProperty("A", "B"), "ab5d42");
  EXPECT_THAT(*ConfigCacheHelper(config).GetBin("A", "B"), ContainerEq(data2));
}

}  // namespace testing