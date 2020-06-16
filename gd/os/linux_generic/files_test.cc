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

#include "os/files.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <filesystem>

namespace testing {

using bluetooth::os::ReadSmallFile;
using bluetooth::os::WriteToFile;

TEST(FilesTest, write_read_loopback_test) {
  auto temp_dir = std::filesystem::temp_directory_path();
  auto temp_file = temp_dir / "file_1.txt";
  std::string text = "Hello world!\n";
  ASSERT_TRUE(WriteToFile(temp_file.string(), text));
  EXPECT_THAT(ReadSmallFile(temp_file.string()), Optional(StrEq(text)));
  EXPECT_TRUE(std::filesystem::remove(temp_file));
}

TEST(FilesTest, overwrite_test) {
  auto temp_dir = std::filesystem::temp_directory_path();
  auto temp_file = temp_dir / "file_1.txt";
  std::string text = "Hello world!\n";
  ASSERT_TRUE(WriteToFile(temp_file.string(), text));
  EXPECT_THAT(ReadSmallFile(temp_file.string()), Optional(StrEq(text)));
  text = "Foo bar!\n";
  ASSERT_TRUE(WriteToFile(temp_file.string(), text));
  EXPECT_THAT(ReadSmallFile(temp_file.string()), Optional(StrEq(text)));
  EXPECT_TRUE(std::filesystem::remove(temp_file));
}

TEST(FilesTest, write_read_empty_string_test) {
  auto temp_dir = std::filesystem::temp_directory_path();
  auto temp_file = temp_dir / "file_1.txt";
  std::string text;
  ASSERT_TRUE(WriteToFile(temp_file.string(), text));
  EXPECT_THAT(ReadSmallFile(temp_file.string()), Optional(StrEq(text)));
  EXPECT_TRUE(std::filesystem::remove(temp_file));
}

TEST(FilesTest, read_non_existing_file_test) {
  EXPECT_FALSE(ReadSmallFile("/woof"));
}

}  // namespace testing