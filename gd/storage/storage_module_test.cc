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

#include "storage/storage_module.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <chrono>
#include <cstdio>
#include <ctime>
#include <filesystem>
#include <iomanip>
#include <optional>
#include <thread>

#include "module.h"
#include "os/files.h"
#include "storage/config_cache.h"
#include "storage/legacy_config_file.h"

namespace testing {

using bluetooth::TestModuleRegistry;
using bluetooth::storage::ConfigCache;
using bluetooth::storage::LegacyConfigFile;
using bluetooth::storage::StorageModule;

static const std::chrono::milliseconds kTestConfigSaveDelay = std::chrono::milliseconds(100);

static std::optional<std::chrono::system_clock::time_point> ParseTimestamp(
    const std::string& timestamp, const std::string& format) {
  std::istringstream ss(timestamp);
  // 1. Parse to time_t from timestamp that may not contain day light saving information
  std::tm no_dst_tm = {};
  ss >> std::get_time(&no_dst_tm, format.c_str());
  if (ss.fail()) {
    return std::nullopt;
  }
  // 2. Make a copy of the parsed result so that we can set tm_isdst bit later
  auto dst_tm = no_dst_tm;
  auto no_dst_time_t = std::mktime(&no_dst_tm);
  if (no_dst_time_t == -1) {
    return std::nullopt;
  }
  // 3. Convert time_t to tm again, but let system decide if day light saving should be set at that date and time
  auto dst_tm_only = std::localtime(&no_dst_time_t);
  // 4. Set the correct tm_isdst bit
  dst_tm.tm_isdst = dst_tm_only->tm_isdst;
  auto dst_time_t = std::mktime(&dst_tm);
  if (dst_time_t == -1) {
    return std::nullopt;
  }
  // 5. Parse is to time point
  return std::chrono::system_clock::from_time_t(dst_time_t);
}

class TestStorageModule : public StorageModule {
 public:
  TestStorageModule(
      std::string config_file_path,
      std::chrono::milliseconds config_save_delay,
      size_t temp_devices_capacity,
      bool is_restricted_mode,
      bool is_single_user_mode)
      : StorageModule(
            std::move(config_file_path),
            config_save_delay,
            temp_devices_capacity,
            is_restricted_mode,
            is_single_user_mode) {}

  ConfigCache* GetConfigCachePublic() {
    return StorageModule::GetConfigCache();
  }

  void SaveImmediatelyPublic() {
    StorageModule::SaveImmediately();
  }
};

class StorageModuleTest : public Test {
 protected:
  void SetUp() override {
    temp_dir_ = std::filesystem::temp_directory_path();
    temp_config_ = temp_dir_ / "temp_config.txt";
    temp_backup_config_ = temp_dir_ / "temp_config.bak";
    DeleteConfigFiles();
    EXPECT_FALSE(std::filesystem::exists(temp_config_));
    EXPECT_FALSE(std::filesystem::exists(temp_backup_config_));
  }

  void TearDown() override {
    DeleteConfigFiles();
  }

  void DeleteConfigFiles() {
    if (std::filesystem::exists(temp_config_)) {
      EXPECT_TRUE(std::filesystem::remove(temp_config_));
    }
    if (std::filesystem::exists(temp_backup_config_)) {
      EXPECT_TRUE(std::filesystem::remove(temp_backup_config_));
    }
  }

  std::filesystem::path temp_dir_;
  std::filesystem::path temp_config_;
  std::filesystem::path temp_backup_config_;
};

TEST_F(StorageModuleTest, empty_config_no_op_test) {
  // Actual test
  auto time_before = std::chrono::system_clock::now();
  auto* storage = new TestStorageModule(temp_config_.string(), kTestConfigSaveDelay, 10, false, false);
  TestModuleRegistry test_registry;
  test_registry.InjectTestModule(&StorageModule::Factory, storage);
  test_registry.StopAll();
  auto time_after = std::chrono::system_clock::now();

  // Verify states after test
  EXPECT_TRUE(std::filesystem::exists(temp_config_));

  // Verify config after test
  auto config = LegacyConfigFile::FromPath(temp_config_.string()).Read(10);
  EXPECT_TRUE(config);
  EXPECT_TRUE(config->HasSection(StorageModule::kInfoSection));
  EXPECT_THAT(
      config->GetProperty(StorageModule::kInfoSection, StorageModule::kFileSourceProperty), Optional(StrEq("Empty")));

  // Verify file creation timestamp falls between time_before and time_after
  auto timestamp = config->GetProperty(StorageModule::kInfoSection, StorageModule::kTimeCreatedProperty);
  EXPECT_TRUE(timestamp);
  auto file_time = ParseTimestamp(*timestamp, StorageModule::kTimeCreatedFormat);
  EXPECT_TRUE(file_time);
  EXPECT_GE(std::chrono::duration_cast<std::chrono::seconds>(time_after - *file_time).count(), 0);
  EXPECT_GE(std::chrono::duration_cast<std::chrono::seconds>(*file_time - time_before).count(), 0);
}

static const std::string kReadTestConfig =
    "[Info]\n"
    "FileSource = Empty\n"
    "TimeCreated = 2020-05-20 01:20:56\n"
    "\n"
    "[Metrics]\n"
    "Salt256Bit = 1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef\n"
    "\n"
    "[Adapter]\n"
    "Address = 01:02:03:ab:cd:ef\n"
    "LE_LOCAL_KEY_IRK = fedcba0987654321fedcba0987654321\n"
    "LE_LOCAL_KEY_IR = fedcba0987654321fedcba0987654322\n"
    "LE_LOCAL_KEY_DHK = fedcba0987654321fedcba0987654323\n"
    "LE_LOCAL_KEY_ER = fedcba0987654321fedcba0987654324\n"
    "ScanMode = 2\n"
    "DiscoveryTimeout = 120\n"
    "\n"
    "[01:02:03:ab:cd:ea]\n"
    "name = hello world\n"
    "LinkKey = fedcba0987654321fedcba0987654328\n"
    "\n";

TEST_F(StorageModuleTest, read_existing_config_test) {
  EXPECT_TRUE(bluetooth::os::WriteToFile(temp_config_.string(), kReadTestConfig));
  // Actual test

  // Set up
  auto* storage = new TestStorageModule(temp_config_.string(), kTestConfigSaveDelay, 10, false, false);
  TestModuleRegistry test_registry;
  test_registry.InjectTestModule(&StorageModule::Factory, storage);

  // Test
  EXPECT_NE(storage->GetConfigCachePublic(), nullptr);
  EXPECT_TRUE(storage->GetConfigCachePublic()->HasSection("Metrics"));
  EXPECT_THAT(storage->GetConfigCachePublic()->GetPersistentDevices(), ElementsAre("01:02:03:ab:cd:ea"));
  EXPECT_THAT(
      storage->GetConfigCachePublic()->GetProperty(StorageModule::kAdapterSection, "Address"),
      Optional(StrEq("01:02:03:ab:cd:ef")));

  // Tear down
  test_registry.StopAll();

  // Verify states after test
  EXPECT_TRUE(std::filesystem::exists(temp_config_));

  // Verify config after test
  auto config = bluetooth::os::ReadSmallFile(temp_config_.string());
  EXPECT_TRUE(config);
  EXPECT_EQ(*config, kReadTestConfig);
}

TEST_F(StorageModuleTest, save_config_test) {
  // Prepare config file
  EXPECT_TRUE(bluetooth::os::WriteToFile(temp_config_.string(), kReadTestConfig));

  // Set up
  auto* storage = new TestStorageModule(temp_config_.string(), kTestConfigSaveDelay, 10, false, false);
  TestModuleRegistry test_registry;
  test_registry.InjectTestModule(&StorageModule::Factory, storage);

  // Test
  EXPECT_NE(storage->GetConfigCachePublic(), nullptr);

  // Change a property
  EXPECT_THAT(
      storage->GetConfigCachePublic()->GetProperty("01:02:03:ab:cd:ea", "name"), Optional(StrEq("hello world")));
  storage->GetConfigCachePublic()->SetProperty("01:02:03:ab:cd:ea", "name", "foo");
  EXPECT_THAT(storage->GetConfigCachePublic()->GetProperty("01:02:03:ab:cd:ea", "name"), Optional(StrEq("foo")));
  std::this_thread::sleep_for(kTestConfigSaveDelay * 1.5);
  auto config = LegacyConfigFile::FromPath(temp_config_.string()).Read(10);
  EXPECT_TRUE(config);
  EXPECT_THAT(config->GetProperty("01:02:03:ab:cd:ea", "name"), Optional(StrEq("foo")));

  // Remove a property
  storage->GetConfigCachePublic()->RemoveProperty("01:02:03:ab:cd:ea", "name");
  std::this_thread::sleep_for(kTestConfigSaveDelay * 1.5);
  config = LegacyConfigFile::FromPath(temp_config_.string()).Read(10);
  EXPECT_TRUE(config);
  EXPECT_FALSE(config->HasProperty("01:02:03:ab:cd:ea", "name"));

  // Remove a section
  storage->GetConfigCachePublic()->RemoveSection("01:02:03:ab:cd:ea");
  std::this_thread::sleep_for(kTestConfigSaveDelay * 1.5);
  config = LegacyConfigFile::FromPath(temp_config_.string()).Read(10);
  EXPECT_TRUE(config);
  EXPECT_FALSE(config->HasSection("01:02:03:ab:cd:ea"));

  // Add a section and save immediately
  storage->GetConfigCachePublic()->SetProperty("01:02:03:ab:cd:eb", "LinkKey", "123456");
  storage->SaveImmediatelyPublic();
  config = LegacyConfigFile::FromPath(temp_config_.string()).Read(10);
  EXPECT_TRUE(config);
  EXPECT_TRUE(config->HasSection("01:02:03:ab:cd:eb"));

  // Tear down
  test_registry.StopAll();

  // Verify states after test
  EXPECT_TRUE(std::filesystem::exists(temp_config_));
}

}  // namespace testing