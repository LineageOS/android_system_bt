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

#include "hal/snoop_logger.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

namespace testing {

namespace {
std::vector<uint8_t> kInformationRequest = {
    0xfe,
    0x2e,
    0x0a,
    0x00,
    0x06,
    0x00,
    0x01,
    0x00,
    0x0a,
    0x02,
    0x02,
    0x00,
    0x02,
    0x00,
};

std::vector<uint8_t> kSdpConnectionRequest = {
    0x08, 0x20, 0x0c, 0x00, 0x08, 0x00, 0x01, 0x00, 0x02, 0x0c, 0x04, 0x00, 0x01, 0x00, 0x44, 0x00};

std::vector<uint8_t> kAvdtpSuspend = {0x02, 0x02, 0x00, 0x07, 0x00, 0x03, 0x00, 0x8d, 0x00, 0x90, 0x09, 0x04};

std::vector<uint8_t> kHfpAtNrec0 = {0x02, 0x02, 0x20, 0x13, 0x00, 0x0f, 0x00, 0x41, 0x00, 0x09, 0xff, 0x15,
                                    0x01, 0x41, 0x54, 0x2b, 0x4e, 0x52, 0x45, 0x43, 0x3d, 0x30, 0x0d, 0x5c};

}  // namespace

using bluetooth::TestModuleRegistry;
using bluetooth::hal::SnoopLogger;

// Expose protected constructor for test
class TestSnoopLoggerModule : public SnoopLogger {
 public:
  TestSnoopLoggerModule(
      std::string snoop_log_path,
      std::string snooz_log_path,
      size_t max_packets_per_file,
      const std::string& btsnoop_mode)
      : SnoopLogger(std::move(snoop_log_path), std::move(snooz_log_path), max_packets_per_file, btsnoop_mode) {}

  std::string ToString() const override {
    return std::string("TestSnoopLoggerModule");
  }
};

class SnoopLoggerModuleTest : public Test {
 protected:
  void SetUp() override {
    temp_dir_ = std::filesystem::temp_directory_path();
    temp_snoop_log_ = temp_dir_ / "btsnoop_hci.log";
    temp_snoop_log_last_ = temp_dir_ / "btsnoop_hci.log.last";
    temp_snooz_log_ = temp_dir_ / "btsnooz_hci.log";
    temp_snooz_log_last_ = temp_dir_ / "btsnooz_hci.log.last";
    DeleteSnoopLogFiles();
    ASSERT_FALSE(std::filesystem::exists(temp_snoop_log_));
    ASSERT_FALSE(std::filesystem::exists(temp_snoop_log_last_));
    ASSERT_FALSE(std::filesystem::exists(temp_snooz_log_));
    ASSERT_FALSE(std::filesystem::exists(temp_snooz_log_last_));
  }

  void TearDown() override {
    DeleteSnoopLogFiles();
  }

  void DeleteSnoopLogFiles() {
    if (std::filesystem::exists(temp_snoop_log_)) {
      ASSERT_TRUE(std::filesystem::remove(temp_snoop_log_));
    }
    if (std::filesystem::exists(temp_snoop_log_last_)) {
      ASSERT_TRUE(std::filesystem::remove(temp_snoop_log_last_));
    }
    if (std::filesystem::exists(temp_snooz_log_)) {
      ASSERT_TRUE(std::filesystem::remove(temp_snooz_log_));
    }
    if (std::filesystem::exists(temp_snooz_log_last_)) {
      ASSERT_TRUE(std::filesystem::remove(temp_snooz_log_last_));
    }
  }

  std::filesystem::path temp_dir_;
  std::filesystem::path temp_snoop_log_;
  std::filesystem::path temp_snoop_log_last_;
  std::filesystem::path temp_snooz_log_;
  std::filesystem::path temp_snooz_log_last_;
};

TEST_F(SnoopLoggerModuleTest, empty_snoop_log_test) {
  // Actual test
  auto* snoop_looger = new TestSnoopLoggerModule(
      temp_snoop_log_.string(), temp_snooz_log_.string(), 10, SnoopLogger::kBtSnoopLogModeFull);
  TestModuleRegistry test_registry;
  test_registry.InjectTestModule(&SnoopLogger::Factory, snoop_looger);
  test_registry.StopAll();

  // Verify states after test
  ASSERT_TRUE(std::filesystem::exists(temp_snoop_log_));
  ASSERT_FALSE(std::filesystem::exists(temp_snoop_log_last_));
  ASSERT_EQ(std::filesystem::file_size(temp_snoop_log_), sizeof(SnoopLogger::FileHeaderType));
}

TEST_F(SnoopLoggerModuleTest, disable_snoop_log_test) {
  // Actual test
  auto* snoop_looger = new TestSnoopLoggerModule(
      temp_snoop_log_.string(), temp_snooz_log_.string(), 10, SnoopLogger::kBtSnoopLogModeDisabled);
  TestModuleRegistry test_registry;
  test_registry.InjectTestModule(&SnoopLogger::Factory, snoop_looger);
  test_registry.StopAll();

  // Verify states after test
  ASSERT_FALSE(std::filesystem::exists(temp_snoop_log_));
  ASSERT_FALSE(std::filesystem::exists(temp_snoop_log_last_));
  ASSERT_TRUE(std::filesystem::exists(temp_snooz_log_));
}

TEST_F(SnoopLoggerModuleTest, capture_one_packet_test) {
  // Actual test
  auto* snoop_looger = new TestSnoopLoggerModule(
      temp_snoop_log_.string(), temp_snooz_log_.string(), 10, SnoopLogger::kBtSnoopLogModeFull);
  TestModuleRegistry test_registry;
  test_registry.InjectTestModule(&SnoopLogger::Factory, snoop_looger);

  snoop_looger->Capture(kInformationRequest, SnoopLogger::Direction::OUTGOING, SnoopLogger::PacketType::CMD);

  test_registry.StopAll();

  // Verify states after test
  ASSERT_TRUE(std::filesystem::exists(temp_snoop_log_));
  ASSERT_FALSE(std::filesystem::exists(temp_snoop_log_last_));
  ASSERT_EQ(
      std::filesystem::file_size(temp_snoop_log_),
      sizeof(SnoopLogger::FileHeaderType) + sizeof(SnoopLogger::PacketHeaderType) + kInformationRequest.size());
}

TEST_F(SnoopLoggerModuleTest, capture_hci_cmd_btsnooz_test) {
  // Actual test
  auto* snoop_looger = new TestSnoopLoggerModule(
      temp_snoop_log_.string(), temp_snooz_log_.string(), 10, SnoopLogger::kBtSnoopLogModeDisabled);
  TestModuleRegistry test_registry;
  test_registry.InjectTestModule(&SnoopLogger::Factory, snoop_looger);

  snoop_looger->Capture(kInformationRequest, SnoopLogger::Direction::OUTGOING, SnoopLogger::PacketType::CMD);

  test_registry.StopAll();

  // Verify states after test
  ASSERT_FALSE(std::filesystem::exists(temp_snoop_log_));
  ASSERT_FALSE(std::filesystem::exists(temp_snoop_log_last_));
  ASSERT_TRUE(std::filesystem::exists(temp_snooz_log_));
  ASSERT_EQ(
      std::filesystem::file_size(temp_snooz_log_),
      sizeof(SnoopLogger::FileHeaderType) + sizeof(SnoopLogger::PacketHeaderType) + kInformationRequest.size());
}

TEST_F(SnoopLoggerModuleTest, capture_l2cap_signal_packet_btsnooz_test) {
  // Actual test
  auto* snoop_looger = new TestSnoopLoggerModule(
      temp_snoop_log_.string(), temp_snooz_log_.string(), 10, SnoopLogger::kBtSnoopLogModeDisabled);
  TestModuleRegistry test_registry;
  test_registry.InjectTestModule(&SnoopLogger::Factory, snoop_looger);

  snoop_looger->Capture(kSdpConnectionRequest, SnoopLogger::Direction::OUTGOING, SnoopLogger::PacketType::ACL);

  test_registry.StopAll();

  // Verify states after test
  ASSERT_FALSE(std::filesystem::exists(temp_snoop_log_));
  ASSERT_FALSE(std::filesystem::exists(temp_snoop_log_last_));
  ASSERT_TRUE(std::filesystem::exists(temp_snooz_log_));
  ASSERT_EQ(
      std::filesystem::file_size(temp_snooz_log_),
      sizeof(SnoopLogger::FileHeaderType) + sizeof(SnoopLogger::PacketHeaderType) + kSdpConnectionRequest.size());
}

TEST_F(SnoopLoggerModuleTest, capture_l2cap_short_data_packet_btsnooz_test) {
  // Actual test
  auto* snoop_looger = new TestSnoopLoggerModule(
      temp_snoop_log_.string(), temp_snooz_log_.string(), 10, SnoopLogger::kBtSnoopLogModeDisabled);
  TestModuleRegistry test_registry;
  test_registry.InjectTestModule(&SnoopLogger::Factory, snoop_looger);

  snoop_looger->Capture(kAvdtpSuspend, SnoopLogger::Direction::OUTGOING, SnoopLogger::PacketType::ACL);

  test_registry.StopAll();

  // Verify states after test
  ASSERT_FALSE(std::filesystem::exists(temp_snoop_log_));
  ASSERT_FALSE(std::filesystem::exists(temp_snoop_log_last_));
  ASSERT_TRUE(std::filesystem::exists(temp_snooz_log_));
  ASSERT_EQ(
      std::filesystem::file_size(temp_snooz_log_),
      sizeof(SnoopLogger::FileHeaderType) + sizeof(SnoopLogger::PacketHeaderType) + kAvdtpSuspend.size());
}

TEST_F(SnoopLoggerModuleTest, capture_l2cap_long_data_packet_btsnooz_test) {
  // Actual test
  auto* snoop_looger = new TestSnoopLoggerModule(
      temp_snoop_log_.string(), temp_snooz_log_.string(), 10, SnoopLogger::kBtSnoopLogModeDisabled);
  TestModuleRegistry test_registry;
  test_registry.InjectTestModule(&SnoopLogger::Factory, snoop_looger);

  snoop_looger->Capture(kHfpAtNrec0, SnoopLogger::Direction::OUTGOING, SnoopLogger::PacketType::ACL);

  test_registry.StopAll();

  // Verify states after test
  ASSERT_FALSE(std::filesystem::exists(temp_snoop_log_));
  ASSERT_FALSE(std::filesystem::exists(temp_snoop_log_last_));
  ASSERT_TRUE(std::filesystem::exists(temp_snooz_log_));
  ASSERT_EQ(
      std::filesystem::file_size(temp_snooz_log_),
      sizeof(SnoopLogger::FileHeaderType) + sizeof(SnoopLogger::PacketHeaderType) + 14);
}

TEST_F(SnoopLoggerModuleTest, rotate_file_at_new_session_test) {
  // Start once
  {
    auto* snoop_looger = new TestSnoopLoggerModule(
        temp_snoop_log_.string(), temp_snooz_log_.string(), 10, SnoopLogger::kBtSnoopLogModeFull);
    TestModuleRegistry test_registry;
    test_registry.InjectTestModule(&SnoopLogger::Factory, snoop_looger);
    snoop_looger->Capture(kInformationRequest, SnoopLogger::Direction::OUTGOING, SnoopLogger::PacketType::CMD);
    test_registry.StopAll();
  }

  // Verify states after test
  ASSERT_TRUE(std::filesystem::exists(temp_snoop_log_));
  ASSERT_FALSE(std::filesystem::exists(temp_snoop_log_last_));
  ASSERT_EQ(
      std::filesystem::file_size(temp_snoop_log_),
      sizeof(SnoopLogger::FileHeaderType) + sizeof(SnoopLogger::PacketHeaderType) + kInformationRequest.size());

  // Start again
  {
    auto* snoop_looger = new TestSnoopLoggerModule(
        temp_snoop_log_.string(), temp_snooz_log_.string(), 10, SnoopLogger::kBtSnoopLogModeFull);
    TestModuleRegistry test_registry;
    test_registry.InjectTestModule(&SnoopLogger::Factory, snoop_looger);
    snoop_looger->Capture(kInformationRequest, SnoopLogger::Direction::OUTGOING, SnoopLogger::PacketType::CMD);
    snoop_looger->Capture(kInformationRequest, SnoopLogger::Direction::OUTGOING, SnoopLogger::PacketType::CMD);
    test_registry.StopAll();
  }

  // Verify states after test
  ASSERT_TRUE(std::filesystem::exists(temp_snoop_log_));
  ASSERT_TRUE(std::filesystem::exists(temp_snoop_log_last_));
  ASSERT_EQ(
      std::filesystem::file_size(temp_snoop_log_),
      sizeof(SnoopLogger::FileHeaderType) + (sizeof(SnoopLogger::PacketHeaderType) + kInformationRequest.size()) * 2);
  ASSERT_EQ(
      std::filesystem::file_size(temp_snoop_log_last_),
      sizeof(SnoopLogger::FileHeaderType) + sizeof(SnoopLogger::PacketHeaderType) + kInformationRequest.size());
}

TEST_F(SnoopLoggerModuleTest, rotate_file_after_full_test) {
  // Actual test
  auto* snoop_looger = new TestSnoopLoggerModule(
      temp_snoop_log_.string(), temp_snooz_log_.string(), 10, SnoopLogger::kBtSnoopLogModeFull);
  TestModuleRegistry test_registry;
  test_registry.InjectTestModule(&SnoopLogger::Factory, snoop_looger);

  for (int i = 0; i < 11; i++) {
    snoop_looger->Capture(kInformationRequest, SnoopLogger::Direction::OUTGOING, SnoopLogger::PacketType::CMD);
  }

  test_registry.StopAll();

  // Verify states after test
  ASSERT_TRUE(std::filesystem::exists(temp_snoop_log_));
  ASSERT_TRUE(std::filesystem::exists(temp_snoop_log_last_));
  ASSERT_EQ(
      std::filesystem::file_size(temp_snoop_log_),
      sizeof(SnoopLogger::FileHeaderType) + (sizeof(SnoopLogger::PacketHeaderType) + kInformationRequest.size()) * 1);
  ASSERT_EQ(
      std::filesystem::file_size(temp_snoop_log_last_),
      sizeof(SnoopLogger::FileHeaderType) + (sizeof(SnoopLogger::PacketHeaderType) + kInformationRequest.size()) * 10);
}

}  // namespace testing
