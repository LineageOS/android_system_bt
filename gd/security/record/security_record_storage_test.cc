/*
 *  Copyright 2020 The Android Open Source Project
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
 */
#include "security/record/security_record_storage.h"

#include <gtest/gtest.h>

#include "security/test/fake_storage_module.h"

namespace bluetooth {
namespace security {
namespace record {
namespace {

class SecurityRecordStorageTest : public ::testing::Test {
 protected:
  void SetUp() override {
    // Make Fake storage module
    storage_module_ = new FakeStorageModule();

    // Inject
    fake_registry_.InjectTestModule(&storage::StorageModule::Factory, storage_module_);

    // Make storage
    record_storage_ = new record::SecurityRecordStorage(storage_module_, handler_);
  }

  void TearDown() override {
    synchronize();
    fake_registry_.StopAll();
    delete record_storage_;
  }

  void synchronize() {
    fake_registry_.SynchronizeModuleHandler(&FakeStorageModule::Factory, std::chrono::milliseconds(20));
  }

  TestModuleRegistry fake_registry_;
  os::Thread& thread_ = fake_registry_.GetTestThread();
  os::Handler* handler_ = nullptr;
  FakeStorageModule* storage_module_;
  record::SecurityRecordStorage* record_storage_;
};

TEST_F(SecurityRecordStorageTest, setup_teardown) {}

TEST_F(SecurityRecordStorageTest, store_security_record) {
  hci::AddressWithType remote(
      hci::Address({0x01, 0x02, 0x03, 0x04, 0x05, 0x06}), hci::AddressType::PUBLIC_DEVICE_ADDRESS);
  std::array<uint8_t, 16> link_key = {
      0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0};
  std::shared_ptr<record::SecurityRecord> record = std::make_shared<record::SecurityRecord>(remote);

  record->SetLinkKey(link_key, hci::KeyType::DEBUG_COMBINATION);
  std::set<std::shared_ptr<record::SecurityRecord>> record_set;
  record_set.insert(record);
  record_storage_->SaveSecurityRecords(&record_set);

  auto device = storage_module_->GetDeviceByClassicMacAddress(remote.GetAddress());
  ASSERT_TRUE(device.GetDeviceType());
  ASSERT_EQ(device.Classic().GetLinkKeyType(), record->GetKeyType());
  int i = 0;
  for (i = 0; i < 16; ++i) {
    ASSERT_EQ(link_key[i], device.Classic().GetLinkKey()->bytes[i]);
  }
}

TEST_F(SecurityRecordStorageTest, load_security_record) {
  hci::AddressWithType remote(
      hci::Address({0x01, 0x02, 0x03, 0x04, 0x05, 0x06}), hci::AddressType::PUBLIC_DEVICE_ADDRESS);
  std::array<uint8_t, 16> link_key = {
      0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0};
  std::shared_ptr<record::SecurityRecord> record = std::make_shared<record::SecurityRecord>(remote);

  record->SetLinkKey(link_key, hci::KeyType::DEBUG_COMBINATION);
  std::set<std::shared_ptr<record::SecurityRecord>> record_set;
  record_set.insert(record);
  record_storage_->SaveSecurityRecords(&record_set);

  auto device = storage_module_->GetDeviceByClassicMacAddress(remote.GetAddress());
  ASSERT_TRUE(device.GetDeviceType());

  ASSERT_EQ(device.Classic().GetLinkKeyType(), record->GetKeyType());
  int i = 0;
  for (i = 0; i < 16; ++i) {
    ASSERT_EQ(link_key[i], device.Classic().GetLinkKey()->bytes[i]);
  }

  record_set.clear();
  record_storage_->LoadSecurityRecords(&record_set);
  record = *record_set.begin();
  link_key = record->GetLinkKey();

  ASSERT_EQ(device.Classic().GetLinkKeyType(), record->GetKeyType());
  ASSERT_TRUE(device.GetDeviceType());
  for (i = 0; i < 16; ++i) {
    ASSERT_EQ(link_key[i], device.Classic().GetLinkKey()->bytes[i]);
  }
}

TEST_F(SecurityRecordStorageTest, dont_save_temporary_records) {
  hci::AddressWithType remote(
      hci::Address({0x01, 0x02, 0x03, 0x04, 0x05, 0x06}), hci::AddressType::PUBLIC_DEVICE_ADDRESS);
  std::array<uint8_t, 16> link_key = {
      0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0};
  std::shared_ptr<record::SecurityRecord> record = std::make_shared<record::SecurityRecord>(remote);

  record->SetLinkKey(link_key, hci::KeyType::DEBUG_COMBINATION);
  record->SetIsTemporary(true);
  std::set<std::shared_ptr<record::SecurityRecord>> record_set;
  record_set.insert(record);
  record_storage_->SaveSecurityRecords(&record_set);

  auto device = storage_module_->GetDeviceByClassicMacAddress(remote.GetAddress());
  ASSERT_FALSE(device.GetDeviceType());

  record_set.clear();
  record_storage_->LoadSecurityRecords(&record_set);
  ASSERT_EQ(record_set.size(), 0);
}

TEST_F(SecurityRecordStorageTest, test_remove) {
  hci::AddressWithType remote(
      hci::Address({0x01, 0x02, 0x03, 0x04, 0x05, 0x06}), hci::AddressType::PUBLIC_DEVICE_ADDRESS);
  std::array<uint8_t, 16> link_key = {
      0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0};
  std::shared_ptr<record::SecurityRecord> record = std::make_shared<record::SecurityRecord>(remote);

  record->SetLinkKey(link_key, hci::KeyType::DEBUG_COMBINATION);
  std::set<std::shared_ptr<record::SecurityRecord>> record_set;
  record_set.insert(record);
  record_storage_->SaveSecurityRecords(&record_set);

  auto device = storage_module_->GetDeviceByClassicMacAddress(remote.GetAddress());
  ASSERT_TRUE(device.GetDeviceType());

  ASSERT_EQ(device.Classic().GetLinkKeyType(), record->GetKeyType());
  int i = 0;
  for (i = 0; i < 16; ++i) {
    ASSERT_EQ(link_key[i], device.Classic().GetLinkKey()->bytes[i]);
  }

  record_storage_->RemoveDevice(remote);

  record_set.clear();
  record_storage_->LoadSecurityRecords(&record_set);
  ASSERT_EQ(record_set.size(), 0);
}

}  // namespace
}  // namespace record
}  // namespace security
}  // namespace bluetooth
