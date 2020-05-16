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

#include "hci/le_address_rotator.h"

#include <gtest/gtest.h>

#include "os/log.h"

using ::bluetooth::crypto_toolbox::Octet16;
using ::bluetooth::os::Handler;
using ::bluetooth::os::Thread;

namespace bluetooth {
namespace hci {

class RotatorClient : public LeAddressRotatorCallback {
 public:
  RotatorClient(LeAddressRotator* le_address_rotator) : le_address_rotator_(le_address_rotator){};

  void OnPause() {
    le_address_rotator_->AckPause(this);
  }

  void OnResume() {
    le_address_rotator_->AckResume(this);
  }

  LeAddressRotator* le_address_rotator_;
};

class LeAddressRotatorTest : public ::testing::Test {
 public:
  void SetUp() override {
    thread_ = new Thread("thread", Thread::Priority::NORMAL);
    handler_ = new Handler(thread_);
    Address address({0x01, 0x02, 0x03, 0x04, 0x05, 0x06});
    le_address_rotator_ = new LeAddressRotator(
        common::Bind(&LeAddressRotatorTest::SetRandomAddress, common::Unretained(this)), handler_, address);
  }

  void TearDown() override {
    delete le_address_rotator_;
    handler_->Clear();
    delete handler_;
    delete thread_;
  }

  void SetRandomAddress(Address address) {
    le_address_rotator_->OnLeSetRandomAddressComplete(true);
    complete_count_--;
    if (complete_count_ == 0) {
      complete_promise_->set_value();
      complete_promise_ = nullptr;
    }
  }

  void SetCompleteFuture(uint16_t count) {
    ASSERT_LOG(complete_promise_ == nullptr, "Promises, Promises, ... Only one at a time.");
    complete_count_ = count;
    complete_promise_ = std::make_unique<std::promise<void>>();
    complete_future_ = std::make_unique<std::future<void>>(complete_promise_->get_future());
  }

  Thread* thread_;
  Handler* handler_;
  LeAddressRotator* le_address_rotator_;
  uint16_t complete_count_;
  std::unique_ptr<std::promise<void>> complete_promise_;
  std::unique_ptr<std::future<void>> complete_future_;
};

TEST_F(LeAddressRotatorTest, startup_teardown) {}

TEST_F(LeAddressRotatorTest, register_unregister_callback) {
  RotatorClient* rotator_client = new RotatorClient(le_address_rotator_);
  le_address_rotator_->Register(rotator_client);
  le_address_rotator_->Unregister(rotator_client);
  delete rotator_client;
}

TEST_F(LeAddressRotatorTest, rotator_address_for_single_client) {
  RotatorClient* rotator_client = new RotatorClient(le_address_rotator_);
  Octet16 irk = {0xec, 0x02, 0x34, 0xa3, 0x57, 0xc8, 0xad, 0x05, 0x34, 0x10, 0x10, 0xa6, 0x0a, 0x39, 0x7d, 0x9b};
  auto minimum_rotation_time = std::chrono::milliseconds(1000);
  auto maximum_rotation_time = std::chrono::milliseconds(3000);
  AddressWithType remote_address(Address::kEmpty, AddressType::RANDOM_DEVICE_ADDRESS);
  le_address_rotator_->SetPrivacyPolicyForInitiatorAddress(LeAddressRotator::AddressPolicy::USE_RESOLVABLE_ADDRESS,
                                                           remote_address, irk, minimum_rotation_time,
                                                           maximum_rotation_time);

  SetCompleteFuture(3);
  le_address_rotator_->Register(rotator_client);
  complete_future_->wait();
  le_address_rotator_->Unregister(rotator_client);
  delete rotator_client;
}

TEST_F(LeAddressRotatorTest, rotator_non_resolvable_address_for_single_client) {
  RotatorClient* rotator_client = new RotatorClient(le_address_rotator_);
  Octet16 irk = {};
  auto minimum_rotation_time = std::chrono::milliseconds(1000);
  auto maximum_rotation_time = std::chrono::milliseconds(3000);
  AddressWithType remote_address(Address::kEmpty, AddressType::RANDOM_DEVICE_ADDRESS);
  le_address_rotator_->SetPrivacyPolicyForInitiatorAddress(LeAddressRotator::AddressPolicy::USE_NON_RESOLVABLE_ADDRESS,
                                                           remote_address, irk, minimum_rotation_time,
                                                           maximum_rotation_time);

  SetCompleteFuture(3);
  le_address_rotator_->Register(rotator_client);
  complete_future_->wait();
  le_address_rotator_->Unregister(rotator_client);
  delete rotator_client;
}

TEST_F(LeAddressRotatorTest, rotator_address_for_multiple_clients) {
  RotatorClient* rotator_client1 = new RotatorClient(le_address_rotator_);
  RotatorClient* rotator_client2 = new RotatorClient(le_address_rotator_);
  RotatorClient* rotator_client3 = new RotatorClient(le_address_rotator_);
  Octet16 irk = {0xec, 0x02, 0x34, 0xa3, 0x57, 0xc8, 0xad, 0x05, 0x34, 0x10, 0x10, 0xa6, 0x0a, 0x39, 0x7d, 0x9b};
  auto minimum_rotation_time = std::chrono::milliseconds(1000);
  auto maximum_rotation_time = std::chrono::milliseconds(3000);
  AddressWithType remote_address(Address::kEmpty, AddressType::RANDOM_DEVICE_ADDRESS);
  le_address_rotator_->SetPrivacyPolicyForInitiatorAddress(LeAddressRotator::AddressPolicy::USE_RESOLVABLE_ADDRESS,
                                                           remote_address, irk, minimum_rotation_time,
                                                           maximum_rotation_time);
  SetCompleteFuture(3);
  le_address_rotator_->Register(rotator_client1);
  le_address_rotator_->Register(rotator_client2);
  le_address_rotator_->Register(rotator_client3);
  complete_future_->wait();
  le_address_rotator_->Unregister(rotator_client1);
  le_address_rotator_->Unregister(rotator_client2);
  le_address_rotator_->Unregister(rotator_client3);
  delete rotator_client1;
  delete rotator_client2;
  delete rotator_client3;
}

}  // namespace hci
}  // namespace bluetooth
