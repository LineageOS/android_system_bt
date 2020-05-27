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
  RotatorClient(LeAddressRotator* le_address_rotator, size_t id) : le_address_rotator_(le_address_rotator), id_(id){};

  void OnPause() {
    paused = true;
    le_address_rotator_->AckPause(this);
  }

  void OnResume() {
    paused = false;
    le_address_rotator_->AckResume(this);
  }

  bool paused{false};
  LeAddressRotator* le_address_rotator_;
  size_t id_;
};

class LeAddressRotatorTest : public ::testing::Test {
 public:
  void SetUp() override {
    thread_ = new Thread("thread", Thread::Priority::NORMAL);
    handler_ = new Handler(thread_);
    Address address({0x01, 0x02, 0x03, 0x04, 0x05, 0x06});
    le_address_rotator_ = new LeAddressRotator(
        common::Bind(&LeAddressRotatorTest::SetRandomAddress, common::Unretained(this)), handler_, address);
    AllocateClients(1);
  }

  void sync_handler(os::Handler* handler) {
    std::promise<void> promise;
    auto future = promise.get_future();
    handler_->Post(common::BindOnce(&std::promise<void>::set_value, common::Unretained(&promise)));
    auto future_status = future.wait_for(std::chrono::seconds(1));
    EXPECT_EQ(future_status, std::future_status::ready);
  }

  void TearDown() override {
    sync_handler(handler_);
    delete le_address_rotator_;
    handler_->Clear();
    delete handler_;
    delete thread_;
  }

  void AllocateClients(size_t num_clients) {
    size_t first_id = clients.size();
    for (size_t i = 0; i < num_clients; i++) {
      clients.emplace_back(std::make_unique<RotatorClient>(le_address_rotator_, first_id + i));
    }
  }

  void SetRandomAddress(Address address) {
    le_address_rotator_->OnLeSetRandomAddressComplete(true);
    for (auto& client : clients) {
      ASSERT_TRUE(client->paused);
    }
  }

  Thread* thread_;
  Handler* handler_;
  LeAddressRotator* le_address_rotator_;
  std::vector<std::unique_ptr<RotatorClient>> clients;
};

TEST_F(LeAddressRotatorTest, startup_teardown) {}

TEST_F(LeAddressRotatorTest, register_unregister_callback) {
  le_address_rotator_->Register(clients[0].get());
  sync_handler(handler_);
  le_address_rotator_->Unregister(clients[0].get());
  sync_handler(handler_);
}

TEST_F(LeAddressRotatorTest, rotator_address_for_single_client) {
  Octet16 irk = {0xec, 0x02, 0x34, 0xa3, 0x57, 0xc8, 0xad, 0x05, 0x34, 0x10, 0x10, 0xa6, 0x0a, 0x39, 0x7d, 0x9b};
  auto minimum_rotation_time = std::chrono::milliseconds(1000);
  auto maximum_rotation_time = std::chrono::milliseconds(3000);
  AddressWithType remote_address(Address::kEmpty, AddressType::RANDOM_DEVICE_ADDRESS);
  le_address_rotator_->SetPrivacyPolicyForInitiatorAddress(LeAddressRotator::AddressPolicy::USE_RESOLVABLE_ADDRESS,
                                                           remote_address, irk, minimum_rotation_time,
                                                           maximum_rotation_time);

  le_address_rotator_->Register(clients[0].get());
  sync_handler(handler_);
  le_address_rotator_->Unregister(clients[0].get());
  sync_handler(handler_);
}

TEST_F(LeAddressRotatorTest, rotator_non_resolvable_address_for_single_client) {
  Octet16 irk = {};
  auto minimum_rotation_time = std::chrono::milliseconds(1000);
  auto maximum_rotation_time = std::chrono::milliseconds(3000);
  AddressWithType remote_address(Address::kEmpty, AddressType::RANDOM_DEVICE_ADDRESS);
  le_address_rotator_->SetPrivacyPolicyForInitiatorAddress(LeAddressRotator::AddressPolicy::USE_NON_RESOLVABLE_ADDRESS,
                                                           remote_address, irk, minimum_rotation_time,
                                                           maximum_rotation_time);

  le_address_rotator_->Register(clients[0].get());
  sync_handler(handler_);
  le_address_rotator_->Unregister(clients[0].get());
  sync_handler(handler_);
}

// TODO handle the case "register during rotate_random_address" and enable this
TEST_F(LeAddressRotatorTest, DISABLED_rotator_address_for_multiple_clients) {
  AllocateClients(2);
  Octet16 irk = {0xec, 0x02, 0x34, 0xa3, 0x57, 0xc8, 0xad, 0x05, 0x34, 0x10, 0x10, 0xa6, 0x0a, 0x39, 0x7d, 0x9b};
  auto minimum_rotation_time = std::chrono::milliseconds(1000);
  auto maximum_rotation_time = std::chrono::milliseconds(3000);
  AddressWithType remote_address(Address::kEmpty, AddressType::RANDOM_DEVICE_ADDRESS);
  le_address_rotator_->SetPrivacyPolicyForInitiatorAddress(LeAddressRotator::AddressPolicy::USE_RESOLVABLE_ADDRESS,
                                                           remote_address, irk, minimum_rotation_time,
                                                           maximum_rotation_time);
  le_address_rotator_->Register(clients[0].get());
  le_address_rotator_->Register(clients[1].get());
  le_address_rotator_->Register(clients[2].get());
  sync_handler(handler_);

  le_address_rotator_->Unregister(clients[0].get());
  le_address_rotator_->Unregister(clients[1].get());
  le_address_rotator_->Unregister(clients[2].get());
  sync_handler(handler_);
}

}  // namespace hci
}  // namespace bluetooth
