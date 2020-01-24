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

#include "shim/l2cap.h"

#include <algorithm>
#include <chrono>
#include <future>
#include <map>
#include <memory>

#include <unistd.h>

#include <gtest/gtest.h>

#include "common/bind.h"
#include "hci/address.h"
#include "l2cap/classic/dynamic_channel_configuration_option.h"
#include "l2cap/classic/internal/dynamic_channel_service_manager_impl_mock.h"
#include "l2cap/classic/l2cap_classic_module.h"
#include "l2cap/psm.h"
#include "l2cap/security_policy.h"
#include "module.h"
#include "os/handler.h"

namespace bluetooth {
namespace shim {
namespace {

constexpr uint16_t kPsm = 123;
constexpr char device_address[] = "11:22:33:44:55:66";

class TestDynamicChannelService : public l2cap::classic::DynamicChannelService {
 public:
  TestDynamicChannelService(l2cap::Psm psm, l2cap::classic::internal::DynamicChannelServiceManagerImpl* manager,
                            os::Handler* handler)
      : DynamicChannelService(psm, manager, handler) {}
};

class TestDynamicChannelManagerImpl {
 public:
  bool ConnectChannel(hci::Address device, l2cap::classic::DynamicChannelConfigurationOption configuration_option,
                      l2cap::Psm psm,
                      l2cap::classic::DynamicChannelManager::OnConnectionOpenCallback on_connection_open,
                      l2cap::classic::DynamicChannelManager::OnConnectionFailureCallback on_fail_callback,
                      os::Handler* handler) {
    connections_++;
    if (connected_promise_ != nullptr) connected_promise_->set_value();
    return true;
  }
  int connections_{0};

  bool RegisterService(l2cap::Psm psm, l2cap::classic::DynamicChannelConfigurationOption configuration_option,
                       const l2cap::SecurityPolicy& security_policy,
                       l2cap::classic::DynamicChannelManager::OnRegistrationCompleteCallback on_registration_complete,
                       l2cap::classic::DynamicChannelManager::OnConnectionOpenCallback on_connection_open,
                       os::Handler* handler) {
    services_++;
    on_registration_complete_ = std::move(on_registration_complete);
    on_connection_open_ = std::move(on_connection_open);

    if (registered_promise_ != nullptr) registered_promise_->set_value();
    return true;
  }
  int services_{0};

  ~TestDynamicChannelManagerImpl() {
    if (connected_promise_ != nullptr) delete connected_promise_;
    if (registered_promise_ != nullptr) delete registered_promise_;
  }
  std::promise<void>* connected_promise_{nullptr};
  std::promise<void>* registered_promise_{nullptr};

  l2cap::classic::DynamicChannelManager::OnRegistrationCompleteCallback on_registration_complete_;
  l2cap::classic::DynamicChannelManager::OnConnectionOpenCallback on_connection_open_;

  TestDynamicChannelManagerImpl() = default;
};

class TestDynamicChannelManager : public l2cap::classic::DynamicChannelManager {
 public:
  bool ConnectChannel(hci::Address device, l2cap::classic::DynamicChannelConfigurationOption configuration_option,
                      l2cap::Psm psm,
                      l2cap::classic::DynamicChannelManager::OnConnectionOpenCallback on_connection_open,
                      l2cap::classic::DynamicChannelManager::OnConnectionFailureCallback on_fail_callback,
                      os::Handler* handler) override {
    return impl_.ConnectChannel(device, configuration_option, psm, std::move(on_connection_open),
                                std::move(on_fail_callback), handler);
  }

  bool RegisterService(l2cap::Psm psm, l2cap::classic::DynamicChannelConfigurationOption configuration_option,
                       const l2cap::SecurityPolicy& security_policy,
                       l2cap::classic::DynamicChannelManager::OnRegistrationCompleteCallback on_registration_complete,
                       l2cap::classic::DynamicChannelManager::OnConnectionOpenCallback on_connection_open,
                       os::Handler* handler) override {
    return impl_.RegisterService(psm, configuration_option, security_policy, std::move(on_registration_complete),
                                 std::move(on_connection_open), handler);
  }
  TestDynamicChannelManager(TestDynamicChannelManagerImpl& impl) : impl_(impl) {}
  TestDynamicChannelManagerImpl& impl_;
};

class TestL2capClassicModule : public l2cap::classic::L2capClassicModule {
 public:
  std::unique_ptr<l2cap::classic::DynamicChannelManager> GetDynamicChannelManager() override {
    ASSERT(impl_ != nullptr);
    return std::make_unique<TestDynamicChannelManager>(*impl_);
  }

  void ListDependencies(ModuleList* list) override {}
  void Start() override;
  void Stop() override;

  std::unique_ptr<TestDynamicChannelManagerImpl> impl_;
};

void TestL2capClassicModule::Start() {
  impl_ = std::make_unique<TestDynamicChannelManagerImpl>();
}

void TestL2capClassicModule::Stop() {
  impl_.reset();
}

class ShimL2capTest : public ::testing::Test {
 public:
  void OnConnectionComplete(std::string string_address, uint16_t psm, uint16_t cid, bool connected) {}

  shim::L2cap* shim_l2cap_ = nullptr;
  TestL2capClassicModule* test_l2cap_classic_module_{nullptr};

 protected:
  void SetUp() override {
    handler_ = new os::Handler(&thread_);

    test_l2cap_classic_module_ = new TestL2capClassicModule();
    test_l2cap_classic_module_->Start();
    fake_registry_.InjectTestModule(&l2cap::classic::L2capClassicModule::Factory, test_l2cap_classic_module_);

    fake_registry_.Start<shim::L2cap>(&thread_);
    shim_l2cap_ = static_cast<shim::L2cap*>(fake_registry_.GetModuleUnderTest(&shim::L2cap::Factory));
  }

  void TearDown() override {
    fake_registry_.StopAll();
    handler_->Clear();
    delete handler_;
  }
  os::Handler* handler_ = nullptr;
  l2cap::classic::internal::testing::MockDynamicChannelServiceManagerImpl mock_;

 private:
  TestModuleRegistry fake_registry_;
  os::Thread& thread_ = fake_registry_.GetTestThread();
};

TEST_F(ShimL2capTest, Module) {}

TEST_F(ShimL2capTest, ConnectThenDisconnectBeforeCompletion) {
  std::promise<uint16_t> promise;
  auto future = promise.get_future();

  test_l2cap_classic_module_->impl_->connected_promise_ = new std::promise<void>();
  auto connection_started = test_l2cap_classic_module_->impl_->connected_promise_->get_future();

  shim_l2cap_->CreateConnection(
      kPsm, device_address,
      std::bind(&bluetooth::shim::ShimL2capTest::OnConnectionComplete, this, std::placeholders::_1,
                std::placeholders::_2, std::placeholders::_3, std::placeholders::_4),
      std::move(promise));
  uint16_t cid = future.get();

  ASSERT(cid != 0);

  connection_started.wait();

  ASSERT(test_l2cap_classic_module_->impl_->connections_ == 1);

  shim_l2cap_->CloseConnection(cid);
}

TEST_F(ShimL2capTest, RegisterService_Success) {
  std::promise<uint16_t> promise;
  auto future = promise.get_future();

  test_l2cap_classic_module_->impl_->registered_promise_ = new std::promise<void>();
  auto registration_started = test_l2cap_classic_module_->impl_->registered_promise_->get_future();

  shim_l2cap_->RegisterService(
      kPsm, false, 1000,
      std::bind(&bluetooth::shim::ShimL2capTest::OnConnectionComplete, this, std::placeholders::_1,
                std::placeholders::_2, std::placeholders::_3, std::placeholders::_4),
      std::move(promise));

  l2cap::classic::DynamicChannelManager::RegistrationResult result{
      l2cap::classic::DynamicChannelManager::RegistrationResult::SUCCESS,
  };
  auto service = std::make_unique<TestDynamicChannelService>(kPsm, &mock_, handler_);
  registration_started.wait();

  ASSERT_LOG(test_l2cap_classic_module_->impl_->on_registration_complete_, "Synchronization failure");
  handler_->Post(common::BindOnce(std::move(test_l2cap_classic_module_->impl_->on_registration_complete_), result,
                                  std::move(service)));
  uint16_t psm = future.get();
  ASSERT(psm == kPsm);
  ASSERT(test_l2cap_classic_module_->impl_->services_ == 1);
}

TEST_F(ShimL2capTest, RegisterService_Duplicate) {
  std::promise<uint16_t> promise;
  auto future = promise.get_future();

  test_l2cap_classic_module_->impl_->registered_promise_ = new std::promise<void>();
  auto registration_started = test_l2cap_classic_module_->impl_->registered_promise_->get_future();

  shim_l2cap_->RegisterService(
      kPsm, false, 1000,
      std::bind(&bluetooth::shim::ShimL2capTest::OnConnectionComplete, this, std::placeholders::_1,
                std::placeholders::_2, std::placeholders::_3, std::placeholders::_4),
      std::move(promise));

  l2cap::classic::DynamicChannelManager::RegistrationResult result{
      l2cap::classic::DynamicChannelManager::RegistrationResult::FAIL_DUPLICATE_SERVICE,
  };
  auto service = std::make_unique<TestDynamicChannelService>(kPsm, &mock_, handler_);
  registration_started.wait();

  ASSERT_LOG(test_l2cap_classic_module_->impl_->on_registration_complete_, "Synchronization failure");
  handler_->Post(common::BindOnce(std::move(test_l2cap_classic_module_->impl_->on_registration_complete_), result,
                                  std::move(service)));
  uint16_t psm = future.get();
  ASSERT(psm == l2cap::kDefaultPsm);
  ASSERT(test_l2cap_classic_module_->impl_->services_ == 1);
}

TEST_F(ShimL2capTest, RegisterService_Invalid) {
  std::promise<uint16_t> promise;
  auto future = promise.get_future();

  test_l2cap_classic_module_->impl_->registered_promise_ = new std::promise<void>();
  auto registration_started = test_l2cap_classic_module_->impl_->registered_promise_->get_future();

  shim_l2cap_->RegisterService(
      kPsm, false, 1000,
      std::bind(&bluetooth::shim::ShimL2capTest::OnConnectionComplete, this, std::placeholders::_1,
                std::placeholders::_2, std::placeholders::_3, std::placeholders::_4),
      std::move(promise));

  l2cap::classic::DynamicChannelManager::RegistrationResult result{
      l2cap::classic::DynamicChannelManager::RegistrationResult::FAIL_INVALID_SERVICE,
  };
  auto service = std::make_unique<TestDynamicChannelService>(kPsm, &mock_, handler_);
  registration_started.wait();

  ASSERT_LOG(test_l2cap_classic_module_->impl_->on_registration_complete_, "Synchronization failure");
  handler_->Post(common::BindOnce(std::move(test_l2cap_classic_module_->impl_->on_registration_complete_), result,
                                  std::move(service)));
  uint16_t psm = future.get();
  ASSERT(psm == l2cap::kDefaultPsm);
  ASSERT(test_l2cap_classic_module_->impl_->services_ == 1);
}

}  // namespace
}  // namespace shim
}  // namespace bluetooth
