/*
 * Copyright 2019 The Android Open Source Project
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

#include "hal/hci_hal.h"

#include <chrono>
#include <future>

#include <gtest/gtest.h>

namespace bluetooth {
namespace hal {
namespace {

std::promise<void>* g_promise;

class TestBluetoothInitializationCompleteCallback : public BluetoothInitializationCompleteCallback {
 public:
  void initializationComplete(Status status) override {
    EXPECT_EQ(status, Status::SUCCESS);
    g_promise->set_value();
  }
};

class HciHalHidlTest : public ::testing::Test {
 protected:
  void SetUp() override {
    g_promise = new std::promise<void>;
    hal_ = GetBluetoothHciHal();
    hal_->initialize(&init_callback_);
  }

  void TearDown() override {
    hal_->close();
    hal_ = nullptr;
    delete g_promise;
  }

  BluetoothHciHal* hal_ = nullptr;
  TestBluetoothInitializationCompleteCallback init_callback_;
};

TEST_F(HciHalHidlTest, init_and_close) {
  // Give a long timeout because this only checks HAL is initialized, not performance
  auto wait_status = g_promise->get_future().wait_for(std::chrono::seconds(30));
  EXPECT_EQ(wait_status, std::future_status::ready);
}
}  // namespace
}  // namespace hal
}  // namespace bluetooth
