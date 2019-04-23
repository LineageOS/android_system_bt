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

#include "stack_manager.h"

#include <chrono>
#include <future>
#include <queue>

#include "hal/hci_hal.h"
#include "os/handler.h"
#include "os/log.h"

using ::bluetooth::hal::BluetoothHciHalCallbacks;
using ::bluetooth::hal::BluetoothInitializationCompleteCallback;
using ::bluetooth::hal::HciPacket;
using ::bluetooth::hal::Status;
using ::bluetooth::os::Handler;
using ::bluetooth::os::Thread;

namespace bluetooth {
namespace {
std::promise<void>* startup_promise;

class InitCallback : public BluetoothInitializationCompleteCallback {
 public:
  void initializationComplete(Status status) override {
    ASSERT(status == Status::SUCCESS);
    startup_promise->set_value();
  }
} init_callback;

Thread* main_thread_;

}  // namespace

void StackManager::StartUp() {
  startup_promise = new std::promise<void>;
  ::bluetooth::hal::GetBluetoothHciHal()->initialize(&init_callback);
  auto init_status = startup_promise->get_future().wait_for(std::chrono::seconds(3));
  ASSERT_LOG(init_status == std::future_status::ready, "Can't initialize HCI HAL");
  delete startup_promise;

  main_thread_ = new Thread("main_thread", Thread::Priority::NORMAL);

  LOG_INFO("init complete");
  // Bring up HCI layer
}

void StackManager::ShutDown() {
  // Delete HCI layer
  delete main_thread_;
  main_thread_ = nullptr;
  ::bluetooth::hal::GetBluetoothHciHal()->close();
}
}  // namespace bluetooth
