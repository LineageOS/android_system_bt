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
#include "os/thread.h"
#include "os/handler.h"
#include "os/log.h"
#include "module.h"

using ::bluetooth::os::Handler;
using ::bluetooth::os::Thread;

namespace bluetooth {

void StackManager::StartUp(ModuleList* modules) {
  management_thread_ = new Thread("management_thread", Thread::Priority::NORMAL);
  handler_ = new Handler(management_thread_);

  std::promise<void>* promise = new std::promise<void>();
  handler_->Post([this, promise, modules]() {
    registry_.Start(modules);
    promise->set_value();
  });

  auto future = promise->get_future();
  auto init_status = future.wait_for(std::chrono::seconds(3));
  ASSERT_LOG(init_status == std::future_status::ready, "Can't start stack");
  delete promise;

  LOG_INFO("init complete");
}

void StackManager::ShutDown() {
  std::promise<void>* promise = new std::promise<void>();
  handler_->Post([this, promise]() {
    registry_.StopAll();
    promise->set_value();
  });

  auto future = promise->get_future();
  auto stop_status = future.wait_for(std::chrono::seconds(3));
  ASSERT_LOG(stop_status == std::future_status::ready, "Can't stop stack");

  delete promise;
  delete handler_;
  delete management_thread_;
}
}  // namespace bluetooth
