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

#include "os/handler.h"

#include <sys/eventfd.h>

#include <future>
#include <thread>

#include "gtest/gtest.h"
#include "os/log.h"

namespace bluetooth {
namespace os {
namespace {

class HandlerTest : public ::testing::Test {
 protected:
  void SetUp() override {
    thread_ = new Thread("test_thread", Thread::Priority::NORMAL);
    handler_ = new Handler(thread_);
  }
  void TearDown() override {
    delete handler_;
    delete thread_;
  }

  Handler* handler_;
  Thread* thread_;
};

TEST_F(HandlerTest, empty) {
  handler_->Clear();
}

TEST_F(HandlerTest, post_task_invoked) {
  int val = 0;
  std::promise<void> closure_ran;
  Closure closure = [&val, &closure_ran]() {
    val++;
    closure_ran.set_value();
  };
  handler_->Post(closure);
  closure_ran.get_future().wait();
  ASSERT_EQ(val, 1);
  handler_->Clear();
}

TEST_F(HandlerTest, post_task_cleared) {
  int val = 0;
  std::promise<void> closure_started;
  std::promise<void> closure_can_continue;
  auto can_continue_future = closure_can_continue.get_future();
  handler_->Post([&val, &can_continue_future, &closure_started]() {
    closure_started.set_value();
    val++;
    can_continue_future.wait();
  });
  handler_->Post([]() { ASSERT_TRUE(false); });
  closure_started.get_future().wait();
  handler_->Clear();
  closure_can_continue.set_value();
  ASSERT_EQ(val, 1);
}

// For Death tests, all the threading needs to be done in the ASSERT_DEATH call
class HandlerDeathTest : public ::testing::Test {
 protected:
  void ThreadSetUp() {
    thread_ = new Thread("test_thread", Thread::Priority::NORMAL);
    handler_ = new Handler(thread_);
  }

  void ThreadTearDown() {
    delete handler_;
    delete thread_;
  }

  void ClearTwice() {
    ThreadSetUp();
    handler_->Clear();
    handler_->Clear();
    ThreadTearDown();
  }

  void NotCleared() {
    ThreadSetUp();
    ThreadTearDown();
  }

  Handler* handler_;
  Thread* thread_;
};

TEST_F(HandlerDeathTest, clear_after_handler_cleared) {
  ASSERT_DEATH(ClearTwice(), "Handlers must only be cleared once");
}

TEST_F(HandlerDeathTest, not_cleared_before_destruction) {
  ASSERT_DEATH(NotCleared(), "Handlers must be cleared");
}

}  // namespace
}  // namespace os
}  // namespace bluetooth
