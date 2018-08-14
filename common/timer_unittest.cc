/*
 * Copyright 2018 The Android Open Source Project
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

#include <base/bind.h>
#include <base/logging.h>
#include <gtest/gtest.h>
#include <future>

#include "message_loop_thread.h"
#include "timer.h"

using bluetooth::common::MessageLoopThread;
using bluetooth::common::Timer;

// Allowed error between the expected and actual delay for DoInThreadDelayed().
constexpr uint32_t delay_error_ms = 3;

/**
 * Unit tests to verify Task Scheduler.
 */
class TimerTest : public ::testing::Test {
 public:
  void ShouldNotHappen() { FAIL() << "Should not happen"; }

  void IncreaseTaskCounter(int scheduled_tasks, std::promise<void>* promise) {
    counter_++;
    if (counter_ == scheduled_tasks) {
      promise->set_value();
    }
  }

  void GetName(std::string* name, std::promise<void>* promise) {
    char my_name[256];
    pthread_getname_np(pthread_self(), my_name, sizeof(my_name));
    name->append(my_name);
    promise->set_value();
  }

  void SleepAndGetName(std::string* name, std::promise<void>* name_promise,
                       int sleep_ms) {
    std::this_thread::sleep_for(std::chrono::milliseconds(sleep_ms));
    GetName(name, name_promise);
  }

  void VerifyDelayTimeAndSleep(std::chrono::steady_clock::time_point start_time,
                               int interval_ms, int scheduled_tasks,
                               int task_length_ms,
                               std::promise<void>* promise) {
    auto end_time = std::chrono::steady_clock::now();
    auto actual_delay = std::chrono::duration_cast<std::chrono::milliseconds>(
        end_time - start_time);
    counter_++;
    int64_t scheduled_delay_ms = interval_ms * counter_;
    if (counter_ >= scheduled_tasks) {
      promise->set_value();
    }
    ASSERT_NEAR(scheduled_delay_ms, actual_delay.count(), delay_error_ms);
    std::this_thread::sleep_for(std::chrono::milliseconds(task_length_ms));
  }

  void VerifyMultipleDelayedTasks(int scheduled_tasks, int task_length_ms,
                                  int interval_between_tasks_ms) {
    std::string name = "test_thread";
    MessageLoopThread message_loop_thread(name);
    message_loop_thread.StartUp();
    message_loop_thread.EnableRealTimeScheduling();
    auto future = promise_->get_future();
    auto start_time = std::chrono::steady_clock::now();
    timer_->SchedulePeriodic(
        message_loop_thread.GetWeakPtr(), FROM_HERE,
        base::Bind(&TimerTest::VerifyDelayTimeAndSleep, base::Unretained(this),
                   start_time, interval_between_tasks_ms, scheduled_tasks,
                   task_length_ms, promise_),
        base::TimeDelta::FromMilliseconds(interval_between_tasks_ms));
    future.get();
    timer_->CancelAndWait();
  }

  void CancelTimerAndWait() { timer_->CancelAndWait(); }

 protected:
  void SetUp() override {
    ::testing::Test::SetUp();
    counter_ = 0;
    timer_ = new Timer();
    promise_ = new std::promise<void>();
  }

  void TearDown() override {
    if (promise_ != nullptr) {
      delete promise_;
      promise_ = nullptr;
    }
    if (timer_ != nullptr) {
      delete timer_;
      timer_ = nullptr;
    }
  }

  int counter_;
  Timer* timer_;
  std::promise<void>* promise_;
};

TEST_F(TimerTest, initial_is_not_scheduled) {
  ASSERT_FALSE(timer_->IsScheduled());
}

TEST_F(TimerTest, schedule_task) {
  std::string name = "test_thread";
  MessageLoopThread message_loop_thread(name);
  message_loop_thread.StartUp();
  auto future = promise_->get_future();
  std::string my_name;
  uint32_t delay_ms = 5;

  timer_->Schedule(message_loop_thread.GetWeakPtr(), FROM_HERE,
                   base::Bind(&TimerTest::GetName, base::Unretained(this),
                              &my_name, promise_),
                   base::TimeDelta::FromMilliseconds(delay_ms));
  EXPECT_TRUE(timer_->IsScheduled());
  future.get();
  ASSERT_EQ(name, my_name);
  EXPECT_FALSE(timer_->IsScheduled());
}

TEST_F(TimerTest, cancel_without_scheduling) {
  std::string name = "test_thread";
  MessageLoopThread message_loop_thread(name);
  message_loop_thread.StartUp();

  EXPECT_FALSE(timer_->IsScheduled());
  timer_->CancelAndWait();
  EXPECT_FALSE(timer_->IsScheduled());
}

TEST_F(TimerTest, cancel_in_callback_no_deadlock) {
  std::string name = "test_thread";
  MessageLoopThread message_loop_thread(name);
  message_loop_thread.StartUp();
  uint32_t delay_ms = 5;

  timer_->Schedule(
      message_loop_thread.GetWeakPtr(), FROM_HERE,
      base::Bind(&TimerTest::CancelTimerAndWait, base::Unretained(this)),
      base::TimeDelta::FromMilliseconds(delay_ms));
}

TEST_F(TimerTest, periodic_run) {
  std::string name = "test_thread";
  MessageLoopThread message_loop_thread(name);
  message_loop_thread.StartUp();
  auto future = promise_->get_future();
  uint32_t delay_ms = 5;
  int num_tasks = 200;

  timer_->SchedulePeriodic(
      message_loop_thread.GetWeakPtr(), FROM_HERE,
      base::Bind(&TimerTest::IncreaseTaskCounter, base::Unretained(this),
                 num_tasks, promise_),
      base::TimeDelta::FromMilliseconds(delay_ms));
  future.get();
  ASSERT_EQ(counter_, num_tasks);
  timer_->CancelAndWait();
}

TEST_F(TimerTest, schedule_periodic_task_zero_interval) {
  std::string name = "test_thread";
  MessageLoopThread message_loop_thread(name);
  message_loop_thread.StartUp();
  uint32_t interval_ms = 0;

  ASSERT_FALSE(timer_->SchedulePeriodic(
      message_loop_thread.GetWeakPtr(), FROM_HERE,
      base::Bind(&TimerTest::ShouldNotHappen, base::Unretained(this)),
      base::TimeDelta::FromMilliseconds(interval_ms)));
  std::this_thread::sleep_for(std::chrono::milliseconds(delay_error_ms));
}

// Verify that deleting the timer without cancelling it will cancel the task
TEST_F(TimerTest, periodic_delete_without_cancel) {
  std::string name = "test_thread";
  MessageLoopThread message_loop_thread(name);
  message_loop_thread.StartUp();
  uint32_t delay_ms = 5;
  timer_->SchedulePeriodic(
      message_loop_thread.GetWeakPtr(), FROM_HERE,
      base::Bind(&TimerTest::ShouldNotHappen, base::Unretained(this)),
      base::TimeDelta::FromMilliseconds(delay_ms));
  delete timer_;
  timer_ = nullptr;
  std::this_thread::sleep_for(std::chrono::milliseconds(delay_error_ms));
}

TEST_F(TimerTest, cancel_single_task) {
  std::string name = "test_thread";
  MessageLoopThread message_loop_thread(name);
  message_loop_thread.StartUp();
  uint32_t delay_ms = 5;
  uint32_t time_cancellation_ms = 3;
  timer_->SchedulePeriodic(
      message_loop_thread.GetWeakPtr(), FROM_HERE,
      base::Bind(&TimerTest::ShouldNotHappen, base::Unretained(this)),
      base::TimeDelta::FromMilliseconds(delay_ms));
  std::this_thread::sleep_for(std::chrono::milliseconds(time_cancellation_ms));
  timer_->Cancel();
  std::this_thread::sleep_for(std::chrono::milliseconds(delay_error_ms));
}

TEST_F(TimerTest, cancel_periodic_task) {
  std::string name = "test_thread";
  MessageLoopThread message_loop_thread(name);
  message_loop_thread.StartUp();
  uint32_t delay_ms = 5;
  uint32_t time_cancellation_ms = 3;
  timer_->SchedulePeriodic(
      message_loop_thread.GetWeakPtr(), FROM_HERE,
      base::Bind(&TimerTest::ShouldNotHappen, base::Unretained(this)),
      base::TimeDelta::FromMilliseconds(delay_ms));
  std::this_thread::sleep_for(std::chrono::milliseconds(time_cancellation_ms));
  timer_->CancelAndWait();
  std::this_thread::sleep_for(std::chrono::milliseconds(delay_error_ms));
}

// Verify that if a task is being executed, then cancelling it is no-op
TEST_F(TimerTest, cancel_current_task_no_effect) {
  std::string name = "test_thread";
  MessageLoopThread message_loop_thread(name);
  message_loop_thread.StartUp();
  auto future = promise_->get_future();
  std::string my_name;
  uint32_t delay_ms = 5;

  timer_->Schedule(
      message_loop_thread.GetWeakPtr(), FROM_HERE,
      base::Bind(&TimerTest::SleepAndGetName, base::Unretained(this), &my_name,
                 promise_, delay_ms),
      base::TimeDelta::FromMilliseconds(delay_ms));
  EXPECT_TRUE(timer_->IsScheduled());
  std::this_thread::sleep_for(
      std::chrono::milliseconds(delay_ms + delay_error_ms));
  timer_->CancelAndWait();
  future.get();
  ASSERT_EQ(name, my_name);
  EXPECT_FALSE(timer_->IsScheduled());
}

// Schedule 10 short periodic tasks with interval 1 ms between each; verify the
// functionality
TEST_F(TimerTest, schedule_multiple_delayed_tasks) {
  VerifyMultipleDelayedTasks(10, 0, 1);
}

// Schedule 10 periodic tasks with interval 2 ms between each and each takes 1
// ms; verify the functionality
TEST_F(TimerTest, schedule_multiple_delayed_slow_tasks) {
  VerifyMultipleDelayedTasks(10, 1, 2);
}

// Schedule 100 periodic tasks with interval 20 ms between each and each takes
// 10 ms; verify the functionality
TEST_F(TimerTest, schedule_multiple_delayed_slow_tasks_stress) {
  VerifyMultipleDelayedTasks(100, 10, 20);
}

// Verify that when MessageLoopThread is shutdown, the pending task will be
// cancelled
TEST_F(TimerTest, message_loop_thread_down_cancel_pending_task) {
  std::string name = "test_thread";
  MessageLoopThread message_loop_thread(name);
  message_loop_thread.StartUp();
  std::string my_name;
  uint32_t delay_ms = 5;

  timer_->Schedule(
      message_loop_thread.GetWeakPtr(), FROM_HERE,
      base::Bind(&TimerTest::ShouldNotHappen, base::Unretained(this)),
      base::TimeDelta::FromMilliseconds(delay_ms));
  EXPECT_TRUE(timer_->IsScheduled());
  std::this_thread::sleep_for(std::chrono::milliseconds(delay_ms - 3));
  message_loop_thread.ShutDown();
  std::this_thread::sleep_for(std::chrono::milliseconds(delay_ms));
}

// Verify that when MessageLoopThread is shutdown, the pending periodic task
// will be cancelled
TEST_F(TimerTest, message_loop_thread_down_cancel_pending_periodic_task) {
  std::string name = "test_thread";
  MessageLoopThread message_loop_thread(name);
  message_loop_thread.StartUp();
  uint32_t delay_ms = 5;

  timer_->Schedule(
      message_loop_thread.GetWeakPtr(), FROM_HERE,
      base::Bind(&TimerTest::ShouldNotHappen, base::Unretained(this)),
      base::TimeDelta::FromMilliseconds(delay_ms));
  EXPECT_TRUE(timer_->IsScheduled());
  std::this_thread::sleep_for(std::chrono::milliseconds(delay_ms - 2));
  message_loop_thread.ShutDown();
  timer_->CancelAndWait();
  EXPECT_FALSE(timer_->IsScheduled());
  std::this_thread::sleep_for(std::chrono::milliseconds(delay_ms));
}

TEST_F(TimerTest, schedule_task_cancel_previous_task) {
  std::string name = "test_thread";
  MessageLoopThread message_loop_thread(name);
  message_loop_thread.StartUp();
  std::string my_name;
  auto future = promise_->get_future();
  uint32_t delay_ms = 5;

  timer_->SchedulePeriodic(
      message_loop_thread.GetWeakPtr(), FROM_HERE,
      base::Bind(&TimerTest::ShouldNotHappen, base::Unretained(this)),
      base::TimeDelta::FromMilliseconds(delay_ms));
  std::this_thread::sleep_for(std::chrono::milliseconds(delay_ms - 2));
  timer_->Schedule(message_loop_thread.GetWeakPtr(), FROM_HERE,
                   base::Bind(&TimerTest::GetName, base::Unretained(this),
                              &my_name, promise_),
                   base::TimeDelta::FromMilliseconds(delay_ms));
  future.wait();
  ASSERT_EQ(name, my_name);
}
