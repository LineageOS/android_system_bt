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

#include "timer.h"
#include "message_loop_thread.h"
#include "time_util.h"

namespace bluetooth {

namespace common {

constexpr base::TimeDelta kMinimumPeriod = base::TimeDelta::FromMicroseconds(1);

Timer::~Timer() {
  std::lock_guard<std::recursive_mutex> api_lock(api_mutex_);
  if (message_loop_thread_ != nullptr && message_loop_thread_->IsRunning()) {
    CancelAndWait();
  }
}

// This runs on user thread
bool Timer::Schedule(const base::WeakPtr<MessageLoopThread>& thread,
                     const tracked_objects::Location& from_here,
                     base::Closure task, base::TimeDelta delay) {
  return ScheduleTaskHelper(thread, from_here, std::move(task), delay, false);
}

// This runs on user thread
bool Timer::SchedulePeriodic(const base::WeakPtr<MessageLoopThread>& thread,
                             const tracked_objects::Location& from_here,
                             base::Closure task, base::TimeDelta period) {
  if (period < kMinimumPeriod) {
    LOG(ERROR) << __func__ << ": period must be at least " << kMinimumPeriod;
    return false;
  }
  return ScheduleTaskHelper(thread, from_here, std::move(task), period, true);
}

// This runs on user thread
bool Timer::ScheduleTaskHelper(const base::WeakPtr<MessageLoopThread>& thread,
                               const tracked_objects::Location& from_here,
                               base::Closure task, base::TimeDelta delay,
                               bool is_periodic) {
  uint64_t time_now_us = time_get_os_boottime_us();
  uint64_t time_next_task_us = time_now_us + delay.InMicroseconds();
  std::lock_guard<std::recursive_mutex> api_lock(api_mutex_);
  if (thread == nullptr) {
    LOG(ERROR) << __func__ << ": thread must be non-null";
    return false;
  }
  CancelAndWait();
  expected_time_next_task_us_ = time_next_task_us;
  task_ = std::move(task);
  uint64_t time_until_next_us = time_next_task_us - time_get_os_boottime_us();
  if (!thread->DoInThreadDelayed(
          from_here, task_wrapper_,
          base::TimeDelta::FromMicroseconds(time_until_next_us))) {
    LOG(ERROR) << __func__
               << ": failed to post task to message loop for thread " << *thread
               << ", from " << from_here.ToString();
    expected_time_next_task_us_ = 0;
    task_.Reset();
    return false;
  }
  message_loop_thread_ = thread;
  period_ = delay;
  is_periodic_ = is_periodic;
  return true;
}

// This runs on user thread
void Timer::Cancel() {
  std::lock_guard<std::recursive_mutex> api_lock(api_mutex_);
  CancelHelper(false);
}

// This runs on user thread
void Timer::CancelAndWait() {
  std::lock_guard<std::recursive_mutex> api_lock(api_mutex_);
  CancelHelper(true);
}

// This runs on user thread
void Timer::CancelHelper(bool is_synchronous) {
  if (message_loop_thread_ == nullptr) {
    return;
  }
  std::promise<void> promise;
  auto future = promise.get_future();
  if (message_loop_thread_->GetThreadId() ==
      base::PlatformThread::CurrentId()) {
    CancelClosure(std::move(promise));
    return;
  }
  message_loop_thread_->DoInThread(
      FROM_HERE, base::BindOnce(&Timer::CancelClosure, base::Unretained(this),
                                std::move(promise)));
  if (is_synchronous) {
    future.wait();
  }
}

// This runs on message loop thread
void Timer::CancelClosure(std::promise<void> promise) {
  message_loop_thread_ = nullptr;
  task_.Reset();
  period_ = base::TimeDelta();
  is_periodic_ = false;
  expected_time_next_task_us_ = 0;
  promise.set_value();
}

// This runs in user thread
bool Timer::IsScheduled() const {
  std::lock_guard<std::recursive_mutex> api_lock(api_mutex_);
  return message_loop_thread_ != nullptr && message_loop_thread_->IsRunning();
}

// This runs in message loop thread
void Timer::RunTask() {
  if (message_loop_thread_ == nullptr || !message_loop_thread_->IsRunning()) {
    LOG(ERROR) << __func__
               << ": message_loop_thread_ is null or is not running";
    return;
  }
  if (is_periodic_) {
    int64_t period_us = period_.InMicroseconds();
    expected_time_next_task_us_ += period_us;
    uint64_t time_now_us = time_get_os_boottime_us();
    int64_t remaining_time_us = expected_time_next_task_us_ - time_now_us;
    if (remaining_time_us < 0) {
      // if remaining_time_us is negative, schedule the task to the nearest
      // multiple of period
      remaining_time_us =
          (remaining_time_us % period_us + period_us) % period_us;
    }
    message_loop_thread_->DoInThreadDelayed(
        FROM_HERE, task_wrapper_,
        base::TimeDelta::FromMicroseconds(remaining_time_us));
  }
  uint64_t time_before_task_us = time_get_os_boottime_us();
  task_.Run();
  uint64_t time_after_task_us = time_get_os_boottime_us();
  int64_t task_time_us =
      static_cast<int64_t>(time_after_task_us - time_before_task_us);
  if (is_periodic_ && task_time_us > period_.InMicroseconds()) {
    LOG(ERROR) << __func__ << ": Periodic task execution took " << task_time_us
               << " microseconds, longer than interval "
               << period_.InMicroseconds() << " microseconds";
  }
  if (!is_periodic_) {
    message_loop_thread_ = nullptr;
    task_.Reset();
    period_ = base::TimeDelta();
    expected_time_next_task_us_ = 0;
  }
}

}  // namespace common

}  // namespace bluetooth
