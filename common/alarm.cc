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

#include "alarm.h"

#include <sys/timerfd.h>
#include <cstring>

#include "base/logging.h"
#include "utils.h"

namespace bluetooth {
namespace common {

Alarm::Alarm(Thread* thread)
  : thread_(thread),
    fd_(timerfd_create(CLOCK_BOOTTIME_ALARM, 0)) {
  CHECK_NE(fd_, -1) << __func__ << ": cannot create timerfd: " << strerror(errno);

  token_ = thread_->GetReactor()->Register(fd_, [this] { on_fire(); }, nullptr);
}

Alarm::~Alarm() {
  thread_->GetReactor()->Unregister(token_);

  int close_status;
  RUN_NO_INTR(close_status = close(fd_));
  CHECK_NE(close_status, -1) << __func__ << ": cannot close timerfd: " << strerror(errno);
}

void Alarm::Schedule(Closure task, std::chrono::milliseconds delay) {
  std::lock_guard<std::mutex> lock(mutex_);
  long delay_ms = delay.count();
  itimerspec timer_itimerspec{
    {/* interval for periodic timer */},
    {delay_ms / 1000, delay_ms % 1000 * 1000000}
  };
  int result = timerfd_settime(fd_, 0, &timer_itimerspec, nullptr);
  CHECK_EQ(result, 0) << __func__ << ": failed, error=" << strerror(errno);

  task_ = std::move(task);
}

void Alarm::Cancel() {
  std::lock_guard<std::mutex> lock(mutex_);
  itimerspec disarm_itimerspec{/* disarm timer */};
  int result = timerfd_settime(fd_, 0, &disarm_itimerspec, nullptr);
  CHECK_EQ(result, 0) << __func__ << ": failed, error=" << strerror(errno);
}

void Alarm::on_fire() {
  std::unique_lock<std::mutex> lock(mutex_);
  auto task = std::move(task_);
  uint64_t times_invoked;
  auto bytes_read = read(fd_, &times_invoked, sizeof(uint64_t));
  lock.unlock();
  task();
  CHECK_EQ(bytes_read, static_cast<ssize_t>(sizeof(uint64_t))) << __func__ << ": failed, error=" << strerror(errno);
  CHECK_EQ(times_invoked, static_cast<uint64_t>(1));
}

}  // namespace common
}  // namespace bluetooth
