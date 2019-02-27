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

#include "handler.h"

#include <sys/eventfd.h>
#include <cstring>

#include "base/logging.h"

#include "reactor.h"
#include "utils.h"

#ifndef EFD_SEMAPHORE
#define EFD_SEMAPHORE 1
#endif

namespace bluetooth {
namespace common {

Handler::Handler(Thread* thread)
  : thread_(thread),
    fd_(eventfd(0, EFD_SEMAPHORE | EFD_NONBLOCK)) {
  CHECK_NE(fd_, -1) << __func__ << ": cannot create eventfd: " << strerror(errno);

  reactable_ = thread_->GetReactor()->Register(fd_, [this] { this->handle_next_event(); }, nullptr);
}

Handler::~Handler() {
  thread_->GetReactor()->Unregister(reactable_);
  reactable_ = nullptr;

  int close_status;
  RUN_NO_INTR(close_status = close(fd_));
  CHECK_NE(close_status, -1) << __func__ << ": cannot close eventfd: " << strerror(errno);
}

void Handler::Post(Closure closure) {
  {
    std::lock_guard<std::mutex> lock(mutex_);
    tasks_.emplace(std::move(closure));
  }
  uint64_t val = 1;
  auto write_result = eventfd_write(fd_, val);
  CHECK_NE(write_result, -1) << __func__ << ": failed to write: " << strerror(errno);
}

void Handler::Clear() {
  std::lock_guard<std::mutex> lock(mutex_);

  std::queue<Closure> empty;
  std::swap(tasks_, empty);

  uint64_t val;
  while (eventfd_read(fd_, &val) == 0) {
  }
}

void Handler::handle_next_event() {
  Closure closure;
  uint64_t val = 0;
  auto read_result = eventfd_read(fd_, &val);
  CHECK_NE(read_result, -1) << __func__ << ": failed to read fd: " << strerror(errno);

  {
    std::lock_guard<std::mutex> lock(mutex_);
    closure = std::move(tasks_.front());
    tasks_.pop();
  }
  closure();
}

}  // namespace common
}  // namespace bluetooth
