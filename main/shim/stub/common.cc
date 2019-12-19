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

#include "main/shim/stub/common.h"
#include <base/callback.h>
#include <base/location.h>
#include <string>
#include "common/message_loop_thread.h"

bluetooth::common::MessageLoopThread::MessageLoopThread(
    const std::string& thread_name)
    : message_loop_(nullptr),
      run_loop_(nullptr),
      thread_(nullptr),
      thread_id_(-1),
      linux_tid_(-1),
      weak_ptr_factory_(this),
      shutting_down_(false) {}

bool bluetooth::shim::stub::message_loop_thread_is_running_{true};
bool bluetooth::shim::stub::message_loop_thread_do_in_thread_{true};

bluetooth::common::MessageLoopThread::~MessageLoopThread() {}
void bluetooth::common::MessageLoopThread::StartUp() {}
bool bluetooth::common::MessageLoopThread::IsRunning() const {
  return bluetooth::shim::stub::message_loop_thread_is_running_;
}
void bluetooth::common::MessageLoopThread::ShutDown() {}
bool bluetooth::common::MessageLoopThread::DoInThread(
    base::Location const&, base::OnceCallback<void()>) {
  return bluetooth::shim::stub::message_loop_thread_do_in_thread_;
}
