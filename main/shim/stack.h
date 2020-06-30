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

#pragma once

#include "main/shim/btm.h"

#include "gd/os/handler.h"
#include "gd/os/thread.h"
#include "gd/os/utils.h"
#include "gd/stack_manager.h"

// The shim layer implementation on the Gd stack side.
namespace bluetooth {
namespace shim {

class Stack {
 public:
  static Stack* GetInstance();

  Stack() = default;
  ~Stack() = default;

  void Start();
  void Stop();
  bool IsRunning();

  StackManager* GetStackManager();
  Btm* GetBtm();
  os::Handler* GetHandler();

  DISALLOW_COPY_AND_ASSIGN(Stack);

 private:
  StackManager stack_manager_;
  bool is_running_ = false;
  os::Thread* stack_thread_ = nullptr;
  os::Handler* stack_handler_ = nullptr;
  Btm* btm_ = nullptr;
};

}  // namespace shim
}  // namespace bluetooth
