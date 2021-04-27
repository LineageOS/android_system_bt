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

#include <mutex>

#include "main/shim/acl.h"
#include "main/shim/btm.h"
#include "main/shim/link_policy_interface.h"

#include "gd/module.h"
#include "gd/os/handler.h"
#include "gd/os/thread.h"
#include "gd/os/utils.h"
#include "gd/stack_manager.h"
#include "src/bridge.rs.h"

// The shim layer implementation on the Gd stack side.
namespace bluetooth {
namespace shim {

// GD shim stack, having modes corresponding to legacy stack
class Stack {
 public:
  static Stack* GetInstance();

  Stack() = default;
  ~Stack() = default;

  // Idle mode, config is loaded, but controller is not enabled
  void StartIdleMode();
  // Running mode, everything is up
  void StartEverything();

  void Stop();
  bool IsRunning();
  bool IsDumpsysModuleStarted() const;

  StackManager* GetStackManager();
  const StackManager* GetStackManager() const;

  legacy::Acl* GetAcl();
  LinkPolicyInterface* LinkPolicy();

  Btm* GetBtm();
  os::Handler* GetHandler();

  ::rust::Box<rust::Hci>* GetRustHci() { return rust_hci_; }
  ::rust::Box<rust::Controller>* GetRustController() {
    return rust_controller_;
  }

  DISALLOW_COPY_AND_ASSIGN(Stack);

 private:
  mutable std::recursive_mutex mutex_;
  StackManager stack_manager_;
  bool is_running_ = false;
  os::Thread* stack_thread_ = nullptr;
  os::Handler* stack_handler_ = nullptr;
  legacy::Acl* acl_ = nullptr;
  Btm* btm_ = nullptr;
  ::rust::Box<rust::Stack>* rust_stack_ = nullptr;
  ::rust::Box<rust::Hci>* rust_hci_ = nullptr;
  ::rust::Box<rust::Controller>* rust_controller_ = nullptr;

  void Start(ModuleList* modules);
};

}  // namespace shim
}  // namespace bluetooth
