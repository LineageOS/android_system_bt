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

#include <memory>

#include "neighbor/discoverability.h"
#include "security/security_module.h"
#include "shim/advertising.h"
#include "shim/connectability.h"
#include "shim/dumpsys.h"
#include "shim/hci_layer.h"
#include "shim/inquiry.h"
#include "shim/l2cap.h"
#include "shim/name.h"
#include "shim/page.h"
#include "shim/scanning.h"
#include "shim/security.h"
#include "shim/storage.h"
#include "stack_manager.h"

/**
 * The shim layer implementation on the Gd stack side.
 */
namespace bluetooth {
namespace shim {

class Stack {
 public:
  Stack();
  ~Stack() = default;

  void Start();
  void Stop();

  StackManager* GetStackManager();

 private:
  struct impl;
  std::unique_ptr<impl> pimpl_;

  Stack(const Stack&) = delete;
  void operator=(const Stack&) = delete;
};

Stack* GetGabeldorscheStack();

}  // namespace shim
}  // namespace bluetooth
