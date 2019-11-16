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

#include "shim/iadvertising.h"
#include "shim/iconnectability.h"
#include "shim/icontroller.h"
#include "shim/idiscoverability.h"
#include "shim/ihci_layer.h"
#include "shim/iinquiry.h"
#include "shim/il2cap.h"
#include "shim/iname.h"
#include "shim/ipage.h"
#include "shim/iscanning.h"
#include "shim/istack.h"

/**
 * The shim layer implementation on the Gd stack side.
 */
namespace bluetooth {
namespace shim {

class Stack : public IStack {
 public:
  Stack();
  ~Stack() = default;

  void Start() override;  // IStack
  void Stop() override;   // IStack

  IAdvertising* GetAdvertising() override;  // IStack
  IController* GetController() override;  // IStack
  IConnectability* GetConnectability() override;  // IStack
  IHciLayer* GetHciLayer() override;      // IStack
  IDiscoverability* GetDiscoverability() override;  // IStack
  IInquiry* GetInquiry() override;                  // IStack
  IName* GetName() override;                        // IStack
  IL2cap* GetL2cap() override;                      // IStack
  IPage* GetPage() override;                        // IStack
  IScanning* GetScanning() override;                // IStack

 private:
  struct impl;
  std::unique_ptr<impl> pimpl_;

  Stack(const Stack&) = delete;
  void operator=(const Stack&) = delete;
};

}  // namespace shim
}  // namespace bluetooth
