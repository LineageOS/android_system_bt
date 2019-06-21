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

#include "common/address.h"
#include "common/callback.h"
#include "hci/hci_packets.h"
#include "module.h"
#include "os/handler.h"

namespace bluetooth {
namespace hci {

class Controller : public Module {
 public:
  Controller();
  virtual ~Controller();
  DISALLOW_COPY_AND_ASSIGN(Controller);

  virtual void RegisterCompletedAclPacketsCallback(
      common::Callback<void(uint16_t /* handle */, uint16_t /* num_packets */)> cb, os::Handler* handler);

  virtual uint16_t GetControllerAclPacketLength();

  virtual uint16_t GetControllerNumAclPacketBuffers();

  virtual uint8_t GetControllerScoPacketLength();

  virtual uint16_t GetControllerNumScoPacketBuffers();

  virtual common::Address GetControllerMacAddress();

  static const ModuleFactory Factory;

 protected:
  void ListDependencies(ModuleList* list) override;

  void Start() override;

  void Stop() override;

 private:
  struct impl;
  std::unique_ptr<impl> impl_;
};

}  // namespace hci
}  // namespace bluetooth
