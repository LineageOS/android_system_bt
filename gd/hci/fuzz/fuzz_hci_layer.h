/*
 * Copyright 2020 The Android Open Source Project
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

#include "hci/command_interface.h"
#include "hci/hci_layer.h"
#include "os/fuzz/dev_null_queue.h"
#include "os/fuzz/fuzz_inject_queue.h"

#include <fuzzer/FuzzedDataProvider.h>

namespace bluetooth {
namespace hci {
namespace fuzz {

template <typename T>
class FuzzCommandInterface : public CommandInterface<T> {
 public:
  void EnqueueCommand(std::unique_ptr<T> command,
                      common::ContextualOnceCallback<void(hci::CommandCompleteView)> on_complete) override {}

  void EnqueueCommand(std::unique_ptr<T> command,
                      common::ContextualOnceCallback<void(hci::CommandStatusView)> on_status) override {}
};

class FuzzHciLayer : public HciLayer {
 public:
  void EnqueueCommand(std::unique_ptr<hci::CommandPacketBuilder> command,
                      common::ContextualOnceCallback<void(hci::CommandCompleteView)> on_complete) override {}

  void EnqueueCommand(std::unique_ptr<CommandPacketBuilder> command,
                      common::ContextualOnceCallback<void(hci::CommandStatusView)> on_status) override {}

  common::BidiQueueEnd<hci::AclPacketBuilder, hci::AclPacketView>* GetAclQueueEnd() override;

  void RegisterEventHandler(hci::EventCode event_code,
                            common::ContextualCallback<void(hci::EventPacketView)> event_handler) override {}

  void UnregisterEventHandler(hci::EventCode event_code) override {}

  void RegisterLeEventHandler(hci::SubeventCode subevent_code,
                              common::ContextualCallback<void(hci::LeMetaEventView)> event_handler) override {}

  void UnregisterLeEventHandler(hci::SubeventCode subevent_code) override {}

  hci::SecurityInterface* GetSecurityInterface(
      common::ContextualCallback<void(hci::EventPacketView)> event_handler) override;

  hci::LeSecurityInterface* GetLeSecurityInterface(
      common::ContextualCallback<void(hci::LeMetaEventView)> event_handler) override;

  hci::AclConnectionInterface* GetAclConnectionInterface(
      common::ContextualCallback<void(hci::EventPacketView)> event_handler,
      common::ContextualCallback<void(uint16_t, hci::ErrorCode)> on_disconnect) override;

  hci::LeAclConnectionInterface* GetLeAclConnectionInterface(
      common::ContextualCallback<void(hci::LeMetaEventView)> event_handler,
      common::ContextualCallback<void(uint16_t, hci::ErrorCode)> on_disconnect) override;

  hci::LeAdvertisingInterface* GetLeAdvertisingInterface(
      common::ContextualCallback<void(hci::LeMetaEventView)> event_handler) override;

  hci::LeScanningInterface* GetLeScanningInterface(
      common::ContextualCallback<void(hci::LeMetaEventView)> event_handler) override;

  void injectArbitrary(FuzzedDataProvider& fdp);

  std::string ToString() const override {
    return "FuzzHciLayer";
  }

  static const ModuleFactory Factory;

 protected:
  void ListDependencies(ModuleList* list) override {}
  void Start() override;
  void Stop() override;

 private:
  void injectAclData(std::vector<uint8_t> data);

  common::BidiQueue<hci::AclPacketView, hci::AclPacketBuilder> acl_queue_{3};
  os::fuzz::DevNullQueue<AclPacketBuilder>* acl_dev_null_;
  os::fuzz::FuzzInjectQueue<AclPacketView>* acl_inject_;

  FuzzCommandInterface<ConnectionManagementCommandBuilder> acl_connection_interface_{};
  FuzzCommandInterface<LeConnectionManagementCommandBuilder> le_acl_connection_interface_{};
  FuzzCommandInterface<SecurityCommandBuilder> security_interface_{};
  FuzzCommandInterface<LeSecurityCommandBuilder> le_security_interface_{};
  FuzzCommandInterface<LeAdvertisingCommandBuilder> le_advertising_interface_{};
  FuzzCommandInterface<LeScanningCommandBuilder> le_scanning_interface_{};
};

}  // namespace fuzz
}  // namespace hci
}  // namespace bluetooth
