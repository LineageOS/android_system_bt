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

#include <chrono>
#include <map>

#include "address.h"
#include "class_of_device.h"
#include "common/bidi_queue.h"
#include "common/callback.h"
#include "common/contextual_callback.h"
#include "hal/hci_hal.h"
#include "hci/acl_connection_interface.h"
#include "hci/hci_packets.h"
#include "hci/le_acl_connection_interface.h"
#include "hci/le_advertising_interface.h"
#include "hci/le_scanning_interface.h"
#include "hci/le_security_interface.h"
#include "hci/security_interface.h"
#include "module.h"
#include "os/utils.h"

namespace bluetooth {
namespace hci {

class HciLayer : public Module, public CommandInterface<CommandPacketBuilder> {
 public:
  HciLayer();
  virtual ~HciLayer();
  DISALLOW_COPY_AND_ASSIGN(HciLayer);

  void EnqueueCommand(std::unique_ptr<CommandPacketBuilder> command,
                      common::ContextualOnceCallback<void(CommandCompleteView)> on_complete) override;

  void EnqueueCommand(std::unique_ptr<CommandPacketBuilder> command,
                      common::ContextualOnceCallback<void(CommandStatusView)> on_status) override;

  virtual common::BidiQueueEnd<AclPacketBuilder, AclPacketView>* GetAclQueueEnd();

  virtual void RegisterEventHandler(EventCode event_code, common::Callback<void(EventPacketView)> event_handler,
                                    os::Handler* handler);

  virtual void UnregisterEventHandler(EventCode event_code);

  virtual void RegisterLeEventHandler(SubeventCode subevent_code, common::Callback<void(LeMetaEventView)> event_handler,
                                      os::Handler* handler);

  virtual void UnregisterLeEventHandler(SubeventCode subevent_code);

  virtual SecurityInterface* GetSecurityInterface(common::Callback<void(EventPacketView)> event_handler,
                                                  os::Handler* handler);

  virtual LeSecurityInterface* GetLeSecurityInterface(common::Callback<void(LeMetaEventView)> event_handler,
                                                      os::Handler* handler);

  virtual AclConnectionInterface* GetAclConnectionInterface(
      common::Callback<void(EventPacketView)> event_handler,
      common::Callback<void(uint16_t, hci::ErrorCode)> on_disconnect, os::Handler* handler);

  virtual LeAclConnectionInterface* GetLeAclConnectionInterface(
      common::Callback<void(LeMetaEventView)> event_handler,
      common::Callback<void(uint16_t, hci::ErrorCode)> on_disconnect, os::Handler* handler);

  virtual LeAdvertisingInterface* GetLeAdvertisingInterface(common::Callback<void(LeMetaEventView)> event_handler,
                                                            os::Handler* handler);

  virtual LeScanningInterface* GetLeScanningInterface(common::Callback<void(LeMetaEventView)> event_handler,
                                                      os::Handler* handler);

  os::Handler* GetHciHandler() {
    return GetHandler();
  }

  std::string ToString() const override {
    return "Hci Layer";
  }

  static constexpr std::chrono::milliseconds kHciTimeoutMs = std::chrono::milliseconds(2000);

  static const ModuleFactory Factory;

 protected:
  void ListDependencies(ModuleList* list) override;

  void Start() override;

  void Stop() override;

 private:
  struct impl;
  struct hal_callbacks;
  impl* impl_;
  hal_callbacks* hal_callbacks_;
};
}  // namespace hci
}  // namespace bluetooth
