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
#include "hci/le_iso_interface.h"
#include "hci/le_scanning_interface.h"
#include "hci/le_security_interface.h"
#include "hci/security_interface.h"
#include "module.h"
#include "os/utils.h"

namespace bluetooth {
namespace hci {

class HciLayer : public Module, public CommandInterface<CommandBuilder> {
  // LINT.IfChange
 public:
  HciLayer();
  virtual ~HciLayer();
  DISALLOW_COPY_AND_ASSIGN(HciLayer);

  void EnqueueCommand(
      std::unique_ptr<CommandBuilder> command,
      common::ContextualOnceCallback<void(CommandCompleteView)> on_complete) override;

  void EnqueueCommand(
      std::unique_ptr<CommandBuilder> command,
      common::ContextualOnceCallback<void(CommandStatusView)> on_status) override;

  virtual common::BidiQueueEnd<AclPacketBuilder, AclPacketView>* GetAclQueueEnd();

  virtual void RegisterEventHandler(EventCode event_code,
                                    common::ContextualCallback<void(EventPacketView)> event_handler);

  virtual void UnregisterEventHandler(EventCode event_code);

  virtual void RegisterLeEventHandler(SubeventCode subevent_code,
                                      common::ContextualCallback<void(LeMetaEventView)> event_handler);

  virtual void UnregisterLeEventHandler(SubeventCode subevent_code);

  virtual SecurityInterface* GetSecurityInterface(common::ContextualCallback<void(EventPacketView)> event_handler);

  virtual LeSecurityInterface* GetLeSecurityInterface(common::ContextualCallback<void(LeMetaEventView)> event_handler);

  virtual AclConnectionInterface* GetAclConnectionInterface(
      common::ContextualCallback<void(EventPacketView)> event_handler,
      common::ContextualCallback<void(uint16_t, hci::ErrorCode)> on_disconnect,
      common::ContextualCallback<void(uint16_t, uint8_t, uint16_t, uint16_t)> on_read_remote_version_complete);

  virtual LeAclConnectionInterface* GetLeAclConnectionInterface(
      common::ContextualCallback<void(LeMetaEventView)> event_handler,
      common::ContextualCallback<void(uint16_t, hci::ErrorCode)> on_disconnect,
      common::ContextualCallback<void(uint16_t, uint8_t, uint16_t, uint16_t)> on_read_remote_version_complete);

  virtual LeAdvertisingInterface* GetLeAdvertisingInterface(
      common::ContextualCallback<void(LeMetaEventView)> event_handler);

  virtual LeScanningInterface* GetLeScanningInterface(common::ContextualCallback<void(LeMetaEventView)> event_handler);

  virtual LeIsoInterface* GetLeIsoInterface(common::ContextualCallback<void(LeMetaEventView)> event_handler);

  std::string ToString() const override {
    return "Hci Layer";
  }

  static constexpr std::chrono::milliseconds kHciTimeoutMs = std::chrono::milliseconds(2000);

  static const ModuleFactory Factory;

 protected:
  // LINT.ThenChange(fuzz/fuzz_hci_layer.h)
  void ListDependencies(ModuleList* list) override;

  void Start() override;

  void Stop() override;

  virtual void Disconnect(uint16_t handle, ErrorCode reason);
  virtual void ReadRemoteVersion(uint16_t handle, uint8_t version, uint16_t manufacturer_name, uint16_t sub_version);
  virtual void RegisterLeMetaEventHandler(common::ContextualCallback<void(EventPacketView)> event_handler);

 private:
  struct impl;
  struct hal_callbacks;
  impl* impl_;
  hal_callbacks* hal_callbacks_;

  template <typename T>
  class CommandInterfaceImpl : public CommandInterface<T> {
   public:
    explicit CommandInterfaceImpl(HciLayer& hci) : hci_(hci) {}
    ~CommandInterfaceImpl() = default;

    void EnqueueCommand(std::unique_ptr<T> command,
                        common::ContextualOnceCallback<void(CommandCompleteView)> on_complete) override {
      hci_.EnqueueCommand(move(command), std::move(on_complete));
    }

    void EnqueueCommand(std::unique_ptr<T> command,
                        common::ContextualOnceCallback<void(CommandStatusView)> on_status) override {
      hci_.EnqueueCommand(move(command), std::move(on_status));
    }
    HciLayer& hci_;
  };

  std::list<common::ContextualCallback<void(uint16_t, ErrorCode)>> disconnect_handlers_;
  std::list<common::ContextualCallback<void(uint16_t, uint8_t, uint16_t, uint16_t)>> read_remote_version_handlers_;
  void on_disconnection_complete(EventPacketView event_view);
  void on_read_remote_version_complete(EventPacketView event_view);

  // Interfaces
  CommandInterfaceImpl<AclCommandBuilder> acl_connection_manager_interface_{*this};
  CommandInterfaceImpl<AclCommandBuilder> le_acl_connection_manager_interface_{*this};
  CommandInterfaceImpl<SecurityCommandBuilder> security_interface{*this};
  CommandInterfaceImpl<LeSecurityCommandBuilder> le_security_interface{*this};
  CommandInterfaceImpl<LeAdvertisingCommandBuilder> le_advertising_interface{*this};
  CommandInterfaceImpl<LeScanningCommandBuilder> le_scanning_interface{*this};
  CommandInterfaceImpl<LeIsoCommandBuilder> le_iso_interface{*this};
};
}  // namespace hci
}  // namespace bluetooth
