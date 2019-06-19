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

#include "common/address.h"
#include "common/bidi_queue.h"
#include "common/callback.h"
#include "hci/hci_layer.h"
#include "hci/hci_packets.h"
#include "module.h"
#include "os/handler.h"

namespace bluetooth {
namespace hci {

class AclManager;

class AclConnection {
 public:
  AclConnection() : manager_(nullptr) {}

  common::Address GetAddress() const {
    return address_;
  }

  using Queue = common::BidiQueue<PacketView<kLittleEndian>, BasePacketBuilder>;
  using QueueUpEnd = common::BidiQueueEnd<BasePacketBuilder, PacketView<kLittleEndian>>;
  using QueueDownEnd = common::BidiQueueEnd<PacketView<kLittleEndian>, BasePacketBuilder>;
  QueueUpEnd* GetAclQueueEnd() const;
  void RegisterDisconnectCallback(common::OnceCallback<void(ErrorCode)> on_disconnect, os::Handler* handler);
  bool Disconnect(DisconnectReason);
  // Ask AclManager to clean me up. Must invoke after on_disconnect is called
  void Finish();

  // TODO: API to change link settings ... ?

 private:
  friend AclManager;
  AclConnection(AclManager* manager, uint16_t handle, common::Address address)
      : manager_(manager), handle_(handle), address_(address) {}
  AclManager* manager_;
  uint16_t handle_;
  common::Address address_;
};

class ConnectionCallbacks {
 public:
  virtual ~ConnectionCallbacks() = default;
  // Invoked when controller sends Connection Complete event with Success error code
  virtual void OnConnectSuccess(AclConnection /* , initiated_by_local ? */) = 0;
  // Invoked when controller sends Connection Complete event with non-Success error code
  virtual void OnConnectFail(common::Address, ErrorCode reason) = 0;
};

class AclManager : public Module {
 public:
  AclManager();

  // Returns true if callbacks are successfully registered. Should register only once when user module starts.
  // Generates OnConnectSuccess when an incoming connection is established.
  bool RegisterCallbacks(ConnectionCallbacks* callbacks, os::Handler* handler);

  // Generates OnConnectSuccess if connected, or OnConnectFail otherwise
  void CreateConnection(common::Address address);

  // Generates OnConnectFail with error code "terminated by local host 0x16" if cancelled, or OnConnectSuccess if not
  // successfully cancelled and already connected
  void CancelConnect(common::Address address);

  static const ModuleFactory Factory;

 protected:
  void ListDependencies(ModuleList* list) override;

  void Start() override;

  void Stop() override;

 private:
  friend AclConnection;

  struct impl;
  std::unique_ptr<impl> pimpl_;

  struct acl_connection;
};

}  // namespace hci
}  // namespace bluetooth
