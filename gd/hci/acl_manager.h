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

#include "common/bidi_queue.h"
#include "common/callback.h"
#include "hci/address.h"
#include "hci/hci_layer.h"
#include "hci/hci_packets.h"
#include "module.h"
#include "os/handler.h"

namespace bluetooth {
namespace hci {

class AclManager;

class AclConnection {
 public:
  AclConnection() : manager_(nullptr), handle_(0), address_(Address::kEmpty){};
  virtual ~AclConnection() = default;

  virtual Address GetAddress() const {
    return address_;
  }

  uint16_t GetHandle() const {
    return handle_;
  }

  using Queue = common::BidiQueue<PacketView<kLittleEndian>, BasePacketBuilder>;
  using QueueUpEnd = common::BidiQueueEnd<BasePacketBuilder, PacketView<kLittleEndian>>;
  using QueueDownEnd = common::BidiQueueEnd<PacketView<kLittleEndian>, BasePacketBuilder>;
  virtual QueueUpEnd* GetAclQueueEnd() const;
  virtual void RegisterDisconnectCallback(common::OnceCallback<void(ErrorCode)> on_disconnect, os::Handler* handler);
  virtual bool Disconnect(DisconnectReason reason);
  // Ask AclManager to clean me up. Must invoke after on_disconnect is called
  virtual void Finish();

  // TODO: API to change link settings ... ?

 private:
  friend AclManager;
  AclConnection(AclManager* manager, uint16_t handle, Address address)
      : manager_(manager), handle_(handle), address_(address) {}
  AclManager* manager_;
  uint16_t handle_;
  Address address_;
  DISALLOW_COPY_AND_ASSIGN(AclConnection);
};

class ConnectionCallbacks {
 public:
  virtual ~ConnectionCallbacks() = default;
  // Invoked when controller sends Connection Complete event with Success error code
  virtual void OnConnectSuccess(std::unique_ptr<AclConnection> /* , initiated_by_local ? */) = 0;
  // Invoked when controller sends Connection Complete event with non-Success error code
  virtual void OnConnectFail(Address, ErrorCode reason) = 0;
};

class AclManager : public Module {
 public:
  AclManager();
  // NOTE: It is necessary to forward declare a default destructor that overrides the base class one, because
  // "struct impl" is forwarded declared in .cc and compiler needs a concrete definition of "struct impl" when
  // compiling AclManager's destructor. Hence we need to forward declare the destructor for AclManager to delay
  // compiling AclManager's destructor until it starts linking the .cc file.
  ~AclManager() override;

  // Returns true if callbacks are successfully registered. Should register only once when user module starts.
  // Generates OnConnectSuccess when an incoming connection is established.
  virtual bool RegisterCallbacks(ConnectionCallbacks* callbacks, os::Handler* handler);

  // Generates OnConnectSuccess if connected, or OnConnectFail otherwise
  virtual void CreateConnection(Address address);

  // Generates OnConnectFail with error code "terminated by local host 0x16" if cancelled, or OnConnectSuccess if not
  // successfully cancelled and already connected
  virtual void CancelConnect(Address address);

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
  DISALLOW_COPY_AND_ASSIGN(AclManager);
};

}  // namespace hci
}  // namespace bluetooth
