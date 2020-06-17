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
#include "hci/acl_manager/connection_callbacks.h"
#include "hci/acl_manager/le_connection_callbacks.h"
#include "hci/address.h"
#include "hci/address_with_type.h"
#include "hci/hci_layer.h"
#include "hci/hci_packets.h"
#include "hci/le_address_manager.h"
#include "module.h"
#include "os/handler.h"

namespace bluetooth {

namespace security {
class SecurityModule;
}

namespace hci {

class AclManager : public Module {
 public:
  AclManager();
  // NOTE: It is necessary to forward declare a default destructor that overrides the base class one, because
  // "struct impl" is forwarded declared in .cc and compiler needs a concrete definition of "struct impl" when
  // compiling AclManager's destructor. Hence we need to forward declare the destructor for AclManager to delay
  // compiling AclManager's destructor until it starts linking the .cc file.
  ~AclManager() override;

  // Should register only once when user module starts.
  // Generates OnConnectSuccess when an incoming connection is established.
  virtual void RegisterCallbacks(acl_manager::ConnectionCallbacks* callbacks, os::Handler* handler);

  // Should register only once when user module starts.
  virtual void RegisterLeCallbacks(acl_manager::LeConnectionCallbacks* callbacks, os::Handler* handler);

  // Generates OnConnectSuccess if connected, or OnConnectFail otherwise
  virtual void CreateConnection(Address address);

  // Generates OnLeConnectSuccess if connected, or OnLeConnectFail otherwise
  virtual void CreateLeConnection(AddressWithType address_with_type);

  virtual void SetPrivacyPolicyForInitiatorAddress(
      LeAddressManager::AddressPolicy address_policy,
      AddressWithType fixed_address,
      crypto_toolbox::Octet16 rotation_irk,
      std::chrono::milliseconds minimum_rotation_time,
      std::chrono::milliseconds maximum_rotation_time);

  // Generates OnConnectFail with error code "terminated by local host 0x16" if cancelled, or OnConnectSuccess if not
  // successfully cancelled and already connected
  virtual void CancelConnect(Address address);

  virtual void CancelLeConnect(AddressWithType address_with_type);

  virtual void MasterLinkKey(KeyFlag key_flag);
  virtual void SwitchRole(Address address, Role role);
  virtual uint16_t ReadDefaultLinkPolicySettings();
  virtual void WriteDefaultLinkPolicySettings(uint16_t default_link_policy_settings);

  // In order to avoid circular dependency use setter rather than module dependency.
  virtual void SetSecurityModule(security::SecurityModule* security_module);

  virtual LeAddressManager* GetLeAddressManager();

  static const ModuleFactory Factory;

 protected:
  void ListDependencies(ModuleList* list) override;

  void Start() override;

  void Stop() override;

  std::string ToString() const override;

 private:
  struct impl;
  std::unique_ptr<impl> pimpl_;

  DISALLOW_COPY_AND_ASSIGN(AclManager);
};

}  // namespace hci
}  // namespace bluetooth
