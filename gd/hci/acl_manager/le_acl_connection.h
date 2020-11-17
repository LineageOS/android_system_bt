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

#include "hci/acl_manager/acl_connection.h"
#include "hci/acl_manager/le_connection_management_callbacks.h"
#include "hci/address_with_type.h"
#include "hci/hci_packets.h"
#include "hci/le_acl_connection_interface.h"

namespace bluetooth {
namespace hci {
namespace acl_manager {

class LeAclConnection : public AclConnection {
 public:
  LeAclConnection();
  LeAclConnection(
      std::shared_ptr<Queue> queue,
      LeAclConnectionInterface* le_acl_connection_interface,
      uint16_t handle,
      AddressWithType local_address,
      AddressWithType remote_address,
      Role role);
  ~LeAclConnection() override;

  virtual AddressWithType GetLocalAddress() const {
    return local_address_;
  }

  virtual void SetLocalAddress(AddressWithType local_address) {
    local_address_ = local_address;
  }

  virtual AddressWithType GetRemoteAddress() const {
    return remote_address_;
  }

  virtual Role GetRole() const {
    return role_;
  }

  virtual void RegisterCallbacks(LeConnectionManagementCallbacks* callbacks, os::Handler* handler);
  virtual void Disconnect(DisconnectReason reason);

  virtual bool LeConnectionUpdate(uint16_t conn_interval_min, uint16_t conn_interval_max, uint16_t conn_latency,
                                  uint16_t supervision_timeout, uint16_t min_ce_length, uint16_t max_ce_length);

  virtual bool ReadRemoteVersionInformation() override;

  // TODO implement LeRemoteConnectionParameterRequestReply, LeRemoteConnectionParameterRequestNegativeReply

  // Called once before passing the connection to the client
  virtual LeConnectionManagementCallbacks* GetEventCallbacks();

 private:
  virtual bool check_connection_parameters(
      uint16_t conn_interval_min,
      uint16_t conn_interval_max,
      uint16_t expected_conn_latency,
      uint16_t expected_supervision_timeout);
  struct impl;
  struct impl* pimpl_ = nullptr;
  AddressWithType local_address_;
  AddressWithType remote_address_;
  Role role_;
  DISALLOW_COPY_AND_ASSIGN(LeAclConnection);
};

}  // namespace acl_manager
}  // namespace hci
}  // namespace bluetooth
