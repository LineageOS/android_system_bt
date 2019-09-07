/*
 * Copyright 2018 The Android Open Source Project
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

#include <cstdint>
#include <set>
#include <unordered_map>

#include "acl_connection.h"
#include "include/acl.h"
#include "types/address.h"

namespace test_vendor_lib {

class AclConnectionHandler {
 public:
  AclConnectionHandler() = default;

  virtual ~AclConnectionHandler() = default;

  bool CreatePendingConnection(Address addr);
  bool HasPendingConnection(Address addr);
  bool CancelPendingConnection(Address addr);

  bool CreatePendingLeConnection(Address addr, uint8_t addr_type);
  bool HasPendingLeConnection(Address addr, uint8_t addr_type);
  bool CancelPendingLeConnection(Address addr, uint8_t addr_type);

  uint16_t CreateConnection(Address addr);
  uint16_t CreateLeConnection(Address addr, uint8_t address_type, uint8_t own_address_type);
  bool Disconnect(uint16_t handle);
  bool HasHandle(uint16_t handle) const;

  uint16_t GetHandle(Address addr) const;
  Address GetAddress(uint16_t handle) const;
  uint8_t GetAddressType(uint16_t handle) const;
  uint8_t GetOwnAddressType(uint16_t handle) const;

  void SetConnected(uint16_t handle, bool connected);
  bool IsConnected(uint16_t handle) const;

  bool IsDeviceConnected(Address addr, uint8_t address_type = 0) const;

  void Encrypt(uint16_t handle);
  bool IsEncrypted(uint16_t handle) const;

  void SetAddress(uint16_t handle, Address address, uint8_t address_type = 0);  // default to public

 private:
  std::unordered_map<uint16_t, AclConnection> acl_connections_;
  bool classic_connection_pending_{false};
  Address pending_connection_address_;
  bool le_connection_pending_{false};
  Address pending_le_connection_address_;
  uint8_t pending_le_connection_address_type_;
  uint16_t GetUnusedHandle();
  uint16_t last_handle_{acl::kReservedHandle - 2};
  void set_own_address_type(uint16_t handle, uint8_t own_address_type);
};

}  // namespace test_vendor_lib
