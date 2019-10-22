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

#include "acl_connection_handler.h"

#include "os/log.h"

#include "types/address.h"

using std::shared_ptr;

namespace test_vendor_lib {

bool AclConnectionHandler::HasHandle(uint16_t handle) const {
  if (acl_connections_.count(handle) == 0) {
    return false;
  }
  return true;
}

uint16_t AclConnectionHandler::GetUnusedHandle() {
  while (acl_connections_.count(last_handle_) == 1) {
    last_handle_ = (last_handle_ + 1) % acl::kReservedHandle;
  }
  uint16_t unused_handle = last_handle_;
  last_handle_ = (last_handle_ + 1) % acl::kReservedHandle;
  return unused_handle;
}

bool AclConnectionHandler::CreatePendingConnection(Address addr) {
  if (classic_connection_pending_) {
    return false;
  }
  classic_connection_pending_ = true;
  pending_connection_address_ = addr;
  return true;
}

bool AclConnectionHandler::HasPendingConnection(Address addr) {
  return classic_connection_pending_ && pending_connection_address_ == addr;
}

bool AclConnectionHandler::CancelPendingConnection(Address addr) {
  if (!classic_connection_pending_ || pending_connection_address_ != addr) {
    return false;
  }
  classic_connection_pending_ = false;
  pending_connection_address_ = Address::kEmpty;
  return true;
}

bool AclConnectionHandler::CreatePendingLeConnection(Address addr, uint8_t address_type) {
  if (IsDeviceConnected(addr, address_type)) {
    LOG_INFO("%s: %s (type %hhx) is already connected", __func__, addr.ToString().c_str(), address_type);
    return false;
  }
  if (le_connection_pending_) {
    LOG_INFO("%s: connection already pending", __func__);
    return false;
  }
  le_connection_pending_ = true;
  pending_le_connection_address_ = addr;
  pending_le_connection_address_type_ = address_type;
  return true;
}

bool AclConnectionHandler::HasPendingLeConnection(Address addr, uint8_t address_type) {
  return le_connection_pending_ && pending_le_connection_address_ == addr &&
         pending_le_connection_address_type_ == address_type;
}

bool AclConnectionHandler::CancelPendingLeConnection(Address addr, uint8_t address_type) {
  if (!le_connection_pending_ || pending_le_connection_address_ != addr ||
      pending_le_connection_address_type_ != address_type) {
    return false;
  }
  le_connection_pending_ = false;
  pending_le_connection_address_ = Address::kEmpty;
  pending_le_connection_address_type_ = 0xba;
  return true;
}

uint16_t AclConnectionHandler::CreateConnection(Address addr) {
  if (CancelPendingConnection(addr)) {
    uint16_t handle = GetUnusedHandle();
    acl_connections_.emplace(handle, addr);
    return handle;
  }
  return acl::kReservedHandle;
}

uint16_t AclConnectionHandler::CreateLeConnection(Address addr, uint8_t address_type, uint8_t own_address_type) {
  if (CancelPendingLeConnection(addr, address_type)) {
    uint16_t handle = GetUnusedHandle();
    acl_connections_.emplace(handle, addr);
    set_own_address_type(handle, own_address_type);
    SetAddress(handle, addr, address_type);
    return handle;
  }
  return acl::kReservedHandle;
}

bool AclConnectionHandler::Disconnect(uint16_t handle) {
  return acl_connections_.erase(handle) > 0;
}

uint16_t AclConnectionHandler::GetHandle(Address addr) const {
  for (auto pair : acl_connections_) {
    if (std::get<AclConnection>(pair).GetAddress() == addr) {
      return std::get<0>(pair);
    }
  }
  return acl::kReservedHandle;
}

Address AclConnectionHandler::GetAddress(uint16_t handle) const {
  ASSERT_LOG(HasHandle(handle), "Handle unknown %hd", handle);
  return acl_connections_.at(handle).GetAddress();
}

uint8_t AclConnectionHandler::GetAddressType(uint16_t handle) const {
  ASSERT_LOG(HasHandle(handle), "Handle unknown %hd", handle);
  return acl_connections_.at(handle).GetAddressType();
}

void AclConnectionHandler::set_own_address_type(uint16_t handle, uint8_t address_type) {
  ASSERT_LOG(HasHandle(handle), "Handle unknown %hd", handle);
  acl_connections_.at(handle).SetOwnAddressType(address_type);
}

uint8_t AclConnectionHandler::GetOwnAddressType(uint16_t handle) const {
  ASSERT_LOG(HasHandle(handle), "Handle unknown %hd", handle);
  return acl_connections_.at(handle).GetOwnAddressType();
}

bool AclConnectionHandler::IsConnected(uint16_t handle) const {
  if (!HasHandle(handle)) {
    return false;
  }
  return true;
}

bool AclConnectionHandler::IsDeviceConnected(Address addr, uint8_t address_type) const {
  for (auto pair : acl_connections_) {
    auto connection = std::get<AclConnection>(pair);
    if (connection.GetAddress() == addr && connection.GetAddressType() == address_type) {
      return true;
    }
  }
  return false;
}

void AclConnectionHandler::Encrypt(uint16_t handle) {
  if (!HasHandle(handle)) {
    return;
  }
  acl_connections_.at(handle).Encrypt();
}

bool AclConnectionHandler::IsEncrypted(uint16_t handle) const {
  if (!HasHandle(handle)) {
    return false;
  }
  return acl_connections_.at(handle).IsEncrypted();
}

void AclConnectionHandler::SetAddress(uint16_t handle, Address address, uint8_t address_type) {
  if (!HasHandle(handle)) {
    return;
  }
  auto connection = acl_connections_.at(handle);
  connection.SetAddress(address);
  connection.SetAddressType(address_type);
}

}  // namespace test_vendor_lib
