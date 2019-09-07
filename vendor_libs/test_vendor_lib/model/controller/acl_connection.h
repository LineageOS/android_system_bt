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

#include "types/address.h"

namespace test_vendor_lib {

// Model the connection of a device to the controller.
class AclConnection {
 public:
  AclConnection(Address addr) : address_(addr), address_type_(0), own_address_type_(0) {}

  virtual ~AclConnection() = default;

  void Encrypt() {
    encrypted_ = true;
  };
  bool IsEncrypted() const {
    return encrypted_;
  };

  Address GetAddress() const {
    return address_;
  }
  void SetAddress(Address address) {
    address_ = address;
  }

  uint8_t GetAddressType() const {
    return address_type_;
  }
  void SetAddressType(uint8_t address_type) {
    address_type_ = address_type;
  }
  uint8_t GetOwnAddressType() const {
    return own_address_type_;
  }
  void SetOwnAddressType(uint8_t address_type) {
    own_address_type_ = address_type;
  }

 private:
  Address address_;
  uint8_t address_type_;
  uint8_t own_address_type_;

  // State variables
  bool encrypted_{false};
};

}  // namespace test_vendor_lib
