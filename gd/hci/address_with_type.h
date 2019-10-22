/******************************************************************************
 *
 *  Copyright 2019 The Android Open Source Project
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at:
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 ******************************************************************************/

#pragma once

#include <sstream>
#include <string>
#include <utility>

#include "hci/address.h"
#include "hci/hci_packets.h"

namespace bluetooth {
namespace hci {

class AddressWithType final {
 public:
  AddressWithType(Address address, AddressType address_type) : address_(address), address_type_(address_type) {}

  explicit AddressWithType() : address_(Address::kEmpty), address_type_(AddressType::PUBLIC_DEVICE_ADDRESS) {}

  inline Address GetAddress() const {
    return address_;
  }

  inline AddressType GetAddressType() const {
    return address_type_;
  }

  bool operator<(const AddressWithType& rhs) const {
    return address_ < rhs.address_ && address_type_ < rhs.address_type_;
  }
  bool operator==(const AddressWithType& rhs) const {
    return address_ == rhs.address_ && address_type_ == rhs.address_type_;
  }
  bool operator>(const AddressWithType& rhs) const {
    return (rhs < *this);
  }
  bool operator<=(const AddressWithType& rhs) const {
    return !(*this > rhs);
  }
  bool operator>=(const AddressWithType& rhs) const {
    return !(*this < rhs);
  }
  bool operator!=(const AddressWithType& rhs) const {
    return !(*this == rhs);
  }

  std::string ToString() const {
    std::stringstream ss;
    ss << address_ << "[" << AddressTypeText(address_type_) << "]";
    return ss.str();
  }

 private:
  Address address_;
  AddressType address_type_;
};

inline std::ostream& operator<<(std::ostream& os, const AddressWithType& a) {
  os << a.ToString();
  return os;
}

}  // namespace hci
}  // namespace bluetooth

namespace std {
template <>
struct hash<bluetooth::hci::AddressWithType> {
  std::size_t operator()(const bluetooth::hci::AddressWithType& val) const {
    static_assert(sizeof(uint64_t) >= (sizeof(bluetooth::hci::Address) + sizeof(bluetooth::hci::AddressType)));
    uint64_t int_addr = 0;
    memcpy(reinterpret_cast<uint8_t*>(&int_addr), val.GetAddress().address, sizeof(bluetooth::hci::Address));
    bluetooth::hci::AddressType address_type = val.GetAddressType();
    memcpy(reinterpret_cast<uint8_t*>(&int_addr) + sizeof(bluetooth::hci::Address), &address_type,
           sizeof(address_type));
    return std::hash<uint64_t>{}(int_addr);
  }
};
}  // namespace std