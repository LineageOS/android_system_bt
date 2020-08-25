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

#include "hci/address_with_type.h"

#include "gd/packet/raw_builder.h"
#include "stack/include/bt_types.h"

namespace bluetooth {

inline RawAddress ToRawAddress(const hci::Address& address) {
  RawAddress ret;
  ret.address[0] = address.address[5];
  ret.address[1] = address.address[4];
  ret.address[2] = address.address[3];
  ret.address[3] = address.address[2];
  ret.address[4] = address.address[1];
  ret.address[5] = address.address[0];
  return ret;
}

inline hci::Address ToGdAddress(const RawAddress& address) {
  hci::Address ret;
  ret.address[0] = address.address[5];
  ret.address[1] = address.address[4];
  ret.address[2] = address.address[3];
  ret.address[3] = address.address[2];
  ret.address[4] = address.address[1];
  ret.address[5] = address.address[0];
  return ret;
}

inline hci::AddressWithType ToAddressWithType(const RawAddress& legacy_address,
                                       tBLE_ADDR_TYPE legacy_type) {
  hci::Address address = ToGdAddress(legacy_address);

  hci::AddressType type;
  if (legacy_type == BLE_ADDR_PUBLIC)
    type = hci::AddressType::PUBLIC_DEVICE_ADDRESS;
  else if (legacy_type == BLE_ADDR_RANDOM)
    type = hci::AddressType::RANDOM_DEVICE_ADDRESS;
  else if (legacy_type == BLE_ADDR_PUBLIC_ID)
    type = hci::AddressType::PUBLIC_IDENTITY_ADDRESS;
  else if (legacy_type == BLE_ADDR_RANDOM_ID)
    type = hci::AddressType::RANDOM_IDENTITY_ADDRESS;
  else {
    LOG_ALWAYS_FATAL("Bad address type %02x", legacy_type);
    return hci::AddressWithType{address,
                                hci::AddressType::PUBLIC_DEVICE_ADDRESS};
  }

  return hci::AddressWithType{address, type};
}

inline std::unique_ptr<bluetooth::packet::RawBuilder> MakeUniquePacket(
    const uint8_t* data, size_t len) {
  bluetooth::packet::RawBuilder builder;
  std::vector<uint8_t> bytes(data, data + len);
  auto payload = std::make_unique<bluetooth::packet::RawBuilder>();
  payload->AddOctets(bytes);
  return payload;
}

}  // namespace bluetooth
