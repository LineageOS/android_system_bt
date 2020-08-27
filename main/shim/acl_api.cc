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

#include <cstddef>
#include <cstdint>

#include "main/shim/acl_api.h"
#include "main/shim/helpers.h"
#include "main/shim/stack.h"
#include "types/raw_address.h"

void bluetooth::shim::ACL_CreateClassicConnection(
    const RawAddress& raw_address) {
  auto address = ToGdAddress(raw_address);
  Stack::GetInstance()->GetAcl()->CreateClassicConnection(address);
}

void bluetooth::shim::ACL_CreateLeConnection(const RawAddress& raw_address) {
  auto address_with_type = ToAddressWithType(raw_address, BLE_ADDR_PUBLIC);
  Stack::GetInstance()->GetAcl()->CreateLeConnection(address_with_type);
}

void bluetooth::shim::ACL_WriteData(uint16_t handle, const uint8_t* data,
                                    size_t len) {
  std::unique_ptr<bluetooth::packet::RawBuilder> packet =
      MakeUniquePacket(data, len);
  Stack::GetInstance()->GetAcl()->WriteData(handle, std::move(packet));
}
