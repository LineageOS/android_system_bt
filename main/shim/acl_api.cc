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

#include "gd/hci/acl_manager.h"
#include "main/shim/acl_api.h"
#include "main/shim/helpers.h"
#include "main/shim/stack.h"
#include "types/ble_address_with_type.h"
#include "types/raw_address.h"

void bluetooth::shim::ACL_CreateClassicConnection(
    const RawAddress& raw_address) {
  auto address = ToGdAddress(raw_address);
  Stack::GetInstance()->GetAcl()->CreateClassicConnection(address);
}

void bluetooth::shim::ACL_CreateLeConnection(
    const tBLE_BD_ADDR& legacy_address_with_type) {
  Stack::GetInstance()->GetAcl()->CreateLeConnection(
      ToAddressWithTypeFromLegacy(legacy_address_with_type));
}

void bluetooth::shim::ACL_CancelLeConnection(
    const tBLE_BD_ADDR& legacy_address_with_type) {
  Stack::GetInstance()->GetAcl()->CancelLeConnection(
      ToAddressWithTypeFromLegacy(legacy_address_with_type));
}

void bluetooth::shim::ACL_WriteData(uint16_t handle, const BT_HDR* p_buf) {
  std::unique_ptr<bluetooth::packet::RawBuilder> packet =
      MakeUniquePacket(p_buf->data + p_buf->offset + HCI_DATA_PREAMBLE_SIZE,
                       p_buf->len - HCI_DATA_PREAMBLE_SIZE);
  Stack::GetInstance()->GetAcl()->WriteData(handle, std::move(packet));
}

void bluetooth::shim::ACL_ConfigureLePrivacy(bool is_le_privacy_enabled) {
  hci::LeAddressManager::AddressPolicy address_policy =
      is_le_privacy_enabled
          ? hci::LeAddressManager::AddressPolicy::USE_RESOLVABLE_ADDRESS
          : hci::LeAddressManager::AddressPolicy::USE_PUBLIC_ADDRESS;
  hci::AddressWithType empty_address_with_type(
      hci::Address{}, hci::AddressType::RANDOM_DEVICE_ADDRESS);
  /* 7 minutes minimum, 15 minutes maximum for random address refreshing */
  auto minimum_rotation_time = std::chrono::minutes(7);
  auto maximum_rotation_time = std::chrono::minutes(15);

  Stack::GetInstance()
      ->GetStackManager()
      ->GetInstance<bluetooth::hci::AclManager>()
      ->SetPrivacyPolicyForInitiatorAddress(
          address_policy, empty_address_with_type, minimum_rotation_time,
          maximum_rotation_time);
}

void bluetooth::shim::ACL_Disconnect(uint16_t handle, bool is_classic,
                                     tHCI_STATUS reason) {
  (is_classic)
      ? Stack::GetInstance()->GetAcl()->DisconnectClassic(handle, reason)
      : Stack::GetInstance()->GetAcl()->DisconnectLe(handle, reason);
}
