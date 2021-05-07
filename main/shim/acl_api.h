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

#include "stack/include/bt_types.h"
#include "stack/include/hci_error_code.h"
#include "types/ble_address_with_type.h"
#include "types/raw_address.h"

namespace bluetooth {
namespace shim {

void ACL_CreateClassicConnection(const RawAddress& raw_address);
void ACL_CancelClassicConnection(const RawAddress& raw_address);
bool ACL_AcceptLeConnectionFrom(const tBLE_BD_ADDR& legacy_address_with_type,
                                bool is_direct);
void ACL_IgnoreLeConnectionFrom(const tBLE_BD_ADDR& legacy_address_with_type);

void ACL_Disconnect(uint16_t handle, bool is_classic, tHCI_STATUS reason);
void ACL_WriteData(uint16_t handle, BT_HDR* p_buf);
void ACL_ConfigureLePrivacy(bool is_le_privacy_enabled);
void ACL_Shutdown();
void ACL_IgnoreAllLeConnections();

void ACL_ReadConnectionAddress(const RawAddress& pseudo_addr,
                               RawAddress& conn_addr, uint8_t* p_addr_type);

}  // namespace shim
}  // namespace bluetooth
