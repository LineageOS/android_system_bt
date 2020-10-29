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
#include "types/raw_address.h"

namespace bluetooth {
namespace shim {

void ACL_CancelClassicConnection(const RawAddress& raw_address);
void ACL_CancelLeConnection(const tBLE_BD_ADDR& legacy_address_with_type);
void ACL_CreateClassicConnection(const RawAddress& raw_address);
void ACL_CreateLeConnection(const tBLE_BD_ADDR& legacy_address_with_type);
void ACL_WriteData(uint16_t handle, const BT_HDR* p_buf);
void ACL_ConfigureLePrivacy(bool is_le_privacy_enabled);

}  // namespace shim
}  // namespace bluetooth
