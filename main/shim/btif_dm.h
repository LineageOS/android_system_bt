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

#include <cstdint>
#include <functional>

#include "include/hardware/bluetooth.h"
#include "types/raw_address.h"

namespace bluetooth {
namespace shim {

/**
 * Sets handler to SecurityModule and provides callback to handler
 */
void BTIF_DM_SetUiCallback(std::function<void(RawAddress, bt_bdname_t, uint32_t, bt_ssp_variant_t, uint32_t)> callback);
void BTIF_DM_ssp_reply(const RawAddress bd_addr, uint8_t, bt_ssp_variant_t variant, uint8_t accept);
void BTIF_DM_pin_reply(const RawAddress bd_addr, uint8_t, uint8_t, uint8_t, bt_pin_code_t);
void BTIF_RegisterBondStateChangeListener(
    std::function<void(RawAddress)> bond_state_bonding_cb,
    std::function<void(RawAddress)> bond_state_bonded_cb,
    std::function<void(RawAddress)> bond_state_none_cb);
}  // namespace shim
}  // namespace bluetooth
