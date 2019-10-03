/*
 * Copyright 2019 The Android Open Source Project
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

#include "main/shim/l2cap.h"

bool bluetooth::shim::PsmData::IsPsmAllocated(uint16_t psm) const {
  return psm_to_callback_map.find(psm) != psm_to_callback_map.end();
}

bool bluetooth::shim::PsmData::IsPsmRegistered(uint16_t psm) const {
  return IsPsmAllocated(psm) && psm_to_callback_map.at(psm) != nullptr;
}

void bluetooth::shim::PsmData::AllocatePsm(uint16_t psm) {
  RegisterPsm(psm, nullptr);
}

void bluetooth::shim::PsmData::RegisterPsm(uint16_t psm,
                                           const tL2CAP_APPL_INFO* callbacks) {
  psm_to_callback_map[psm] = callbacks;
}

void bluetooth::shim::PsmData::UnregisterPsm(uint16_t psm) {
  psm_to_callback_map[psm] = nullptr;
}

void bluetooth::shim::PsmData::DeallocatePsm(uint16_t psm) {
  psm_to_callback_map.erase(psm);
}

bluetooth::shim::L2cap::L2cap()
    : classic_dynamic_psm_(kInitialClassicDynamicPsm),
      le_dynamic_psm_(kInitialLeDynamicPsm),
      classic_virtual_psm_(kInitialClassicVirtualPsm) {}

bluetooth::shim::PsmData& bluetooth::shim::L2cap::Le() { return le_; }

bluetooth::shim::PsmData& bluetooth::shim::L2cap::Classic() { return classic_; }

uint16_t bluetooth::shim::L2cap::ConvertClientToRealPsm(
    uint16_t client_psm, bool is_outgoing_only_connection) {
  if (!is_outgoing_only_connection) {
    return client_psm;
  }
  return GetNextVirtualPsm(client_psm);
}

uint16_t bluetooth::shim::L2cap::ConvertClientToRealPsm(uint16_t client_psm) {
  if (client_psm_to_real_psm_map_.find(client_psm) ==
      client_psm_to_real_psm_map_.end()) {
    return client_psm;
  }
  return client_psm_to_real_psm_map_.at(client_psm);
}

void bluetooth::shim::L2cap::RemoveClientPsm(uint16_t client_psm) {
  if (client_psm_to_real_psm_map_.find(client_psm) !=
      client_psm_to_real_psm_map_.end()) {
    client_psm_to_real_psm_map_.erase(client_psm);
  }
}

uint16_t bluetooth::shim::L2cap::GetNextVirtualPsm(uint16_t real_psm) {
  if (real_psm < kInitialClassicDynamicPsm) {
    return real_psm;
  }

  while (Classic().IsPsmAllocated(classic_virtual_psm_)) {
    classic_virtual_psm_ += 2;
    if (classic_virtual_psm_ >= kFinalClassicVirtualPsm) {
      classic_virtual_psm_ = kInitialClassicVirtualPsm;
    }
  }
  return classic_virtual_psm_;
}

uint16_t bluetooth::shim::L2cap::GetNextDynamicLePsm() {
  while (Le().IsPsmAllocated(le_dynamic_psm_)) {
    le_dynamic_psm_++;
    if (le_dynamic_psm_ > kFinalLeDynamicPsm) {
      le_dynamic_psm_ = kInitialLeDynamicPsm;
    }
  }
  return le_dynamic_psm_;
}

uint16_t bluetooth::shim::L2cap::GetNextDynamicClassicPsm() {
  while (Classic().IsPsmAllocated(classic_dynamic_psm_)) {
    classic_dynamic_psm_ += 2;
    if (classic_dynamic_psm_ > kFinalClassicDynamicPsm) {
      classic_dynamic_psm_ = kInitialClassicDynamicPsm;
    } else if (classic_dynamic_psm_ & 0x0100) {
      /* the upper byte must be even */
      classic_dynamic_psm_ += 0x0100;
    }

    /* if psm is in range of reserved BRCM Aware features */
    if ((BRCM_RESERVED_PSM_START <= classic_dynamic_psm_) &&
        (classic_dynamic_psm_ <= BRCM_RESERVED_PSM_END)) {
      classic_dynamic_psm_ = BRCM_RESERVED_PSM_END + 2;
    }
  }
  return classic_dynamic_psm_;
}
