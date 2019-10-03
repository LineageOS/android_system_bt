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

#pragma once

#include <cstdint>
#include <unordered_map>

#include "stack/include/l2c_api.h"

namespace bluetooth {
namespace shim {

static constexpr uint16_t kInitialClassicDynamicPsm = 0x1001;
static constexpr uint16_t kFinalClassicDynamicPsm = 0xfeff;
static constexpr uint16_t kInitialClassicVirtualPsm = kInitialClassicDynamicPsm;
static constexpr uint16_t kFinalClassicVirtualPsm = 0x8000;
static constexpr uint16_t kInitialLeDynamicPsm = 0x0080;
static constexpr uint16_t kFinalLeDynamicPsm = 0x00ff;

using PsmData = struct {
  bool IsPsmAllocated(uint16_t psm) const;
  bool IsPsmRegistered(uint16_t psm) const;

  void AllocatePsm(uint16_t psm);
  void RegisterPsm(uint16_t psm, const tL2CAP_APPL_INFO* callbacks);

  void UnregisterPsm(uint16_t psm);
  void DeallocatePsm(uint16_t psm);

 private:
  std::unordered_map<uint16_t, const tL2CAP_APPL_INFO*> psm_to_callback_map;
};

class L2cap {
 public:
  L2cap();

  PsmData& Classic();
  PsmData& Le();

  uint16_t GetNextDynamicClassicPsm();
  uint16_t GetNextDynamicLePsm();

  uint16_t ConvertClientToRealPsm(uint16_t psm,
                                  bool is_outgoing_only_connection);
  uint16_t ConvertClientToRealPsm(uint16_t psm);
  void RemoveClientPsm(uint16_t client_psm);

 private:
  uint16_t GetNextVirtualPsm(uint16_t real_psm);

  PsmData classic_;
  PsmData le_;

  uint16_t classic_dynamic_psm_;
  uint16_t le_dynamic_psm_;
  uint16_t classic_virtual_psm_;

  std::unordered_map<uint16_t, uint16_t> client_psm_to_real_psm_map_;
};

}  // namespace shim
}  // namespace bluetooth
