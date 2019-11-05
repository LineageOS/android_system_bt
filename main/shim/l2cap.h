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
namespace legacy {
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

  const tL2CAP_APPL_INFO* Callbacks(uint16_t psm);

 private:
  std::unordered_map<uint16_t, const tL2CAP_APPL_INFO*> psm_to_callback_map_;
};

class L2cap {
 public:
  void RegisterService(uint16_t psm, const tL2CAP_APPL_INFO* callbacks,
                       bool enable_snoop);
  uint16_t CreateConnection(uint16_t psm, const RawAddress& raw_address);
  void OnConnectionReady(
      uint16_t psm, uint16_t cid,
      std::function<void(std::function<void(uint16_t cid)>)> func);

  bool Write(uint16_t cid, BT_HDR* bt_hdr);
  bool WriteFlushable(uint16_t cid, BT_HDR* bt_hdr);
  bool WriteNonFlushable(uint16_t cid, BT_HDR* bt_hdr);
  bool IsCongested(uint16_t cid) const;

  bool SetCallbacks(uint16_t cid, const tL2CAP_APPL_INFO* callbacks);
  void ClearCallbacks(uint16_t cid);

  uint16_t GetNextDynamicClassicPsm();
  uint16_t GetNextDynamicLePsm();

  uint16_t ConvertClientToRealPsm(uint16_t psm,
                                  bool is_outgoing_only_connection);
  uint16_t ConvertClientToRealPsm(uint16_t psm);
  void RemoveClientPsm(uint16_t client_psm);

  // Legacy API entry points
  bool ConnectResponse(const RawAddress& raw_address, uint8_t signal_id,
                       uint16_t cid, uint16_t result, uint16_t status,
                       tL2CAP_ERTM_INFO* ertm_info);
  bool ConfigRequest(uint16_t cid, const tL2CAP_CFG_INFO* config_info);
  bool ConfigResponse(uint16_t cid, const tL2CAP_CFG_INFO* config_info);
  bool DisconnectRequest(uint16_t cid);
  bool DisconnectResponse(uint16_t cid);

  void Test(void* context);
  void Test2();

  L2cap();

  PsmData& Classic();
  PsmData& Le();

 private:
  uint16_t GetNextVirtualPsm(uint16_t real_psm);

  PsmData classic_;
  PsmData le_;

  uint16_t classic_dynamic_psm_;
  uint16_t le_dynamic_psm_;
  uint16_t classic_virtual_psm_;

  std::unordered_map<uint16_t,
                     std::function<void(std::function<void(uint16_t c)>)>>
      cid_to_postable_map_;
  std::unordered_map<uint16_t, uint16_t> cid_to_psm_map_;
  std::unordered_map<uint16_t, uint16_t> client_psm_to_real_psm_map_;
  std::unordered_map<uint16_t, const tL2CAP_APPL_INFO*> cid_to_callback_map_;
};

}  // namespace shim
}  // namespace legacy
}  // namespace bluetooth
