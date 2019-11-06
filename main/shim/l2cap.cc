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
#define LOG_TAG "bt_shim_l2cap"

#include <cstdint>

#include "main/shim/entry.h"
#include "main/shim/l2cap.h"
#include "main/shim/shim.h"
#include "osi/include/allocator.h"
#include "osi/include/log.h"

constexpr size_t kBtHdrSize = sizeof(BT_HDR);
constexpr uint16_t kInvalidConnectionInterfaceDescriptor = 0;

bool bluetooth::legacy::shim::PsmData::IsPsmAllocated(uint16_t psm) const {
  return psm_to_callback_map_.find(psm) != psm_to_callback_map_.end();
}

bool bluetooth::legacy::shim::PsmData::IsPsmRegistered(uint16_t psm) const {
  return IsPsmAllocated(psm) && psm_to_callback_map_.at(psm) != nullptr;
}

void bluetooth::legacy::shim::PsmData::AllocatePsm(uint16_t psm) {
  RegisterPsm(psm, nullptr);
}

void bluetooth::legacy::shim::PsmData::RegisterPsm(
    uint16_t psm, const tL2CAP_APPL_INFO* callbacks) {
  psm_to_callback_map_[psm] = callbacks;
}

void bluetooth::legacy::shim::PsmData::UnregisterPsm(uint16_t psm) {
  psm_to_callback_map_[psm] = nullptr;
}

void bluetooth::legacy::shim::PsmData::DeallocatePsm(uint16_t psm) {
  psm_to_callback_map_.erase(psm);
}

const tL2CAP_APPL_INFO* bluetooth::legacy::shim::PsmData::Callbacks(
    uint16_t psm) {
  if (psm_to_callback_map_.find(psm) == psm_to_callback_map_.end()) {
    LOG_WARN(LOG_TAG, "Accessing unknown psm:%hd:", psm);
    return nullptr;
  }
  return psm_to_callback_map_[psm];
}

bluetooth::legacy::shim::L2cap::L2cap()
    : classic_dynamic_psm_(kInitialClassicDynamicPsm),
      le_dynamic_psm_(kInitialLeDynamicPsm),
      classic_virtual_psm_(kInitialClassicVirtualPsm) {}

bluetooth::legacy::shim::PsmData& bluetooth::legacy::shim::L2cap::Le() {
  return le_;
}

bluetooth::legacy::shim::PsmData& bluetooth::legacy::shim::L2cap::Classic() {
  return classic_;
}

uint16_t bluetooth::legacy::shim::L2cap::ConvertClientToRealPsm(
    uint16_t client_psm, bool is_outgoing_only_connection) {
  if (!is_outgoing_only_connection) {
    return client_psm;
  }
  return GetNextVirtualPsm(client_psm);
}

uint16_t bluetooth::legacy::shim::L2cap::ConvertClientToRealPsm(
    uint16_t client_psm) {
  if (client_psm_to_real_psm_map_.find(client_psm) ==
      client_psm_to_real_psm_map_.end()) {
    return client_psm;
  }
  return client_psm_to_real_psm_map_.at(client_psm);
}

void bluetooth::legacy::shim::L2cap::RemoveClientPsm(uint16_t client_psm) {
  if (client_psm_to_real_psm_map_.find(client_psm) !=
      client_psm_to_real_psm_map_.end()) {
    client_psm_to_real_psm_map_.erase(client_psm);
  }
}

uint16_t bluetooth::legacy::shim::L2cap::GetNextVirtualPsm(uint16_t real_psm) {
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

uint16_t bluetooth::legacy::shim::L2cap::GetNextDynamicLePsm() {
  while (Le().IsPsmAllocated(le_dynamic_psm_)) {
    le_dynamic_psm_++;
    if (le_dynamic_psm_ > kFinalLeDynamicPsm) {
      le_dynamic_psm_ = kInitialLeDynamicPsm;
    }
  }
  return le_dynamic_psm_;
}

uint16_t bluetooth::legacy::shim::L2cap::GetNextDynamicClassicPsm() {
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

void bluetooth::legacy::shim::L2cap::RegisterService(
    uint16_t psm, const tL2CAP_APPL_INFO* callbacks, bool enable_snoop) {
  LOG_DEBUG(LOG_TAG, "Registering service on psm:%hd", psm);

  if (!enable_snoop) {
    LOG_WARN(LOG_TAG, "UNIMPLEMENTED Cannot disable snooping on psm:%d", psm);
  }

  Classic().RegisterPsm(psm, callbacks);

  std::promise<void> register_completed;
  auto completed = register_completed.get_future();
  bluetooth::shim::GetL2cap()->RegisterService(
      psm,
      std::bind(&bluetooth::legacy::shim::L2cap::OnConnectionReady, this,
                std::placeholders::_1, std::placeholders::_2,
                std::placeholders::_3),
      std::move(register_completed));
  completed.wait();
  LOG_DEBUG(LOG_TAG, "Successfully registered service on psm:%hd", psm);
}

uint16_t bluetooth::legacy::shim::L2cap::CreateConnection(
    uint16_t psm, const RawAddress& raw_address) {
  LOG_DEBUG(LOG_TAG, "Requesting connection to psm:%hd address:%s", psm,
            raw_address.ToString().c_str());

  if (!Classic().IsPsmRegistered(psm)) {
    LOG_WARN(LOG_TAG, "Service must be registered in order to connect psm:%hd",
             psm);
    return kInvalidConnectionInterfaceDescriptor;
  }

  std::promise<uint16_t> connect_completed;
  auto completed = connect_completed.get_future();
  bluetooth::shim::GetL2cap()->CreateConnection(psm, raw_address.ToString(),
                                                std::move(connect_completed));
  uint16_t cid = completed.get();
  if (cid == kInvalidConnectionInterfaceDescriptor) {
    LOG_WARN(LOG_TAG,
             "Failed to allocate resources to connect to psm:%hd address:%s",
             psm, raw_address.ToString().c_str());
  } else {
    LOG_DEBUG(LOG_TAG,
              "Successfully started connection to psm:%hd address:%s"
              " connection_interface_descriptor:%hd",
              psm, raw_address.ToString().c_str(), cid);
    CHECK(cid_to_psm_map_.find(cid) == cid_to_psm_map_.end());
    cid_to_psm_map_[cid] = psm;
    SetCallbacks(cid, Classic().Callbacks(psm));
    const tL2CAP_APPL_INFO* callbacks = Classic().Callbacks(psm);
    CHECK(callbacks != nullptr);
  }
  return cid;
}

void bluetooth::legacy::shim::L2cap::OnConnectionReady(
    uint16_t psm, uint16_t cid,
    std::function<void(std::function<void(uint16_t c)>)> func) {
  LOG_DEBUG(
      LOG_TAG,
      "l2cap got new connection psm:%hd connection_interface_descriptor:%hd",
      psm, cid);
  const tL2CAP_APPL_INFO* callbacks = Classic().Callbacks(psm);
  if (callbacks == nullptr) {
    return;
  }
  LOG_DEBUG(LOG_TAG, "%s Setting postable map for cid:%d", __func__, cid);
  cid_to_postable_map_[cid] = func;

  func([&cid, &callbacks](uint16_t cid2) {
    LOG_WARN(LOG_TAG, "Cid:%hd Cid2:%hd", cid, cid2);
    callbacks->pL2CA_ConnectCfm_Cb(cid2, 0);
  });
}

bool bluetooth::legacy::shim::L2cap::IsCongested(uint16_t cid) const {
  LOG_WARN(LOG_TAG, "UNIMPLEMENTED checking congestion on a channel");
  return false;
}

bool bluetooth::legacy::shim::L2cap::Write(uint16_t cid, BT_HDR* bt_hdr) {
  CHECK(bt_hdr != nullptr);
  const uint8_t* data = bt_hdr->data + bt_hdr->offset;
  size_t len = bt_hdr->len;
  return bluetooth::shim::GetL2cap()->Write(cid, data, len);
}

bool bluetooth::legacy::shim::L2cap::WriteFlushable(uint16_t cid,
                                                    BT_HDR* bt_hdr) {
  CHECK(bt_hdr != nullptr);
  const uint8_t* data = bt_hdr->data + bt_hdr->offset;
  size_t len = bt_hdr->len;
  return bluetooth::shim::GetL2cap()->WriteFlushable(cid, data, len);
}

bool bluetooth::legacy::shim::L2cap::WriteNonFlushable(uint16_t cid,
                                                       BT_HDR* bt_hdr) {
  CHECK(bt_hdr != nullptr);
  const uint8_t* data = bt_hdr->data + bt_hdr->offset;
  size_t len = bt_hdr->len;
  return bluetooth::shim::GetL2cap()->WriteNonFlushable(cid, data, len);
}

bool bluetooth::legacy::shim::L2cap::SetCallbacks(
    uint16_t cid, const tL2CAP_APPL_INFO* callbacks) {
  LOG_DEBUG(LOG_TAG, "Mapping cid:%hd to callbacks", cid);
  CHECK(callbacks != nullptr);
  if (cid_to_callback_map_.find(cid) != cid_to_callback_map_.end()) {
    LOG_WARN(LOG_TAG, "Already have mapped cid:%hd to callbacks", cid);
  }
  LOG_ASSERT(cid_to_callback_map_.find(cid) != cid_to_callback_map_.end())
      << "Registering multiple channel callbacks "
         "connection_interface_descriptor:"
      << cid;
  cid_to_callback_map_[cid] = callbacks;

  bluetooth::shim::GetL2cap()->SetReadDataReadyCallback(
      cid, [this](uint16_t cid, std::vector<const uint8_t> data) {
        LOG_DEBUG(LOG_TAG,
                  "Got data on connection_interface_descriptor:%hd len:%zd",
                  cid, data.size());

        BT_HDR* bt_hdr =
            static_cast<BT_HDR*>(osi_calloc(data.size() + kBtHdrSize));
        std::copy(data.begin(), data.end(), bt_hdr->data);
        bt_hdr->len = data.size();
        cid_to_callback_map_[cid]->pL2CA_DataInd_Cb(cid, bt_hdr);
      });

  bluetooth::shim::GetL2cap()->SetConnectionClosedCallback(
      cid, [this](uint16_t cid, int error_code) {
        LOG_DEBUG(LOG_TAG, "Channel closed connection_interface_descriptor:%hd",
                  cid);
        cid_to_callback_map_[cid]->pL2CA_DisconnectInd_Cb(cid, true);
      });
  return true;
}

void bluetooth::legacy::shim::L2cap::ClearCallbacks(uint16_t cid) {
  LOG_ASSERT(cid_to_callback_map_.find(cid) == cid_to_callback_map_.end())
      << "Clearing callbacks that do not exist connection_interface_descriptor:"
      << cid;
  cid_to_callback_map_.erase(cid);
}

bool bluetooth::legacy::shim::L2cap::ConfigRequest(
    uint16_t cid, const tL2CAP_CFG_INFO* config_info) {
  CHECK(cid_to_psm_map_.find(cid) != cid_to_psm_map_.end());
  const tL2CAP_APPL_INFO* callbacks = Classic().Callbacks(cid_to_psm_map_[cid]);
  CHECK(callbacks != nullptr);
  CHECK(cid_to_postable_map_.count(cid) == 1);

  auto func = cid_to_postable_map_[cid];
  func([&cid, &callbacks](uint16_t cid2) {
    LOG_WARN(LOG_TAG, "Hello world %hd %hd", cid, cid2);
    callbacks->pL2CA_ConfigCfm_Cb(cid, nullptr);
  });
  return true;
}

bool bluetooth::legacy::shim::L2cap::ConnectResponse(
    const RawAddress& raw_address, uint8_t signal_id, uint16_t cid,
    uint16_t result, uint16_t status, tL2CAP_ERTM_INFO* ertm_info) {
  LOG_INFO(LOG_TAG, "%s UNIMPLEMENTED", __func__);
  return false;
}

bool bluetooth::legacy::shim::L2cap::ConfigResponse(
    uint16_t cid, const tL2CAP_CFG_INFO* config_info) {
  LOG_INFO(LOG_TAG, "%s UNIMPLEMENTED", __func__);
  return false;
}

bool bluetooth::legacy::shim::L2cap::DisconnectRequest(uint16_t cid) {
  LOG_INFO(LOG_TAG, "%s UNIMPLEMENTED", __func__);
  return false;
}

bool bluetooth::legacy::shim::L2cap::DisconnectResponse(uint16_t cid) {
  LOG_INFO(LOG_TAG, "%s UNIMPLEMENTED", __func__);
  return false;
}
