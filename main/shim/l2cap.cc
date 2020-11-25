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

#include "main/shim/dumpsys.h"
#include "main/shim/entry.h"
#include "main/shim/l2cap.h"
#include "main/shim/shim.h"
#include "osi/include/allocator.h"
#include "osi/include/log.h"
#include "stack/include/btu.h"

#include "shim/l2cap.h"

namespace {
constexpr char kModuleName[] = "shim::legacy::L2cap";
constexpr bool kDisconnectResponseRequired = false;
constexpr size_t kBtHdrSize = sizeof(BT_HDR);
constexpr uint16_t kConnectionFail = 1;
constexpr uint16_t kConnectionSuccess = 0;
constexpr uint16_t kInvalidConnectionInterfaceDescriptor = 0;
constexpr uint8_t kUnusedId = 0;
}  // namespace

bool bluetooth::shim::legacy::PsmManager::IsPsmRegistered(uint16_t psm) const {
  return psm_to_callback_map_.find(psm) != psm_to_callback_map_.end();
}

bool bluetooth::shim::legacy::PsmManager::HasClient(uint16_t psm) const {
  return IsPsmRegistered(psm) &&
         psm_to_callback_map_.find(psm) != psm_to_callback_map_.end();
}

void bluetooth::shim::legacy::PsmManager::RegisterPsm(
    uint16_t psm, const tL2CAP_APPL_INFO& callbacks) {
  CHECK(!HasClient(psm));
  psm_to_callback_map_.try_emplace(psm, tL2CAP_APPL_INFO(callbacks));
}

void bluetooth::shim::legacy::PsmManager::UnregisterPsm(uint16_t psm) {
  CHECK(IsPsmRegistered(psm));
  psm_to_callback_map_.erase(psm);
}

const tL2CAP_APPL_INFO bluetooth::shim::legacy::PsmManager::Callbacks(
    uint16_t psm) {
  CHECK(HasClient(psm));
  return psm_to_callback_map_[psm];
}

bluetooth::shim::legacy::L2cap::L2cap()
    : le_dynamic_psm_(kInitialLeDynamicPsm),
      classic_virtual_psm_(kInitialClassicVirtualPsm) {
  bluetooth::shim::RegisterDumpsysFunction(static_cast<void*>(this),
                                           [this](int fd) { Dump(fd); });
}

bluetooth::shim::legacy::L2cap::~L2cap() {
  bluetooth::shim::UnregisterDumpsysFunction(static_cast<void*>(this));
}

bluetooth::shim::legacy::PsmManager& bluetooth::shim::legacy::L2cap::Le() {
  return le_;
}

bluetooth::shim::legacy::PsmManager& bluetooth::shim::legacy::L2cap::Classic() {
  return classic_;
}

bool bluetooth::shim::legacy::L2cap::ConnectionExists(uint16_t cid) const {
  return cid_to_psm_map_.find(cid) != cid_to_psm_map_.end();
}

uint16_t bluetooth::shim::legacy::L2cap::CidToPsm(uint16_t cid) const {
  CHECK(ConnectionExists(cid));
  return cid_to_psm_map_.at(cid);
}

uint16_t bluetooth::shim::legacy::L2cap::ConvertClientToRealPsm(
    uint16_t client_psm, bool is_outgoing_only_connection) {
  if (!is_outgoing_only_connection) {
    return client_psm;
  }
  return GetNextVirtualPsm(client_psm);
}

uint16_t bluetooth::shim::legacy::L2cap::ConvertClientToRealPsm(
    uint16_t client_psm) {
  if (client_psm_to_real_psm_map_.find(client_psm) ==
      client_psm_to_real_psm_map_.end()) {
    return client_psm;
  }
  return client_psm_to_real_psm_map_.at(client_psm);
}

void bluetooth::shim::legacy::L2cap::RemoveClientPsm(uint16_t client_psm) {
  if (client_psm_to_real_psm_map_.find(client_psm) !=
      client_psm_to_real_psm_map_.end()) {
    client_psm_to_real_psm_map_.erase(client_psm);
  }
}

uint16_t bluetooth::shim::legacy::L2cap::GetNextVirtualPsm(uint16_t real_psm) {
  if (real_psm < kInitialClassicDynamicPsm) {
    return real_psm;
  }

  while (Classic().IsPsmRegistered(classic_virtual_psm_)) {
    classic_virtual_psm_ += 2;
    if (classic_virtual_psm_ >= kFinalClassicVirtualPsm) {
      classic_virtual_psm_ = kInitialClassicVirtualPsm;
    }
  }
  return classic_virtual_psm_;
}

uint16_t bluetooth::shim::legacy::L2cap::GetNextDynamicLePsm() {
  while (Le().IsPsmRegistered(le_dynamic_psm_)) {
    le_dynamic_psm_++;
    if (le_dynamic_psm_ > kFinalLeDynamicPsm) {
      le_dynamic_psm_ = kInitialLeDynamicPsm;
    }
  }
  return le_dynamic_psm_;
}

uint16_t bluetooth::shim::legacy::L2cap::RegisterService(
    uint16_t psm, const tL2CAP_APPL_INFO& callbacks, bool enable_snoop,
    tL2CAP_ERTM_INFO* p_ertm_info, uint16_t my_mtu,
    uint16_t required_remote_mtu) {
  if (Classic().IsPsmRegistered(psm)) {
    LOG_WARN("Service is already registered psm:%hd", psm);
    return 0;
  }
  if (!enable_snoop) {
    LOG_INFO("Disable snooping on psm basis unsupported psm:%d", psm);
  }

  LOG_INFO("Registering service on psm:%hd", psm);
  RegisterServicePromise register_promise;
  auto service_registered = register_promise.get_future();
  bool use_ertm = false;
  if (p_ertm_info != nullptr &&
      p_ertm_info->preferred_mode == L2CAP_FCR_ERTM_MODE) {
    use_ertm = true;
  }
  bluetooth::shim::GetL2cap()->RegisterClassicService(
      psm, use_ertm, my_mtu, required_remote_mtu,
      std::bind(
          &bluetooth::shim::legacy::L2cap::OnRemoteInitiatedConnectionCreated,
          this, std::placeholders::_1, std::placeholders::_2,
          std::placeholders::_3, std::placeholders::_4),
      std::move(register_promise));

  uint16_t registered_psm = service_registered.get();
  if (registered_psm != psm) {
    LOG_WARN("Unable to register psm:%hd", psm);
  } else {
    LOG_INFO("Successfully registered psm:%hd", psm);
    Classic().RegisterPsm(registered_psm, callbacks);
  }
  return registered_psm;
}

void bluetooth::shim::legacy::L2cap::UnregisterService(uint16_t psm) {
  if (!Classic().IsPsmRegistered(psm)) {
    LOG_WARN("Service must be registered in order to unregister psm:%hd", psm);
    return;
  }
  for (auto& entry : cid_to_psm_map_) {
    if (entry.second == psm) {
      LOG_WARN("  Unregistering service with active channels psm:%hd cid:%hd",
               psm, entry.first);
    }
  }

  LOG_INFO("Unregistering service on psm:%hd", psm);
  UnregisterServicePromise unregister_promise;
  auto service_unregistered = unregister_promise.get_future();
  bluetooth::shim::GetL2cap()->UnregisterClassicService(
      psm, std::move(unregister_promise));
  service_unregistered.wait();
  Classic().UnregisterPsm(psm);
}

uint16_t bluetooth::shim::legacy::L2cap::CreateConnection(
    uint16_t psm, const RawAddress& raw_address) {
  if (!Classic().IsPsmRegistered(psm)) {
    LOG_WARN("Service must be registered in order to connect psm:%hd", psm);
    return kInvalidConnectionInterfaceDescriptor;
  }

  CreateConnectionPromise create_promise;
  auto created = create_promise.get_future();
  LOG_INFO("Initiating local connection to psm:%hd address:%s", psm,
           raw_address.ToString().c_str());

  bluetooth::shim::GetL2cap()->CreateClassicConnection(
      psm, raw_address.ToString(),
      std::bind(
          &bluetooth::shim::legacy::L2cap::OnLocalInitiatedConnectionCreated,
          this, std::placeholders::_1, std::placeholders::_2,
          std::placeholders::_3, std::placeholders::_4, std::placeholders::_5),
      std::move(create_promise));

  uint16_t cid = created.get();
  if (cid == kInvalidConnectionInterfaceDescriptor) {
    LOG_WARN("Failed to initiate connection interface to psm:%hd address:%s",
             psm, raw_address.ToString().c_str());
  } else {
    LOG_INFO(
        "Successfully initiated connection to psm:%hd address:%s"
        " connection_interface_descriptor:%hd",
        psm, raw_address.ToString().c_str(), cid);
    CHECK(!ConnectionExists(cid));
    cid_to_psm_map_[cid] = psm;
  }
  return cid;
}

void bluetooth::shim::legacy::L2cap::OnLocalInitiatedConnectionCreated(
    std::string string_address, uint16_t psm, uint16_t cid, uint16_t remote_cid,
    bool connected) {
  cid_to_remote_cid_map_[cid] = remote_cid;
  if (cid_closing_set_.count(cid) == 0) {
    if (connected) {
      SetDownstreamCallbacks(cid);
    } else {
      LOG_WARN("Failed intitiating connection remote:%s psm:%hd cid:%hd",
               string_address.c_str(), psm, cid);
    }
    do_in_main_thread(
        FROM_HERE,
        base::Bind(classic_.Callbacks(psm).pL2CA_ConnectCfm_Cb, cid,
                   connected ? (kConnectionSuccess) : (kConnectionFail)));
    tL2CAP_CFG_INFO cfg_info{};
    do_in_main_thread(
        FROM_HERE,
        base::Bind(classic_.Callbacks(CidToPsm(cid)).pL2CA_ConfigCfm_Cb, cid,
                   L2CAP_INITIATOR_LOCAL, base::Unretained(&cfg_info)));

  } else {
    LOG_INFO("Connection Closed before presentation to upper layer");
    if (connected) {
      SetDownstreamCallbacks(cid);
      bluetooth::shim::GetL2cap()->CloseClassicConnection(cid);
    } else {
      LOG_INFO("Connection failed after initiator closed");
    }
  }
}

void bluetooth::shim::legacy::L2cap::OnRemoteInitiatedConnectionCreated(
    std::string string_address, uint16_t psm, uint16_t cid,
    uint16_t remote_cid) {
  RawAddress raw_address;
  RawAddress::FromString(string_address, raw_address);

  LOG_INFO(
      "Sending connection indicator to upper stack from device:%s "
      "psm:%hd cid:%hd",
      string_address.c_str(), psm, cid);

  CHECK(!ConnectionExists(cid));
  cid_to_psm_map_[cid] = psm;
  cid_to_remote_cid_map_[cid] = remote_cid;
  SetDownstreamCallbacks(cid);
  do_in_main_thread(
      FROM_HERE,
      base::Bind(classic_.Callbacks(CidToPsm(cid)).pL2CA_ConnectInd_Cb,
                 raw_address, cid, psm, kUnusedId));
  tL2CAP_CFG_INFO cfg_info{};
  do_in_main_thread(
      FROM_HERE,
      base::Bind(classic_.Callbacks(CidToPsm(cid)).pL2CA_ConfigCfm_Cb, cid,
                 L2CAP_INITIATOR_REMOTE, base::Unretained(&cfg_info)));
}

bool bluetooth::shim::legacy::L2cap::Write(uint16_t cid, BT_HDR* bt_hdr) {
  CHECK(bt_hdr != nullptr);
  const uint8_t* data = bt_hdr->data + bt_hdr->offset;
  size_t len = bt_hdr->len;
  if (!ConnectionExists(cid) || len == 0) {
    return false;
  }
  LOG_INFO("Writing data cid:%hd len:%zd", cid, len);
  bluetooth::shim::GetL2cap()->Write(cid, data, len);
  return true;
}

void bluetooth::shim::legacy::L2cap::SetDownstreamCallbacks(uint16_t cid) {
  bluetooth::shim::GetL2cap()->SetReadDataReadyCallback(
      cid, [this](uint16_t cid, std::vector<const uint8_t> data) {
        LOG_INFO("OnDataReady cid:%hd len:%zd", cid, data.size());
        BT_HDR* bt_hdr =
            static_cast<BT_HDR*>(osi_calloc(data.size() + kBtHdrSize));
        std::copy(data.begin(), data.end(), bt_hdr->data);
        bt_hdr->len = data.size();
        do_in_main_thread(
            FROM_HERE,
            base::Bind(classic_.Callbacks(CidToPsm(cid)).pL2CA_DataInd_Cb, cid,
                       base::Unretained(bt_hdr)));
      });

  bluetooth::shim::GetL2cap()->SetConnectionClosedCallback(
      cid, [this](uint16_t cid, int error_code) {
        LOG_INFO("OnChannel closed callback cid:%hd", cid);
        if (!ConnectionExists(cid)) {
          LOG_WARN("%s Unexpected channel closure cid:%hd", __func__, cid);
          return;
        }
        if (cid_closing_set_.count(cid) == 1) {
          cid_closing_set_.erase(cid);
        } else {
          do_in_main_thread(
              FROM_HERE,
              base::Bind(
                  classic_.Callbacks(CidToPsm(cid)).pL2CA_DisconnectInd_Cb, cid,
                  kDisconnectResponseRequired));
        }
        cid_to_psm_map_.erase(cid);
        cid_to_remote_cid_map_.erase(cid);
      });
}

bool bluetooth::shim::legacy::L2cap::DisconnectRequest(uint16_t cid) {
  CHECK(ConnectionExists(cid));
  if (cid_closing_set_.find(cid) != cid_closing_set_.end()) {
    LOG_WARN("%s Channel already in closing state cid:%hu", __func__, cid);
    return false;
  }
  LOG_INFO("%s initiated locally cid:%hu", __func__, cid);
  cid_closing_set_.insert(cid);
  bluetooth::shim::GetL2cap()->CloseClassicConnection(cid);
  return true;
}

void bluetooth::shim::legacy::L2cap::Dump(int fd) {
  if (cid_to_psm_map_.empty()) {
    dprintf(fd, "%s No active l2cap channels\n", kModuleName);
  } else {
    for (auto& connection : cid_to_psm_map_) {
      dprintf(fd, "%s active l2cap channel cid:%hd psm:%hd\n", kModuleName,
              connection.first, connection.second);
    }
  }
}

bool bluetooth::shim::legacy::L2cap::GetRemoteCid(uint16_t cid,
                                                  uint16_t* remote_cid) {
  auto it = cid_to_remote_cid_map_.find(cid);
  if (it == cid_to_remote_cid_map_.end()) {
    return false;
  }

  *remote_cid = it->second;
  return true;
}
