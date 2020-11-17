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

#include "main/shim/l2c_api.h"
#include "bta/include/bta_dm_acl.h"
#include "gd/l2cap/classic/l2cap_classic_module.h"
#include "gd/l2cap/le/l2cap_le_module.h"
#include "gd/os/log.h"
#include "gd/os/queue.h"
#include "main/shim/btm.h"
#include "main/shim/entry.h"
#include "main/shim/helpers.h"
#include "main/shim/l2cap.h"
#include "main/shim/stack.h"
#include "osi/include/allocator.h"
#include "stack/btm/btm_sec.h"
#include "stack/include/acl_hci_link_interface.h"
#include "stack/include/btm_api.h"

static bluetooth::shim::legacy::L2cap shim_l2cap;

// Helper: L2cap security enforcement shim

std::unordered_map<intptr_t,
                   bluetooth::common::ContextualOnceCallback<void(bool)>>
    security_enforce_callback_map = {};

class ClassicSecurityEnforcementShim
    : public bluetooth::l2cap::classic::SecurityEnforcementInterface {
 public:
  static void security_enforce_result_callback(const RawAddress* bd_addr,
                                               tBT_TRANSPORT trasnport,
                                               void* p_ref_data,
                                               tBTM_STATUS result) {
    intptr_t counter = (intptr_t)p_ref_data;
    if (security_enforce_callback_map.count(counter) == 0) {
      LOG_ERROR("Received unexpected callback");
      return;
    }

    auto& callback = security_enforce_callback_map[counter];
    std::move(callback).Invoke(result == BTM_SUCCESS);
    security_enforce_callback_map.erase(counter);
  }

  void Enforce(bluetooth::hci::AddressWithType remote,
               bluetooth::l2cap::classic::SecurityPolicy policy,
               ResultCallback result_callback) override {
    uint16_t sec_mask = 0;
    switch (policy) {
      case bluetooth::l2cap::classic::SecurityPolicy::
          _SDP_ONLY_NO_SECURITY_WHATSOEVER_PLAINTEXT_TRANSPORT_OK:
        result_callback.Invoke(true);
        return;
      case bluetooth::l2cap::classic::SecurityPolicy::ENCRYPTED_TRANSPORT:
        sec_mask = BTM_SEC_IN_AUTHENTICATE | BTM_SEC_IN_ENCRYPT |
                   BTM_SEC_OUT_AUTHENTICATE | BTM_SEC_OUT_ENCRYPT;
        break;
      case bluetooth::l2cap::classic::SecurityPolicy::BEST:
      case bluetooth::l2cap::classic::SecurityPolicy::
          AUTHENTICATED_ENCRYPTED_TRANSPORT:
        sec_mask = BTM_SEC_IN_AUTHENTICATE | BTM_SEC_IN_ENCRYPT |
                   BTM_SEC_IN_MITM | BTM_SEC_OUT_AUTHENTICATE |
                   BTM_SEC_OUT_ENCRYPT | BTM_SEC_OUT_MITM;
        break;
    }
    auto bd_addr = bluetooth::ToRawAddress(remote.GetAddress());
    security_enforce_callback_map[security_enforce_callback_counter_] =
        std::move(result_callback);
    btm_sec_l2cap_access_req_by_requirement(
        bd_addr, sec_mask, true, security_enforce_result_callback,
        (void*)security_enforce_callback_counter_);
    security_enforce_callback_counter_++;
  }

  intptr_t security_enforce_callback_counter_ = 100;
} security_enforcement_shim_;

struct RemoteFeature {
  uint8_t lmp_version = 0;
  uint16_t manufacturer_name = 0;
  uint16_t sub_version = 0;
  bool version_info_received = false;
  bool role_switch_supported = false;
  bool ssp_supported = false;
  bool sc_supported = false;
};

std::unordered_map<RawAddress, RemoteFeature> remote_feature_map_;

class SecurityListenerShim
    : public bluetooth::l2cap::classic::LinkSecurityInterfaceListener {
 public:
  void OnLinkConnected(
      std::unique_ptr<bluetooth::l2cap::classic::LinkSecurityInterface>
          interface) override {
    auto bda = bluetooth::ToRawAddress(interface->GetRemoteAddress());

    uint16_t handle = interface->GetAclHandle();
    address_to_handle_[bda] = handle;
    btm_sec_connected(bda, handle, HCI_SUCCESS, 0);
    BTA_dm_acl_up(bda, BT_TRANSPORT_BR_EDR);
    address_to_interface_[bda] = std::move(interface);
  }

  void OnAuthenticationComplete(bluetooth::hci::Address remote) override {
    auto bda = bluetooth::ToRawAddress(remote);
    uint16_t handle = address_to_handle_[bda];
    btm_sec_auth_complete(handle, HCI_SUCCESS);
  }

  void OnLinkDisconnected(bluetooth::hci::Address remote) override {
    auto bda = bluetooth::ToRawAddress(remote);
    uint16_t handle = address_to_handle_[bda];
    btm_sec_disconnected(handle, HCI_ERR_PEER_USER);
    BTA_dm_acl_down(bda, BT_TRANSPORT_BR_EDR);
    address_to_handle_.erase(bda);
    address_to_interface_.erase(bda);
  }

  void OnEncryptionChange(bluetooth::hci::Address remote,
                          bool encrypted) override {
    auto bda = bluetooth::ToRawAddress(remote);
    uint16_t handle = address_to_handle_[bda];
    btm_sec_encrypt_change(handle, HCI_SUCCESS, encrypted);
  }

  void OnReadRemoteVersionInformation(bluetooth::hci::Address remote,
                                      uint8_t lmp_version,
                                      uint16_t manufacturer_name,
                                      uint16_t sub_version) override {
    auto bda = bluetooth::ToRawAddress(remote);
    auto& entry = remote_feature_map_[bda];
    entry.lmp_version = lmp_version;
    entry.manufacturer_name = manufacturer_name;
    entry.sub_version = sub_version;
    entry.version_info_received = true;
  }

  void OnReadRemoteExtendedFeatures(bluetooth::hci::Address remote,
                                    uint8_t page_number,
                                    uint8_t max_page_number,
                                    uint64_t features) override {
    auto bda = bluetooth::ToRawAddress(remote);
    uint16_t handle = address_to_handle_[bda];
    uint8_t* features_array = (uint8_t*)&features;
    if (page_number == 0) {
      btm_read_remote_features_complete(handle, features_array);
    } else {
      btm_read_remote_ext_features_complete(handle, page_number,
                                            max_page_number, features_array);
    }
  }

  void UpdateLinkHoldForSecurity(RawAddress remote, bool is_bonding) {
    if (address_to_interface_.count(remote) == 0) {
      return;
    }
    if (is_bonding) {
      address_to_interface_[remote]->Hold();
    } else {
      address_to_interface_[remote]->Release();
    }
  }

  bool IsRoleCentral(RawAddress remote) {
    if (address_to_interface_.count(remote) == 0) {
      return false;
    }
    return address_to_interface_[remote]->GetRole() ==
           bluetooth::hci::Role::CENTRAL;
  }

  std::unordered_map<RawAddress, uint16_t> address_to_handle_;
  std::unordered_map<
      RawAddress,
      std::unique_ptr<bluetooth::l2cap::classic::LinkSecurityInterface>>
      address_to_interface_;
} security_listener_shim_;

bluetooth::l2cap::classic::SecurityInterface* security_interface_ = nullptr;

std::unordered_map<intptr_t,
                   bluetooth::common::ContextualOnceCallback<void(bool)>>
    le_security_enforce_callback_map = {};

class LeSecurityEnforcementShim
    : public bluetooth::l2cap::le::SecurityEnforcementInterface {
 public:
  static void le_security_enforce_result_callback(const RawAddress* bd_addr,
                                                  tBT_TRANSPORT trasnport,
                                                  void* p_ref_data,
                                                  tBTM_STATUS result) {
    intptr_t counter = (intptr_t)p_ref_data;
    if (le_security_enforce_callback_map.count(counter) == 0) {
      LOG_ERROR("Received unexpected callback");
      return;
    }

    auto& callback = le_security_enforce_callback_map[counter];
    std::move(callback).Invoke(result == BTM_SUCCESS);
    le_security_enforce_callback_map.erase(counter);
  }

  void Enforce(bluetooth::hci::AddressWithType remote,
               bluetooth::l2cap::le::SecurityPolicy policy,
               ResultCallback result_callback) override {
    tBTM_BLE_SEC_ACT sec_act = 0;
    switch (policy) {
      case bluetooth::l2cap::le::SecurityPolicy::
          NO_SECURITY_WHATSOEVER_PLAINTEXT_TRANSPORT_OK:
        result_callback.Invoke(true);
        return;
      case bluetooth::l2cap::le::SecurityPolicy::ENCRYPTED_TRANSPORT:
        sec_act = BTM_BLE_SEC_ENCRYPT;
        break;
      case bluetooth::l2cap::le::SecurityPolicy::BEST:
      case bluetooth::l2cap::le::SecurityPolicy::
          AUTHENTICATED_ENCRYPTED_TRANSPORT:
        sec_act = BTM_BLE_SEC_ENCRYPT_MITM;
        break;
      default:
        result_callback.Invoke(false);
    }
    auto bd_addr = bluetooth::ToRawAddress(remote.GetAddress());
    le_security_enforce_callback_map[security_enforce_callback_counter_] =
        std::move(result_callback);
    BTM_SetEncryption(bd_addr, BT_TRANSPORT_LE,
                      le_security_enforce_result_callback,
                      (void*)security_enforce_callback_counter_, sec_act);
    security_enforce_callback_counter_++;
  }

  intptr_t security_enforce_callback_counter_ = 100;
} le_security_enforcement_shim_;

bool bluetooth::shim::L2CA_ReadRemoteVersion(const RawAddress& addr,
                                             uint8_t* lmp_version,
                                             uint16_t* manufacturer,
                                             uint16_t* lmp_sub_version) {
  auto& entry = remote_feature_map_[addr];
  if (!entry.version_info_received) {
    return false;
  }
  *lmp_version = entry.lmp_version;
  *manufacturer = entry.manufacturer_name;
  *lmp_sub_version = entry.sub_version;
  return true;
}

void bluetooth::shim::L2CA_UseLegacySecurityModule() {
  LOG_INFO("GD L2cap is using legacy security module");
  bluetooth::shim::GetL2capClassicModule()->InjectSecurityEnforcementInterface(
      &security_enforcement_shim_);
  security_interface_ =
      bluetooth::shim::GetL2capClassicModule()->GetSecurityInterface(
          bluetooth::shim::GetGdShimHandler(), &security_listener_shim_);

  bluetooth::shim::GetL2capLeModule()->InjectSecurityEnforcementInterface(
      &le_security_enforcement_shim_);
}

/**
 * Classic Service Registration APIs
 */
uint16_t bluetooth::shim::L2CA_Register(uint16_t client_psm,
                                        const tL2CAP_APPL_INFO& callbacks,
                                        bool enable_snoop,
                                        tL2CAP_ERTM_INFO* p_ertm_info,
                                        uint16_t my_mtu,
                                        uint16_t required_remote_mtu) {
  if (L2C_INVALID_PSM(client_psm)) {
    LOG_ERROR("%s Invalid classic psm:%hd", __func__, client_psm);
    return 0;
  }

  if ((callbacks.pL2CA_ConfigCfm_Cb == nullptr) ||
      (callbacks.pL2CA_ConfigInd_Cb == nullptr) ||
      (callbacks.pL2CA_DataInd_Cb == nullptr) ||
      (callbacks.pL2CA_DisconnectInd_Cb == nullptr)) {
    LOG_ERROR("%s Invalid classic callbacks psm:%hd", __func__, client_psm);
    return 0;
  }

  /**
   * Check if this is a registration for an outgoing-only connection.
   */
  const bool is_outgoing_connection_only =
      callbacks.pL2CA_ConnectInd_Cb == nullptr;
  const uint16_t psm = shim_l2cap.ConvertClientToRealPsm(
      client_psm, is_outgoing_connection_only);

  if (shim_l2cap.Classic().IsPsmRegistered(psm)) {
    LOG_ERROR("%s Already registered classic client_psm:%hd psm:%hd", __func__,
              client_psm, psm);
    return 0;
  }
  LOG_INFO("%s classic client_psm:%hd psm:%hd", __func__, client_psm, psm);
  // Minimum acceptable MTU is 48 bytes
  required_remote_mtu = std::max<uint16_t>(required_remote_mtu, 48);
  return shim_l2cap.RegisterService(psm, callbacks, enable_snoop, p_ertm_info,
                                    my_mtu, required_remote_mtu);
}

void bluetooth::shim::L2CA_Deregister(uint16_t client_psm) {
  if (L2C_INVALID_PSM(client_psm)) {
    LOG_ERROR("%s Invalid classic client_psm:%hd", __func__, client_psm);
    return;
  }
  uint16_t psm = shim_l2cap.ConvertClientToRealPsm(client_psm);

  shim_l2cap.UnregisterService(psm);
  shim_l2cap.RemoveClientPsm(psm);
}

uint16_t bluetooth::shim::L2CA_AllocatePSM(void) {
  return shim_l2cap.GetNextDynamicClassicPsm();
}

uint16_t bluetooth::shim::L2CA_AllocateLePSM(void) {
  return shim_l2cap.GetNextDynamicLePsm();
}

void bluetooth::shim::L2CA_FreeLePSM(uint16_t psm) {
  if (!shim_l2cap.Le().IsPsmRegistered(psm)) {
    LOG_ERROR("%s Not previously registered le psm:%hd", __func__, psm);
    return;
  }
  shim_l2cap.Le().UnregisterPsm(psm);
}

/**
 * Classic Connection Oriented Channel APIS
 */
uint16_t bluetooth::shim::L2CA_ConnectReq(uint16_t psm,
                                          const RawAddress& raw_address) {
  return shim_l2cap.CreateConnection(psm, raw_address);
}

bool bluetooth::shim::L2CA_DisconnectReq(uint16_t cid) {
  return shim_l2cap.DisconnectRequest(cid);
}

bool bluetooth::shim::L2CA_ReconfigCreditBasedConnsReq(
    const RawAddress& bd_addr, std::vector<uint16_t>& lcids,
    tL2CAP_LE_CFG_INFO* p_cfg) {
  LOG_INFO("UNIMPLEMENTED %s addr: %s cfg:%p", __func__,
           bd_addr.ToString().c_str(), p_cfg);
  return false;
}

std::vector<uint16_t> bluetooth::shim::L2CA_ConnectCreditBasedReq(
    uint16_t psm, const RawAddress& p_bd_addr, tL2CAP_LE_CFG_INFO* p_cfg) {
  LOG_INFO("UNIMPLEMENTED %s addr:%s", __func__, p_bd_addr.ToString().c_str());
  std::vector<uint16_t> result;
  return result;
}

bool bluetooth::shim::L2CA_ConnectCreditBasedRsp(
    const RawAddress& bd_addr, uint8_t id,
    std::vector<uint16_t>& accepted_lcids, uint16_t result,
    tL2CAP_LE_CFG_INFO* p_cfg) {
  LOG_INFO("UNIMPLEMENTED %s addr:%s", __func__, bd_addr.ToString().c_str());
  return false;
}

uint8_t bluetooth::shim::L2CA_DataWrite(uint16_t cid, BT_HDR* p_data) {
  bool write_success = shim_l2cap.Write(cid, p_data);
  return write_success ? L2CAP_DW_SUCCESS : L2CAP_DW_FAILED;
}

/**
 * Link APIs
 */
bool bluetooth::shim::L2CA_SetIdleTimeoutByBdAddr(const RawAddress& bd_addr,
                                                  uint16_t timeout,
                                                  tBT_TRANSPORT transport) {
  LOG_INFO("UNIMPLEMENTED %s", __func__);
  return false;
}

bool bluetooth::shim::L2CA_SetAclPriority(const RawAddress& bd_addr,
                                          tL2CAP_PRIORITY priority) {
  LOG_INFO("UNIMPLEMENTED %s", __func__);
  return false;
}

bool bluetooth::shim::L2CA_GetPeerFeatures(const RawAddress& bd_addr,
                                           uint32_t* p_ext_feat,
                                           uint8_t* p_chnl_mask) {
  LOG_INFO("UNIMPLEMENTED %s", __func__);
  return false;
}

using bluetooth::hci::AddressWithType;
using bluetooth::l2cap::le::DynamicChannel;
using bluetooth::l2cap::le::DynamicChannelManager;
using bluetooth::l2cap::le::DynamicChannelService;
using bluetooth::l2cap::le::FixedChannel;
using bluetooth::l2cap::le::FixedChannelManager;
using bluetooth::l2cap::le::FixedChannelService;

static constexpr uint16_t kAttCid = 4;
static constexpr uint16_t kSmpCid = 6;

struct LeFixedChannelHelper {
  LeFixedChannelHelper(uint16_t cid) : cid_(cid) {}

  uint16_t cid_;

  void on_registration_complete(FixedChannelManager::RegistrationResult result,
                                std::unique_ptr<FixedChannelService> service) {
    if (result != FixedChannelManager::RegistrationResult::SUCCESS) {
      LOG(ERROR) << "Channel is not registered. cid=" << +cid_;
      return;
    }
    channel_service_ = std::move(service);
  }

  std::unique_ptr<FixedChannelService> channel_service_ = nullptr;

  void on_channel_close(bluetooth::hci::AddressWithType device,
                        bluetooth::hci::ErrorCode error_code) {
    auto address = bluetooth::ToRawAddress(device.GetAddress());
    channel_enqueue_buffer_[device] = nullptr;
    channels_[device]->GetQueueUpEnd()->UnregisterDequeue();
    channels_[device] = nullptr;
    (freg_.pL2CA_FixedConn_Cb)(cid_, address, true, 0, 2);
  }

  void on_channel_open(std::unique_ptr<FixedChannel> channel) {
    auto device = channel->GetDevice();
    channel->RegisterOnCloseCallback(
        bluetooth::shim::GetGdShimHandler(),
        bluetooth::common::BindOnce(&LeFixedChannelHelper::on_channel_close,
                                    bluetooth::common::Unretained(this),
                                    device));
    channel->Acquire();
    channel_enqueue_buffer_[device] = std::make_unique<
        bluetooth::os::EnqueueBuffer<bluetooth::packet::BasePacketBuilder>>(
        channel->GetQueueUpEnd());
    channel->GetQueueUpEnd()->RegisterDequeue(
        bluetooth::shim::GetGdShimHandler(),
        bluetooth::common::Bind(&LeFixedChannelHelper::on_incoming_data,
                                bluetooth::common::Unretained(this), device));
    channels_[device] = std::move(channel);

    auto address = bluetooth::ToRawAddress(device.GetAddress());

    (freg_.pL2CA_FixedConn_Cb)(cid_, address, true, 0, BT_TRANSPORT_LE);
    bluetooth::shim::Btm::StoreAddressType(
        address, static_cast<tBLE_ADDR_TYPE>(device.GetAddressType()));
  }

  void on_incoming_data(bluetooth::hci::AddressWithType remote) {
    auto channel = channels_.find(remote);
    if (channel == channels_.end()) {
      LOG_ERROR("Channel is not open");
      return;
    }
    auto packet = channel->second->GetQueueUpEnd()->TryDequeue();
    std::vector<uint8_t> packet_vector(packet->begin(), packet->end());
    BT_HDR* buffer =
        static_cast<BT_HDR*>(osi_calloc(packet_vector.size() + sizeof(BT_HDR)));
    std::copy(packet_vector.begin(), packet_vector.end(), buffer->data);
    buffer->len = packet_vector.size();
    auto address = bluetooth::ToRawAddress(remote.GetAddress());
    freg_.pL2CA_FixedData_Cb(cid_, address, buffer);
  }

  void on_outgoing_connection_fail(
      RawAddress remote, FixedChannelManager::ConnectionResult result) {
    LOG(ERROR) << "Outgoing connection failed";
    freg_.pL2CA_FixedConn_Cb(cid_, remote, true, 0, BT_TRANSPORT_LE);
  }

  bool send(AddressWithType remote,
            std::unique_ptr<bluetooth::packet::BasePacketBuilder> packet) {
    auto buffer = channel_enqueue_buffer_.find(remote);
    if (buffer == channel_enqueue_buffer_.end() || buffer->second == nullptr) {
      LOG(ERROR) << "Channel is not open";
      return false;
    }
    buffer->second->Enqueue(std::move(packet),
                            bluetooth::shim::GetGdShimHandler());
    return true;
  }

  std::unordered_map<AddressWithType, std::unique_ptr<FixedChannel>> channels_;
  std::unordered_map<AddressWithType,
                     std::unique_ptr<bluetooth::os::EnqueueBuffer<
                         bluetooth::packet::BasePacketBuilder>>>
      channel_enqueue_buffer_;
  tL2CAP_FIXED_CHNL_REG freg_;
};

static LeFixedChannelHelper att_helper{4};
static LeFixedChannelHelper smp_helper{6};
static std::unordered_map<uint16_t, LeFixedChannelHelper&>
    le_fixed_channel_helper_{
        {4, att_helper},
        {6, smp_helper},
    };

/**
 * Fixed Channel APIs. Note: Classic fixed channel (connectionless and BR SMP)
 * is not supported
 */
bool bluetooth::shim::L2CA_RegisterFixedChannel(uint16_t cid,
                                                tL2CAP_FIXED_CHNL_REG* p_freg) {
  if (cid != kAttCid && cid != kSmpCid) {
    LOG(ERROR) << "Invalid cid: " << cid;
    return false;
  }
  auto* helper = &le_fixed_channel_helper_.find(cid)->second;
  if (helper == nullptr) {
    LOG(ERROR) << "Can't register cid " << cid;
    return false;
  }
  bluetooth::shim::GetL2capLeModule()
      ->GetFixedChannelManager()
      ->RegisterService(
          cid,
          common::BindOnce(&LeFixedChannelHelper::on_registration_complete,
                           common::Unretained(helper)),
          common::Bind(&LeFixedChannelHelper::on_channel_open,
                       common::Unretained(helper)),
          GetGdShimHandler());
  helper->freg_ = *p_freg;
  return true;
}

bool bluetooth::shim::L2CA_ConnectFixedChnl(uint16_t cid,
                                            const RawAddress& rem_bda) {
  if (cid != kAttCid && cid != kSmpCid) {
    LOG(ERROR) << "Invalid cid " << cid;
    return false;
  }

  auto* helper = &le_fixed_channel_helper_.find(cid)->second;
  auto remote = ToAddressWithType(rem_bda, Btm::GetAddressType(rem_bda));
  auto manager = bluetooth::shim::GetL2capLeModule()->GetFixedChannelManager();
  manager->ConnectServices(
      remote,
      common::BindOnce(&LeFixedChannelHelper::on_outgoing_connection_fail,
                       common::Unretained(helper), rem_bda),
      GetGdShimHandler());
  return true;
}

bool bluetooth::shim::L2CA_ConnectFixedChnl(uint16_t cid,
                                            const RawAddress& rem_bda,
                                            uint8_t initiating_phys) {
  return bluetooth::shim::L2CA_ConnectFixedChnl(cid, rem_bda);
}

uint16_t bluetooth::shim::L2CA_SendFixedChnlData(uint16_t cid,
                                                 const RawAddress& rem_bda,
                                                 BT_HDR* p_buf) {
  if (cid != kAttCid && cid != kSmpCid) {
    LOG(ERROR) << "Invalid cid " << cid;
    return false;
  }
  auto* helper = &le_fixed_channel_helper_.find(cid)->second;
  auto remote = ToAddressWithType(rem_bda, Btm::GetAddressType(rem_bda));
  auto len = p_buf->len;
  auto* data = p_buf->data + p_buf->offset;
  bool sent = helper->send(remote, MakeUniquePacket(data, len));
  return sent ? len : 0;
}

bool bluetooth::shim::L2CA_RemoveFixedChnl(uint16_t cid,
                                           const RawAddress& rem_bda) {
  if (cid != kAttCid && cid != kSmpCid) {
    LOG(ERROR) << "Invalid cid " << cid;
    return false;
  }
  auto* helper = &le_fixed_channel_helper_.find(cid)->second;
  auto remote = ToAddressWithType(rem_bda, Btm::GetAddressType(rem_bda));
  auto channel = helper->channels_.find(remote);
  if (channel == helper->channels_.end() || channel->second == nullptr) {
    LOG(ERROR) << "Channel is not open";
    return false;
  }
  channel->second->Release();
  return true;
}

/**
 * Channel hygiene APIs
 */
bool bluetooth::shim::L2CA_GetRemoteCid(uint16_t lcid, uint16_t* rcid) {
  return shim_l2cap.GetRemoteCid(lcid, rcid);
}

bool bluetooth::shim::L2CA_SetTxPriority(uint16_t cid,
                                         tL2CAP_CHNL_PRIORITY priority) {
  LOG_INFO("UNIMPLEMENTED %s", __func__);
  return false;
}

bool bluetooth::shim::L2CA_SetFixedChannelTout(const RawAddress& rem_bda,
                                               uint16_t fixed_cid,
                                               uint16_t idle_tout) {
  LOG_INFO("UNIMPLEMENTED %s", __func__);
  return false;
}

bool bluetooth::shim::L2CA_SetChnlFlushability(uint16_t cid,
                                               bool is_flushable) {
  LOG_INFO("UNIMPLEMENTED %s", __func__);
  return false;
}

uint16_t bluetooth::shim::L2CA_FlushChannel(uint16_t lcid,
                                            uint16_t num_to_flush) {
  LOG_INFO("UNIMPLEMENTED %s", __func__);
  return 0;
}

bool bluetooth::shim::L2CA_IsLinkEstablished(const RawAddress& bd_addr,
                                             tBT_TRANSPORT transport) {
  LOG_INFO("UNIMPLEMENTED %s", __func__);
  return true;
}

void bluetooth::shim::L2CA_ConnectForSecurity(const RawAddress& bd_addr) {
  security_interface_->InitiateConnectionForSecurity(
      bluetooth::ToGdAddress(bd_addr));
}

void bluetooth::shim::L2CA_SetBondingState(const RawAddress& bd_addr,
                                           bool is_bonding) {
  security_listener_shim_.UpdateLinkHoldForSecurity(bd_addr, is_bonding);
}

// LE COC Shim Helper

uint16_t cid_token_counter_ = 1;

struct LeCocChannelInfo {
  uint16_t psm;
  RawAddress remote;
};
std::unordered_map<uint16_t, LeCocChannelInfo> cid_token_to_channel_map_;

uint16_t add_cid_token_entry(uint16_t psm, RawAddress remote) {
  uint16_t new_token = cid_token_counter_;
  cid_token_to_channel_map_[new_token] = {psm, remote};
  cid_token_counter_++;
  if (cid_token_counter_ == 0) cid_token_counter_++;
  return new_token;
}

void remove_cid_token_entry(uint16_t cid_token) {
  cid_token_to_channel_map_.erase(cid_token);
}

uint16_t find_cid_token_by_psm_address(uint16_t psm, RawAddress remote) {
  for (const auto& entry : cid_token_to_channel_map_) {
    if (entry.second.psm == psm && entry.second.remote == remote) {
      return entry.first;
    }
  }
  LOG(ERROR) << __func__ << "Can't find channel";
  return 0;
}

struct LeDynamicChannelHelper {
  LeDynamicChannelHelper(uint16_t psm, tL2CAP_APPL_INFO appl_info)
      : psm_(psm), appl_info_(appl_info) {}

  uint16_t psm_;
  tL2CAP_APPL_INFO appl_info_;

  void Register() {
    bluetooth::shim::GetL2capLeModule()
        ->GetDynamicChannelManager()
        ->RegisterService(
            psm_, {}, {},
            bluetooth::common::BindOnce(
                &LeDynamicChannelHelper::on_registration_complete,
                bluetooth::common::Unretained(this)),
            bluetooth::common::Bind(&LeDynamicChannelHelper::on_channel_open,
                                    bluetooth::common::Unretained(this)),
            bluetooth::shim::GetGdShimHandler());
  }

  void on_registration_complete(
      DynamicChannelManager::RegistrationResult result,
      std::unique_ptr<DynamicChannelService> service) {
    if (result != DynamicChannelManager::RegistrationResult::SUCCESS) {
      LOG(ERROR) << "Channel is not registered. psm=" << +psm_ << (int)result;
      return;
    }
    channel_service_ = std::move(service);
  }

  std::unique_ptr<DynamicChannelService> channel_service_ = nullptr;

  void Connect(bluetooth::hci::AddressWithType device) {
    if (channel_service_ == nullptr) {
      return;
    }
    initiated_by_us_[device] = true;
    bluetooth::shim::GetL2capLeModule()
        ->GetDynamicChannelManager()
        ->ConnectChannel(
            device, {}, psm_,
            bluetooth::common::Bind(&LeDynamicChannelHelper::on_channel_open,
                                    bluetooth::common::Unretained(this)),
            bluetooth::common::Bind(
                &LeDynamicChannelHelper::on_outgoing_connection_fail,
                bluetooth::common::Unretained(this)),
            bluetooth::shim::GetGdShimHandler());
  }

  void Disconnect(bluetooth::hci::AddressWithType device) {
    if (channel_service_ == nullptr) {
      return;
    }
    if (channels_.count(device) == 0) {
      return;
    }
    channels_[device]->Close();
    disconnected_by_us_[device] = true;
  }

  void Unregister() {
    if (channel_service_ != nullptr) {
      channel_service_->Unregister(
          bluetooth::common::BindOnce(&LeDynamicChannelHelper::on_unregistered,
                                      bluetooth::common::Unretained(this)),
          bluetooth::shim::GetGdShimHandler());
      channel_service_ = nullptr;
    }
  }

  void on_unregistered() {
    for (const auto& device : channels_) {
      device.second->Close();
    }
  }

  void on_channel_close(bluetooth::hci::AddressWithType device,
                        bluetooth::hci::ErrorCode error_code) {
    channel_enqueue_buffer_[device] = nullptr;
    channels_[device]->GetQueueUpEnd()->UnregisterDequeue();
    channels_.erase(device);
    auto address = bluetooth::ToRawAddress(device.GetAddress());
    auto cid_token = find_cid_token_by_psm_address(psm_, address);
    (appl_info_.pL2CA_DisconnectInd_Cb)(cid_token, false);
    remove_cid_token_entry(cid_token);
    initiated_by_us_.erase(device);

    if (channel_service_ == nullptr && channels_.empty()) {
      // Try again
      bluetooth::shim::L2CA_DeregisterLECoc(psm_);
    }
  }

  void on_channel_open(std::unique_ptr<DynamicChannel> channel) {
    auto device = channel->GetDevice();
    channel->RegisterOnCloseCallback(
        bluetooth::shim::GetGdShimHandler()->BindOnceOn(
            this, &LeDynamicChannelHelper::on_channel_close, device));
    channel_enqueue_buffer_[device] = std::make_unique<
        bluetooth::os::EnqueueBuffer<bluetooth::packet::BasePacketBuilder>>(
        channel->GetQueueUpEnd());
    channel->GetQueueUpEnd()->RegisterDequeue(
        bluetooth::shim::GetGdShimHandler(),
        bluetooth::common::Bind(&LeDynamicChannelHelper::on_incoming_data,
                                bluetooth::common::Unretained(this), device));
    channels_[device] = std::move(channel);

    auto address = bluetooth::ToRawAddress(device.GetAddress());
    if (initiated_by_us_[device]) {
      auto cid_token = find_cid_token_by_psm_address(psm_, address);
      appl_info_.pL2CA_ConnectCfm_Cb(cid_token, 0);
    } else {
      if (appl_info_.pL2CA_ConnectInd_Cb == nullptr) {
        Disconnect(device);
        return;
      }
      auto cid_token = add_cid_token_entry(psm_, address);
      appl_info_.pL2CA_ConnectInd_Cb(address, cid_token, psm_, 0);
    }
  }

  void on_incoming_data(bluetooth::hci::AddressWithType remote) {
    auto channel = channels_.find(remote);
    if (channel == channels_.end()) {
      LOG_ERROR("Channel is not open");
      return;
    }
    auto packet = channel->second->GetQueueUpEnd()->TryDequeue();
    std::vector<uint8_t> packet_vector(packet->begin(), packet->end());
    BT_HDR* buffer =
        static_cast<BT_HDR*>(osi_calloc(packet_vector.size() + sizeof(BT_HDR)));
    std::copy(packet_vector.begin(), packet_vector.end(), buffer->data);
    buffer->len = packet_vector.size();
    auto address = bluetooth::ToRawAddress(remote.GetAddress());
    auto cid_token = find_cid_token_by_psm_address(psm_, address);
    appl_info_.pL2CA_DataInd_Cb(cid_token, buffer);
  }

  void on_outgoing_connection_fail(
      DynamicChannelManager::ConnectionResult result) {
    LOG(ERROR) << "Outgoing connection failed";
  }

  bool send(AddressWithType remote,
            std::unique_ptr<bluetooth::packet::BasePacketBuilder> packet) {
    auto buffer = channel_enqueue_buffer_.find(remote);
    if (buffer == channel_enqueue_buffer_.end() || buffer->second == nullptr) {
      LOG(ERROR) << "Channel is not open";
      return false;
    }
    buffer->second->Enqueue(std::move(packet),
                            bluetooth::shim::GetGdShimHandler());
    return true;
  }

  uint16_t GetMtu(AddressWithType remote) {
    if (channels_.count(remote) == 0) {
      return 0;
    }
    return static_cast<uint16_t>(channels_[remote]->GetMtu());
  }

  std::unordered_map<AddressWithType, std::unique_ptr<DynamicChannel>>
      channels_;
  std::unordered_map<AddressWithType,
                     std::unique_ptr<bluetooth::os::EnqueueBuffer<
                         bluetooth::packet::BasePacketBuilder>>>
      channel_enqueue_buffer_;
  std::unordered_map<AddressWithType, uint16_t> cid_map_;
  std::unordered_map<AddressWithType, bool> initiated_by_us_;
  std::unordered_map<AddressWithType, bool> disconnected_by_us_;
};

std::unordered_map<uint16_t, std::unique_ptr<LeDynamicChannelHelper>>
    le_dynamic_channel_helper_map_;

/**
 * Le Connection Oriented Channel APIs
 */
uint16_t bluetooth::shim::L2CA_RegisterLECoc(uint16_t psm,
                                             const tL2CAP_APPL_INFO& callbacks,
                                             uint16_t sec_level) {
  if (le_dynamic_channel_helper_map_.count(psm) != 0) {
    LOG(ERROR) << __func__ << "Already registered psm: " << psm;
    return 0;
  }
  le_dynamic_channel_helper_map_[psm] =
      std::make_unique<LeDynamicChannelHelper>(psm, callbacks);
  le_dynamic_channel_helper_map_[psm]->Register();
  return psm;
}

void bluetooth::shim::L2CA_DeregisterLECoc(uint16_t psm) {
  if (le_dynamic_channel_helper_map_.count(psm) == 0) {
    LOG(ERROR) << __func__ << "Not registered psm: " << psm;
    return;
  }
  le_dynamic_channel_helper_map_[psm]->Unregister();
  if (le_dynamic_channel_helper_map_[psm]->channels_.empty()) {
    le_dynamic_channel_helper_map_.erase(psm);
  }
}

uint16_t bluetooth::shim::L2CA_ConnectLECocReq(uint16_t psm,
                                               const RawAddress& p_bd_addr,
                                               tL2CAP_LE_CFG_INFO* p_cfg) {
  if (le_dynamic_channel_helper_map_.count(psm) == 0) {
    LOG(ERROR) << __func__ << "Not registered psm: " << psm;
    return 0;
  }
  le_dynamic_channel_helper_map_[psm]->Connect(
      ToAddressWithType(p_bd_addr, Btm::GetAddressType(p_bd_addr)));
  return add_cid_token_entry(psm, p_bd_addr);
}

bool bluetooth::shim::L2CA_GetPeerLECocConfig(uint16_t cid,
                                              tL2CAP_LE_CFG_INFO* peer_cfg) {
  if (cid_token_to_channel_map_.count(cid) == 0) {
    LOG(ERROR) << __func__ << "Invalid cid: " << cid;
    return false;
  }
  auto psm = cid_token_to_channel_map_[cid].psm;
  auto remote = cid_token_to_channel_map_[cid].remote;
  if (le_dynamic_channel_helper_map_.count(psm) == 0) {
    LOG(ERROR) << __func__ << "Not registered psm: " << psm;
    return false;
  }
  auto mtu = le_dynamic_channel_helper_map_[psm]->GetMtu(
      bluetooth::ToAddressWithType(remote, Btm::GetAddressType(remote)));
  peer_cfg->mtu = mtu;
  return mtu;
}

bool bluetooth::shim::L2CA_DisconnectLECocReq(uint16_t cid) {
  if (cid_token_to_channel_map_.count(cid) == 0) {
    LOG(ERROR) << __func__ << "Invalid cid: " << cid;
    return false;
  }
  auto psm = cid_token_to_channel_map_[cid].psm;
  auto remote = cid_token_to_channel_map_[cid].remote;
  if (le_dynamic_channel_helper_map_.count(psm) == 0) {
    LOG(ERROR) << __func__ << "Not registered psm: " << psm;
    return false;
  }
  le_dynamic_channel_helper_map_[psm]->Disconnect(
      bluetooth::ToAddressWithType(remote, Btm::GetAddressType(remote)));
  return true;
}

uint8_t bluetooth::shim::L2CA_LECocDataWrite(uint16_t cid, BT_HDR* p_data) {
  if (cid_token_to_channel_map_.count(cid) == 0) {
    LOG(ERROR) << __func__ << "Invalid cid: " << cid;
    return 0;
  }
  auto psm = cid_token_to_channel_map_[cid].psm;
  auto remote = cid_token_to_channel_map_[cid].remote;
  if (le_dynamic_channel_helper_map_.count(psm) == 0) {
    LOG(ERROR) << __func__ << "Not registered psm: " << psm;
    return 0;
  }
  auto len = p_data->len;
  auto* data = p_data->data + p_data->offset;
  return le_dynamic_channel_helper_map_[psm]->send(
             ToAddressWithType(remote, Btm::GetAddressType(remote)),
             MakeUniquePacket(data, len)) *
         len;
}

void bluetooth::shim::L2CA_SwitchRoleToCentral(const RawAddress& addr) {
  bluetooth::shim::GetAclManager()->SwitchRole(ToGdAddress(addr),
                                               bluetooth::hci::Role::CENTRAL);
}
