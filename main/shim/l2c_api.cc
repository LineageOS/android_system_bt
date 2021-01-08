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

#include <future>
#include <unordered_map>
#include <unordered_set>

#include "main/shim/l2c_api.h"
#include "bta/include/bta_dm_acl.h"
#include "gd/l2cap/classic/l2cap_classic_module.h"
#include "gd/l2cap/le/l2cap_le_module.h"
#include "gd/os/log.h"
#include "gd/os/queue.h"
#include "main/shim/acl_api.h"
#include "main/shim/btm.h"
#include "main/shim/entry.h"
#include "main/shim/helpers.h"
#include "main/shim/stack.h"
#include "osi/include/allocator.h"
#include "stack/btm/btm_sec.h"
#include "stack/include/acl_hci_link_interface.h"
#include "stack/include/btm_api.h"
#include "stack/include/btu.h"

extern void gatt_notify_conn_update(const RawAddress& remote, uint16_t interval,
                                    uint16_t latency, uint16_t timeout,
                                    tHCI_STATUS status);

namespace bluetooth {
namespace shim {

using bluetooth::hci::AddressWithType;
using namespace bluetooth::l2cap;

// Classic Dynamic Channel Shim Helper

namespace {
uint16_t classic_cid_token_counter_ = 0x41;

std::unordered_map<uint16_t /* token */, uint16_t /* psm */>
    classic_cid_token_to_channel_map_;

uint16_t add_classic_cid_token_entry(uint16_t psm) {
  uint16_t new_token = classic_cid_token_counter_;
  classic_cid_token_to_channel_map_[new_token] = psm;
  classic_cid_token_counter_++;
  if (classic_cid_token_counter_ == 0) classic_cid_token_counter_ = 0x41;
  return new_token;
}

void remove_classic_cid_token_entry(uint16_t cid_token) {
  classic_cid_token_to_channel_map_.erase(cid_token);
}

struct ClassicDynamicChannelHelper {
  ClassicDynamicChannelHelper(uint16_t psm, tL2CAP_APPL_INFO appl_info,
                              classic::DynamicChannelConfigurationOption config,
                              classic::SecurityPolicy policy)
      : psm_(psm), appl_info_(appl_info), config_(config), policy_(policy) {}

  uint16_t psm_;
  tL2CAP_APPL_INFO appl_info_;
  classic::DynamicChannelConfigurationOption config_;
  classic::SecurityPolicy policy_;

  void Register() {
    GetL2capClassicModule()->GetDynamicChannelManager()->RegisterService(
        psm_, config_, policy_,
        GetGdShimHandler()->BindOnceOn(
            this, &ClassicDynamicChannelHelper::on_registration_complete),
        GetGdShimHandler()->BindOn(
            this, &ClassicDynamicChannelHelper::on_channel_open, 0));
  }

  void on_registration_complete(
      classic::DynamicChannelManager::RegistrationResult result,
      std::unique_ptr<classic::DynamicChannelService> service) {
    if (result != classic::DynamicChannelManager::RegistrationResult::SUCCESS) {
      LOG(ERROR) << "Channel is not registered. psm=" << +psm_ << (int)result;
      return;
    }
    channel_service_ = std::move(service);
  }

  std::unique_ptr<classic::DynamicChannelService> channel_service_ = nullptr;

  void Connect(uint16_t cid_token, bluetooth::hci::AddressWithType device) {
    if (channel_service_ == nullptr) {
      return;
    }
    initiated_by_us_[cid_token] = true;
    GetL2capClassicModule()->GetDynamicChannelManager()->ConnectChannel(
        device.GetAddress(), config_, psm_,
        GetGdShimHandler()->BindOn(
            this, &ClassicDynamicChannelHelper::on_channel_open, cid_token),
        GetGdShimHandler()->BindOnceOn(
            this, &ClassicDynamicChannelHelper::on_outgoing_connection_fail));
  }

  void Disconnect(uint16_t cid_token) {
    if (channel_service_ == nullptr) {
      return;
    }
    if (channels_.count(cid_token) == 0) {
      return;
    }
    channels_[cid_token]->Close();
  }

  void Unregister() {
    if (channel_service_ != nullptr) {
      channel_service_->Unregister(GetGdShimHandler()->BindOnceOn(
          this, &ClassicDynamicChannelHelper::on_unregistered));
      channel_service_ = nullptr;
    }
  }

  void on_unregistered() {
    for (const auto& device : channels_) {
      device.second->Close();
    }
  }

  void on_channel_close(uint16_t cid_token,
                        bluetooth::hci::ErrorCode error_code) {
    channel_enqueue_buffer_[cid_token] = nullptr;
    channels_[cid_token]->GetQueueUpEnd()->UnregisterDequeue();
    channels_.erase(cid_token);
    do_in_main_thread(FROM_HERE, base::Bind(appl_info_.pL2CA_DisconnectInd_Cb,
                                            cid_token, false));

    remove_classic_cid_token_entry(cid_token);
    initiated_by_us_.erase(cid_token);

    if (channel_service_ == nullptr && channels_.empty()) {
      // Try again
      L2CA_Deregister(psm_);
    }
  }

  void on_channel_open(uint16_t cid_token,
                       std::unique_ptr<classic::DynamicChannel> channel) {
    auto device = channel->GetDevice();
    auto address = bluetooth::ToRawAddress(device.GetAddress());
    bool initiator_local = (cid_token != 0);
    if (cid_token == 0) {
      cid_token = add_classic_cid_token_entry(psm_);
    }

    channel->RegisterOnCloseCallback(GetGdShimHandler()->BindOnceOn(
        this, &ClassicDynamicChannelHelper::on_channel_close, cid_token));

    channel->GetQueueUpEnd()->RegisterDequeue(
        GetGdShimHandler(),
        bluetooth::common::Bind(&ClassicDynamicChannelHelper::on_incoming_data,
                                bluetooth::common::Unretained(this),
                                cid_token));

    channel_enqueue_buffer_[cid_token] = std::make_unique<
        bluetooth::os::EnqueueBuffer<bluetooth::packet::BasePacketBuilder>>(
        channel->GetQueueUpEnd());

    channels_[cid_token] = std::move(channel);

    if (initiator_local) {
      do_in_main_thread(
          FROM_HERE, base::Bind(appl_info_.pL2CA_ConnectCfm_Cb, cid_token, 0));

      tL2CAP_CFG_INFO cfg_info{};
      do_in_main_thread(FROM_HERE, base::Bind(appl_info_.pL2CA_ConfigCfm_Cb,
                                              cid_token, L2CAP_INITIATOR_LOCAL,
                                              base::Unretained(&cfg_info)));
    } else {
      if (appl_info_.pL2CA_ConnectInd_Cb == nullptr) {
        Disconnect(cid_token);
        return;
      }
      do_in_main_thread(FROM_HERE, base::Bind(appl_info_.pL2CA_ConnectInd_Cb,
                                              address, cid_token, psm_, 0));

      tL2CAP_CFG_INFO cfg_info{};
      do_in_main_thread(FROM_HERE, base::Bind(appl_info_.pL2CA_ConfigCfm_Cb,
                                              cid_token, L2CAP_INITIATOR_LOCAL,
                                              base::Unretained(&cfg_info)));
    }
  }

  void on_incoming_data(uint16_t cid_token) {
    auto channel = channels_.find(cid_token);
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
    do_in_main_thread(FROM_HERE,
                      base::Bind(appl_info_.pL2CA_DataInd_Cb, cid_token,
                                 base::Unretained(buffer)));
  }

  void on_outgoing_connection_fail(
      classic::DynamicChannelManager::ConnectionResult result) {
    LOG(ERROR) << "Outgoing connection failed";
  }

  bool send(uint16_t cid,
            std::unique_ptr<bluetooth::packet::BasePacketBuilder> packet) {
    auto buffer = channel_enqueue_buffer_.find(cid);
    if (buffer == channel_enqueue_buffer_.end() || buffer->second == nullptr) {
      LOG(ERROR) << "Channel is not open";
      return false;
    }
    buffer->second->Enqueue(std::move(packet), GetGdShimHandler());
    return true;
  }

  uint16_t GetRemoteCid(uint16_t cid) {
    auto channel = channels_.find(cid);
    if (channel == channels_.end()) {
      LOG_ERROR("Channel is not open");
      return 0;
    }
    return channel->second->HACK_GetRemoteCid();
  }

  std::unordered_map<uint16_t, std::unique_ptr<classic::DynamicChannel>>
      channels_;
  std::unordered_map<uint16_t, std::unique_ptr<bluetooth::os::EnqueueBuffer<
                                   bluetooth::packet::BasePacketBuilder>>>
      channel_enqueue_buffer_;
  std::unordered_map<uint16_t, bool> initiated_by_us_;
};

std::unordered_map<uint16_t, std::unique_ptr<ClassicDynamicChannelHelper>>
    classic_dynamic_channel_helper_map_;

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
    address_to_handle_.erase(bda);
    address_to_interface_.erase(bda);
    btm_sec_disconnected(handle, HCI_ERR_PEER_USER);
    BTA_dm_acl_down(bda, BT_TRANSPORT_BR_EDR);
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

  void Disconnect(RawAddress remote) {
    if (address_to_interface_.count(remote) == 0) {
      return;
    }
    return address_to_interface_[remote]->Disconnect();
  }

  uint16_t GetNumAclLinks() { return address_to_handle_.size(); }

  bool IsLinkUp(RawAddress remote) {
    return address_to_interface_.count(remote) != 0;
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
}  // namespace

bool L2CA_ReadRemoteVersion(const RawAddress& addr, uint8_t* lmp_version,
                            uint16_t* manufacturer, uint16_t* lmp_sub_version) {
  auto& entry = remote_feature_map_[addr];
  if (!entry.version_info_received) {
    return false;
  }
  *lmp_version = entry.lmp_version;
  *manufacturer = entry.manufacturer_name;
  *lmp_sub_version = entry.sub_version;
  return true;
}

void L2CA_UseLegacySecurityModule() {
  LOG_INFO("GD L2cap is using legacy security module");
  GetL2capClassicModule()->InjectSecurityEnforcementInterface(
      &security_enforcement_shim_);
  security_interface_ = GetL2capClassicModule()->GetSecurityInterface(
      GetGdShimHandler(), &security_listener_shim_);

  GetL2capLeModule()->InjectSecurityEnforcementInterface(
      &le_security_enforcement_shim_);

  // TODO(b/161543441): read the privacy policy from device-specific
  // configuration, and IRK from config file.
  hci::LeAddressManager::AddressPolicy address_policy =
      hci::LeAddressManager::AddressPolicy::USE_RESOLVABLE_ADDRESS;
  hci::AddressWithType empty_address_with_type(
      hci::Address{}, hci::AddressType::RANDOM_DEVICE_ADDRESS);
  crypto_toolbox::Octet16 rotation_irk = {0x44, 0xfb, 0x4b, 0x8d, 0x6c, 0x58,
                                          0x21, 0x0c, 0xf9, 0x3d, 0xda, 0xf1,
                                          0x64, 0xa3, 0xbb, 0x7f};
  /* 7 minutes minimum, 15 minutes maximum for random address refreshing */
  auto minimum_rotation_time = std::chrono::minutes(7);
  auto maximum_rotation_time = std::chrono::minutes(15);

  GetAclManager()->SetPrivacyPolicyForInitiatorAddress(
      address_policy, empty_address_with_type, rotation_irk,
      minimum_rotation_time, maximum_rotation_time);
}

/**
 * Classic Service Registration APIs
 */
uint16_t L2CA_Register(uint16_t client_psm, const tL2CAP_APPL_INFO& callbacks,
                       bool enable_snoop, tL2CAP_ERTM_INFO* p_ertm_info,
                       uint16_t my_mtu, uint16_t required_remote_mtu,
                       uint16_t sec_level) {
  if (classic_dynamic_channel_helper_map_.count(client_psm) != 0) {
    LOG(ERROR) << __func__ << "Already registered psm: " << client_psm;
    return 0;
  }

  classic::DynamicChannelConfigurationOption config;
  config.minimal_remote_mtu = std::max<uint16_t>(required_remote_mtu, 48);
  config.incoming_mtu = my_mtu;
  config.channel_mode =
      (p_ertm_info != nullptr &&
               p_ertm_info->preferred_mode == L2CAP_FCR_ERTM_MODE
           ? classic::DynamicChannelConfigurationOption::
                 RetransmissionAndFlowControlMode::ENHANCED_RETRANSMISSION
           : classic::DynamicChannelConfigurationOption::
                 RetransmissionAndFlowControlMode::L2CAP_BASIC);

  classic::SecurityPolicy policy =
      (client_psm == 1
           ? classic::SecurityPolicy::
                 _SDP_ONLY_NO_SECURITY_WHATSOEVER_PLAINTEXT_TRANSPORT_OK
           : classic::SecurityPolicy::ENCRYPTED_TRANSPORT);
  if (sec_level & (BTM_SEC_IN_AUTHENTICATE | BTM_SEC_OUT_AUTHENTICATE)) {
    policy = classic::SecurityPolicy::BEST;
  }

  classic_dynamic_channel_helper_map_[client_psm] =
      std::make_unique<ClassicDynamicChannelHelper>(client_psm, callbacks,
                                                    config, policy);

  classic_dynamic_channel_helper_map_[client_psm]->Register();
  return client_psm;
}

void L2CA_Deregister(uint16_t psm) {
  if (classic_dynamic_channel_helper_map_.count(psm) == 0) {
    LOG(ERROR) << __func__ << "Not registered psm: " << psm;
    return;
  }
  classic_dynamic_channel_helper_map_[psm]->Unregister();
  if (classic_dynamic_channel_helper_map_[psm]->channels_.empty()) {
    classic_dynamic_channel_helper_map_.erase(psm);
  }
}

/**
 * Classic Connection Oriented Channel APIS
 */
uint16_t L2CA_ConnectReq(uint16_t psm, const RawAddress& raw_address) {
  if (classic_dynamic_channel_helper_map_.count(psm) == 0) {
    LOG(ERROR) << __func__ << "Not registered psm: " << psm;
    return 0;
  }
  uint16_t cid_token = add_classic_cid_token_entry(psm);
  classic_dynamic_channel_helper_map_[psm]->Connect(
      cid_token, ToAddressWithType(raw_address, BLE_ADDR_PUBLIC));
  return cid_token;
}

bool L2CA_DisconnectReq(uint16_t cid) {
  auto psm = classic_cid_token_to_channel_map_[cid];
  if (classic_dynamic_channel_helper_map_.count(psm) == 0) {
    LOG(ERROR) << __func__ << "Not registered psm: " << psm;
    return false;
  }
  classic_dynamic_channel_helper_map_[psm]->Disconnect(cid);
  return true;
}

uint8_t L2CA_DataWrite(uint16_t cid, BT_HDR* p_data) {
  if (classic_cid_token_to_channel_map_.count(cid) == 0) {
    LOG(ERROR) << __func__ << "Invalid cid: " << cid;
    return 0;
  }
  auto psm = classic_cid_token_to_channel_map_[cid];
  if (classic_dynamic_channel_helper_map_.count(psm) == 0) {
    LOG(ERROR) << __func__ << "Not registered psm: " << psm;
    return 0;
  }
  auto len = p_data->len;
  auto* data = p_data->data + p_data->offset;
  return classic_dynamic_channel_helper_map_[psm]->send(
             cid, MakeUniquePacket(data, len)) *
         len;
}

bool L2CA_ReconfigCreditBasedConnsReq(const RawAddress& bd_addr,
                                      std::vector<uint16_t>& lcids,
                                      tL2CAP_LE_CFG_INFO* p_cfg) {
  LOG_INFO("UNIMPLEMENTED %s addr: %s cfg:%p", __func__,
           bd_addr.ToString().c_str(), p_cfg);
  return false;
}

std::vector<uint16_t> L2CA_ConnectCreditBasedReq(uint16_t psm,
                                                 const RawAddress& p_bd_addr,
                                                 tL2CAP_LE_CFG_INFO* p_cfg) {
  LOG_INFO("UNIMPLEMENTED %s addr:%s", __func__, p_bd_addr.ToString().c_str());
  std::vector<uint16_t> result;
  return result;
}

bool L2CA_ConnectCreditBasedRsp(const RawAddress& bd_addr, uint8_t id,
                                std::vector<uint16_t>& accepted_lcids,
                                uint16_t result, tL2CAP_LE_CFG_INFO* p_cfg) {
  LOG_INFO("UNIMPLEMENTED %s addr:%s", __func__, bd_addr.ToString().c_str());
  return false;
}

/**
 * Link APIs
 */
bool L2CA_SetIdleTimeoutByBdAddr(const RawAddress& bd_addr, uint16_t timeout,
                                 tBT_TRANSPORT transport) {
  if (transport == BT_TRANSPORT_BR_EDR) {
    LOG_INFO("UNIMPLEMENTED %s", __func__);
    return false;
  }
  constexpr int GATT_LINK_IDLE_TIMEOUT_WHEN_NO_APP = 1;
  if (timeout == 0 || timeout == GATT_LINK_IDLE_TIMEOUT_WHEN_NO_APP) {
    bluetooth::shim::L2CA_RemoveFixedChnl(kLeAttributeCid, bd_addr);
    return true;
  } else {
    LOG_INFO("UNIMPLEMENTED %s", __func__);
    return false;
  }
}

bool L2CA_SetAclPriority(const RawAddress& bd_addr, tL2CAP_PRIORITY priority) {
  LOG_INFO("UNIMPLEMENTED %s", __func__);
  return false;
}

bool L2CA_GetPeerFeatures(const RawAddress& bd_addr, uint32_t* p_ext_feat,
                          uint8_t* p_chnl_mask) {
  LOG_INFO("UNIMPLEMENTED %s", __func__);
  return false;
}

static constexpr uint16_t kAttCid = 4;

struct LeFixedChannelHelper {
  LeFixedChannelHelper(uint16_t cid) : cid_(cid) {}

  uint16_t cid_;

  void on_registration_complete(
      le::FixedChannelManager::RegistrationResult result,
      std::unique_ptr<le::FixedChannelService> service) {
    if (result != le::FixedChannelManager::RegistrationResult::SUCCESS) {
      LOG(ERROR) << "Channel is not registered. cid=" << +cid_;
      return;
    }
    channel_service_ = std::move(service);
  }

  std::unique_ptr<le::FixedChannelService> channel_service_ = nullptr;

  void on_channel_close(bluetooth::hci::AddressWithType device,
                        bluetooth::hci::ErrorCode error_code) {
    auto address = bluetooth::ToRawAddress(device.GetAddress());
    channel_enqueue_buffer_[device] = nullptr;
    channels_[device]->GetQueueUpEnd()->UnregisterDequeue();
    channels_[device] = nullptr;
    (freg_.pL2CA_FixedConn_Cb)(cid_, address, false, 0, BT_TRANSPORT_LE);
  }

  void on_channel_open(std::unique_ptr<le::FixedChannel> channel) {
    auto device = channel->GetDevice();
    channel->RegisterOnCloseCallback(
        GetGdShimHandler(), bluetooth::common::BindOnce(
                                &LeFixedChannelHelper::on_channel_close,
                                bluetooth::common::Unretained(this), device));
    if (cid_ == kAttCid) {
      channel->Acquire();
    }
    channel_enqueue_buffer_[device] = std::make_unique<
        bluetooth::os::EnqueueBuffer<bluetooth::packet::BasePacketBuilder>>(
        channel->GetQueueUpEnd());
    channel->GetQueueUpEnd()->RegisterDequeue(
        GetGdShimHandler(),
        bluetooth::common::Bind(&LeFixedChannelHelper::on_incoming_data,
                                bluetooth::common::Unretained(this), device));
    channels_[device] = std::move(channel);

    auto address = bluetooth::ToRawAddress(device.GetAddress());

    (freg_.pL2CA_FixedConn_Cb)(cid_, address, true, 0, BT_TRANSPORT_LE);
    Btm::StoreAddressType(address,
                          static_cast<tBLE_ADDR_TYPE>(device.GetAddressType()));
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
      RawAddress remote, le::FixedChannelManager::ConnectionResult result) {
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
    buffer->second->Enqueue(std::move(packet), GetGdShimHandler());
    return true;
  }

  std::unordered_map<AddressWithType, std::unique_ptr<le::FixedChannel>>
      channels_;
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
bool L2CA_RegisterFixedChannel(uint16_t cid, tL2CAP_FIXED_CHNL_REG* p_freg) {
  if (cid != kAttCid && cid != kSmpCid) {
    LOG(ERROR) << "Invalid cid: " << cid;
    return false;
  }
  auto* helper = &le_fixed_channel_helper_.find(cid)->second;
  if (helper == nullptr) {
    LOG(ERROR) << "Can't register cid " << cid;
    return false;
  }
  GetL2capLeModule()->GetFixedChannelManager()->RegisterService(
      cid,
      common::BindOnce(&LeFixedChannelHelper::on_registration_complete,
                       common::Unretained(helper)),
      common::Bind(&LeFixedChannelHelper::on_channel_open,
                   common::Unretained(helper)),
      GetGdShimHandler());
  helper->freg_ = *p_freg;
  return true;
}

bool L2CA_ConnectFixedChnl(uint16_t cid, const RawAddress& rem_bda) {
  if (cid != kAttCid && cid != kSmpCid) {
    LOG(ERROR) << "Invalid cid " << cid;
    return false;
  }

  auto* helper = &le_fixed_channel_helper_.find(cid)->second;
  auto remote = ToAddressWithType(rem_bda, Btm::GetAddressType(rem_bda));
  auto manager = GetL2capLeModule()->GetFixedChannelManager();
  manager->ConnectServices(
      remote,
      common::BindOnce(&LeFixedChannelHelper::on_outgoing_connection_fail,
                       common::Unretained(helper), rem_bda),
      GetGdShimHandler());
  return true;
}

uint16_t L2CA_SendFixedChnlData(uint16_t cid, const RawAddress& rem_bda,
                                BT_HDR* p_buf) {
  if (cid != kAttCid && cid != kSmpCid) {
    LOG(ERROR) << "Invalid cid " << cid;
    return L2CAP_DW_FAILED;
  }
  auto* helper = &le_fixed_channel_helper_.find(cid)->second;
  auto remote = ToAddressWithType(rem_bda, Btm::GetAddressType(rem_bda));
  auto len = p_buf->len;
  auto* data = p_buf->data + p_buf->offset;
  bool sent = helper->send(remote, MakeUniquePacket(data, len));
  return sent ? L2CAP_DW_SUCCESS : L2CAP_DW_FAILED;
}

bool L2CA_RemoveFixedChnl(uint16_t cid, const RawAddress& rem_bda) {
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

uint16_t L2CA_GetLeHandle(uint16_t cid, const RawAddress& rem_bda) {
  if (cid != kAttCid && cid != kSmpCid) {
    LOG(ERROR) << "Invalid cid " << cid;
    return 0;
  }
  auto* helper = &le_fixed_channel_helper_.find(cid)->second;
  auto remote = ToAddressWithType(rem_bda, Btm::GetAddressType(rem_bda));
  auto channel = helper->channels_.find(remote);
  if (channel == helper->channels_.end() || channel->second == nullptr) {
    LOG(ERROR) << "Channel is not open";
    return 0;
  }
  return channel->second->GetLinkOptions()->GetHandle();
}

void L2CA_LeConnectionUpdate(const RawAddress& rem_bda) {
  auto* helper = &le_fixed_channel_helper_.find(4)->second;
  auto remote = ToAddressWithType(rem_bda, Btm::GetAddressType(rem_bda));
  auto channel = helper->channels_.find(remote);
  if (channel == helper->channels_.end() || channel->second == nullptr) {
    LOG(ERROR) << "Channel is not open";
  }

  channel->second->GetLinkOptions()->UpdateConnectionParameter(0x24, 0x24, 0,
                                                               0x01f4, 0, 0);
}

/**
 * Channel hygiene APIs
 */
bool L2CA_GetRemoteCid(uint16_t lcid, uint16_t* rcid) {
  auto psm = classic_cid_token_to_channel_map_[lcid];
  if (classic_dynamic_channel_helper_map_.count(psm) == 0) {
    LOG(ERROR) << __func__ << "Not registered psm: " << psm;
    return false;
  }
  *rcid = classic_dynamic_channel_helper_map_[psm]->GetRemoteCid(lcid);
  return *rcid != 0;
}

bool L2CA_SetTxPriority(uint16_t cid, tL2CAP_CHNL_PRIORITY priority) {
  LOG_INFO("UNIMPLEMENTED %s", __func__);
  return false;
}

bool L2CA_SetFixedChannelTout(const RawAddress& rem_bda, uint16_t fixed_cid,
                              uint16_t idle_tout) {
  if (fixed_cid != kLeAttributeCid) {
    LOG_INFO("UNIMPLEMENTED %s", __func__);
    return false;
  }
  if (idle_tout == 0xffff) {
    bluetooth::shim::L2CA_ConnectFixedChnl(kLeAttributeCid, rem_bda);
  } else {
    bluetooth::shim::L2CA_RemoveFixedChnl(kLeAttributeCid, rem_bda);
  }
  return true;
}

bool L2CA_SetChnlFlushability(uint16_t cid, bool is_flushable) {
  LOG_INFO("UNIMPLEMENTED %s", __func__);
  return false;
}

uint16_t L2CA_FlushChannel(uint16_t lcid, uint16_t num_to_flush) {
  LOG_INFO("UNIMPLEMENTED %s", __func__);
  return 0;
}

bool L2CA_IsLinkEstablished(const RawAddress& bd_addr,
                            tBT_TRANSPORT transport) {
  if (transport == BT_TRANSPORT_BR_EDR) {
    return security_listener_shim_.IsLinkUp(bd_addr);
  } else {
    return bluetooth::shim::L2CA_GetLeHandle(kAttCid, bd_addr) != 0;
  }
}

void L2CA_ConnectForSecurity(const RawAddress& bd_addr) {
  security_interface_->InitiateConnectionForSecurity(
      bluetooth::ToGdAddress(bd_addr));
}

void L2CA_SetBondingState(const RawAddress& bd_addr, bool is_bonding) {
  security_listener_shim_.UpdateLinkHoldForSecurity(bd_addr, is_bonding);
}

void L2CA_DisconnectLink(const RawAddress& remote) {
  security_listener_shim_.Disconnect(remote);
}

uint16_t L2CA_GetNumLinks() { return security_listener_shim_.GetNumAclLinks(); }

// LE COC Shim Helper

namespace {

uint16_t le_cid_token_counter_ = 0x41;

std::unordered_map<uint16_t /* token */, uint16_t /* psm */>
    le_cid_token_to_channel_map_;

uint16_t add_le_cid_token_entry(uint16_t psm) {
  uint16_t new_token = le_cid_token_counter_;
  le_cid_token_to_channel_map_[new_token] = psm;
  le_cid_token_counter_++;
  if (le_cid_token_counter_ == 0) le_cid_token_counter_ = 0x41;
  return new_token;
}

void remove_le_cid_token_entry(uint16_t cid_token) {
  le_cid_token_to_channel_map_.erase(cid_token);
}

struct LeDynamicChannelHelper {
  LeDynamicChannelHelper(uint16_t psm, tL2CAP_APPL_INFO appl_info,
                         le::DynamicChannelConfigurationOption config,
                         le::SecurityPolicy policy)
      : psm_(psm), appl_info_(appl_info), config_(config), policy_(policy) {}

  uint16_t psm_;
  tL2CAP_APPL_INFO appl_info_;
  le::DynamicChannelConfigurationOption config_;
  le::SecurityPolicy policy_;

  void Register() {
    std::promise<void> promise;
    auto future = promise.get_future();
    GetL2capLeModule()->GetDynamicChannelManager()->RegisterService(
        psm_, config_, policy_,
        base::BindOnce(&LeDynamicChannelHelper::on_registration_complete,
                       base::Unretained(this), std::move(promise)),
        base::Bind(&LeDynamicChannelHelper::on_channel_open,
                   base::Unretained(this), 0),
        GetGdShimHandler());
    future.wait_for(std::chrono::milliseconds(300));
  }

  void on_registration_complete(
      std::promise<void> promise,
      le::DynamicChannelManager::RegistrationResult result,
      std::unique_ptr<le::DynamicChannelService> service) {
    if (result != le::DynamicChannelManager::RegistrationResult::SUCCESS) {
      LOG(ERROR) << "Channel is not registered. psm=" << +psm_ << (int)result;
      promise.set_value();
      return;
    }
    channel_service_ = std::move(service);
    promise.set_value();
  }

  std::unique_ptr<le::DynamicChannelService> channel_service_ = nullptr;

  void Connect(uint16_t cid_token, bluetooth::hci::AddressWithType device) {
    if (channel_service_ == nullptr) {
      LOG(ERROR) << __func__ << "Not registered";
      return;
    }
    initiated_by_us_[cid_token] = true;
    GetL2capLeModule()->GetDynamicChannelManager()->ConnectChannel(
        device, config_, psm_,
        base::Bind(&LeDynamicChannelHelper::on_channel_open,
                   base::Unretained(this), cid_token),
        base::BindOnce(&LeDynamicChannelHelper::on_outgoing_connection_fail,
                       base::Unretained(this)),
        GetGdShimHandler());
  }

  void Disconnect(uint16_t cid_token) {
    if (channel_service_ == nullptr) {
      return;
    }
    if (channels_.count(cid_token) == 0) {
      return;
    }
    channels_[cid_token]->Close();
  }

  void Unregister() {
    if (channel_service_ != nullptr) {
      channel_service_->Unregister(
          base::BindOnce(&LeDynamicChannelHelper::on_unregistered,
                         base::Unretained(this)),
          GetGdShimHandler());
      channel_service_ = nullptr;
    }
  }

  void on_unregistered() {
    for (const auto& device : channels_) {
      device.second->Close();
    }
  }

  void on_channel_close(uint16_t cid_token,
                        bluetooth::hci::ErrorCode error_code) {
    channel_enqueue_buffer_[cid_token] = nullptr;
    channels_[cid_token]->GetQueueUpEnd()->UnregisterDequeue();
    channels_.erase(cid_token);
    do_in_main_thread(FROM_HERE, base::Bind(appl_info_.pL2CA_DisconnectInd_Cb,
                                            cid_token, false));

    remove_le_cid_token_entry(cid_token);
    initiated_by_us_.erase(cid_token);

    if (channel_service_ == nullptr && channels_.empty()) {
      // Try again
      L2CA_Deregister(psm_);
    }
  }

  void on_channel_open(uint16_t cid_token,
                       std::unique_ptr<le::DynamicChannel> channel) {
    auto device = channel->GetDevice();
    auto address = bluetooth::ToRawAddress(device.GetAddress());
    bool initiator_local = (cid_token != 0);
    if (cid_token == 0) {
      cid_token = add_le_cid_token_entry(psm_);
    }

    channel->RegisterOnCloseCallback(GetGdShimHandler()->BindOnceOn(
        this, &LeDynamicChannelHelper::on_channel_close, cid_token));

    channel->GetQueueUpEnd()->RegisterDequeue(
        GetGdShimHandler(),
        bluetooth::common::Bind(&LeDynamicChannelHelper::on_incoming_data,
                                bluetooth::common::Unretained(this),
                                cid_token));

    channel_enqueue_buffer_[cid_token] = std::make_unique<
        bluetooth::os::EnqueueBuffer<bluetooth::packet::BasePacketBuilder>>(
        channel->GetQueueUpEnd());

    channels_[cid_token] = std::move(channel);

    if (initiator_local) {
      do_in_main_thread(
          FROM_HERE, base::Bind(appl_info_.pL2CA_ConnectCfm_Cb, cid_token, 0));

    } else {
      if (appl_info_.pL2CA_ConnectInd_Cb == nullptr) {
        Disconnect(cid_token);
        return;
      }
      do_in_main_thread(FROM_HERE, base::Bind(appl_info_.pL2CA_ConnectInd_Cb,
                                              address, cid_token, psm_, 0));
    }
  }

  void on_incoming_data(uint16_t cid_token) {
    auto channel = channels_.find(cid_token);
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
    do_in_main_thread(FROM_HERE,
                      base::Bind(appl_info_.pL2CA_DataInd_Cb, cid_token,
                                 base::Unretained(buffer)));
  }

  void on_outgoing_connection_fail(
      le::DynamicChannelManager::ConnectionResult result) {
    LOG(ERROR) << "Outgoing connection failed";
  }

  bool send(uint16_t cid,
            std::unique_ptr<bluetooth::packet::BasePacketBuilder> packet) {
    auto buffer = channel_enqueue_buffer_.find(cid);
    if (buffer == channel_enqueue_buffer_.end() || buffer->second == nullptr) {
      LOG(ERROR) << "Channel is not open";
      return false;
    }
    buffer->second->Enqueue(std::move(packet), GetGdShimHandler());
    return true;
  }

  uint16_t GetMtu(uint16_t cid_token) {
    if (channels_.count(cid_token) == 0) {
      return 0;
    }
    return static_cast<uint16_t>(channels_[cid_token]->GetMtu());
  }

  std::unordered_map<uint16_t, std::unique_ptr<le::DynamicChannel>> channels_;
  std::unordered_map<uint16_t, std::unique_ptr<bluetooth::os::EnqueueBuffer<
                                   bluetooth::packet::BasePacketBuilder>>>
      channel_enqueue_buffer_;
  std::unordered_map<uint16_t, bool> initiated_by_us_;
};

std::unordered_map<uint16_t, std::unique_ptr<LeDynamicChannelHelper>>
    le_dynamic_channel_helper_map_;

std::unordered_set<uint16_t> assigned_dynamic_le_psm_;
uint16_t next_assigned_dynamic_le_psm_ = 0x80;
}  // namespace

/**
 * Le Connection Oriented Channel APIs
 */

uint16_t L2CA_AllocateLePSM() {
  if (le_dynamic_channel_helper_map_.size() > 100) {
    LOG_ERROR("Why do we need more than 100 dynamic channel PSMs?");
    return 0;
  }
  while (le_dynamic_channel_helper_map_.count(next_assigned_dynamic_le_psm_)) {
    next_assigned_dynamic_le_psm_++;
    if (next_assigned_dynamic_le_psm_ > 0xff) {
      next_assigned_dynamic_le_psm_ = 0x80;
    }
  }
  assigned_dynamic_le_psm_.emplace(next_assigned_dynamic_le_psm_);
  return next_assigned_dynamic_le_psm_;
}

void L2CA_FreeLePSM(uint16_t psm) { assigned_dynamic_le_psm_.erase(psm); }

uint16_t L2CA_RegisterLECoc(uint16_t psm, const tL2CAP_APPL_INFO& callbacks,
                            uint16_t sec_level, tL2CAP_LE_CFG_INFO cfg) {
  if (le_dynamic_channel_helper_map_.count(psm) != 0) {
    LOG(ERROR) << __func__ << "Already registered psm: " << psm;
    return 0;
  }

  le::DynamicChannelConfigurationOption config;
  config.mtu = cfg.mtu;
  le::SecurityPolicy policy =
      le::SecurityPolicy::NO_SECURITY_WHATSOEVER_PLAINTEXT_TRANSPORT_OK;
  if (sec_level & (BTM_SEC_IN_AUTHENTICATE | BTM_SEC_OUT_AUTHENTICATE)) {
    policy = le::SecurityPolicy::AUTHENTICATED_ENCRYPTED_TRANSPORT;
  }

  le_dynamic_channel_helper_map_[psm] =
      std::make_unique<LeDynamicChannelHelper>(psm, callbacks, config, policy);
  le_dynamic_channel_helper_map_[psm]->Register();
  return psm;
}

void L2CA_DeregisterLECoc(uint16_t psm) {
  if (le_dynamic_channel_helper_map_.count(psm) == 0) {
    LOG(ERROR) << __func__ << "Not registered psm: " << psm;
    return;
  }
  le_dynamic_channel_helper_map_[psm]->Unregister();
  if (le_dynamic_channel_helper_map_[psm]->channels_.empty()) {
    le_dynamic_channel_helper_map_.erase(psm);
  }
}

uint16_t L2CA_ConnectLECocReq(uint16_t psm, const RawAddress& p_bd_addr,
                              tL2CAP_LE_CFG_INFO* p_cfg) {
  if (le_dynamic_channel_helper_map_.count(psm) == 0) {
    LOG(ERROR) << __func__ << "Not registered psm: " << psm;
    return 0;
  }
  uint16_t cid_token = add_le_cid_token_entry(psm);
  le_dynamic_channel_helper_map_[psm]->Connect(
      cid_token, ToAddressWithType(p_bd_addr, Btm::GetAddressType(p_bd_addr)));
  return cid_token;
}

bool L2CA_GetPeerLECocConfig(uint16_t cid, tL2CAP_LE_CFG_INFO* peer_cfg) {
  if (le_cid_token_to_channel_map_.count(cid) == 0) {
    LOG(ERROR) << __func__ << "Invalid cid: " << cid;
    return false;
  }
  auto psm = le_cid_token_to_channel_map_[cid];
  if (le_dynamic_channel_helper_map_.count(psm) == 0) {
    LOG(ERROR) << __func__ << "Not registered psm: " << psm;
    return false;
  }
  auto mtu = le_dynamic_channel_helper_map_[psm]->GetMtu(cid);
  peer_cfg->mtu = mtu;
  return mtu;
}

bool L2CA_DisconnectLECocReq(uint16_t cid) {
  if (le_cid_token_to_channel_map_.count(cid) == 0) {
    LOG(ERROR) << __func__ << "Invalid cid: " << cid;
    return false;
  }
  auto psm = le_cid_token_to_channel_map_[cid];
  if (le_dynamic_channel_helper_map_.count(psm) == 0) {
    LOG(ERROR) << __func__ << "Not registered psm: " << psm;
    return false;
  }
  le_dynamic_channel_helper_map_[psm]->Disconnect(cid);
  return true;
}

uint8_t L2CA_LECocDataWrite(uint16_t cid, BT_HDR* p_data) {
  if (le_cid_token_to_channel_map_.count(cid) == 0) {
    LOG(ERROR) << __func__ << "Invalid cid: " << cid;
    return 0;
  }
  auto psm = le_cid_token_to_channel_map_[cid];
  if (le_dynamic_channel_helper_map_.count(psm) == 0) {
    LOG(ERROR) << __func__ << "Not registered psm: " << psm;
    return false;
  }
  auto len = p_data->len;
  auto* data = p_data->data + p_data->offset;
  return le_dynamic_channel_helper_map_[psm]->send(
             cid, MakeUniquePacket(data, len)) *
         len;
}

void L2CA_SwitchRoleToCentral(const RawAddress& addr) {
  GetAclManager()->SwitchRole(ToGdAddress(addr), bluetooth::hci::Role::CENTRAL);
}

}  // namespace shim
}  // namespace bluetooth
