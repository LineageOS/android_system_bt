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
#define LOG_TAG "bt_shim_btif_dm"

#include "osi/include/log.h"

#include "main/shim/btif_dm.h"
#include "main/shim/entry.h"
#include "main/shim/helpers.h"
#include "security/security_module.h"
#include "security/ui.h"

using ::bluetooth::shim::GetSecurityModule;

namespace bluetooth {
namespace shim {

class ShimUi : public security::UI {
 public:
  ~ShimUi() {}
  void DisplayPairingPrompt(const bluetooth::hci::AddressWithType& address,
                            std::string name) {
    LOG_WARN("%s ■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■ TODO Unimplemented",
             __func__);
  }
  void Cancel(const bluetooth::hci::AddressWithType& address) {
    LOG_WARN("%s ■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■ TODO Unimplemented",
             __func__);
  }

  void DisplayConfirmValue(const bluetooth::hci::AddressWithType& address,
                           std::string name, uint32_t numeric_value) {
    bt_bdname_t legacy_name{0};
    memcpy(legacy_name.name, name.data(), name.length());
    callback_(ToRawAddress(address.GetAddress()), legacy_name,
              ((0x1F) << 8) /* COD_UNCLASSIFIED*/,
              BT_SSP_VARIANT_PASSKEY_CONFIRMATION, numeric_value);
  }

  void DisplayYesNoDialog(const bluetooth::hci::AddressWithType& address,
                          std::string name) {
    bt_bdname_t legacy_name{0};
    memcpy(legacy_name.name, name.data(), name.length());
    callback_(ToRawAddress(address.GetAddress()), legacy_name,
              ((0x1F) << 8) /* COD_UNCLASSIFIED*/, BT_SSP_VARIANT_CONSENT, 0);
  }

  void DisplayEnterPasskeyDialog(const bluetooth::hci::AddressWithType& address, std::string name) {
    bt_bdname_t legacy_name{0};
    memcpy(legacy_name.name, name.data(), name.length());
    callback_(ToRawAddress(address.GetAddress()), legacy_name,
              ((0x1F) << 8) /* COD_UNCLASSIFIED*/, BT_SSP_VARIANT_PASSKEY_ENTRY,
              0);
  }

  void DisplayPasskey(const bluetooth::hci::AddressWithType& address, std::string name, uint32_t passkey) {
    bt_bdname_t legacy_name{0};
    memcpy(legacy_name.name, name.data(), name.length());
    callback_(ToRawAddress(address.GetAddress()), legacy_name,
              ((0x1F) << 8) /* COD_UNCLASSIFIED*/,
              BT_SSP_VARIANT_PASSKEY_NOTIFICATION, passkey);
  }

  void SetLegacyCallback(std::function<void(RawAddress, bt_bdname_t, uint32_t, bt_ssp_variant_t, uint32_t)> callback) {
    callback_ = callback;
  }

 private:
  std::function<void(RawAddress, bt_bdname_t, uint32_t, bt_ssp_variant_t,
                     uint32_t)>
      callback_;
};

ShimUi ui;

/**
 * Sets handler to SecurityModule and provides callback to handler
 */
void BTIF_DM_SetUiCallback(std::function<void(RawAddress, bt_bdname_t, uint32_t, bt_ssp_variant_t, uint32_t)> callback) {
  LOG_WARN("%s", __func__);
  auto security_manager = bluetooth::shim::GetSecurityModule()->GetSecurityManager();
  ui.SetLegacyCallback(callback);
  security_manager->SetUserInterfaceHandler(&ui, bluetooth::shim::GetGdShimHandler());
}

class ShimBondListener : public security::ISecurityManagerListener {
 public:
  void SetLegacyCallbacks(std::function<void(RawAddress)> bond_state_bonding_cb,
                          std::function<void(RawAddress)> bond_state_bonded_cb,
                          std::function<void(RawAddress)> bond_state_none_cb) {
    bond_state_bonding_cb_ = bond_state_bonding_cb;
    bond_state_bonded_cb_ = bond_state_bonded_cb;
    bond_state_none_cb_ = bond_state_none_cb;
  }

  void OnDeviceBonded(bluetooth::hci::AddressWithType device) override {
    bond_state_bonded_cb_(ToRawAddress(device.GetAddress()));
  }

  void OnDeviceUnbonded(bluetooth::hci::AddressWithType device) override {
    bond_state_none_cb_(ToRawAddress(device.GetAddress()));
  }

  void OnDeviceBondFailed(bluetooth::hci::AddressWithType device) override {
    bond_state_none_cb_(ToRawAddress(device.GetAddress()));
  }

  void OnEncryptionStateChanged(
      EncryptionChangeView encryption_change_view) override {}

  std::function<void(RawAddress)> bond_state_bonding_cb_;
  std::function<void(RawAddress)> bond_state_bonded_cb_;
  std::function<void(RawAddress)> bond_state_none_cb_;
};

ShimBondListener shim_bond_listener;

void BTIF_RegisterBondStateChangeListener(
    std::function<void(RawAddress)> bonding_cb,
    std::function<void(RawAddress)> bonded_cb,
    std::function<void(RawAddress)> none_cb) {
  auto security_manager =
      bluetooth::shim::GetSecurityModule()->GetSecurityManager();
  shim_bond_listener.SetLegacyCallbacks(bonding_cb, bonded_cb, none_cb);
  security_manager->RegisterCallbackListener(
      &shim_bond_listener, bluetooth::shim::GetGdShimHandler());
}

void BTIF_DM_ssp_reply(const RawAddress bd_addr, uint8_t addr_type, bt_ssp_variant_t variant, uint8_t accept) {
  hci::AddressWithType address = ToAddressWithType(bd_addr, addr_type);
  auto security_manager = bluetooth::shim::GetSecurityModule()->GetSecurityManager();

  if (variant == BT_SSP_VARIANT_PASSKEY_CONFIRMATION || variant == BT_SSP_VARIANT_CONSENT) {
    security_manager->OnConfirmYesNo(address, accept);
  } else {
    //TODO:
    // void OnPairingPromptAccepted(const bluetooth::hci::AddressWithType& address, bool confirmed) override;
    //  void OnPasskeyEntry(const bluetooth::hci::AddressWithType& address, uint32_t passkey) override;
    LOG_WARN(
        "■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■ Variant not implemented yet "
        "%02x",
        variant);
  }
}

void BTIF_DM_pin_reply(const RawAddress bd_addr, uint8_t addr_type, uint8_t accept, uint8_t pin_len, bt_pin_code_t pin_code) {
  hci::AddressWithType address = ToAddressWithType(bd_addr, addr_type);
  auto security_manager = bluetooth::shim::GetSecurityModule()->GetSecurityManager();

  if (!accept) {
    LOG_WARN("This case is not implemented!!");
    return;
  }

  uint32_t passkey = 0;
  int multi[] = {100000, 10000, 1000, 100, 10, 1};
  for (int i = 0; i < pin_len; i++) {
    passkey += (multi[i] * (pin_code.pin[i] - '0'));
  }

  security_manager->OnPasskeyEntry(address, passkey);
}

}  // namespace shim
}  // namespace bluetooth
