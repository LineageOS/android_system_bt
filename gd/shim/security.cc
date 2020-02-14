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
#define LOG_TAG "bt_gd_shim"

#include "shim/security.h"

#include <functional>
#include <memory>
#include <string>

#include "common/bind.h"
#include "hci/address.h"
#include "module.h"
#include "os/handler.h"
#include "os/log.h"
#include "security/security_manager.h"
#include "security/security_module.h"

namespace bluetooth {
namespace shim {

namespace {
constexpr char kModuleName[] = "shim::Security";

constexpr uint8_t kLegacyAddressTypePublic = 0;
constexpr uint8_t kLegacyAddressTypeRandom = 1;
constexpr uint8_t kLegacyAddressTypePublicIdentity = 2;
constexpr uint8_t kLegacyAddressTypeRandomIdentity = 3;

// TOOD: implement properly, have it passed from above shim ?
class UIHandler : public ::bluetooth::security::UI {
 public:
  void DisplayPairingPrompt(const hci::AddressWithType& address, std::string name) override {}
  void Cancel(const hci::AddressWithType& address) override {}
  void DisplayConfirmValue(const hci::AddressWithType& address, std::string name, uint32_t numeric_value) override {}
  void DisplayYesNoDialog(const bluetooth::hci::AddressWithType& address, std::string name) override {}
  void DisplayEnterPasskeyDialog(const hci::AddressWithType& address, std::string name) override {}
  void DisplayPasskey(const hci::AddressWithType& address, std::string name, uint32_t passkey) override {}
};
UIHandler static_ui_handler;

}  // namespace

struct Security::impl : public security::ISecurityManagerListener {
  void OnDeviceBonded(bluetooth::hci::AddressWithType device) override {
    LOG_DEBUG("UNIMPLEMENTED %s", __func__);
  }

  void OnDeviceUnbonded(bluetooth::hci::AddressWithType device) override {
    LOG_DEBUG("UNIMPLEMENTED %s", __func__);
  }

  void OnDeviceBondFailed(bluetooth::hci::AddressWithType device) override {
    LOG_DEBUG("UNIMPLEMENTED %s", __func__);
  }

  void CreateBond(hci::AddressWithType bdaddr);
  void CreateBondLe(hci::AddressWithType bdaddr);
  void CancelBond(hci::AddressWithType bdaddr);
  void RemoveBond(hci::AddressWithType bdaddr);

  os::Handler* Handler() /*override*/;

  void SetSimplePairingCallback(SimplePairingCallback callback);

  impl(bluetooth::security::SecurityModule* security_module, os::Handler* handler);
  ~impl();

  void Start();
  void Stop();

 private:
  SimplePairingCallback simple_pairing_callback_;

  std::unique_ptr<bluetooth::security::SecurityManager> security_manager_{nullptr};
  os::Handler* handler_;
};

const ModuleFactory Security::Factory = ModuleFactory([]() { return new Security(); });

Security::impl::impl(bluetooth::security::SecurityModule* security_module, os::Handler* handler)
    : security_manager_(security_module->GetSecurityManager()), handler_(handler) {}

Security::impl::~impl() {}

os::Handler* Security::impl::Handler() {
  return handler_;
}

void Security::impl::CreateBond(hci::AddressWithType bdaddr) {
  security_manager_->CreateBond(bdaddr);
}

void Security::impl::CreateBondLe(hci::AddressWithType bdaddr) {
  security_manager_->CreateBondLe(bdaddr);
}

void Security::impl::CancelBond(hci::AddressWithType bdaddr) {
  security_manager_->CancelBond(bdaddr);
}

void Security::impl::RemoveBond(hci::AddressWithType bdaddr) {
  security_manager_->RemoveBond(bdaddr);
}

void Security::impl::SetSimplePairingCallback(SimplePairingCallback callback) {
  ASSERT(!simple_pairing_callback_);
  simple_pairing_callback_ = callback;
}

void Security::impl::Start() {
  LOG_DEBUG("Starting security manager shim");
  security_manager_->SetUserInterfaceHandler(&static_ui_handler, handler_);
  security_manager_->RegisterCallbackListener(this, handler_);
}

void Security::impl::Stop() {
  security_manager_->UnregisterCallbackListener(this);
  LOG_DEBUG("Stopping security manager shim");
}

void Security::CreateBond(std::string string_address) {
  hci::Address address;
  if (!hci::Address::FromString(string_address, address)) {
    LOG_ERROR("%s bad address: %s, aborting", __func__, address.ToString().c_str());
    return;
  }
  pimpl_->CreateBond(hci::AddressWithType{address, hci::AddressType::PUBLIC_DEVICE_ADDRESS});
}

void Security::CreateBondLe(std::string string_address, uint8_t type) {
  hci::AddressType address_type;
  switch (type) {
    case kLegacyAddressTypePublic:
    default:
      address_type = hci::AddressType::PUBLIC_DEVICE_ADDRESS;
      break;
    case kLegacyAddressTypeRandom:
      address_type = hci::AddressType::RANDOM_DEVICE_ADDRESS;
      break;
    case kLegacyAddressTypePublicIdentity:
      address_type = hci::AddressType::PUBLIC_IDENTITY_ADDRESS;
      break;
    case kLegacyAddressTypeRandomIdentity:
      address_type = hci::AddressType::RANDOM_IDENTITY_ADDRESS;
      break;
  }

  hci::Address address;
  if (!hci::Address::FromString(string_address, address)) {
    LOG_ERROR("%s bad address: %s, aborting", __func__, address.ToString().c_str());
    return;
  }
  pimpl_->CreateBondLe(hci::AddressWithType{address, address_type});
}

void Security::CancelBond(std::string string_address) {
  hci::Address address;
  if (!hci::Address::FromString(string_address, address)) {
    LOG_ERROR("%s bad address: %s, aborting", __func__, address.ToString().c_str());
    return;
  }
  pimpl_->CancelBond(hci::AddressWithType{address, hci::AddressType::PUBLIC_DEVICE_ADDRESS});
}

void Security::RemoveBond(std::string string_address) {
  hci::Address address;
  if (!hci::Address::FromString(string_address, address)) {
    LOG_ERROR("%s bad address: %s, aborting", __func__, address.ToString().c_str());
    return;
  }
  pimpl_->RemoveBond(hci::AddressWithType{address, hci::AddressType::PUBLIC_DEVICE_ADDRESS});
}

void Security::SetSimplePairingCallback(SimplePairingCallback callback) {
  pimpl_->SetSimplePairingCallback(callback);
}

/**
 * Module methods
 */
void Security::ListDependencies(ModuleList* list) {
  list->add<bluetooth::security::SecurityModule>();
}

void Security::Start() {
  pimpl_ = std::make_unique<impl>(GetDependency<bluetooth::security::SecurityModule>(), GetHandler());
  pimpl_->Start();
}

void Security::Stop() {
  pimpl_->Stop();
  pimpl_.reset();
}

std::string Security::ToString() const {
  return kModuleName;
}

}  // namespace shim
}  // namespace bluetooth
