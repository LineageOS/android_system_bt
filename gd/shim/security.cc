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
}  // namespace

struct Security::impl {
  void CreateBond(std::string address, uint8_t address_type, uint8_t transport);

  os::Handler* Handler() /*override*/;

  impl(bluetooth::security::SecurityModule* security_module, os::Handler* handler);
  ~impl();

 private:
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

void Security::impl::CreateBond(std::string address, uint8_t address_type, uint8_t transport) {
  hci::Address bdaddr;
  if (!hci::Address::FromString(address, bdaddr)) {
    LOG_ERROR("%s bad address: %s, aborting", __func__, address.c_str());
    return;
  }

  if (transport == 0x01 /* BT_TRANSPORT_BR_EDR */)
    security_manager_->CreateBond(hci::AddressWithType{bdaddr, hci::AddressType::PUBLIC_DEVICE_ADDRESS});
  else if (transport == 0x02 /* BT_TRANSPORT_LE */)
    security_manager_->CreateBondLe(
        hci::AddressWithType{bdaddr, static_cast<bluetooth::hci::AddressType>(address_type)});
  else
    LOG_ALWAYS_FATAL("Bad transport in CreateBond %d", transport);
}

void Security::CreateBond(std::string address, uint8_t address_type, uint8_t transport) {
  pimpl_->CreateBond(address, address_type, transport);
}

/**
 * Module methods
 */
void Security::ListDependencies(ModuleList* list) {
  list->add<bluetooth::security::SecurityModule>();
}

void Security::Start() {
  pimpl_ = std::make_unique<impl>(GetDependency<bluetooth::security::SecurityModule>(), GetHandler());
}

void Security::Stop() {
  pimpl_.reset();
}

std::string Security::ToString() const {
  return kModuleName;
}

}  // namespace shim
}  // namespace bluetooth
