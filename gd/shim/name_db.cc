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
#define LOG_TAG "bt_gd_shim"

#include <functional>
#include <memory>
#include <string>
#include <unordered_map>

#include "hci/address.h"
#include "module.h"
#include "neighbor/name_db.h"
#include "os/handler.h"
#include "shim/name_db.h"

namespace bluetooth {
namespace shim {

namespace {
constexpr char kModuleName[] = "shim::NameDb";
}  // namespace

struct NameDb::impl {
  impl(neighbor::NameDbModule* module, os::Handler* handler);
  ~impl() = default;

  void OnReadRemoteName(hci::Address address, bool success);
  void ReadRemoteNameDbRequest(hci::Address address, ReadRemoteNameDbCallback callback);

  std::unordered_map<hci::Address, ReadRemoteNameDbCallback> address_to_read_remote_callback_map_;
  neighbor::NameDbModule* module_{nullptr};
  os::Handler* handler_;
};

const ModuleFactory NameDb::Factory = ModuleFactory([]() { return new NameDb(); });

NameDb::impl::impl(neighbor::NameDbModule* module, os::Handler* handler) : module_(module), handler_(handler) {}

void NameDb::impl::OnReadRemoteName(hci::Address address, bool success) {
  LOG_DEBUG("%s from %s status:%s", __func__, address.ToString().c_str(), success ? "true" : "false");
  ASSERT(address_to_read_remote_callback_map_.find(address) != address_to_read_remote_callback_map_.end());
  ReadRemoteNameDbCallback callback = std::move(address_to_read_remote_callback_map_.at(address));
  address_to_read_remote_callback_map_.erase(address);
  callback(address.ToString(), success);
}

void NameDb::impl::ReadRemoteNameDbRequest(hci::Address address, ReadRemoteNameDbCallback callback) {
  ASSERT(address_to_read_remote_callback_map_.find(address) == address_to_read_remote_callback_map_.end());
  address_to_read_remote_callback_map_[address] = std::move(callback);

  module_->ReadRemoteNameRequest(address, common::BindOnce(&NameDb::impl::OnReadRemoteName, common::Unretained(this)),
                                 handler_);
}

void NameDb::ReadRemoteNameDbRequest(std::string string_address, ReadRemoteNameDbCallback callback) {
  hci::Address address;
  ASSERT(hci::Address::FromString(string_address, address));
  pimpl_->ReadRemoteNameDbRequest(address, std::move(callback));
}

bool NameDb::IsNameCached(std::string string_address) const {
  hci::Address address;
  ASSERT(hci::Address::FromString(string_address, address));
  return pimpl_->module_->IsNameCached(address);
}

std::array<uint8_t, 248> NameDb::ReadCachedRemoteName(std::string string_address) const {
  hci::Address address;
  ASSERT(hci::Address::FromString(string_address, address));
  return pimpl_->module_->ReadCachedRemoteName(address);
}

/**
 * Module methods
 */
void NameDb::ListDependencies(ModuleList* list) {
  list->add<neighbor::NameDbModule>();
}

void NameDb::Start() {
  pimpl_ = std::make_unique<impl>(GetDependency<neighbor::NameDbModule>(), GetHandler());
}

void NameDb::Stop() {
  pimpl_.reset();
}

std::string NameDb::ToString() const {
  return kModuleName;
}

}  // namespace shim
}  // namespace bluetooth
