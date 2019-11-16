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

#include <functional>
#include <memory>
#include <string>
#include <unordered_map>

#include "hci/address.h"
#include "hci/hci_packets.h"
#include "module.h"
#include "neighbor/name.h"
#include "os/handler.h"
#include "os/log.h"
#include "shim/name.h"

namespace bluetooth {
namespace shim {

struct Name::impl {
  void ReadRemoteNameRequest(const hci::Address address, hci::PageScanRepetitionMode page_scan_repetition_mode,
                             uint16_t clock_offset, hci::ClockOffsetValid clock_offset_valid,
                             ReadRemoteNameCallback callback);
  void CancelRemoteNameRequest(const hci::Address address, CancelRemoteNameCallback callback);

  void OnReadRemoteName(hci::ErrorCode status, hci::Address address, std::array<uint8_t, 248> name);
  void OnCancelRemoteName(hci::ErrorCode status, hci::Address address);

  impl(neighbor::NameModule* module, os::Handler* handler);
  ~impl();

 private:
  std::unordered_map<hci::Address, ReadRemoteNameCallback> address_to_read_remote_callback_map_;
  std::unordered_map<hci::Address, CancelRemoteNameCallback> address_to_cancel_remote_callback_map_;

  neighbor::NameModule* module_{nullptr};
  os::Handler* handler_;
};

const ModuleFactory Name::Factory = ModuleFactory([]() { return new Name(); });

void Name::impl::OnReadRemoteName(hci::ErrorCode status, hci::Address address, std::array<uint8_t, 248> name) {
  LOG_DEBUG("%s from %s", __func__, address.ToString().c_str());
  ASSERT(address_to_read_remote_callback_map_.find(address) != address_to_read_remote_callback_map_.end());
  ReadRemoteNameCallback callback = address_to_read_remote_callback_map_[address];
  address_to_read_remote_callback_map_.erase(address);
  callback(address.ToString(), static_cast<uint8_t>(status), name);
}

void Name::impl::OnCancelRemoteName(hci::ErrorCode status, hci::Address address) {
  LOG_DEBUG("%s from %s", __func__, address.ToString().c_str());
  ASSERT(address_to_cancel_remote_callback_map_.find(address) != address_to_cancel_remote_callback_map_.end());
  CancelRemoteNameCallback callback = address_to_cancel_remote_callback_map_[address];
  address_to_cancel_remote_callback_map_.erase(address);
  callback(address.ToString(), static_cast<uint8_t>(status));
}

void Name::impl::ReadRemoteNameRequest(const hci::Address address,
                                       hci::PageScanRepetitionMode page_scan_repetition_mode, uint16_t clock_offset,
                                       hci::ClockOffsetValid clock_offset_valid, ReadRemoteNameCallback callback) {
  ASSERT(address_to_read_remote_callback_map_.find(address) == address_to_read_remote_callback_map_.end());
  address_to_read_remote_callback_map_[address] = callback;
  module_->ReadRemoteNameRequest(address, page_scan_repetition_mode, clock_offset, clock_offset_valid,
                                 common::BindOnce(&Name::impl::OnReadRemoteName, common::Unretained(this)), handler_);
}

void Name::impl::CancelRemoteNameRequest(const hci::Address address, CancelRemoteNameCallback callback) {
  ASSERT(address_to_cancel_remote_callback_map_.find(address) == address_to_cancel_remote_callback_map_.end());
  address_to_cancel_remote_callback_map_[address] = callback;
  module_->CancelRemoteNameRequest(address, common::BindOnce(&Name::impl::OnCancelRemoteName, common::Unretained(this)),
                                   handler_);
}

Name::impl::impl(neighbor::NameModule* module, os::Handler* handler) : module_(module), handler_(handler) {}

Name::impl::~impl() {}

void Name::ReadRemoteNameRequest(std::string remote_address, ReadRemoteNameCallback callback) {
  hci::Address address;
  hci::Address::FromString(remote_address, address);

  // TODO(cmanton) Use remote name request defaults for now
  hci::PageScanRepetitionMode page_scan_repetition_mode = hci::PageScanRepetitionMode::R1;
  uint16_t clock_offset = 0;
  hci::ClockOffsetValid clock_offset_valid = hci::ClockOffsetValid::INVALID;
  pimpl_->ReadRemoteNameRequest(address, page_scan_repetition_mode, clock_offset, clock_offset_valid, callback);
}

void Name::CancelRemoteNameRequest(std::string remote_address, CancelRemoteNameCallback callback) {
  hci::Address address;
  hci::Address::FromString(remote_address, address);
  pimpl_->CancelRemoteNameRequest(address, callback);
}

/**
 * Module methods
 */
void Name::ListDependencies(ModuleList* list) {
  list->add<neighbor::NameModule>();
}

void Name::Start() {
  pimpl_ = std::make_unique<impl>(GetDependency<neighbor::NameModule>(), GetHandler());
}

void Name::Stop() {
  pimpl_.reset();
}

}  // namespace shim
}  // namespace bluetooth
