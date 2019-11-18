/******************************************************************************
 *
 *  Copyright 2019 The Android Open Source Project
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at:
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 ******************************************************************************/
#include "security_manager_impl.h"

#include <iostream>
#include <unordered_map>

#include "os/log.h"
#include "security/pairing/classic_pairing_handler.h"
#include "security/security_manager.h"

using namespace bluetooth::security::internal;
using bluetooth::hci::Device;
using bluetooth::hci::DeviceType;
using bluetooth::security::ISecurityManagerListener;
using bluetooth::security::pairing::PairingHandler;

namespace {
std::unordered_map<std::shared_ptr<Device>, std::unique_ptr<PairingHandler>> pairing_handler_map_;

void dispatch_new_pairing_handler(std::shared_ptr<bluetooth::security::record::SecurityRecord> record) {
  auto entry = pairing_handler_map_.find(record->GetDevice());
  if (entry != pairing_handler_map_.end()) {
    LOG_WARN("Device already has a pairing handler, and is in the middle of pairing!");
    return;
  }
  std::unique_ptr<PairingHandler> pairing_handler = nullptr;
  switch (record->GetDevice()->GetDeviceType()) {
    case DeviceType::CLASSIC:
      pairing_handler = std::make_unique<bluetooth::security::pairing::ClassicPairingHandler>(record);
      break;
    default:
      ASSERT_LOG(false, "Pairing type %d not implemented!", record->GetDevice()->GetDeviceType());
  }
  auto new_entry = std::pair<std::shared_ptr<Device>, std::unique_ptr<PairingHandler>>(record->GetDevice(),
                                                                                       std::move(pairing_handler));
  pairing_handler_map_.insert(std::move(new_entry));
}
}  // namespace

void SecurityManagerImpl::Init() {
  // TODO(optedoblivion): Populate security record memory map from disk
  //  security_manager_channel_->SetChannelListener(this);
}

void SecurityManagerImpl::CreateBond(std::shared_ptr<hci::ClassicDevice> device) {
  std::string uuid = device->GetUuid();
  // Security record check
  //  if (device_database_->GetDeviceById(uuid) != nullptr) {
  //    LOG_WARN("Device already exists in the database");
  // TODO(optedoblivion): Check security record if device is already bonded
  // if no security record, need to initiate bonding
  // if security record and not bonded, need to initiate bonding
  // if security record and is bonded, then do nothing
  //  }

  // device_database_->AddDevice(device);
  // Create security record
  // Pass to pairing handler
  std::shared_ptr<record::SecurityRecord> record = std::make_shared<record::SecurityRecord>(device);
  dispatch_new_pairing_handler(record);
  // init the pairing handler
  // Update bonded flag on security record
  // Update bonded flag on device to BONDING (pairing handler does this)
}

void SecurityManagerImpl::CancelBond(std::shared_ptr<hci::ClassicDevice> device) {
  auto entry = pairing_handler_map_.find(device);
  if (entry != pairing_handler_map_.end()) {
    pairing_handler_map_.erase(device);
  }
  // Remove from DB
  // device_database_->RemoveDevice(device);
  // Remove from map, no longer will the event queue use it
  // If currently bonding, cancel pairing handler job
  // else, cancel fails
}

void SecurityManagerImpl::RemoveBond(std::shared_ptr<hci::ClassicDevice> device) {
  CancelBond(device);
  // Update bonded flag on device to UNBONDED
  // Signal disconnect
  // Signal unbonding
  // Remove security record
  // Signal Remove from database
}

void SecurityManagerImpl::RegisterCallbackListener(ISecurityManagerListener* listener, os::Handler* handler) {
  for (auto it = listeners_.begin(); it != listeners_.end(); ++it) {
    if (it->first == listener) {
      LOG_ALWAYS_FATAL("Listener has already been registered!");
    }
  }

  listeners_.push_back({listener, handler});
}

void SecurityManagerImpl::UnregisterCallbackListener(ISecurityManagerListener* listener) {
  for (auto it = listeners_.begin(); it != listeners_.end(); ++it) {
    if (it->first == listener) {
      listeners_.erase(it);
      return;
    }
  }

  LOG_ALWAYS_FATAL("Listener has not been registered!");
}

void SecurityManagerImpl::NotifyDeviceBonded(std::shared_ptr<Device> device) {
  for (auto& iter : listeners_) {
    iter.second->Post(common::Bind(&ISecurityManagerListener::OnDeviceBonded, common::Unretained(iter.first), device));
  }
}

void SecurityManagerImpl::NotifyDeviceBondFailed(std::shared_ptr<Device> device) {
  for (auto& iter : listeners_) {
    iter.second->Post(
        common::Bind(&ISecurityManagerListener::OnDeviceBondFailed, common::Unretained(iter.first), device));
  }
}

void SecurityManagerImpl::NotifyDeviceUnbonded(std::shared_ptr<Device> device) {
  for (auto& iter : listeners_) {
    iter.second->Post(
        common::Bind(&ISecurityManagerListener::OnDeviceUnbonded, common::Unretained(iter.first), device));
  }
}
