/*
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
 */
#include "security_manager_impl.h"

#include <iostream>

#include "hci/address_with_type.h"
#include "os/log.h"
#include "security/security_manager.h"

namespace bluetooth {
namespace security {
namespace internal {

std::shared_ptr<bluetooth::security::record::SecurityRecord> SecurityManagerImpl::CreateSecurityRecord(
    hci::Address address) {
  hci::AddressWithType device(address, hci::AddressType::PUBLIC_DEVICE_ADDRESS);
  // Security record check
  auto entry = security_record_map_.find(device.GetAddress());
  if (entry == security_record_map_.end()) {
    LOG_INFO("No security record for device: %s ", device.ToString().c_str());
    // Create one
    std::shared_ptr<security::record::SecurityRecord> record =
        std::make_shared<security::record::SecurityRecord>(device);
    auto new_entry = std::pair<hci::Address, std::shared_ptr<security::record::SecurityRecord>>(
        record->GetDevice().GetAddress(), record);
    // Keep track of it
    security_record_map_.insert(new_entry);
    return record;
  }
  return entry->second;
}

void SecurityManagerImpl::DispatchPairingHandler(std::shared_ptr<security::record::SecurityRecord> record,
                                                 bool locally_initiated) {
  common::OnceCallback<void(hci::Address)> callback =
      common::BindOnce(&SecurityManagerImpl::OnPairingHandlerComplete, common::Unretained(this));
  auto entry = pairing_handler_map_.find(record->GetDevice().GetAddress());
  if (entry != pairing_handler_map_.end()) {
    LOG_WARN("Device already has a pairing handler, and is in the middle of pairing!");
    return;
  }
  std::shared_ptr<pairing::PairingHandler> pairing_handler = nullptr;
  switch (record->GetDevice().GetAddressType()) {
    case hci::AddressType::PUBLIC_DEVICE_ADDRESS:
      pairing_handler = std::make_shared<security::pairing::ClassicPairingHandler>(
          l2cap_classic_module_->GetFixedChannelManager(), security_manager_channel_, record, security_handler_,
          std::move(callback));
      break;
    default:
      ASSERT_LOG(false, "Pairing type %hhu not implemented!", record->GetDevice().GetAddressType());
  }
  auto new_entry = std::pair<hci::Address, std::shared_ptr<pairing::PairingHandler>>(record->GetDevice().GetAddress(),
                                                                                     pairing_handler);
  pairing_handler_map_.insert(std::move(new_entry));
  pairing_handler->Initiate(locally_initiated, pairing::kDefaultIoCapability, pairing::kDefaultOobDataPresent,
                            pairing::kDefaultAuthenticationRequirements);
}

void SecurityManagerImpl::Init() {
  security_manager_channel_->SetChannelListener(this);
  security_manager_channel_->SendCommand(hci::WriteSimplePairingModeBuilder::Create(hci::Enable::ENABLED));
  security_manager_channel_->SendCommand(hci::WriteSecureConnectionsHostSupportBuilder::Create(hci::Enable::ENABLED));
  // TODO(optedoblivion): Populate security record memory map from disk
}

void SecurityManagerImpl::CreateBond(hci::AddressWithType device) {
  auto record = CreateSecurityRecord(device.GetAddress());
  if (record->IsBonded()) {
    NotifyDeviceBonded(device);
  } else {
    // Dispatch pairing handler, if we are calling create we are the initiator
    DispatchPairingHandler(record, true);
  }
}

void SecurityManagerImpl::CancelBond(hci::AddressWithType device) {
  auto entry = pairing_handler_map_.find(device.GetAddress());
  if (entry != pairing_handler_map_.end()) {
    auto cancel_me = entry->second;
    pairing_handler_map_.erase(entry);
    cancel_me->Cancel();
  }
}

void SecurityManagerImpl::RemoveBond(hci::AddressWithType device) {
  CancelBond(device);
  auto entry = security_record_map_.find(device.GetAddress());
  if (entry != security_record_map_.end()) {
    security_record_map_.erase(entry);
  }
  // Signal disconnect
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

void SecurityManagerImpl::NotifyDeviceBonded(hci::AddressWithType device) {
  for (auto& iter : listeners_) {
    iter.second->Post(common::Bind(&ISecurityManagerListener::OnDeviceBonded, common::Unretained(iter.first), device));
  }
}

void SecurityManagerImpl::NotifyDeviceBondFailed(hci::AddressWithType device) {
  for (auto& iter : listeners_) {
    iter.second->Post(
        common::Bind(&ISecurityManagerListener::OnDeviceBondFailed, common::Unretained(iter.first), device));
  }
}

void SecurityManagerImpl::NotifyDeviceUnbonded(hci::AddressWithType device) {
  for (auto& iter : listeners_) {
    iter.second->Post(
        common::Bind(&ISecurityManagerListener::OnDeviceUnbonded, common::Unretained(iter.first), device));
  }
}

template <class T>
void SecurityManagerImpl::HandleEvent(T packet) {
  ASSERT(packet.IsValid());
  auto entry = pairing_handler_map_.find(packet.GetBdAddr());
  if (entry != pairing_handler_map_.end()) {
    entry->second->OnReceive(packet);
  } else {
    auto bd_addr = packet.GetBdAddr();
    auto event_code = packet.GetEventCode();
    auto event = hci::EventPacketView::Create(std::move(packet));
    ASSERT_LOG(event.IsValid(), "Received invalid packet");
    const hci::EventCode code = event.GetEventCode();
    auto record = CreateSecurityRecord(bd_addr);
    switch (code) {
      case hci::EventCode::LINK_KEY_REQUEST:
        DispatchPairingHandler(record, true);
        break;
      default:
        LOG_ERROR("No classic pairing handler for device '%s' ready for command '%hhx' ", bd_addr.ToString().c_str(),
                  event_code);
        break;
    }
  }
}

void SecurityManagerImpl::OnHciEventReceived(hci::EventPacketView packet) {
  auto event = hci::EventPacketView::Create(packet);
  ASSERT_LOG(event.IsValid(), "Received invalid packet");
  const hci::EventCode code = event.GetEventCode();
  switch (code) {
    case hci::EventCode::PIN_CODE_REQUEST:
      HandleEvent<hci::PinCodeRequestView>(hci::PinCodeRequestView::Create(event));
      break;
    case hci::EventCode::LINK_KEY_REQUEST:
      HandleEvent(hci::LinkKeyRequestView::Create(event));
      break;
    case hci::EventCode::LINK_KEY_NOTIFICATION:
      HandleEvent(hci::LinkKeyNotificationView::Create(event));
      break;
    case hci::EventCode::IO_CAPABILITY_REQUEST:
      HandleEvent(hci::IoCapabilityRequestView::Create(event));
      break;
    case hci::EventCode::IO_CAPABILITY_RESPONSE:
      HandleEvent(hci::IoCapabilityResponseView::Create(event));
      break;
    case hci::EventCode::SIMPLE_PAIRING_COMPLETE:
      HandleEvent(hci::SimplePairingCompleteView::Create(event));
      break;
    case hci::EventCode::REMOTE_OOB_DATA_REQUEST:
      HandleEvent(hci::RemoteOobDataRequestView::Create(event));
      break;
    case hci::EventCode::USER_PASSKEY_NOTIFICATION:
      HandleEvent<hci::UserPasskeyNotificationView>(hci::UserPasskeyNotificationView::Create(event));
      break;
    case hci::EventCode::KEYPRESS_NOTIFICATION:
      HandleEvent(hci::KeypressNotificationView::Create(event));
      break;
    case hci::EventCode::USER_CONFIRMATION_REQUEST:
      HandleEvent(hci::UserConfirmationRequestView::Create(event));
      break;
    case hci::EventCode::USER_PASSKEY_REQUEST:
      HandleEvent(hci::UserPasskeyRequestView::Create(event));
      break;
    default:
      ASSERT_LOG(false, "Cannot handle received packet: %s", hci::EventCodeText(code).c_str());
      break;
  }
}

void SecurityManagerImpl::OnPairingHandlerComplete(hci::Address address) {
  auto entry = pairing_handler_map_.find(address);
  if (entry != pairing_handler_map_.end()) {
    pairing_handler_map_.erase(entry);
  }
  NotifyDeviceBonded(hci::AddressWithType(address, hci::AddressType::PUBLIC_DEVICE_ADDRESS));
}

}  // namespace internal
}  // namespace security
}  // namespace bluetooth
