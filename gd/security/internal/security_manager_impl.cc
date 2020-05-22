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

#include "common/bind.h"
#include "crypto_toolbox/crypto_toolbox.h"
#include "hci/address_with_type.h"
#include "os/log.h"
#include "security/initial_informations.h"
#include "security/internal/security_manager_impl.h"
#include "security/pairing_handler_le.h"
#include "security/security_manager.h"
#include "security/ui.h"

namespace bluetooth {
namespace security {
namespace internal {

void SecurityManagerImpl::DispatchPairingHandler(record::SecurityRecord& record, bool locally_initiated) {
  common::OnceCallback<void(hci::Address, PairingResultOrFailure)> callback =
      common::BindOnce(&SecurityManagerImpl::OnPairingHandlerComplete, common::Unretained(this));
  auto entry = pairing_handler_map_.find(record.GetPseudoAddress().GetAddress());
  if (entry != pairing_handler_map_.end()) {
    LOG_WARN("Device already has a pairing handler, and is in the middle of pairing!");
    return;
  }
  std::shared_ptr<pairing::PairingHandler> pairing_handler = nullptr;
  switch (record.GetPseudoAddress().GetAddressType()) {
    case hci::AddressType::PUBLIC_DEVICE_ADDRESS: {
      std::shared_ptr<record::SecurityRecord> record_copy =
          std::make_shared<record::SecurityRecord>(record.GetPseudoAddress());
      pairing_handler = std::make_shared<security::pairing::ClassicPairingHandler>(
          security_manager_channel_, record_copy, security_handler_, std::move(callback), user_interface_,
          user_interface_handler_, "TODO: grab device name properly");
      break;
    }
    default:
      ASSERT_LOG(false, "Pairing type %hhu not implemented!", record.GetPseudoAddress().GetAddressType());
  }
  auto new_entry = std::pair<hci::Address, std::shared_ptr<pairing::PairingHandler>>(
      record.GetPseudoAddress().GetAddress(), pairing_handler);
  pairing_handler_map_.insert(std::move(new_entry));
  pairing_handler->Initiate(locally_initiated, this->local_io_capability_, this->local_oob_data_present_,
                            this->local_authentication_requirements_);
}

void SecurityManagerImpl::Init() {
  security_manager_channel_->SetChannelListener(this);
  security_manager_channel_->SendCommand(hci::WriteSimplePairingModeBuilder::Create(hci::Enable::ENABLED));
  security_manager_channel_->SendCommand(hci::WriteSecureConnectionsHostSupportBuilder::Create(hci::Enable::ENABLED));
  // TODO(optedoblivion): Populate security record memory map from disk
}

void SecurityManagerImpl::CreateBond(hci::AddressWithType device) {
  record::SecurityRecord& record = security_database_.FindOrCreate(device);
  if (record.IsBonded()) {
    NotifyDeviceBonded(device);
  } else {
    // Dispatch pairing handler, if we are calling create we are the initiator
    DispatchPairingHandler(record, true);
  }
}

void SecurityManagerImpl::CreateBondLe(hci::AddressWithType address) {
  record::SecurityRecord& record = security_database_.FindOrCreate(address);
  if (record.IsBonded()) {
    NotifyDeviceBondFailed(address, PairingFailure("Already bonded"));
    return;
  }

  pending_le_pairing_.address_ = address;

  l2cap_manager_le_->ConnectServices(
      address, common::BindOnce(&SecurityManagerImpl::OnConnectionFailureLe, common::Unretained(this)),
      security_handler_);
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
  security_database_.Remove(device);
  security_manager_channel_->Disconnect(device.GetAddress());
  // Signal disconnect
  // Remove security record
  // Signal Remove from database
}

void SecurityManagerImpl::SetUserInterfaceHandler(UI* user_interface, os::Handler* handler) {
  if (user_interface_ != nullptr || user_interface_handler_ != nullptr) {
    LOG_ALWAYS_FATAL("Listener has already been registered!");
  }
  user_interface_ = user_interface;
  user_interface_handler_ = handler;
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

void SecurityManagerImpl::NotifyDeviceBondFailed(hci::AddressWithType device, PairingResultOrFailure status) {
  for (auto& iter : listeners_) {
    iter.second->Post(common::Bind(&ISecurityManagerListener::OnDeviceBondFailed, common::Unretained(iter.first),
                                   device /*, status */));
  }
}

void SecurityManagerImpl::NotifyDeviceUnbonded(hci::AddressWithType device) {
  for (auto& iter : listeners_) {
    iter.second->Post(
        common::Bind(&ISecurityManagerListener::OnDeviceUnbonded, common::Unretained(iter.first), device));
  }
}

void SecurityManagerImpl::NotifyEncryptionStateChanged(hci::EncryptionChangeView encryption_change_view) {
  for (auto& iter : listeners_) {
    iter.second->Post(common::Bind(&ISecurityManagerListener::OnEncryptionStateChanged, common::Unretained(iter.first),
                                   encryption_change_view));
  }
}

template <class T>
void SecurityManagerImpl::HandleEvent(T packet) {
  ASSERT(packet.IsValid());
  auto entry = pairing_handler_map_.find(packet.GetBdAddr());

  if (entry == pairing_handler_map_.end()) {
    auto bd_addr = packet.GetBdAddr();
    auto event_code = packet.GetEventCode();

    if (event_code != hci::EventCode::LINK_KEY_REQUEST) {
      LOG_ERROR("No classic pairing handler for device '%s' ready for command %s ", bd_addr.ToString().c_str(),
                hci::EventCodeText(event_code).c_str());
      return;
    }

    auto record =
        security_database_.FindOrCreate(hci::AddressWithType{bd_addr, hci::AddressType::PUBLIC_DEVICE_ADDRESS});
    DispatchPairingHandler(record, true);
    entry = pairing_handler_map_.find(bd_addr);
  }
  entry->second->OnReceive(packet);
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
      HandleEvent(hci::UserPasskeyNotificationView::Create(event));
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
    case hci::EventCode::REMOTE_HOST_SUPPORTED_FEATURES_NOTIFICATION:
      LOG_INFO("Unhandled event: %s", hci::EventCodeText(code).c_str());
      break;

    case hci::EventCode::ENCRYPTION_CHANGE: {
      EncryptionChangeView encryption_change_view = EncryptionChangeView::Create(event);
      if (!encryption_change_view.IsValid()) {
        LOG_ERROR("Invalid EncryptionChange packet received");
        return;
      }
      if (encryption_change_view.GetConnectionHandle() == pending_le_pairing_.connection_handle_) {
        pending_le_pairing_.handler_->OnHciEvent(event);
        return;
      }
      NotifyEncryptionStateChanged(encryption_change_view);
      break;
    }

    default:
      ASSERT_LOG(false, "Cannot handle received packet: %s", hci::EventCodeText(code).c_str());
      break;
  }
}

void SecurityManagerImpl::OnConnectionClosed(hci::Address address) {
  auto entry = pairing_handler_map_.find(address);
  if (entry != pairing_handler_map_.end()) {
    LOG_DEBUG("Cancelling pairing handler for '%s'", address.ToString().c_str());
    entry->second->Cancel();
  }
}

void SecurityManagerImpl::OnHciLeEvent(hci::LeMetaEventView event) {
  // hci::SubeventCode::LONG_TERM_KEY_REQUEST,
  // hci::SubeventCode::READ_LOCAL_P256_PUBLIC_KEY_COMPLETE,
  // hci::SubeventCode::GENERATE_DHKEY_COMPLETE,
  LOG_ERROR("Unhandled HCI LE security event");
}

void SecurityManagerImpl::OnPairingPromptAccepted(const bluetooth::hci::AddressWithType& address, bool confirmed) {
  auto entry = pairing_handler_map_.find(address.GetAddress());
  if (entry != pairing_handler_map_.end()) {
    entry->second->OnPairingPromptAccepted(address, confirmed);
  } else {
    pending_le_pairing_.handler_->OnUiAction(PairingEvent::UI_ACTION_TYPE::PAIRING_ACCEPTED, confirmed);
  }
}

void SecurityManagerImpl::OnConfirmYesNo(const bluetooth::hci::AddressWithType& address, bool confirmed) {
  auto entry = pairing_handler_map_.find(address.GetAddress());
  if (entry != pairing_handler_map_.end()) {
    entry->second->OnConfirmYesNo(address, confirmed);
  } else {
    if (pending_le_pairing_.address_ == address) {
      pending_le_pairing_.handler_->OnUiAction(PairingEvent::UI_ACTION_TYPE::CONFIRM_YESNO, confirmed);
    }
  }
}

void SecurityManagerImpl::OnPasskeyEntry(const bluetooth::hci::AddressWithType& address, uint32_t passkey) {
  auto entry = pairing_handler_map_.find(address.GetAddress());
  if (entry != pairing_handler_map_.end()) {
    entry->second->OnPasskeyEntry(address, passkey);
  } else {
    if (pending_le_pairing_.address_ == address) {
      pending_le_pairing_.handler_->OnUiAction(PairingEvent::UI_ACTION_TYPE::PASSKEY, passkey);
    }
  }
}

void SecurityManagerImpl::OnPairingHandlerComplete(hci::Address address, PairingResultOrFailure status) {
  auto entry = pairing_handler_map_.find(address);
  if (entry != pairing_handler_map_.end()) {
    pairing_handler_map_.erase(entry);
    security_manager_channel_->Release(address);
  }
  if (!std::holds_alternative<PairingFailure>(status)) {
    NotifyDeviceBonded(hci::AddressWithType(address, hci::AddressType::PUBLIC_DEVICE_ADDRESS));
  } else {
    NotifyDeviceBondFailed(hci::AddressWithType(address, hci::AddressType::PUBLIC_DEVICE_ADDRESS), status);
  }
}

void SecurityManagerImpl::OnL2capRegistrationCompleteLe(
    l2cap::le::FixedChannelManager::RegistrationResult result,
    std::unique_ptr<l2cap::le::FixedChannelService> le_smp_service) {
  ASSERT_LOG(result == bluetooth::l2cap::le::FixedChannelManager::RegistrationResult::SUCCESS,
             "Failed to register to LE SMP Fixed Channel Service");
}

void SecurityManagerImpl::OnSmpCommandLe() {
  auto packet = pending_le_pairing_.channel_->GetQueueUpEnd()->TryDequeue();
  if (!packet) LOG_ERROR("Received dequeue, but no data ready...");

  auto temp_cmd_view = CommandView::Create(*packet);
  pending_le_pairing_.handler_->OnCommandView(temp_cmd_view);
}

void SecurityManagerImpl::OnConnectionOpenLe(std::unique_ptr<l2cap::le::FixedChannel> channel) {
  if (pending_le_pairing_.address_ != channel->GetDevice()) {
    return;
  }
  pending_le_pairing_.channel_ = std::move(channel);
  pending_le_pairing_.channel_->RegisterOnCloseCallback(
      security_handler_, common::BindOnce(&SecurityManagerImpl::OnConnectionClosedLe, common::Unretained(this),
                                          pending_le_pairing_.channel_->GetDevice()));
  // TODO: this enqueue buffer must be stored together with pairing_handler, and we must make sure it doesn't go out of
  // scope while the pairing happens
  pending_le_pairing_.enqueue_buffer_ =
      std::make_unique<os::EnqueueBuffer<packet::BasePacketBuilder>>(pending_le_pairing_.channel_->GetQueueUpEnd());
  pending_le_pairing_.channel_->GetQueueUpEnd()->RegisterDequeue(
      security_handler_, common::Bind(&SecurityManagerImpl::OnSmpCommandLe, common::Unretained(this)));

  // TODO: this doesn't have to be a unique ptr, if there is a way to properly std::move it into place where it's stored
  pending_le_pairing_.connection_handle_ = pending_le_pairing_.channel_->GetLinkOptions()->GetHandle();
  InitialInformations initial_informations{
      .my_role = pending_le_pairing_.channel_->GetLinkOptions()->GetRole(),
      .my_connection_address = pending_le_pairing_.channel_->GetLinkOptions()->GetLocalAddress(),
      /*TODO: properly obtain capabilities from device-specific storage*/
      .myPairingCapabilities = {.io_capability = IoCapability::KEYBOARD_DISPLAY,
                                .oob_data_flag = OobDataFlag::NOT_PRESENT,
                                .auth_req = AuthReqMaskBondingFlag | AuthReqMaskMitm | AuthReqMaskSc,
                                .maximum_encryption_key_size = 16,
                                .initiator_key_distribution = 0x07,
                                .responder_key_distribution = 0x07},
      .remotely_initiated = false,
      .connection_handle = pending_le_pairing_.channel_->GetLinkOptions()->GetHandle(),
      .remote_connection_address = pending_le_pairing_.channel_->GetDevice(),
      .remote_name = "TODO: grab proper device name in sec mgr",
      /* contains pairing request, if the pairing was remotely initiated */
      .pairing_request = std::nullopt,  // TODO: handle remotely initiated pairing in SecurityManager properly
      .remote_oob_data = std::nullopt,  // TODO:
      .my_oob_data = std::nullopt,      // TODO:
      /* Used by Pairing Handler to present user with requests*/
      .user_interface = user_interface_,
      .user_interface_handler = user_interface_handler_,

      /* HCI interface to use */
      .le_security_interface = hci_security_interface_le_,
      .proper_l2cap_interface = pending_le_pairing_.enqueue_buffer_.get(),
      .l2cap_handler = security_handler_,
      /* Callback to execute once the Pairing process is finished */
      // TODO: make it an common::OnceCallback ?
      .OnPairingFinished = std::bind(&SecurityManagerImpl::OnPairingFinished, this, std::placeholders::_1),
  };
  pending_le_pairing_.handler_ = std::make_unique<PairingHandlerLe>(PairingHandlerLe::PHASE1, initial_informations);
}

void SecurityManagerImpl::OnConnectionClosedLe(hci::AddressWithType address, hci::ErrorCode error_code) {
  if (pending_le_pairing_.address_ != address) {
    return;
  }
  pending_le_pairing_.handler_->SendExitSignal();
  NotifyDeviceBondFailed(address, PairingFailure("Connection closed"));
}

void SecurityManagerImpl::OnConnectionFailureLe(bluetooth::l2cap::le::FixedChannelManager::ConnectionResult result) {
  if (result.connection_result_code ==
      bluetooth::l2cap::le::FixedChannelManager::ConnectionResultCode::FAIL_ALL_SERVICES_HAVE_CHANNEL) {
    // TODO: already connected
  }

  // This callback is invoked only for devices we attempted to connect to.
  NotifyDeviceBondFailed(pending_le_pairing_.address_, PairingFailure("Connection establishment failed"));
}

SecurityManagerImpl::SecurityManagerImpl(os::Handler* security_handler, l2cap::le::L2capLeModule* l2cap_le_module,
                                         channel::SecurityManagerChannel* security_manager_channel,
                                         hci::HciLayer* hci_layer)
    : security_handler_(security_handler), l2cap_le_module_(l2cap_le_module),
      l2cap_manager_le_(l2cap_le_module_->GetFixedChannelManager()),
      hci_security_interface_le_(
          hci_layer->GetLeSecurityInterface(security_handler_->BindOn(this, &SecurityManagerImpl::OnHciLeEvent))),
      security_manager_channel_(security_manager_channel) {
  Init();

  l2cap_manager_le_->RegisterService(
      bluetooth::l2cap::kSmpCid,
      common::BindOnce(&SecurityManagerImpl::OnL2capRegistrationCompleteLe, common::Unretained(this)),
      common::Bind(&SecurityManagerImpl::OnConnectionOpenLe, common::Unretained(this)), security_handler_);
}

void SecurityManagerImpl::OnPairingFinished(security::PairingResultOrFailure pairing_result) {
  LOG_INFO(" ■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■ Received pairing result");

  pending_le_pairing_.channel_->GetQueueUpEnd()->UnregisterDequeue();
  pending_le_pairing_.enqueue_buffer_.reset();

  if (std::holds_alternative<PairingFailure>(pairing_result)) {
    PairingFailure failure = std::get<PairingFailure>(pairing_result);
    LOG_INFO(" ■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■ failure message: %s",
             failure.message.c_str());
    return;
  }

  LOG_INFO("Pairing with %s was successfull",
           std::get<PairingResult>(pairing_result).connection_address.ToString().c_str());
}

// Facade Configuration API functions
void SecurityManagerImpl::SetIoCapability(hci::IoCapability io_capability) {
  this->local_io_capability_ = io_capability;
}

void SecurityManagerImpl::SetAuthenticationRequirements(hci::AuthenticationRequirements authentication_requirements) {
  this->local_authentication_requirements_ = authentication_requirements;
}

void SecurityManagerImpl::SetOobDataPresent(hci::OobDataPresent data_present) {
  this->local_oob_data_present_ = data_present;
}

void SecurityManagerImpl::EnforceSecurityPolicy(
    hci::AddressWithType remote, l2cap::classic::SecurityPolicy policy,
    l2cap::classic::SecurityEnforcementInterface::ResultCallback result_callback) {
  bool result = false;
  auto record = this->security_database_.FindOrCreate(remote);
  switch (policy) {
    case l2cap::classic::SecurityPolicy::BEST:
    case l2cap::classic::SecurityPolicy::AUTHENTICATED_ENCRYPTED_TRANSPORT:
      result = record.IsAuthenticated() && record.RequiresMitmProtection() && record.IsEncryptionRequired();
      break;
    case l2cap::classic::SecurityPolicy::ENCRYPTED_TRANSPORT:
      result = record.IsAuthenticated() && record.IsEncryptionRequired();
      break;
    case l2cap::classic::SecurityPolicy::_SDP_ONLY_NO_SECURITY_WHATSOEVER_PLAINTEXT_TRANSPORT_OK:
      result = true;
      break;
  }
  if (!result) {
    // TODO(optedoblivion): Start pairing process to meet requirements
  }
  result_callback.Invoke(result);
}

void SecurityManagerImpl::EnforceLeSecurityPolicy(
    hci::AddressWithType remote, l2cap::le::SecurityPolicy policy,
    l2cap::le::SecurityEnforcementInterface::ResultCallback result_callback) {
  bool result = false;
  // TODO(jpawlowski): Implement for LE
  switch (policy) {
    case l2cap::le::SecurityPolicy::BEST:
      break;
    case l2cap::le::SecurityPolicy::AUTHENTICATED_ENCRYPTED_TRANSPORT:
      break;
    case l2cap::le::SecurityPolicy::ENCRYPTED_TRANSPORT:
      break;
    case l2cap::le::SecurityPolicy::NO_SECURITY_WHATSOEVER_PLAINTEXT_TRANSPORT_OK:
      result = true;
      break;
    case l2cap::le::SecurityPolicy::_NOT_FOR_YOU__AUTHENTICATED_PAIRING_WITH_128_BIT_KEY:
      break;
    case l2cap::le::SecurityPolicy::_NOT_FOR_YOU__AUTHORIZATION:
      break;
  }
  result_callback.Invoke(result);
}

}  // namespace internal
}  // namespace security
}  // namespace bluetooth
