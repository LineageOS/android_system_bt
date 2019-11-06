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
#include "security_manager_channel.h"

#include "security/smp_packets.h"

using namespace bluetooth::hci;
using namespace bluetooth::packet;
using namespace bluetooth::security::channel;

void SecurityManagerChannel::SendCommand(std::shared_ptr<hci::Device> device,
                                         std::unique_ptr<SecurityCommandBuilder> command) {
  hci_security_interface_->EnqueueCommand(
      std::move(command), common::BindOnce(&SecurityManagerChannel::OnCommandComplete, common::Unretained(this)),
      handler_);
}

void SecurityManagerChannel::OnCommandComplete(CommandCompleteView packet) {
  ASSERT_LOG(packet.IsValid(), "Received invalid packet: %hx", packet.GetCommandOpCode());
  // TODO(optedoblivion): Verify HCI commands
}

void SecurityManagerChannel::OnHciEventReceived(EventPacketView packet) {
  ASSERT_LOG(listener_ != nullptr, "No listener set!");
  std::shared_ptr<Device> device = nullptr;
  auto event = EventPacketView::Create(std::move(packet));
  ASSERT_LOG(event.IsValid(), "Received invalid packet: %hhx", event.GetEventCode());
  const hci::EventCode code = event.GetEventCode();
  switch (code) {
    case hci::EventCode::CHANGE_CONNECTION_LINK_KEY_COMPLETE:
      listener_->OnChangeConnectionLinkKeyComplete(device,
                                                   hci::ChangeConnectionLinkKeyCompleteView::Create(std::move(event)));
      break;
    case hci::EventCode::MASTER_LINK_KEY_COMPLETE:
      listener_->OnMasterLinkKeyComplete(device, hci::MasterLinkKeyCompleteView::Create(std::move(event)));
      break;
    case hci::EventCode::PIN_CODE_REQUEST:
      listener_->OnPinCodeRequest(device, hci::PinCodeRequestView::Create(std::move(event)));
      break;
    case hci::EventCode::LINK_KEY_REQUEST:
      listener_->OnLinkKeyRequest(device, hci::LinkKeyRequestView::Create(std::move(event)));
      break;
    case hci::EventCode::LINK_KEY_NOTIFICATION:
      listener_->OnLinkKeyNotification(device, hci::LinkKeyNotificationView::Create(std::move(event)));
      break;
    case hci::EventCode::IO_CAPABILITY_REQUEST:
      listener_->OnIoCapabilityRequest(device, hci::IoCapabilityRequestView::Create(std::move(event)));
      break;
    case hci::EventCode::IO_CAPABILITY_RESPONSE:
      listener_->OnIoCapabilityResponse(device, IoCapabilityResponseView::Create(std::move(event)));
      break;
    case hci::EventCode::SIMPLE_PAIRING_COMPLETE:
      listener_->OnSimplePairingComplete(device, SimplePairingCompleteView::Create(std::move(event)));
      break;
    case hci::EventCode::RETURN_LINK_KEYS:
      listener_->OnReturnLinkKeys(device, hci::ReturnLinkKeysView::Create(std::move(event)));
      break;
    case hci::EventCode::ENCRYPTION_CHANGE:
      listener_->OnEncryptionChange(device, hci::EncryptionChangeView::Create(std::move(event)));
      break;
    case hci::EventCode::ENCRYPTION_KEY_REFRESH_COMPLETE:
      listener_->OnEncryptionKeyRefreshComplete(device,
                                                hci::EncryptionKeyRefreshCompleteView::Create(std::move(event)));
      break;
    case hci::EventCode::REMOTE_OOB_DATA_REQUEST:
      listener_->OnRemoteOobDataRequest(device, hci::RemoteOobDataRequestView::Create(std::move(event)));
      break;
    case hci::EventCode::USER_PASSKEY_NOTIFICATION:
      //      listener_->OnUserPasskeyNotification(device, <packet>);
      break;
    case hci::EventCode::KEYPRESS_NOTIFICATION:
      //      listener_->OnSendKeypressNotification(device, <packet>);
      break;
    default:
      ASSERT_LOG(false, "Invalid packet received: %hhx", code);
      break;
  }
}
