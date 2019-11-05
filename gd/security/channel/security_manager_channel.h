/******************************************************************************
 *
 *  Copyright 2019 The Android Open Source Project
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at:
 *
 *  http://www.apache.org/licenses/LICENSE-2.0;
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 ******************************************************************************/
#pragma once

#include <memory>
#include <vector>

#include "hci/classic_device.h"
#include "hci/hci_layer.h"
#include "hci/security_interface.h"
#include "security/smp_packets.h"

namespace bluetooth {
namespace security {
namespace channel {

using hci::CommandCompleteView;
using hci::EventPacketView;
using hci::SecurityCommandBuilder;
using hci::SecurityCommandView;

/**
 * Interface for listening to the channel for SMP commands.
 */
class ISecurityManagerChannelListener {
 public:
  virtual ~ISecurityManagerChannelListener() = default;

  virtual void OnChangeConnectionLinkKeyComplete(std::shared_ptr<hci::Device> device,
                                                 hci::ChangeConnectionLinkKeyCompleteView packet) = 0;
  virtual void OnMasterLinkKeyComplete(std::shared_ptr<hci::Device> device, hci::MasterLinkKeyCompleteView packet) = 0;
  virtual void OnPinCodeRequest(std::shared_ptr<hci::Device> device, hci::PinCodeRequestView packet) = 0;
  virtual void OnLinkKeyRequest(std::shared_ptr<hci::Device> device, hci::LinkKeyRequestView packet) = 0;
  virtual void OnLinkKeyNotification(std::shared_ptr<hci::Device> device, hci::LinkKeyNotificationView packet) = 0;
  virtual void OnIoCapabilityRequest(std::shared_ptr<hci::Device> device, hci::IoCapabilityRequestView packet) = 0;
  virtual void OnIoCapabilityResponse(std::shared_ptr<hci::Device> device, hci::IoCapabilityResponseView packet) = 0;
  virtual void OnSimplePairingComplete(std::shared_ptr<hci::Device> device, hci::SimplePairingCompleteView packet) = 0;
  virtual void OnReturnLinkKeys(std::shared_ptr<hci::Device> device, hci::ReturnLinkKeysView packet) = 0;
  virtual void OnEncryptionChange(std::shared_ptr<hci::Device> device, hci::EncryptionChangeView packet) = 0;
  virtual void OnEncryptionKeyRefreshComplete(std::shared_ptr<hci::Device> device,
                                              hci::EncryptionKeyRefreshCompleteView packet) = 0;
  virtual void OnRemoteOobDataRequest(std::shared_ptr<hci::Device> device, hci::RemoteOobDataRequestView packet) = 0;
};

/**
 * Channel for consolidating traffic and making the transport agnostic.
 */
class SecurityManagerChannel {
 public:
  explicit SecurityManagerChannel(os::Handler* handler, hci::HciLayer* hci_layer)
      : listener_(nullptr),
        hci_security_interface_(hci_layer->GetSecurityInterface(
            common::Bind(&SecurityManagerChannel::OnHciEventReceived, common::Unretained(this)), handler)),
        handler_(handler) {}
  ~SecurityManagerChannel() {
    delete listener_;
  }

  /**
   * Send a given SMP command over the SecurityManagerChannel
   *
   * @param device target where command will be sent
   * @param command smp command to send
   */
  void SendCommand(std::shared_ptr<hci::Device> device, std::unique_ptr<SecurityCommandBuilder> command);

  /**
   * Sets the listener to listen for channel events
   *
   * @param listener the caller interested in events
   */
  void SetChannelListener(ISecurityManagerChannelListener* listener) {
    listener_ = listener;
  }

  /**
   * Called when an incoming HCI event happens
   *
   * @param event_packet
   */
  void OnHciEventReceived(EventPacketView packet);

  /**
   * Called when an HCI command is completed
   *
   * @param on_complete
   */
  void OnCommandComplete(CommandCompleteView packet);

 private:
  ISecurityManagerChannelListener* listener_;
  hci::SecurityInterface* hci_security_interface_;
  os::Handler* handler_;
};

}  // namespace channel
}  // namespace security
}  // namespace bluetooth
