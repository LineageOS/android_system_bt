/*
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
 */
#pragma once

#include <memory>
#include <unordered_map>
#include <vector>

#include "hci/address_with_type.h"
#include "hci/hci_layer.h"
#include "hci/hci_packets.h"
#include "hci/security_interface.h"
#include "l2cap/classic/l2cap_classic_module.h"

namespace bluetooth {
namespace security {
namespace channel {

/**
 * Interface for listening to the channel for SMP commands.
 */
class ISecurityManagerChannelListener {
 public:
  virtual ~ISecurityManagerChannelListener() = default;
  virtual void OnHciEventReceived(hci::EventPacketView packet) = 0;
  virtual void OnConnectionClosed(hci::Address, bluetooth::hci::ErrorCode error_code) = 0;
  virtual void OnConnectionFailed(hci::Address,
                                  bluetooth::l2cap::classic::FixedChannelManager::ConnectionResult result) = 0;
};

/**
 * Channel for consolidating traffic and making the transport agnostic.
 */
class SecurityManagerChannel {
 public:
  SecurityManagerChannel(os::Handler* handler, hci::HciLayer* hci_layer,
                         std::unique_ptr<l2cap::classic::FixedChannelManager> fixed_channel_manager);

  virtual ~SecurityManagerChannel();

  /**
   * Creates a connection to the device which triggers pairing
   *
   * @param address remote address of device to pair with
   */
  void Connect(hci::Address address);

  /**
   * Disconnects currently connected channel
   */
  void Disconnect(hci::Address address);

  /**
   * Send a given SMP command over the SecurityManagerChannel
   *
   * @param command smp command to send
   */
  void SendCommand(std::unique_ptr<hci::SecurityCommandBuilder> command);

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
  void OnHciEventReceived(hci::EventPacketView packet);

  /**
   * Called when an HCI command is completed
   *
   * @param on_complete
   */
  void OnCommandComplete(hci::CommandCompleteView packet);

 protected:
  SecurityManagerChannel(os::Handler* handler, hci::HciLayer* hci_layer);

  virtual void OnRegistrationComplete(l2cap::classic::FixedChannelManager::RegistrationResult result,
                                      std::unique_ptr<l2cap::classic::FixedChannelService> fixed_channel_service);
  virtual void OnUnregistered();
  virtual void OnConnectionOpen(std::unique_ptr<l2cap::classic::FixedChannel> fixed_channel);
  virtual void OnConnectionFail(hci::Address address, l2cap::classic::FixedChannelManager::ConnectionResult result);
  virtual void OnConnectionClose(hci::Address address, hci::ErrorCode error_code);

  bool is_test_mode_ = false;

 private:
  ISecurityManagerChannelListener* listener_{nullptr};
  hci::SecurityInterface* hci_security_interface_{nullptr};
  os::Handler* handler_{nullptr};
  l2cap::classic::SecurityPolicy security_policy_{
      l2cap::classic::SecurityPolicy::_SDP_ONLY_NO_SECURITY_WHATSOEVER_PLAINTEXT_TRANSPORT_OK};

  std::unique_ptr<l2cap::classic::FixedChannelManager> fixed_channel_manager_{nullptr};
  std::unique_ptr<l2cap::classic::FixedChannelService> fixed_channel_service_{nullptr};
  std::unordered_map<hci::Address, std::unique_ptr<l2cap::classic::FixedChannel>> fixed_channel_map_;
};

}  // namespace channel
}  // namespace security
}  // namespace bluetooth
