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
#include "security/channel/security_manager_channel.h"

#include "hci/address.h"
#include "security/smp_packets.h"

namespace bluetooth {
namespace security {
namespace channel {

/**
 * Constructor for testing onlyu
 */
SecurityManagerChannel::SecurityManagerChannel(os::Handler* handler, hci::HciLayer* hci_layer)
    : listener_(nullptr),
      hci_security_interface_(hci_layer->GetSecurityInterface(
          common::Bind(&SecurityManagerChannel::OnHciEventReceived, common::Unretained(this)), handler)),
      handler_(handler) {
  is_test_mode_ = true;
}

/**
 * Main Constructor
 */
SecurityManagerChannel::SecurityManagerChannel(
    os::Handler* handler, hci::HciLayer* hci_layer,
    std::unique_ptr<l2cap::classic::FixedChannelManager> fixed_channel_manager)
    : listener_(nullptr),
      hci_security_interface_(hci_layer->GetSecurityInterface(
          common::Bind(&SecurityManagerChannel::OnHciEventReceived, common::Unretained(this)), handler)),
      handler_(handler), fixed_channel_manager_(std::move(fixed_channel_manager)) {
  ASSERT_LOG(fixed_channel_manager_ != nullptr, "No channel manager!");
  LOG_DEBUG("Registering for a fixed channel service");
  fixed_channel_manager_->RegisterService(
      l2cap::kClassicPairingTriggerCid, security_policy_,
      common::BindOnce(&SecurityManagerChannel::OnRegistrationComplete, common::Unretained(this)),
      common::Bind(&SecurityManagerChannel::OnConnectionOpen, common::Unretained(this)), handler_);
}

SecurityManagerChannel::~SecurityManagerChannel() {
  if (fixed_channel_service_ != nullptr) {
    fixed_channel_service_->Unregister(common::Bind(&SecurityManagerChannel::OnUnregistered, common::Unretained(this)),
                                       handler_);
    fixed_channel_service_.reset();
  }
}

void SecurityManagerChannel::Connect(hci::Address address) {
  if (is_test_mode_) return;
  ASSERT_LOG(fixed_channel_manager_ != nullptr, "No channel manager!");
  auto entry = fixed_channel_map_.find(address);
  if (entry != fixed_channel_map_.end()) {
    LOG_ERROR("Already connected to device: %s", address.ToString().c_str());
    return;
  }
  fixed_channel_manager_->ConnectServices(
      address, common::Bind(&SecurityManagerChannel::OnConnectionFail, common::Unretained(this), address), handler_);
}

void SecurityManagerChannel::Disconnect(hci::Address address) {
  if (is_test_mode_) return;
  auto entry = fixed_channel_map_.find(address);
  if (entry != fixed_channel_map_.end()) {
    entry->second->Release();
    entry->second.reset();
    fixed_channel_map_.erase(entry);
  } else {
    LOG_WARN("Unknown address '%s'", address.ToString().c_str());
  }
}

void SecurityManagerChannel::OnCommandComplete(hci::CommandCompleteView packet) {
  ASSERT_LOG(packet.IsValid(), "Bad command response");
}

void SecurityManagerChannel::SendCommand(std::unique_ptr<hci::SecurityCommandBuilder> command) {
  hci_security_interface_->EnqueueCommand(std::move(command),
                                          handler_->BindOnceOn(this, &SecurityManagerChannel::OnCommandComplete));
}

void SecurityManagerChannel::OnHciEventReceived(hci::EventPacketView packet) {
  ASSERT_LOG(listener_ != nullptr, "No listener set!");
  ASSERT(packet.IsValid());
  listener_->OnHciEventReceived(packet);
}

void SecurityManagerChannel::OnRegistrationComplete(
    l2cap::classic::FixedChannelManager::RegistrationResult result,
    std::unique_ptr<l2cap::classic::FixedChannelService> fixed_channel_service) {
  ASSERT(fixed_channel_service_ == nullptr);
  ASSERT_LOG(result == l2cap::classic::FixedChannelManager::RegistrationResult::SUCCESS,
             "Failed service registration!");
  fixed_channel_service_ = std::move(fixed_channel_service);
}

void SecurityManagerChannel::OnUnregistered() {
  fixed_channel_manager_.reset();
}

void SecurityManagerChannel::OnConnectionOpen(std::unique_ptr<l2cap::classic::FixedChannel> fixed_channel) {
  ASSERT_LOG(fixed_channel != nullptr, "Null channel passed in");
  ASSERT_LOG(fixed_channel_map_.find(fixed_channel->GetDevice()) == fixed_channel_map_.end(),
             "Multiple fixed channel for a single device is not allowed.");
  fixed_channel->RegisterOnCloseCallback(
      handler_, common::BindOnce(&SecurityManagerChannel::OnConnectionClose, common::Unretained(this),
                                 fixed_channel->GetDevice()));
  fixed_channel->Acquire();
  auto new_entry = std::pair<hci::Address, std::unique_ptr<l2cap::classic::FixedChannel>>(fixed_channel->GetDevice(),
                                                                                          std::move(fixed_channel));
  fixed_channel_map_.insert(std::move(new_entry));
}

void SecurityManagerChannel::OnConnectionFail(hci::Address address,
                                              l2cap::classic::FixedChannelManager::ConnectionResult result) {
  LOG_ERROR("Connection closed due to: %s ; %d", hci::ErrorCodeText(result.hci_error).c_str(),
            result.connection_result_code);
  auto entry = fixed_channel_map_.find(address);
  if (entry != fixed_channel_map_.end()) {
    entry->second.reset();
    fixed_channel_map_.erase(entry);
  }
  listener_->OnConnectionFailed(address, result);
}

void SecurityManagerChannel::OnConnectionClose(hci::Address address, hci::ErrorCode error_code) {
  // Called when the connection gets closed
  LOG_ERROR("Connection closed due to: %s", hci::ErrorCodeText(error_code).c_str());
  auto entry = fixed_channel_map_.find(address);
  if (entry != fixed_channel_map_.end()) {
    entry->second.reset();
    fixed_channel_map_.erase(entry);
  }
  listener_->OnConnectionClosed(address, error_code);
}

}  // namespace channel
}  // namespace security
}  // namespace bluetooth
