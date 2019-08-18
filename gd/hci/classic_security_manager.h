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

#pragma once

#include "common/address.h"
#include "common/link_key.h"
#include "hci/hci_packets.h"
#include "module.h"

namespace bluetooth {
namespace hci {

class ClassicSecurityCommandCallbacks {
 public:
  virtual ~ClassicSecurityCommandCallbacks() = default;
  // Invoked when controller sends Command Complete event
  virtual void OnCommandComplete(CommandCompleteView status) = 0;
};

class ClassicSecurityManager : public Module {
 public:
  ClassicSecurityManager();

  bool RegisterCallbacks(ClassicSecurityCommandCallbacks* callbacks, os::Handler* handler);

  void LinkKeyRequestReply(common::Address address, common::LinkKey link_key);
  void LinkKeyRequestNegativeReply(common::Address address);
  void PinCodeRequestReply(common::Address address, uint8_t len, std::string pin_code);
  void PinCodeRequestNegativeReply(common::Address address);
  void IoCapabilityRequestReply(common::Address address, IoCapability io_capability, OobDataPresent oob_present,
                                AuthenticationRequirements authentication_requirements);
  void IoCapabilityRequestNegativeReply(common::Address address, ErrorCode reason);
  void UserConfirmationRequestReply(common::Address address);
  void UserConfirmationRequestNegativeReply(common::Address address);
  void UserPasskeyRequestReply(common::Address address, uint32_t passkey);
  void UserPasskeyRequestNegativeReply(common::Address address);
  void RemoteOobDataRequestReply(common::Address address, std::array<uint8_t, 16> c, std::array<uint8_t, 16> r);
  void RemoteOobDataRequestNegativeReply(common::Address address);
  void ReadStoredLinkKey(common::Address address, ReadStoredLinkKeyReadAllFlag read_all_flag);
  void WriteStoredLinkKey(uint8_t num_keys_to_write, common::Address address, common::LinkKey link_key);
  void DeleteStoredLinkKey(common::Address address, DeleteStoredLinkKeyDeleteAllFlag delete_all_flag);
  void RefreshEncryptionKey(uint16_t connection_handle);
  void ReadSimplePairingMode();
  void WriteSimplePairingMode(Enable simple_pairing_mode);
  void ReadLocalOobData();
  void SendKeypressNotification(common::Address address, KeypressNotificationType notification_type);
  void ReadLocalOobExtendedData();
  void ReadEncryptionKeySize(uint16_t connection_handle);

  void AuthenticationRequested(uint16_t connection_handle);  // TODO remove

  static const ModuleFactory Factory;

 protected:
  void ListDependencies(ModuleList* list) override;

  void Start() override;

  void Stop() override;

 private:
  struct impl;
  std::unique_ptr<impl> pimpl_;
};

}  // namespace hci
}  // namespace bluetooth
