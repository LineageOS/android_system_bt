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

#include "classic_security_manager.h"

#include <future>
#include <set>
#include <utility>
#include "os/log.h"

#include "acl_manager.h"
#include "common/bidi_queue.h"
#include "hci/controller.h"
#include "hci/hci_layer.h"

namespace bluetooth {
namespace hci {

using common::Bind;
using common::BindOnce;

struct ClassicSecurityManager::impl {
  impl(ClassicSecurityManager& classic_security_manager) : classic_security_manager_(classic_security_manager) {}

  void Start() {
    hci_layer_ = classic_security_manager_.GetDependency<HciLayer>();
    handler_ = classic_security_manager_.GetHandler();
    hci_layer_->RegisterEventHandler(EventCode::IO_CAPABILITY_REQUEST,
                                     Bind(&impl::on_request_event, common::Unretained(this)), handler_);
    hci_layer_->RegisterEventHandler(EventCode::LINK_KEY_REQUEST,
                                     Bind(&impl::on_request_event, common::Unretained(this)), handler_);
    hci_layer_->RegisterEventHandler(EventCode::PIN_CODE_REQUEST,
                                     Bind(&impl::on_request_event, common::Unretained(this)), handler_);
    hci_layer_->RegisterEventHandler(EventCode::ENCRYPTION_KEY_REFRESH_COMPLETE,
                                     Bind(&impl::on_complete_event, common::Unretained(this)), handler_);
    hci_layer_->RegisterEventHandler(EventCode::LINK_KEY_NOTIFICATION,
                                     Bind(&impl::on_link_key_notification, common::Unretained(this)), handler_);
  }

  void Stop() {
    hci_layer_->UnregisterEventHandler(EventCode::IO_CAPABILITY_REQUEST);
    handler_ = nullptr;
    hci_layer_ = nullptr;
  }

  void handle_register_callbacks(ClassicSecurityCommandCallbacks* callbacks, os::Handler* handler) {
    ASSERT(client_callbacks_ == nullptr);
    ASSERT(client_handler_ == nullptr);
    client_callbacks_ = callbacks;
    client_handler_ = handler;
  }

  void link_key_request_reply(Address address, common::LinkKey link_key) {
    std::array<uint8_t, 16> link_key_array;
    std::copy(std::begin(link_key.link_key), std::end(link_key.link_key), std::begin(link_key_array));

    std::unique_ptr<LinkKeyRequestReplyBuilder> packet = LinkKeyRequestReplyBuilder::Create(address, link_key_array);
    hci_layer_->EnqueueCommand(std::move(packet),
                               common::BindOnce(&impl::on_command_complete, common::Unretained(this)), handler_);
  }

  void link_key_request_negative_reply(Address address) {
    std::unique_ptr<LinkKeyRequestNegativeReplyBuilder> packet = LinkKeyRequestNegativeReplyBuilder::Create(address);

    hci_layer_->EnqueueCommand(std::move(packet),
                               common::BindOnce(&impl::on_command_complete, common::Unretained(this)), handler_);
  }

  void pin_code_request_reply(Address address, uint8_t len, std::string pin_code) {
    ASSERT(len > 0 && len <= 16 && pin_code.length() == len);
    // fill remaining char with 0
    pin_code.append(std::string(16 - len, '0'));
    std::array<uint8_t, 16> pin_code_array;
    std::copy(std::begin(pin_code), std::end(pin_code), std::begin(pin_code_array));

    std::unique_ptr<PinCodeRequestReplyBuilder> packet =
        PinCodeRequestReplyBuilder::Create(address, len, pin_code_array);
    hci_layer_->EnqueueCommand(std::move(packet),
                               common::BindOnce(&impl::on_command_complete, common::Unretained(this)), handler_);
  }

  void pin_code_request_negative_reply(Address address) {
    std::unique_ptr<PinCodeRequestNegativeReplyBuilder> packet = PinCodeRequestNegativeReplyBuilder::Create(address);
    hci_layer_->EnqueueCommand(std::move(packet),
                               common::BindOnce(&impl::on_command_complete, common::Unretained(this)), handler_);
  }

  void io_capability_request_reply(Address address, IoCapability io_capability, OobDataPresent oob_present,
                                   AuthenticationRequirements authentication_requirements) {
    std::unique_ptr<IoCapabilityRequestReplyBuilder> packet =
        IoCapabilityRequestReplyBuilder::Create(address, io_capability, oob_present, authentication_requirements);
    hci_layer_->EnqueueCommand(std::move(packet),
                               common::BindOnce(&impl::on_command_complete, common::Unretained(this)), handler_);
  }

  void io_capability_request_negative_reply(Address address, ErrorCode reason) {
    std::unique_ptr<IoCapabilityRequestNegativeReplyBuilder> packet =
        IoCapabilityRequestNegativeReplyBuilder::Create(address, reason);
    hci_layer_->EnqueueCommand(std::move(packet),
                               common::BindOnce(&impl::on_command_complete, common::Unretained(this)), handler_);
  }

  void user_confirmation_request_reply(Address address) {
    std::unique_ptr<UserConfirmationRequestReplyBuilder> packet = UserConfirmationRequestReplyBuilder::Create(address);
    hci_layer_->EnqueueCommand(std::move(packet),
                               common::BindOnce(&impl::on_command_complete, common::Unretained(this)), handler_);
  }

  void user_confirmation_request_negative_reply(Address address) {
    std::unique_ptr<UserConfirmationRequestNegativeReplyBuilder> packet =
        UserConfirmationRequestNegativeReplyBuilder::Create(address);
    hci_layer_->EnqueueCommand(std::move(packet),
                               common::BindOnce(&impl::on_command_complete, common::Unretained(this)), handler_);
  }

  void user_passkey_request_reply(Address address, uint32_t passkey) {
    ASSERT(passkey <= 999999);
    std::unique_ptr<UserPasskeyRequestReplyBuilder> packet = UserPasskeyRequestReplyBuilder::Create(address, passkey);
    hci_layer_->EnqueueCommand(std::move(packet),
                               common::BindOnce(&impl::on_command_complete, common::Unretained(this)), handler_);
  }

  void user_passkey_request_negative_reply(Address address) {
    std::unique_ptr<UserPasskeyRequestNegativeReplyBuilder> packet =
        UserPasskeyRequestNegativeReplyBuilder::Create(address);
    hci_layer_->EnqueueCommand(std::move(packet),
                               common::BindOnce(&impl::on_command_complete, common::Unretained(this)), handler_);
  }

  void remote_oob_data_request_reply(Address address, std::array<uint8_t, 16> c, std::array<uint8_t, 16> r) {
    std::unique_ptr<RemoteOobDataRequestReplyBuilder> packet = RemoteOobDataRequestReplyBuilder::Create(address, c, r);
    hci_layer_->EnqueueCommand(std::move(packet),
                               common::BindOnce(&impl::on_command_complete, common::Unretained(this)), handler_);
  }

  void remote_oob_data_request_negative_reply(Address address) {
    std::unique_ptr<RemoteOobDataRequestNegativeReplyBuilder> packet =
        RemoteOobDataRequestNegativeReplyBuilder::Create(address);
    hci_layer_->EnqueueCommand(std::move(packet),
                               common::BindOnce(&impl::on_command_complete, common::Unretained(this)), handler_);
  }

  void read_stored_link_key(Address address, ReadStoredLinkKeyReadAllFlag read_all_flag) {
    std::unique_ptr<ReadStoredLinkKeyBuilder> packet = ReadStoredLinkKeyBuilder::Create(address, read_all_flag);
    hci_layer_->EnqueueCommand(std::move(packet),
                               common::BindOnce(&impl::on_command_complete, common::Unretained(this)), handler_);
  }

  void write_stored_link_key(std::vector<KeyAndAddress> keys) {
    std::unique_ptr<WriteStoredLinkKeyBuilder> packet = WriteStoredLinkKeyBuilder::Create(keys);
    hci_layer_->EnqueueCommand(std::move(packet),
                               common::BindOnce(&impl::on_command_complete, common::Unretained(this)), handler_);
  }

  void delete_stored_link_key(Address address, DeleteStoredLinkKeyDeleteAllFlag delete_all_flag) {
    std::unique_ptr<DeleteStoredLinkKeyBuilder> packet = DeleteStoredLinkKeyBuilder::Create(address, delete_all_flag);
    hci_layer_->EnqueueCommand(std::move(packet),
                               common::BindOnce(&impl::on_command_complete, common::Unretained(this)), handler_);
  }

  void refresh_encryption_key(uint16_t connection_handle) {
    std::unique_ptr<RefreshEncryptionKeyBuilder> packet = RefreshEncryptionKeyBuilder::Create(connection_handle);
    hci_layer_->EnqueueCommand(std::move(packet), common::BindOnce([](CommandStatusView status) { /* TODO: check? */ }),
                               handler_);
  }

  void read_simple_pairing_mode() {
    std::unique_ptr<ReadSimplePairingModeBuilder> packet = ReadSimplePairingModeBuilder::Create();
    hci_layer_->EnqueueCommand(std::move(packet),
                               common::BindOnce(&impl::on_command_complete, common::Unretained(this)), handler_);
  }

  void write_simple_pairing_mode(Enable connection_handle) {
    std::unique_ptr<WriteSimplePairingModeBuilder> packet = WriteSimplePairingModeBuilder::Create(connection_handle);
    hci_layer_->EnqueueCommand(std::move(packet),
                               common::BindOnce(&impl::on_command_complete, common::Unretained(this)), handler_);
  }

  void read_local_oob_data() {
    std::unique_ptr<ReadLocalOobDataBuilder> packet = ReadLocalOobDataBuilder::Create();
    hci_layer_->EnqueueCommand(std::move(packet),
                               common::BindOnce(&impl::on_command_complete, common::Unretained(this)), handler_);
  }

  void send_keypress_notification(Address address, KeypressNotificationType notification_type) {
    std::unique_ptr<SendKeypressNotificationBuilder> packet =
        SendKeypressNotificationBuilder::Create(address, notification_type);
    hci_layer_->EnqueueCommand(std::move(packet),
                               common::BindOnce(&impl::on_command_complete, common::Unretained(this)), handler_);
  }

  void read_local_oob_extended_data() {
    std::unique_ptr<ReadLocalOobExtendedDataBuilder> packet = ReadLocalOobExtendedDataBuilder::Create();
    hci_layer_->EnqueueCommand(std::move(packet),
                               common::BindOnce(&impl::on_command_complete, common::Unretained(this)), handler_);
  }

  void read_encryption_key_size(uint16_t connection_handle) {
    std::unique_ptr<ReadEncryptionKeySizeBuilder> packet = ReadEncryptionKeySizeBuilder::Create(connection_handle);
    hci_layer_->EnqueueCommand(std::move(packet),
                               common::BindOnce(&impl::on_command_complete, common::Unretained(this)), handler_);
  }

  // TODO remove
  void on_request_event(EventPacketView packet) {
    EventCode event_code = packet.GetEventCode();
    LOG_DEBUG("receive request %d", (uint8_t)event_code);
  }

  // TODO remove
  void on_complete_event(EventPacketView packet) {
    EventCode event_code = packet.GetEventCode();
    LOG_DEBUG("receive complete event %d", (uint8_t)event_code);
  }

  void on_link_key_notification(EventPacketView packet) {
    auto view = LinkKeyNotificationView::Create(packet);
    ASSERT(view.IsValid());
    LOG_DEBUG("receive link key notification, key type %d", (uint8_t)view.GetKeyType());
  }

  void on_command_complete(CommandCompleteView status) {
    if (client_handler_ != nullptr) {
      client_handler_->Post(common::BindOnce(&ClassicSecurityCommandCallbacks::OnCommandComplete,
                                             common::Unretained(client_callbacks_), status));
    }
  }

  ClassicSecurityManager& classic_security_manager_;

  Controller* controller_ = nullptr;

  HciLayer* hci_layer_ = nullptr;
  os::Handler* handler_ = nullptr;
  ClassicSecurityCommandCallbacks* client_callbacks_ = nullptr;
  os::Handler* client_handler_ = nullptr;
};

ClassicSecurityManager::ClassicSecurityManager() : pimpl_(std::make_unique<impl>(*this)) {}

bool ClassicSecurityManager::RegisterCallbacks(ClassicSecurityCommandCallbacks* callbacks, os::Handler* handler) {
  ASSERT(callbacks != nullptr && handler != nullptr);
  GetHandler()->Post(common::BindOnce(&impl::handle_register_callbacks, common::Unretained(pimpl_.get()),
                                      common::Unretained(callbacks), common::Unretained(handler)));
  return true;
}

void ClassicSecurityManager::LinkKeyRequestReply(Address address, common::LinkKey link_key) {
  GetHandler()->Post(BindOnce(&impl::link_key_request_reply, common::Unretained(pimpl_.get()), address, link_key));
}

void ClassicSecurityManager::LinkKeyRequestNegativeReply(Address address) {
  GetHandler()->Post(BindOnce(&impl::link_key_request_negative_reply, common::Unretained(pimpl_.get()), address));
}

void ClassicSecurityManager::PinCodeRequestReply(Address address, uint8_t len, std::string pin_code) {
  GetHandler()->Post(BindOnce(&impl::pin_code_request_reply, common::Unretained(pimpl_.get()), address, len, pin_code));
}

void ClassicSecurityManager::PinCodeRequestNegativeReply(Address address) {
  GetHandler()->Post(BindOnce(&impl::pin_code_request_negative_reply, common::Unretained(pimpl_.get()), address));
}

void ClassicSecurityManager::IoCapabilityRequestReply(Address address, IoCapability io_capability,
                                                      OobDataPresent oob_present,
                                                      AuthenticationRequirements authentication_requirements) {
  GetHandler()->Post(BindOnce(&impl::io_capability_request_reply, common::Unretained(pimpl_.get()), address,
                              io_capability, oob_present, authentication_requirements));
}

void ClassicSecurityManager::IoCapabilityRequestNegativeReply(Address address, ErrorCode reason) {
  GetHandler()->Post(
      BindOnce(&impl::io_capability_request_negative_reply, common::Unretained(pimpl_.get()), address, reason));
}

void ClassicSecurityManager::UserConfirmationRequestReply(Address address) {
  GetHandler()->Post(BindOnce(&impl::user_confirmation_request_reply, common::Unretained(pimpl_.get()), address));
}

void ClassicSecurityManager::UserConfirmationRequestNegativeReply(Address address) {
  GetHandler()->Post(
      BindOnce(&impl::user_confirmation_request_negative_reply, common::Unretained(pimpl_.get()), address));
}

void ClassicSecurityManager::UserPasskeyRequestReply(bluetooth::hci::Address address, uint32_t passkey) {
  GetHandler()->Post(BindOnce(&impl::user_passkey_request_reply, common::Unretained(pimpl_.get()), address, passkey));
}

void ClassicSecurityManager::UserPasskeyRequestNegativeReply(Address address) {
  GetHandler()->Post(BindOnce(&impl::user_passkey_request_negative_reply, common::Unretained(pimpl_.get()), address));
}

void ClassicSecurityManager::RemoteOobDataRequestReply(Address address, std::array<uint8_t, 16> c,
                                                       std::array<uint8_t, 16> r) {
  GetHandler()->Post(BindOnce(&impl::remote_oob_data_request_reply, common::Unretained(pimpl_.get()), address, c, r));
}

void ClassicSecurityManager::RemoteOobDataRequestNegativeReply(Address address) {
  GetHandler()->Post(
      BindOnce(&impl::remote_oob_data_request_negative_reply, common::Unretained(pimpl_.get()), address));
}

void ClassicSecurityManager::ReadStoredLinkKey(Address address, ReadStoredLinkKeyReadAllFlag read_all_flag) {
  GetHandler()->Post(BindOnce(&impl::read_stored_link_key, common::Unretained(pimpl_.get()), address, read_all_flag));
}

void ClassicSecurityManager::WriteStoredLinkKey(std::vector<KeyAndAddress> keys) {
  GetHandler()->Post(BindOnce(&impl::write_stored_link_key, common::Unretained(pimpl_.get()), keys));
}

void ClassicSecurityManager::DeleteStoredLinkKey(Address address, DeleteStoredLinkKeyDeleteAllFlag delete_all_flag) {
  GetHandler()->Post(
      BindOnce(&impl::delete_stored_link_key, common::Unretained(pimpl_.get()), address, delete_all_flag));
}

void ClassicSecurityManager::RefreshEncryptionKey(uint16_t connection_handle) {
  GetHandler()->Post(BindOnce(&impl::refresh_encryption_key, common::Unretained(pimpl_.get()), connection_handle));
}
void ClassicSecurityManager::ReadSimplePairingMode() {
  GetHandler()->Post(BindOnce(&impl::read_simple_pairing_mode, common::Unretained(pimpl_.get())));
}

void ClassicSecurityManager::WriteSimplePairingMode(Enable simple_pairing_mode) {
  GetHandler()->Post(BindOnce(&impl::write_simple_pairing_mode, common::Unretained(pimpl_.get()), simple_pairing_mode));
}

void ClassicSecurityManager::ReadLocalOobData() {
  GetHandler()->Post(BindOnce(&impl::read_local_oob_data, common::Unretained(pimpl_.get())));
}

void ClassicSecurityManager::SendKeypressNotification(Address address, KeypressNotificationType notification_type) {
  GetHandler()->Post(
      BindOnce(&impl::send_keypress_notification, common::Unretained(pimpl_.get()), address, notification_type));
}

void ClassicSecurityManager::ReadLocalOobExtendedData() {
  GetHandler()->Post(BindOnce(&impl::read_local_oob_extended_data, common::Unretained(pimpl_.get())));
}

void ClassicSecurityManager::ReadEncryptionKeySize(uint16_t connection_handle) {
  GetHandler()->Post(BindOnce(&impl::read_encryption_key_size, common::Unretained(pimpl_.get()), connection_handle));
}

void ClassicSecurityManager::ListDependencies(ModuleList* list) {
  list->add<HciLayer>();
}

void ClassicSecurityManager::Start() {
  pimpl_->Start();
}

void ClassicSecurityManager::Stop() {
  pimpl_->Stop();
}

std::string ClassicSecurityManager::ToString() const {
  return "Classic Security Manager";
}

const ModuleFactory ClassicSecurityManager::Factory = ModuleFactory([]() { return new ClassicSecurityManager(); });

}  // namespace hci
}  // namespace bluetooth
