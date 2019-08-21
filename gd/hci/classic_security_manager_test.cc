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
#include "hci/classic_security_manager.h"

#include <condition_variable>
#include "gtest/gtest.h"

#include "common/bind.h"
#include "hci/hci_layer.h"
#include "os/thread.h"
#include "packet/raw_builder.h"

namespace bluetooth {
namespace hci {
namespace {

using common::BidiQueue;
using common::BidiQueueEnd;
using common::OnceCallback;
using os::Handler;
using os::Thread;
using packet::RawBuilder;

PacketView<kLittleEndian> GetPacketView(std::unique_ptr<packet::BasePacketBuilder> packet) {
  auto bytes = std::make_shared<std::vector<uint8_t>>();
  BitInserter i(*bytes);
  bytes->reserve(packet->size());
  packet->Serialize(i);
  return packet::PacketView<packet::kLittleEndian>(bytes);
}

class CommandQueueEntry {
 public:
  CommandQueueEntry(std::unique_ptr<CommandPacketBuilder> command_packet,
                    OnceCallback<void(CommandCompleteView)> on_complete_function, Handler* handler)
      : command(std::move(command_packet)), waiting_for_status_(false), on_complete(std::move(on_complete_function)),
        caller_handler(handler) {}

  CommandQueueEntry(std::unique_ptr<CommandPacketBuilder> command_packet,
                    OnceCallback<void(CommandStatusView)> on_status_function, Handler* handler)
      : command(std::move(command_packet)), waiting_for_status_(true), on_status(std::move(on_status_function)),
        caller_handler(handler) {}

  std::unique_ptr<CommandPacketBuilder> command;
  bool waiting_for_status_;
  OnceCallback<void(CommandStatusView)> on_status;
  OnceCallback<void(CommandCompleteView)> on_complete;
  Handler* caller_handler;
};

class TestHciLayer : public HciLayer {
 public:
  void EnqueueCommand(std::unique_ptr<CommandPacketBuilder> command, OnceCallback<void(CommandStatusView)> on_status,
                      Handler* handler) override {
    auto command_queue_entry = std::make_unique<CommandQueueEntry>(std::move(command), std::move(on_status), handler);
    command_queue_.push(std::move(command_queue_entry));
  }

  void EnqueueCommand(std::unique_ptr<CommandPacketBuilder> command,
                      OnceCallback<void(CommandCompleteView)> on_complete, Handler* handler) override {
    auto command_queue_entry = std::make_unique<CommandQueueEntry>(std::move(command), std::move(on_complete), handler);
    command_queue_.push(std::move(command_queue_entry));
  }

  std::unique_ptr<CommandQueueEntry> GetLastCommand() {
    EXPECT_FALSE(command_queue_.empty());
    auto last = std::move(command_queue_.front());
    command_queue_.pop();
    return last;
  }

  void RegisterEventHandler(EventCode event_code, common::Callback<void(EventPacketView)> event_handler,
                            Handler* handler) override {
    registered_events_[event_code] = event_handler;
  }

  void UnregisterEventHandler(EventCode event_code) override {
    registered_events_.erase(event_code);
  }

  void IncomingEvent(std::unique_ptr<EventPacketBuilder> event_builder) {
    auto packet = GetPacketView(std::move(event_builder));
    EventPacketView event = EventPacketView::Create(packet);
    EXPECT_TRUE(event.IsValid());
    EventCode event_code = event.GetEventCode();
    EXPECT_TRUE(registered_events_.find(event_code) != registered_events_.end());
    registered_events_[event_code].Run(event);
  }

  void ListDependencies(ModuleList* list) override {}
  void Start() override {}
  void Stop() override {}

 private:
  std::map<EventCode, common::Callback<void(EventPacketView)>> registered_events_;
  std::queue<std::unique_ptr<CommandQueueEntry>> command_queue_;
};

class ClassicSecurityManagerTest : public ::testing::Test, public ::bluetooth::hci::ClassicSecurityCommandCallbacks {
 protected:
  void SetUp() override {
    test_hci_layer_ = new TestHciLayer;
    handler_ = new Handler(&thread_);
    fake_registry_.InjectTestModule(&TestHciLayer::Factory, test_hci_layer_);
    fake_registry_.Start<ClassicSecurityManager>(&thread_);
    classic_security_manager_ =
        static_cast<ClassicSecurityManager*>(fake_registry_.GetModuleUnderTest(&ClassicSecurityManager::Factory));
    classic_security_manager_->RegisterCallbacks(this, handler_);
    test_hci_layer_->RegisterEventHandler(
        EventCode::COMMAND_COMPLETE, base::Bind(&ClassicSecurityManagerTest::ExpectCommand, common::Unretained(this)),
        nullptr);
    test_hci_layer_->RegisterEventHandler(
        EventCode::COMMAND_STATUS,
        base::Bind(&ClassicSecurityManagerTest::ExpectCommandStatus, common::Unretained(this)), nullptr);

    Address::FromString("A1:A2:A3:A4:A5:A6", remote);
  }

  void TearDown() override {
    handler_->Clear();
    delete handler_;
    fake_registry_.SynchronizeModuleHandler(&ClassicSecurityManager::Factory, std::chrono::milliseconds(20));
    fake_registry_.StopAll();
    command_complete_ = false;
  }

  void ExpectCommand(EventPacketView packet) {
    CommandCompleteView command_complete_view = CommandCompleteView::Create(std::move(packet));
    auto last_command_queue_entry = test_hci_layer_->GetLastCommand();
    auto last_command = std::move(last_command_queue_entry->command);
    auto command_packet = GetPacketView(std::move(last_command));
    CommandPacketView command_packet_view = CommandPacketView::Create(command_packet);

    // verify command complete event match last command opcode
    EXPECT_TRUE(command_packet_view.IsValid());
    EXPECT_TRUE(command_complete_view.IsValid());
    EXPECT_EQ(command_packet_view.GetOpCode(), command_complete_view.GetCommandOpCode());

    // verify callback triggered
    auto caller_handler = last_command_queue_entry->caller_handler;
    caller_handler->Post(BindOnce(std::move(last_command_queue_entry->on_complete), std::move(command_complete_view)));
    std::unique_lock<std::mutex> lock(mutex_);
    EXPECT_FALSE(callback_done.wait_for(lock, std::chrono::seconds(3)) == std::cv_status::timeout);

    command_complete_ = true;
  }

  void ExpectCommandStatus(EventPacketView packet) {
    CommandStatusView command_status_view = CommandStatusView::Create(std::move(packet));
    auto last_command_queue_entry = test_hci_layer_->GetLastCommand();
    auto last_command = std::move(last_command_queue_entry->command);
    auto command_packet = GetPacketView(std::move(last_command));
    CommandPacketView command_packet_view = CommandPacketView::Create(command_packet);

    // verify command complete event match last command opcode
    EXPECT_TRUE(command_packet_view.IsValid());
    EXPECT_TRUE(command_status_view.IsValid());
    EXPECT_EQ(command_packet_view.GetOpCode(), command_status_view.GetCommandOpCode());

    command_complete_ = true;
  }

  void OnCommandComplete(CommandCompleteView status) override {
    callback_done.notify_one();
  }

  TestModuleRegistry fake_registry_;
  TestHciLayer* test_hci_layer_ = nullptr;
  os::Thread& thread_ = fake_registry_.GetTestThread();
  Handler* handler_ = nullptr;
  ClassicSecurityManager* classic_security_manager_ = nullptr;
  Address remote;
  mutable std::mutex mutex_;
  std::condition_variable callback_done;
  bool command_complete_ = false;
};

TEST_F(ClassicSecurityManagerTest, startup_teardown) {}

TEST_F(ClassicSecurityManagerTest, send_link_key_request_reply) {
  common::LinkKey link_key;
  common::LinkKey::FromString("4c68384139f574d836bcf34e9dfb01bf\0", link_key);
  classic_security_manager_->LinkKeyRequestReply(remote, link_key);
  EXPECT_TRUE(fake_registry_.SynchronizeModuleHandler(&ClassicSecurityManager::Factory, std::chrono::milliseconds(20)));

  auto payload = std::make_unique<RawBuilder>();
  test_hci_layer_->IncomingEvent(
      CommandCompleteBuilder::Create(0x01, OpCode::LINK_KEY_REQUEST_REPLY, std::move(payload)));
  EXPECT_TRUE(command_complete_);
}

TEST_F(ClassicSecurityManagerTest, send_link_key_request_negative_reply) {
  classic_security_manager_->LinkKeyRequestNegativeReply(remote);
  EXPECT_TRUE(fake_registry_.SynchronizeModuleHandler(&ClassicSecurityManager::Factory, std::chrono::milliseconds(20)));

  auto payload = std::make_unique<RawBuilder>();
  test_hci_layer_->IncomingEvent(
      CommandCompleteBuilder::Create(0x01, OpCode::LINK_KEY_REQUEST_NEGATIVE_REPLY, std::move(payload)));
  EXPECT_TRUE(command_complete_);
}

TEST_F(ClassicSecurityManagerTest, send_pin_code_request_reply) {
  classic_security_manager_->PinCodeRequestReply(remote, 6, "123456");
  EXPECT_TRUE(fake_registry_.SynchronizeModuleHandler(&ClassicSecurityManager::Factory, std::chrono::milliseconds(20)));

  auto payload = std::make_unique<RawBuilder>();
  test_hci_layer_->IncomingEvent(
      CommandCompleteBuilder::Create(0x01, OpCode::PIN_CODE_REQUEST_REPLY, std::move(payload)));
  EXPECT_TRUE(command_complete_);
}

TEST_F(ClassicSecurityManagerTest, send_pin_code_request_negative_reply) {
  classic_security_manager_->PinCodeRequestNegativeReply(remote);
  EXPECT_TRUE(fake_registry_.SynchronizeModuleHandler(&ClassicSecurityManager::Factory, std::chrono::milliseconds(20)));

  auto payload = std::make_unique<RawBuilder>();
  test_hci_layer_->IncomingEvent(
      CommandCompleteBuilder::Create(0x01, OpCode::PIN_CODE_REQUEST_NEGATIVE_REPLY, std::move(payload)));
  EXPECT_TRUE(command_complete_);
}

TEST_F(ClassicSecurityManagerTest, send_io_capability_request_reply) {
  IoCapability io_capability = (IoCapability)0x00;
  OobDataPresent oob_present = (OobDataPresent)0x00;
  AuthenticationRequirements authentication_requirements = (AuthenticationRequirements)0x00;
  classic_security_manager_->IoCapabilityRequestReply(remote, io_capability, oob_present, authentication_requirements);
  EXPECT_TRUE(fake_registry_.SynchronizeModuleHandler(&ClassicSecurityManager::Factory, std::chrono::milliseconds(20)));

  auto payload = std::make_unique<RawBuilder>();
  test_hci_layer_->IncomingEvent(
      CommandCompleteBuilder::Create(0x01, OpCode::IO_CAPABILITY_REQUEST_REPLY, std::move(payload)));
  EXPECT_TRUE(command_complete_);
}

TEST_F(ClassicSecurityManagerTest, send_io_capability_request_negative_reply) {
  ErrorCode reason = (ErrorCode)0x01;
  classic_security_manager_->IoCapabilityRequestNegativeReply(remote, reason);
  EXPECT_TRUE(fake_registry_.SynchronizeModuleHandler(&ClassicSecurityManager::Factory, std::chrono::milliseconds(20)));

  auto payload = std::make_unique<RawBuilder>();
  test_hci_layer_->IncomingEvent(
      CommandCompleteBuilder::Create(0x01, OpCode::IO_CAPABILITY_REQUEST_NEGATIVE_REPLY, std::move(payload)));
  EXPECT_TRUE(command_complete_);
}

TEST_F(ClassicSecurityManagerTest, send_user_confirmation_request_reply) {
  classic_security_manager_->UserConfirmationRequestReply(remote);
  EXPECT_TRUE(fake_registry_.SynchronizeModuleHandler(&ClassicSecurityManager::Factory, std::chrono::milliseconds(20)));

  auto payload = std::make_unique<RawBuilder>();
  test_hci_layer_->IncomingEvent(
      CommandCompleteBuilder::Create(0x01, OpCode::USER_CONFIRMATION_REQUEST_REPLY, std::move(payload)));
  EXPECT_TRUE(command_complete_);
}

TEST_F(ClassicSecurityManagerTest, send_user_confirmation_request_negative_reply) {
  classic_security_manager_->UserConfirmationRequestNegativeReply(remote);
  EXPECT_TRUE(fake_registry_.SynchronizeModuleHandler(&ClassicSecurityManager::Factory, std::chrono::milliseconds(20)));

  auto payload = std::make_unique<RawBuilder>();
  test_hci_layer_->IncomingEvent(
      CommandCompleteBuilder::Create(0x01, OpCode::USER_CONFIRMATION_REQUEST_NEGATIVE_REPLY, std::move(payload)));
  EXPECT_TRUE(command_complete_);
}

TEST_F(ClassicSecurityManagerTest, send_user_passkey_request_reply) {
  classic_security_manager_->UserPasskeyRequestReply(remote, 999999);
  EXPECT_TRUE(fake_registry_.SynchronizeModuleHandler(&ClassicSecurityManager::Factory, std::chrono::milliseconds(20)));

  auto payload = std::make_unique<RawBuilder>();
  test_hci_layer_->IncomingEvent(
      CommandCompleteBuilder::Create(0x01, OpCode::USER_PASSKEY_REQUEST_REPLY, std::move(payload)));
  EXPECT_TRUE(command_complete_);
}

TEST_F(ClassicSecurityManagerTest, send_user_passkey_request_negative_reply) {
  classic_security_manager_->UserPasskeyRequestNegativeReply(remote);
  EXPECT_TRUE(fake_registry_.SynchronizeModuleHandler(&ClassicSecurityManager::Factory, std::chrono::milliseconds(20)));

  auto payload = std::make_unique<RawBuilder>();
  test_hci_layer_->IncomingEvent(
      CommandCompleteBuilder::Create(0x01, OpCode::USER_PASSKEY_REQUEST_NEGATIVE_REPLY, std::move(payload)));
  EXPECT_TRUE(command_complete_);
}

TEST_F(ClassicSecurityManagerTest, send_remote_oob_data_request_reply) {
  std::array<uint8_t, 16> c;
  std::array<uint8_t, 16> r;
  for (int i = 0; i < 16; i++) {
    c[i] = (uint8_t)i;
    r[i] = (uint8_t)i + 16;
  }
  classic_security_manager_->RemoteOobDataRequestReply(remote, c, r);
  EXPECT_TRUE(fake_registry_.SynchronizeModuleHandler(&ClassicSecurityManager::Factory, std::chrono::milliseconds(20)));

  auto payload = std::make_unique<RawBuilder>();
  test_hci_layer_->IncomingEvent(
      CommandCompleteBuilder::Create(0x01, OpCode::REMOTE_OOB_DATA_REQUEST_REPLY, std::move(payload)));
  EXPECT_TRUE(command_complete_);
}

TEST_F(ClassicSecurityManagerTest, send_remote_oob_data_request_negative_reply) {
  classic_security_manager_->RemoteOobDataRequestNegativeReply(remote);
  EXPECT_TRUE(fake_registry_.SynchronizeModuleHandler(&ClassicSecurityManager::Factory, std::chrono::milliseconds(20)));

  auto payload = std::make_unique<RawBuilder>();
  test_hci_layer_->IncomingEvent(
      CommandCompleteBuilder::Create(0x01, OpCode::REMOTE_OOB_DATA_REQUEST_NEGATIVE_REPLY, std::move(payload)));
  EXPECT_TRUE(command_complete_);
}

TEST_F(ClassicSecurityManagerTest, send_read_stored_link_key) {
  ReadStoredLinkKeyReadAllFlag read_all_flag = (ReadStoredLinkKeyReadAllFlag)0x01;
  classic_security_manager_->ReadStoredLinkKey(remote, read_all_flag);
  EXPECT_TRUE(fake_registry_.SynchronizeModuleHandler(&ClassicSecurityManager::Factory, std::chrono::milliseconds(20)));

  auto payload = std::make_unique<RawBuilder>();
  test_hci_layer_->IncomingEvent(
      CommandCompleteBuilder::Create(0x01, OpCode::READ_STORED_LINK_KEY, std::move(payload)));
  EXPECT_TRUE(command_complete_);
}

TEST_F(ClassicSecurityManagerTest, send_delete_stored_link_key) {
  DeleteStoredLinkKeyDeleteAllFlag delete_all_flag = (DeleteStoredLinkKeyDeleteAllFlag)0x01;
  classic_security_manager_->DeleteStoredLinkKey(remote, delete_all_flag);
  EXPECT_TRUE(fake_registry_.SynchronizeModuleHandler(&ClassicSecurityManager::Factory, std::chrono::milliseconds(20)));

  auto payload = std::make_unique<RawBuilder>();
  test_hci_layer_->IncomingEvent(
      CommandCompleteBuilder::Create(0x01, OpCode::DELETE_STORED_LINK_KEY, std::move(payload)));
  EXPECT_TRUE(command_complete_);
}

TEST_F(ClassicSecurityManagerTest, send_refresh_encryption_key) {
  classic_security_manager_->RefreshEncryptionKey(0x01);
  EXPECT_TRUE(fake_registry_.SynchronizeModuleHandler(&ClassicSecurityManager::Factory, std::chrono::milliseconds(20)));

  auto payload = std::make_unique<RawBuilder>();
  test_hci_layer_->IncomingEvent(
      CommandStatusBuilder::Create(ErrorCode::SUCCESS, 0x01, OpCode::REFRESH_ENCRYPTION_KEY, std::move(payload)));
  EXPECT_TRUE(command_complete_);
}

TEST_F(ClassicSecurityManagerTest, send_read_simple_pairing_mode) {
  classic_security_manager_->ReadSimplePairingMode();
  EXPECT_TRUE(fake_registry_.SynchronizeModuleHandler(&ClassicSecurityManager::Factory, std::chrono::milliseconds(20)));

  auto payload = std::make_unique<RawBuilder>();
  test_hci_layer_->IncomingEvent(
      CommandCompleteBuilder::Create(0x01, OpCode::READ_SIMPLE_PAIRING_MODE, std::move(payload)));
  EXPECT_TRUE(command_complete_);
}

TEST_F(ClassicSecurityManagerTest, send_write_simple_pairing_mode) {
  Enable simple_pairing_mode = (Enable)0x01;
  classic_security_manager_->WriteSimplePairingMode(simple_pairing_mode);
  EXPECT_TRUE(fake_registry_.SynchronizeModuleHandler(&ClassicSecurityManager::Factory, std::chrono::milliseconds(20)));

  auto payload = std::make_unique<RawBuilder>();
  test_hci_layer_->IncomingEvent(
      CommandCompleteBuilder::Create(0x01, OpCode::WRITE_SIMPLE_PAIRING_MODE, std::move(payload)));
  EXPECT_TRUE(command_complete_);
}

TEST_F(ClassicSecurityManagerTest, send_read_local_oob_data) {
  classic_security_manager_->ReadLocalOobData();
  EXPECT_TRUE(fake_registry_.SynchronizeModuleHandler(&ClassicSecurityManager::Factory, std::chrono::milliseconds(20)));

  auto payload = std::make_unique<RawBuilder>();
  test_hci_layer_->IncomingEvent(CommandCompleteBuilder::Create(0x01, OpCode::READ_LOCAL_OOB_DATA, std::move(payload)));
  EXPECT_TRUE(command_complete_);
}

TEST_F(ClassicSecurityManagerTest, send_keypress_notification) {
  KeypressNotificationType notification_type = (KeypressNotificationType)0x01;
  classic_security_manager_->SendKeypressNotification(remote, notification_type);
  EXPECT_TRUE(fake_registry_.SynchronizeModuleHandler(&ClassicSecurityManager::Factory, std::chrono::milliseconds(20)));

  auto payload = std::make_unique<RawBuilder>();
  test_hci_layer_->IncomingEvent(
      CommandCompleteBuilder::Create(0x01, OpCode::SEND_KEYPRESS_NOTIFICATION, std::move(payload)));
  EXPECT_TRUE(command_complete_);
}

TEST_F(ClassicSecurityManagerTest, send_read_local_oob_extended_data) {
  classic_security_manager_->ReadLocalOobExtendedData();
  EXPECT_TRUE(fake_registry_.SynchronizeModuleHandler(&ClassicSecurityManager::Factory, std::chrono::milliseconds(20)));

  auto payload = std::make_unique<RawBuilder>();
  test_hci_layer_->IncomingEvent(
      CommandCompleteBuilder::Create(0x01, OpCode::READ_LOCAL_OOB_EXTENDED_DATA, std::move(payload)));
  EXPECT_TRUE(command_complete_);
}

TEST_F(ClassicSecurityManagerTest, send_read_encryption_key_size) {
  classic_security_manager_->ReadEncryptionKeySize(0x01);
  EXPECT_TRUE(fake_registry_.SynchronizeModuleHandler(&ClassicSecurityManager::Factory, std::chrono::milliseconds(20)));

  auto payload = std::make_unique<RawBuilder>();
  test_hci_layer_->IncomingEvent(
      CommandCompleteBuilder::Create(0x01, OpCode::READ_ENCRYPTION_KEY_SIZE, std::move(payload)));
  EXPECT_TRUE(command_complete_);
}

}  // namespace
}  // namespace hci
}  // namespace bluetooth
