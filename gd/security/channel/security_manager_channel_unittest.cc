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

#include <gtest/gtest.h>

#include "hci/device.h"
#include "hci/device_database.h"
#include "hci/hci_packets.h"
#include "packet/raw_builder.h"
#include "security/smp_packets.h"
#include "security/test/fake_hci_layer.h"

namespace bluetooth {
namespace security {
namespace channel {
namespace {

using bluetooth::security::channel::SecurityManagerChannel;
using hci::AuthenticationRequirements;
using hci::CommandCompleteBuilder;
using hci::Device;
using hci::DeviceDatabase;
using hci::IoCapabilityRequestReplyBuilder;
using hci::IoCapabilityRequestView;
using hci::OobDataPresent;
using hci::OpCode;
using os::Handler;
using os::Thread;
using packet::RawBuilder;

static DeviceDatabase kDeviceDatabase;

class SecurityManagerChannelCallback : public ISecurityManagerChannelListener {
 public:
  // HCI
  bool receivedChangeConnectionLinkKeyComplete = false;
  bool receivedMasterLinkKeyComplete = false;
  bool receivedPinCodeRequest = false;
  bool receivedLinkKeyRequest = false;
  bool receivedLinkKeyNotification = false;
  bool receivedIoCapabilityRequest = false;
  bool receivedIoCapabilityResponse = false;
  bool receivedSimplePairingComplete = false;
  bool receivedReturnLinkKeys = false;
  bool receivedEncryptionChange = false;
  bool receivedEncryptionKeyRefreshComplete = false;
  bool receivedRemoteOobDataRequest = false;
  bool receivedUserPasskeyNotification = false;
  bool receivedKeypressNotification = false;

  void OnChangeConnectionLinkKeyComplete(std::shared_ptr<hci::Device> device,
                                         hci::ChangeConnectionLinkKeyCompleteView packet) {
    EXPECT_TRUE(packet.IsValid());
    receivedChangeConnectionLinkKeyComplete = true;
  }
  void OnMasterLinkKeyComplete(std::shared_ptr<hci::Device> device, hci::MasterLinkKeyCompleteView packet) {
    EXPECT_TRUE(packet.IsValid());
    receivedMasterLinkKeyComplete = true;
  }
  void OnPinCodeRequest(std::shared_ptr<hci::Device> device, hci::PinCodeRequestView packet) {
    EXPECT_TRUE(packet.IsValid());
    receivedPinCodeRequest = true;
  }
  void OnLinkKeyRequest(std::shared_ptr<hci::Device> device, hci::LinkKeyRequestView packet) {
    EXPECT_TRUE(packet.IsValid());
    receivedLinkKeyRequest = true;
  }
  void OnLinkKeyNotification(std::shared_ptr<hci::Device> device, hci::LinkKeyNotificationView packet) {
    EXPECT_TRUE(packet.IsValid());
    receivedLinkKeyNotification = true;
  }
  void OnIoCapabilityRequest(std::shared_ptr<Device> device, hci::IoCapabilityRequestView packet) {
    EXPECT_TRUE(packet.IsValid());
    receivedIoCapabilityRequest = true;
  }
  void OnIoCapabilityResponse(std::shared_ptr<Device> device, hci::IoCapabilityResponseView packet) {
    EXPECT_TRUE(packet.IsValid());
    receivedIoCapabilityResponse = true;
  }
  void OnSimplePairingComplete(std::shared_ptr<Device> device, hci::SimplePairingCompleteView packet) {
    EXPECT_TRUE(packet.IsValid());
    receivedSimplePairingComplete = true;
  }
  void OnReturnLinkKeys(std::shared_ptr<Device> device, hci::ReturnLinkKeysView packet) {
    EXPECT_TRUE(packet.IsValid());
    receivedReturnLinkKeys = true;
  }
  void OnEncryptionChange(std::shared_ptr<Device> device, hci::EncryptionChangeView packet) {
    EXPECT_TRUE(packet.IsValid());
    receivedEncryptionChange = true;
  }
  void OnEncryptionKeyRefreshComplete(std::shared_ptr<Device> device, hci::EncryptionKeyRefreshCompleteView packet) {
    EXPECT_TRUE(packet.IsValid());
    receivedEncryptionKeyRefreshComplete = true;
  }
  void OnRemoteOobDataRequest(std::shared_ptr<Device> device, hci::RemoteOobDataRequestView packet) {
    EXPECT_TRUE(packet.IsValid());
    receivedRemoteOobDataRequest = true;
  }
  void OnUserPasskeyNotification(std::shared_ptr<hci::Device> device, hci::UserPasskeyNotificationView packet) {
    EXPECT_TRUE(packet.IsValid());
    receivedUserPasskeyNotification = true;
  }
  void OnKeypressNotification(std::shared_ptr<hci::Device> device, hci::KeypressNotificationView packet) {
    EXPECT_TRUE(packet.IsValid());
    receivedKeypressNotification = true;
  }
};

class SecurityManagerChannelTest : public ::testing::Test {
 protected:
  void SetUp() override {
    device_ = kDeviceDatabase.CreateClassicDevice(hci::Address({0x01, 0x02, 0x03, 0x04, 0x05, 0x06}));
    handler_ = new Handler(&thread_);
    callback_ = new SecurityManagerChannelCallback();
    hci_layer_ = new FakeHciLayer();
    fake_registry_.InjectTestModule(&FakeHciLayer::Factory, hci_layer_);
    fake_registry_.Start<FakeHciLayer>(&thread_);
    channel_ = new SecurityManagerChannel(handler_, hci_layer_);
    channel_->SetChannelListener(callback_);
  }

  void TearDown() override {
    channel_->SetChannelListener(nullptr);
    handler_->Clear();
    fake_registry_.SynchronizeModuleHandler(&FakeHciLayer::Factory, std::chrono::milliseconds(20));
    fake_registry_.StopAll();
    delete handler_;
    delete channel_;
    delete callback_;
  }

  TestModuleRegistry fake_registry_;
  Thread& thread_ = fake_registry_.GetTestThread();
  Handler* handler_ = nullptr;
  FakeHciLayer* hci_layer_ = nullptr;
  SecurityManagerChannel* channel_ = nullptr;
  SecurityManagerChannelCallback* callback_ = nullptr;
  std::shared_ptr<Device> device_ = nullptr;
};

TEST_F(SecurityManagerChannelTest, setup_teardown) {}

TEST_F(SecurityManagerChannelTest, recv_io_cap_request) {
  hci_layer_->IncomingEvent(hci::IoCapabilityRequestBuilder::Create(device_->GetAddress()));
  EXPECT_TRUE(callback_->receivedIoCapabilityRequest);
}

TEST_F(SecurityManagerChannelTest, send_io_cap_request_reply) {
  // Arrange
  hci::IoCapability io_capability = (hci::IoCapability)0x00;
  OobDataPresent oob_present = (OobDataPresent)0x00;
  AuthenticationRequirements authentication_requirements = (AuthenticationRequirements)0x00;
  auto packet = hci::IoCapabilityRequestReplyBuilder::Create(device_->GetAddress(), io_capability, oob_present,
                                                             authentication_requirements);

  // Act
  channel_->SendCommand(device_, std::move(packet));
  auto last_command = std::move(hci_layer_->GetLastCommand()->command);
  auto command_packet = GetPacketView(std::move(last_command));
  hci::CommandPacketView packet_view = hci::CommandPacketView::Create(command_packet);

  // Assert
  EXPECT_TRUE(packet_view.IsValid());
  EXPECT_EQ(OpCode::IO_CAPABILITY_REQUEST_REPLY, packet_view.GetOpCode());
}

TEST_F(SecurityManagerChannelTest, send_io_cap_request_neg_reply) {
  // Arrange
  auto packet =
      hci::IoCapabilityRequestNegativeReplyBuilder::Create(device_->GetAddress(), hci::ErrorCode::COMMAND_DISALLOWED);

  // Act
  channel_->SendCommand(device_, std::move(packet));
  auto last_command = std::move(hci_layer_->GetLastCommand()->command);
  auto command_packet = GetPacketView(std::move(last_command));
  hci::CommandPacketView packet_view = hci::CommandPacketView::Create(command_packet);

  // Assert
  EXPECT_TRUE(packet_view.IsValid());
  EXPECT_EQ(OpCode::IO_CAPABILITY_REQUEST_NEGATIVE_REPLY, packet_view.GetOpCode());
}

TEST_F(SecurityManagerChannelTest, recv_io_cap_response) {
  hci::IoCapability io_capability = (hci::IoCapability)0x00;
  OobDataPresent oob_present = (OobDataPresent)0x00;
  AuthenticationRequirements authentication_requirements = (AuthenticationRequirements)0x00;
  hci_layer_->IncomingEvent(hci::IoCapabilityResponseBuilder::Create(device_->GetAddress(), io_capability, oob_present,
                                                                     authentication_requirements));
  EXPECT_TRUE(callback_->receivedIoCapabilityResponse);
}

TEST_F(SecurityManagerChannelTest, recv_pin_code_request) {
  hci_layer_->IncomingEvent(hci::PinCodeRequestBuilder::Create(device_->GetAddress()));
  EXPECT_TRUE(callback_->receivedPinCodeRequest);
}

TEST_F(SecurityManagerChannelTest, send_pin_code_request_reply) {
  // Arrange
  uint8_t pin_code_length = 6;
  std::array<uint8_t, 16> pin_code = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5};
  auto packet = hci::PinCodeRequestReplyBuilder::Create(device_->GetAddress(), pin_code_length, pin_code);

  // Act
  channel_->SendCommand(device_, std::move(packet));
  auto last_command = std::move(hci_layer_->GetLastCommand()->command);
  auto command_packet = GetPacketView(std::move(last_command));
  hci::CommandPacketView packet_view = hci::CommandPacketView::Create(command_packet);

  // Assert
  EXPECT_TRUE(packet_view.IsValid());
  EXPECT_EQ(OpCode::PIN_CODE_REQUEST_REPLY, packet_view.GetOpCode());
}

TEST_F(SecurityManagerChannelTest, send_pin_code_request_neg_reply) {
  // Arrange
  auto packet = hci::PinCodeRequestNegativeReplyBuilder::Create(device_->GetAddress());

  // Act
  channel_->SendCommand(device_, std::move(packet));
  auto last_command = std::move(hci_layer_->GetLastCommand()->command);
  auto command_packet = GetPacketView(std::move(last_command));
  hci::CommandPacketView packet_view = hci::CommandPacketView::Create(command_packet);

  // Assert
  EXPECT_TRUE(packet_view.IsValid());
  EXPECT_EQ(OpCode::PIN_CODE_REQUEST_NEGATIVE_REPLY, packet_view.GetOpCode());
}

TEST_F(SecurityManagerChannelTest, recv_user_passkey_notification) {
  uint32_t passkey = 0x00;
  hci_layer_->IncomingEvent(hci::UserPasskeyNotificationBuilder::Create(device_->GetAddress(), passkey));
  EXPECT_TRUE(callback_->receivedUserPasskeyNotification);
}

TEST_F(SecurityManagerChannelTest, send_user_confirmation_request_reply) {
  // Arrange
  auto packet = hci::UserConfirmationRequestReplyBuilder::Create(device_->GetAddress());

  // Act
  channel_->SendCommand(device_, std::move(packet));
  auto last_command = std::move(hci_layer_->GetLastCommand()->command);
  auto command_packet = GetPacketView(std::move(last_command));
  hci::CommandPacketView packet_view = hci::CommandPacketView::Create(command_packet);

  // Assert
  EXPECT_TRUE(packet_view.IsValid());
  EXPECT_EQ(OpCode::USER_CONFIRMATION_REQUEST_REPLY, packet_view.GetOpCode());
}

TEST_F(SecurityManagerChannelTest, send_user_confirmation_request_neg_reply) {
  // Arrange
  auto packet = hci::UserConfirmationRequestNegativeReplyBuilder::Create(device_->GetAddress());

  // Act
  channel_->SendCommand(device_, std::move(packet));
  auto last_command = std::move(hci_layer_->GetLastCommand()->command);
  auto command_packet = GetPacketView(std::move(last_command));
  hci::CommandPacketView packet_view = hci::CommandPacketView::Create(command_packet);

  // Assert
  EXPECT_TRUE(packet_view.IsValid());
  EXPECT_EQ(OpCode::USER_CONFIRMATION_REQUEST_NEGATIVE_REPLY, packet_view.GetOpCode());
}

TEST_F(SecurityManagerChannelTest, recv_remote_oob_data_request) {
  hci_layer_->IncomingEvent(hci::RemoteOobDataRequestBuilder::Create(device_->GetAddress()));
  EXPECT_TRUE(callback_->receivedRemoteOobDataRequest);
}

TEST_F(SecurityManagerChannelTest, send_remote_oob_data_request_reply) {
  // Arrange
  std::array<uint8_t, 16> c = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5};
  std::array<uint8_t, 16> r = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5};
  auto packet = hci::RemoteOobDataRequestReplyBuilder::Create(device_->GetAddress(), c, r);

  // Act
  channel_->SendCommand(device_, std::move(packet));
  auto last_command = std::move(hci_layer_->GetLastCommand()->command);
  auto command_packet = GetPacketView(std::move(last_command));
  hci::CommandPacketView packet_view = hci::CommandPacketView::Create(command_packet);

  // Assert
  EXPECT_TRUE(packet_view.IsValid());
  EXPECT_EQ(OpCode::REMOTE_OOB_DATA_REQUEST_REPLY, packet_view.GetOpCode());
}

TEST_F(SecurityManagerChannelTest, send_remote_oob_data_request_neg_reply) {
  // Arrange
  auto packet = hci::RemoteOobDataRequestNegativeReplyBuilder::Create(device_->GetAddress());

  // Act
  channel_->SendCommand(device_, std::move(packet));
  auto last_command = std::move(hci_layer_->GetLastCommand()->command);
  auto command_packet = GetPacketView(std::move(last_command));
  hci::CommandPacketView packet_view = hci::CommandPacketView::Create(command_packet);

  // Assert
  EXPECT_TRUE(packet_view.IsValid());
  EXPECT_EQ(OpCode::REMOTE_OOB_DATA_REQUEST_NEGATIVE_REPLY, packet_view.GetOpCode());
}

TEST_F(SecurityManagerChannelTest, send_read_local_oob_data) {
  // Arrange
  auto packet = hci::ReadLocalOobDataBuilder::Create();

  // Act
  channel_->SendCommand(device_, std::move(packet));
  auto last_command = std::move(hci_layer_->GetLastCommand()->command);
  auto command_packet = GetPacketView(std::move(last_command));
  hci::CommandPacketView packet_view = hci::CommandPacketView::Create(command_packet);

  // Assert
  EXPECT_TRUE(packet_view.IsValid());
  EXPECT_EQ(OpCode::READ_LOCAL_OOB_DATA, packet_view.GetOpCode());
}

TEST_F(SecurityManagerChannelTest, send_read_local_oob_extended_data) {
  // Arrange
  auto packet = hci::ReadLocalOobExtendedDataBuilder::Create();

  // Act
  channel_->SendCommand(device_, std::move(packet));
  auto last_command = std::move(hci_layer_->GetLastCommand()->command);
  auto command_packet = GetPacketView(std::move(last_command));
  hci::CommandPacketView packet_view = hci::CommandPacketView::Create(command_packet);

  // Assert
  EXPECT_TRUE(packet_view.IsValid());
  EXPECT_EQ(OpCode::READ_LOCAL_OOB_EXTENDED_DATA, packet_view.GetOpCode());
}

TEST_F(SecurityManagerChannelTest, recv_link_key_request) {
  hci_layer_->IncomingEvent(hci::LinkKeyRequestBuilder::Create(device_->GetAddress()));
  EXPECT_TRUE(callback_->receivedLinkKeyRequest);
}

TEST_F(SecurityManagerChannelTest, recv_link_key_notification) {
  std::array<uint8_t, 16> link_key = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5};
  hci_layer_->IncomingEvent(
      hci::LinkKeyNotificationBuilder::Create(device_->GetAddress(), link_key, hci::KeyType::DEBUG_COMBINATION));
  EXPECT_TRUE(callback_->receivedLinkKeyNotification);
}

TEST_F(SecurityManagerChannelTest, recv_master_link_key_complete) {
  uint16_t connection_handle = 0x0;
  hci_layer_->IncomingEvent(
      hci::MasterLinkKeyCompleteBuilder::Create(hci::ErrorCode::SUCCESS, connection_handle, hci::KeyFlag::TEMPORARY));
  EXPECT_TRUE(callback_->receivedMasterLinkKeyComplete);
}

TEST_F(SecurityManagerChannelTest, recv_change_connection_link_key_complete) {
  uint16_t connection_handle = 0x0;
  hci_layer_->IncomingEvent(
      hci::ChangeConnectionLinkKeyCompleteBuilder::Create(hci::ErrorCode::SUCCESS, connection_handle));
  EXPECT_TRUE(callback_->receivedChangeConnectionLinkKeyComplete);
}

TEST_F(SecurityManagerChannelTest, recv_return_link_keys) {
  std::vector<hci::ZeroKeyAndAddress> keys;
  hci_layer_->IncomingEvent(hci::ReturnLinkKeysBuilder::Create(keys));
  EXPECT_TRUE(callback_->receivedReturnLinkKeys);
}

TEST_F(SecurityManagerChannelTest, send_link_key_request_reply) {
  // Arrange
  std::array<uint8_t, 16> link_key = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5};
  auto packet = hci::LinkKeyRequestReplyBuilder::Create(device_->GetAddress(), link_key);

  // Act
  channel_->SendCommand(device_, std::move(packet));
  auto last_command = std::move(hci_layer_->GetLastCommand()->command);
  auto command_packet = GetPacketView(std::move(last_command));
  hci::CommandPacketView packet_view = hci::CommandPacketView::Create(command_packet);

  // Assert
  EXPECT_TRUE(packet_view.IsValid());
  EXPECT_EQ(OpCode::LINK_KEY_REQUEST_REPLY, packet_view.GetOpCode());
}

TEST_F(SecurityManagerChannelTest, send_link_key_request_neg_reply) {
  // Arrange
  auto packet = hci::LinkKeyRequestNegativeReplyBuilder::Create(device_->GetAddress());

  // Act
  channel_->SendCommand(device_, std::move(packet));
  auto last_command = std::move(hci_layer_->GetLastCommand()->command);
  auto command_packet = GetPacketView(std::move(last_command));
  hci::CommandPacketView packet_view = hci::CommandPacketView::Create(command_packet);

  // Assert
  EXPECT_TRUE(packet_view.IsValid());
  EXPECT_EQ(OpCode::LINK_KEY_REQUEST_NEGATIVE_REPLY, packet_view.GetOpCode());
}

TEST_F(SecurityManagerChannelTest, send_read_stored_link_key) {
  // Arrange
  auto packet = hci::ReadStoredLinkKeyBuilder::Create(device_->GetAddress(), hci::ReadStoredLinkKeyReadAllFlag::ALL);

  // Act
  channel_->SendCommand(device_, std::move(packet));
  auto last_command = std::move(hci_layer_->GetLastCommand()->command);
  auto command_packet = GetPacketView(std::move(last_command));
  hci::CommandPacketView packet_view = hci::CommandPacketView::Create(command_packet);

  // Assert
  EXPECT_TRUE(packet_view.IsValid());
  EXPECT_EQ(OpCode::READ_STORED_LINK_KEY, packet_view.GetOpCode());
}

TEST_F(SecurityManagerChannelTest, send_write_stored_link_key) {
  // Arrange
  std::vector<hci::KeyAndAddress> keys_to_write;
  auto packet = hci::WriteStoredLinkKeyBuilder::Create(keys_to_write);

  // Act
  channel_->SendCommand(device_, std::move(packet));
  auto last_command = std::move(hci_layer_->GetLastCommand()->command);
  auto command_packet = GetPacketView(std::move(last_command));
  hci::CommandPacketView packet_view = hci::CommandPacketView::Create(command_packet);

  // Assert
  EXPECT_TRUE(packet_view.IsValid());
  EXPECT_EQ(OpCode::WRITE_STORED_LINK_KEY, packet_view.GetOpCode());
}

TEST_F(SecurityManagerChannelTest, send_delete_stored_link_key) {
  // Arrange
  auto packet =
      hci::DeleteStoredLinkKeyBuilder::Create(device_->GetAddress(), hci::DeleteStoredLinkKeyDeleteAllFlag::ALL);

  // Act
  channel_->SendCommand(device_, std::move(packet));
  auto last_command = std::move(hci_layer_->GetLastCommand()->command);
  auto command_packet = GetPacketView(std::move(last_command));
  hci::CommandPacketView packet_view = hci::CommandPacketView::Create(command_packet);

  // Assert
  EXPECT_TRUE(packet_view.IsValid());
  EXPECT_EQ(OpCode::DELETE_STORED_LINK_KEY, packet_view.GetOpCode());
}

TEST_F(SecurityManagerChannelTest, recv_encryption_change) {
  uint16_t connection_handle = 0x0;
  hci_layer_->IncomingEvent(
      hci::EncryptionChangeBuilder::Create(hci::ErrorCode::SUCCESS, connection_handle, hci::EncryptionEnabled::ON));
  EXPECT_TRUE(callback_->receivedEncryptionChange);
}

TEST_F(SecurityManagerChannelTest, send_refresh_encryption_key) {
  // Arrange
  uint16_t connection_handle = 0x0;
  auto packet = hci::RefreshEncryptionKeyBuilder::Create(connection_handle);

  // Act
  channel_->SendCommand(device_, std::move(packet));
  auto last_command = std::move(hci_layer_->GetLastCommand()->command);
  auto command_packet = GetPacketView(std::move(last_command));
  hci::CommandPacketView packet_view = hci::CommandPacketView::Create(command_packet);

  // Assert
  EXPECT_TRUE(packet_view.IsValid());
  EXPECT_EQ(OpCode::REFRESH_ENCRYPTION_KEY, packet_view.GetOpCode());
}

TEST_F(SecurityManagerChannelTest, send_read_encryption_key_size) {
  // Arrange
  uint16_t connection_handle = 0x0;
  auto packet = hci::ReadEncryptionKeySizeBuilder::Create(connection_handle);

  // Act
  channel_->SendCommand(device_, std::move(packet));
  auto last_command = std::move(hci_layer_->GetLastCommand()->command);
  auto command_packet = GetPacketView(std::move(last_command));
  hci::CommandPacketView packet_view = hci::CommandPacketView::Create(command_packet);

  // Assert
  EXPECT_TRUE(packet_view.IsValid());
  EXPECT_EQ(OpCode::READ_ENCRYPTION_KEY_SIZE, packet_view.GetOpCode());
}

TEST_F(SecurityManagerChannelTest, recv_simple_pairing_complete) {
  hci_layer_->IncomingEvent(hci::SimplePairingCompleteBuilder::Create(hci::ErrorCode::SUCCESS, device_->GetAddress()));
  EXPECT_TRUE(callback_->receivedSimplePairingComplete);
}

TEST_F(SecurityManagerChannelTest, send_read_simple_pairing_mode) {
  // Arrange
  auto packet = hci::ReadSimplePairingModeBuilder::Create();

  // Act
  channel_->SendCommand(device_, std::move(packet));
  auto last_command = std::move(hci_layer_->GetLastCommand()->command);
  auto command_packet = GetPacketView(std::move(last_command));
  hci::CommandPacketView packet_view = hci::CommandPacketView::Create(command_packet);

  // Assert
  EXPECT_TRUE(packet_view.IsValid());
  EXPECT_EQ(OpCode::READ_SIMPLE_PAIRING_MODE, packet_view.GetOpCode());
}

TEST_F(SecurityManagerChannelTest, send_write_simple_pairing_mode) {
  // Arrange
  auto packet = hci::WriteSimplePairingModeBuilder::Create(hci::Enable::ENABLED);

  // Act
  channel_->SendCommand(device_, std::move(packet));
  auto last_command = std::move(hci_layer_->GetLastCommand()->command);
  auto command_packet = GetPacketView(std::move(last_command));
  hci::CommandPacketView packet_view = hci::CommandPacketView::Create(command_packet);

  // Assert
  EXPECT_TRUE(packet_view.IsValid());
  EXPECT_EQ(OpCode::WRITE_SIMPLE_PAIRING_MODE, packet_view.GetOpCode());
}

TEST_F(SecurityManagerChannelTest, recv_keypress_notification) {
  hci_layer_->IncomingEvent(
      hci::KeypressNotificationBuilder::Create(device_->GetAddress(), hci::KeypressNotificationType::ENTRY_COMPLETED));
  EXPECT_TRUE(callback_->receivedKeypressNotification);
}

TEST_F(SecurityManagerChannelTest, send_keypress_notification) {
  // Arrange
  auto packet =
      hci::SendKeypressNotificationBuilder::Create(device_->GetAddress(), hci::KeypressNotificationType::ENTRY_STARTED);

  // Act
  channel_->SendCommand(device_, std::move(packet));
  auto last_command = std::move(hci_layer_->GetLastCommand()->command);
  auto command_packet = GetPacketView(std::move(last_command));
  hci::CommandPacketView packet_view = hci::CommandPacketView::Create(command_packet);

  // Assert
  EXPECT_TRUE(packet_view.IsValid());
  EXPECT_EQ(OpCode::SEND_KEYPRESS_NOTIFICATION, packet_view.GetOpCode());
}

}  // namespace
}  // namespace channel
}  // namespace security
}  // namespace bluetooth
