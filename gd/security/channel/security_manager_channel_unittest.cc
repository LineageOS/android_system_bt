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

class TestPayloadBuilder : public PacketBuilder<kLittleEndian> {
 public:
  ~TestPayloadBuilder() override = default;
  size_t size() const override {
    return 1;
  }
  void Serialize(BitInserter& inserter) const override {}
  static std::unique_ptr<TestPayloadBuilder> Create() {
    return std::unique_ptr<TestPayloadBuilder>(new TestPayloadBuilder());
  }

 private:
  TestPayloadBuilder() : PacketBuilder<kLittleEndian>(){};
};

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

TEST_F(SecurityManagerChannelTest, send_pin_code_request_reply) {}

TEST_F(SecurityManagerChannelTest, send_pin_code_request_neg_reply) {}

TEST_F(SecurityManagerChannelTest, recv_user_passkey_notification) {}

TEST_F(SecurityManagerChannelTest, send_user_confirmation_request_reply) {}

TEST_F(SecurityManagerChannelTest, send_user_confirmation_request_neg_reply) {}

TEST_F(SecurityManagerChannelTest, recv_remote_oob_data_request) {}

TEST_F(SecurityManagerChannelTest, send_remote_oob_data_request_reply) {}

TEST_F(SecurityManagerChannelTest, send_remote_oob_data_request_neg_reply) {}

TEST_F(SecurityManagerChannelTest, send_read_local_oob_data) {}

TEST_F(SecurityManagerChannelTest, send_read_local_oob_extended_data) {}

TEST_F(SecurityManagerChannelTest, recv_link_key_request) {}

TEST_F(SecurityManagerChannelTest, recv_link_key_notification) {}

TEST_F(SecurityManagerChannelTest, recv_master_link_complete) {}

TEST_F(SecurityManagerChannelTest, recv_change_connection_link_key_complete) {}

TEST_F(SecurityManagerChannelTest, recv_return_link_keys) {}

TEST_F(SecurityManagerChannelTest, send_link_key_reply) {}

TEST_F(SecurityManagerChannelTest, send_link_key_neg_reply) {}

TEST_F(SecurityManagerChannelTest, send_read_stored_link_key) {}

TEST_F(SecurityManagerChannelTest, send_write_stored_link_key) {}

TEST_F(SecurityManagerChannelTest, send_delete_stored_link_key) {}

TEST_F(SecurityManagerChannelTest, recv_encryption_change) {}

TEST_F(SecurityManagerChannelTest, send_refresh_encryption_key) {}

TEST_F(SecurityManagerChannelTest, send_read_encryption_key_size) {}

TEST_F(SecurityManagerChannelTest, recv_simple_pairing_complete) {}

TEST_F(SecurityManagerChannelTest, send_read_simple_pairing_mode) {}

TEST_F(SecurityManagerChannelTest, send_write_simple_pairing_mode) {}

TEST_F(SecurityManagerChannelTest, send_keypress_notification) {}

}  // namespace
}  // namespace channel
}  // namespace security
}  // namespace bluetooth
