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

#include "hci/hci_layer.h"

#include <gtest/gtest.h>
#include <list>
#include <memory>

#include "hal/hci_hal.h"
#include "hci/hci_packets.h"
#include "module.h"
#include "os/log.h"
#include "os/thread.h"
#include "packet/bit_inserter.h"
#include "packet/raw_builder.h"

using bluetooth::os::Thread;
using bluetooth::packet::BitInserter;
using bluetooth::packet::RawBuilder;
using std::vector;

namespace {
vector<uint8_t> information_request = {
    0xfe, 0x2e, 0x0a, 0x00, 0x06, 0x00, 0x01, 0x00, 0x0a, 0x02, 0x02, 0x00, 0x02, 0x00,
};
// 0x00, 0x01, 0x02, 0x03, ...
vector<uint8_t> counting_bytes;
// 0xFF, 0xFE, 0xFD, 0xFC, ...
vector<uint8_t> counting_down_bytes;
const size_t count_size = 0x8;

}  // namespace

namespace bluetooth {
namespace hci {

class TestHciHal : public hal::HciHal {
 public:
  TestHciHal() : hal::HciHal() {}

  ~TestHciHal() {
    ASSERT_LOG(callbacks == nullptr, "unregisterIncomingPacketCallback() must be called");
  }

  void registerIncomingPacketCallback(hal::HciHalCallbacks* callback) override {
    callbacks = callback;
  }

  void unregisterIncomingPacketCallback() override {
    callbacks = nullptr;
  }

  void sendHciCommand(hal::HciPacket command) override {
    outgoing_commands_.push_back(std::move(command));
  }

  void sendAclData(hal::HciPacket data) override {
    outgoing_acl_.push_front(std::move(data));
  }

  void sendScoData(hal::HciPacket data) override {
    outgoing_sco_.push_front(std::move(data));
  }

  hal::HciHalCallbacks* callbacks = nullptr;

  PacketView<kLittleEndian> GetPacketView(hal::HciPacket data) {
    auto shared = std::make_shared<std::vector<uint8_t>>(data);
    return PacketView<kLittleEndian>(shared);
  }

  size_t GetNumSentCommands() {
    return outgoing_commands_.size();
  }

  CommandPacketView GetSentCommand() {
    while (outgoing_commands_.size() == 0)
      ;
    auto packetview = GetPacketView(std::move(outgoing_commands_.front()));
    outgoing_commands_.pop_front();
    return CommandPacketView::Create(packetview);
  }

  PacketView<kLittleEndian> GetSentAcl() {
    while (outgoing_acl_.size() == 0)
      ;
    auto packetview = GetPacketView(std::move(outgoing_acl_.front()));
    outgoing_acl_.pop_front();
    return packetview;
  }

  void Start() {}

  void Stop() {}

  void ListDependencies(ModuleList*) {}

  static const ModuleFactory Factory;

 private:
  std::list<hal::HciPacket> outgoing_commands_;
  std::list<hal::HciPacket> outgoing_acl_;
  std::list<hal::HciPacket> outgoing_sco_;
};

const ModuleFactory TestHciHal::Factory = ModuleFactory([]() { return new TestHciHal(); });

class DependsOnHci : public Module {
 public:
  DependsOnHci() : Module() {}

  void SendHciCommandExpectingStatus(std::unique_ptr<CommandPacketBuilder> command) {
    hci_->EnqueueCommand(std::move(command),
                         common::Bind(&DependsOnHci::handle_event<CommandStatusView>, common::Unretained(this)),
                         GetHandler());
  }

  void SendHciCommandExpectingComplete(std::unique_ptr<CommandPacketBuilder> command) {
    hci_->EnqueueCommand(std::move(command),
                         common::Bind(&DependsOnHci::handle_event<CommandCompleteView>, common::Unretained(this)),
                         GetHandler());
  }

  void SendAclData(std::unique_ptr<AclPacketBuilder> acl) {
    outgoing_acl_.push(std::move(acl));
    auto queue_end = hci_->GetAclQueueEnd();
    queue_end->RegisterEnqueue(GetHandler(), common::Bind(&DependsOnHci::handle_enqueue, common::Unretained(this)));
  }

  EventPacketView GetReceivedEvent() {
    while (incoming_events_.size() == 0)
      ;
    EventPacketView packetview = incoming_events_.front();
    incoming_events_.pop_front();
    return packetview;
  }

  AclPacketView GetReceivedAcl() {
    auto queue_end = hci_->GetAclQueueEnd();
    std::unique_ptr<AclPacketView> incoming_acl_ptr;
    while (incoming_acl_ptr == nullptr) {
      incoming_acl_ptr = queue_end->TryDequeue();
    }
    AclPacketView packetview = *incoming_acl_ptr;
    return packetview;
  }

  void Start() {
    hci_ = GetDependency<HciLayer>();
    hci_->RegisterEventHandler(EventCode::CONNECTION_COMPLETE,
                               common::Bind(&DependsOnHci::handle_event<EventPacketView>, common::Unretained(this)),
                               GetHandler());
  }

  void Stop() {}

  void ListDependencies(ModuleList* list) {
    list->add<HciLayer>();
  }

  static const ModuleFactory Factory;

 private:
  HciLayer* hci_ = nullptr;
  std::list<EventPacketView> incoming_events_;

  template <typename T>
  void handle_event(T event) {
    incoming_events_.push_back(event);
  }

  std::queue<std::unique_ptr<AclPacketBuilder>> outgoing_acl_;

  std::unique_ptr<AclPacketBuilder> handle_enqueue() {
    hci_->GetAclQueueEnd()->UnregisterEnqueue();
    auto acl = std::move(outgoing_acl_.front());
    outgoing_acl_.pop();
    return acl;
  }
};

const ModuleFactory DependsOnHci::Factory = ModuleFactory([]() { return new DependsOnHci(); });

class HciTest : public ::testing::Test {
 public:
  void SetUp() override {
    counting_bytes.reserve(count_size);
    counting_down_bytes.reserve(count_size);
    for (size_t i = 0; i < count_size; i++) {
      counting_bytes.push_back(i);
      counting_down_bytes.push_back(~i);
    }
    hal = new TestHciHal();
    fake_registry_.InjectTestModule(&hal::HciHal::Factory, hal);
    fake_registry_.Start<DependsOnHci>(&fake_registry_.GetTestThread());
    hci = static_cast<HciLayer*>(fake_registry_.GetModuleUnderTest(&HciLayer::Factory));
    upper = static_cast<DependsOnHci*>(fake_registry_.GetModuleUnderTest(&DependsOnHci::Factory));
    ASSERT(fake_registry_.IsStarted<HciLayer>());
    // Wait for the reset
    while (hal->GetNumSentCommands() == 0)
      ;
    // Verify that reset was received
    ASSERT_EQ(1, hal->GetNumSentCommands());

    auto sent_command = hal->GetSentCommand();
    auto reset_view = ResetView::Create(CommandPacketView::Create(sent_command));
    ASSERT_TRUE(reset_view.IsValid());

    // Verify that only one was sent
    ASSERT_EQ(0, hal->GetNumSentCommands());

    // Send the response event
    uint8_t num_packets = 1;
    ErrorCode error_code = ErrorCode::SUCCESS;
    hal->callbacks->hciEventReceived(GetPacketBytes(ResetCompleteBuilder::Create(num_packets, error_code)));
  }

  void TearDown() override {
    fake_registry_.StopAll();
  }

  std::vector<uint8_t> GetPacketBytes(std::unique_ptr<packet::BasePacketBuilder> packet) {
    std::vector<uint8_t> bytes;
    BitInserter i(bytes);
    bytes.reserve(packet->size());
    packet->Serialize(i);
    return bytes;
  }

  DependsOnHci* upper = nullptr;
  TestHciHal* hal = nullptr;
  HciLayer* hci = nullptr;
  TestModuleRegistry fake_registry_;
};

TEST_F(HciTest, initAndClose) {}

TEST_F(HciTest, noOpCredits) {
  ASSERT_EQ(0, hal->GetNumSentCommands());

  // Send 0 credits
  uint8_t num_packets = 0;
  hal->callbacks->hciEventReceived(GetPacketBytes(NoCommandCompleteBuilder::Create(num_packets)));

  upper->SendHciCommandExpectingComplete(ReadLocalVersionInformationBuilder::Create());

  // Verify that nothing was sent
  ASSERT_EQ(0, hal->GetNumSentCommands());

  num_packets = 1;
  hal->callbacks->hciEventReceived(GetPacketBytes(NoCommandCompleteBuilder::Create(num_packets)));
  // Verify that one was sent
  while (hal->GetNumSentCommands() == 0)
    ;
  ASSERT_EQ(1, hal->GetNumSentCommands());

  // Send the response event
  ErrorCode error_code = ErrorCode::SUCCESS;
  HciVersion hci_version = HciVersion::V_5_0;
  uint16_t hci_subversion = 0x1234;
  LmpVersion lmp_version = LmpVersion::V_4_2;
  uint16_t manufacturer_name = 0xBAD;
  uint16_t lmp_subversion = 0x5678;
  hal->callbacks->hciEventReceived(GetPacketBytes(ReadLocalVersionInformationCompleteBuilder::Create(
      num_packets, error_code, hci_version, hci_subversion, lmp_version, manufacturer_name, lmp_subversion)));
  auto event = upper->GetReceivedEvent();
  ASSERT(ReadLocalVersionInformationCompleteView::Create(CommandCompleteView::Create(EventPacketView::Create(event)))
             .IsValid());
}

TEST_F(HciTest, creditsTest) {
  ASSERT_EQ(0, hal->GetNumSentCommands());

  // Send all three commands
  upper->SendHciCommandExpectingComplete(ReadLocalVersionInformationBuilder::Create());
  upper->SendHciCommandExpectingComplete(ReadLocalSupportedCommandsBuilder::Create());
  upper->SendHciCommandExpectingComplete(ReadLocalSupportedFeaturesBuilder::Create());

  while (hal->GetNumSentCommands() == 0)
    ;

  // Verify that the first one is sent
  ASSERT_EQ(1, hal->GetNumSentCommands());

  auto sent_command = hal->GetSentCommand();
  auto version_view = ReadLocalVersionInformationView::Create(CommandPacketView::Create(sent_command));
  ASSERT_TRUE(version_view.IsValid());

  // Verify that only one was sent
  ASSERT_EQ(0, hal->GetNumSentCommands());

  // Send the response event
  uint8_t num_packets = 1;
  ErrorCode error_code = ErrorCode::SUCCESS;
  HciVersion hci_version = HciVersion::V_5_0;
  uint16_t hci_subversion = 0x1234;
  LmpVersion lmp_version = LmpVersion::V_4_2;
  uint16_t manufacturer_name = 0xBAD;
  uint16_t lmp_subversion = 0x5678;
  hal->callbacks->hciEventReceived(GetPacketBytes(ReadLocalVersionInformationCompleteBuilder::Create(
      num_packets, error_code, hci_version, hci_subversion, lmp_version, manufacturer_name, lmp_subversion)));
  auto event = upper->GetReceivedEvent();
  ASSERT(ReadLocalVersionInformationCompleteView::Create(CommandCompleteView::Create(EventPacketView::Create(event)))
             .IsValid());

  // Verify that the second one is sent
  while (hal->GetNumSentCommands() == 0)
    ;
  ASSERT_EQ(1, hal->GetNumSentCommands());

  sent_command = hal->GetSentCommand();
  auto supported_commands_view = ReadLocalSupportedCommandsView::Create(CommandPacketView::Create(sent_command));
  ASSERT_TRUE(supported_commands_view.IsValid());

  // Verify that only one was sent
  ASSERT_EQ(0, hal->GetNumSentCommands());

  // Send the response event
  std::vector<uint8_t> supported_commands;
  for (uint8_t i = 0; i < 64; i++) {
    supported_commands.push_back(i);
  }
  hal->callbacks->hciEventReceived(
      GetPacketBytes(ReadLocalSupportedCommandsCompleteBuilder::Create(num_packets, error_code, supported_commands)));
  event = upper->GetReceivedEvent();
  ASSERT(ReadLocalSupportedCommandsCompleteView::Create(CommandCompleteView::Create(EventPacketView::Create(event)))
             .IsValid());

  // Verify that the third one is sent
  while (hal->GetNumSentCommands() == 0)
    ;
  ASSERT_EQ(1, hal->GetNumSentCommands());

  sent_command = hal->GetSentCommand();
  auto supported_features_view = ReadLocalSupportedFeaturesView::Create(CommandPacketView::Create(sent_command));
  ASSERT_TRUE(supported_features_view.IsValid());

  // Verify that only one was sent
  ASSERT_EQ(0, hal->GetNumSentCommands());

  // Send the response event
  uint64_t lmp_features = 0x012345678abcdef;
  hal->callbacks->hciEventReceived(
      GetPacketBytes(ReadLocalSupportedFeaturesCompleteBuilder::Create(num_packets, error_code, lmp_features)));
  event = upper->GetReceivedEvent();
  ASSERT(ReadLocalSupportedFeaturesCompleteView::Create(CommandCompleteView::Create(EventPacketView::Create(event)))
             .IsValid());
}

TEST_F(HciTest, createConnectionTest) {
  // Send CreateConnection to the controller
  common::Address bd_addr;
  ASSERT_TRUE(common::Address::FromString("A1:A2:A3:A4:A5:A6", bd_addr));
  uint16_t packet_type = 0x1234;
  PageScanRepetitionMode page_scan_repetition_mode = PageScanRepetitionMode::R0;
  uint16_t clock_offset = 0x3456;
  ClockOffsetValid clock_offset_valid = ClockOffsetValid::VALID;
  CreateConnectionRoleSwitch allow_role_switch = CreateConnectionRoleSwitch::ALLOW_ROLE_SWITCH;
  upper->SendHciCommandExpectingStatus(CreateConnectionBuilder::Create(
      bd_addr, packet_type, page_scan_repetition_mode, clock_offset, clock_offset_valid, allow_role_switch));

  // Check the command
  auto sent_command = hal->GetSentCommand();
  ASSERT_LT(0, sent_command.size());
  CreateConnectionView view =
      CreateConnectionView::Create(ConnectionManagementCommandView::Create(CommandPacketView::Create(sent_command)));
  ASSERT_TRUE(view.IsValid());
  ASSERT_EQ(bd_addr, view.GetBdAddr());
  ASSERT_EQ(packet_type, view.GetPacketType());
  ASSERT_EQ(page_scan_repetition_mode, view.GetPageScanRepetitionMode());
  ASSERT_EQ(clock_offset, view.GetClockOffset());
  ASSERT_EQ(clock_offset_valid, view.GetClockOffsetValid());
  ASSERT_EQ(allow_role_switch, view.GetAllowRoleSwitch());

  // Send a Command Status to the host
  ErrorCode status = ErrorCode::SUCCESS;
  uint16_t handle = 0x123;
  LinkType link_type = LinkType::ACL;
  Enable encryption_enabled = Enable::DISABLED;
  hal->callbacks->hciEventReceived(GetPacketBytes(CreateConnectionStatusBuilder::Create(ErrorCode::SUCCESS, 1)));

  // Verify the event
  auto event = upper->GetReceivedEvent();
  ASSERT_TRUE(event.IsValid());
  ASSERT_EQ(EventCode::COMMAND_STATUS, event.GetEventCode());

  // Send a ConnectionComplete to the host
  hal->callbacks->hciEventReceived(
      GetPacketBytes(ConnectionCompleteBuilder::Create(status, handle, bd_addr, link_type, encryption_enabled)));

  // Verify the event
  event = upper->GetReceivedEvent();
  ASSERT_TRUE(event.IsValid());
  ASSERT_EQ(EventCode::CONNECTION_COMPLETE, event.GetEventCode());
  ConnectionCompleteView connection_complete_view = ConnectionCompleteView::Create(event);
  ASSERT_TRUE(connection_complete_view.IsValid());
  ASSERT_EQ(status, connection_complete_view.GetStatus());
  ASSERT_EQ(handle, connection_complete_view.GetConnectionHandle());
  ASSERT_EQ(link_type, connection_complete_view.GetLinkType());
  ASSERT_EQ(encryption_enabled, connection_complete_view.GetEncryptionEnabled());

  // Send an ACL packet from the remote
  PacketBoundaryFlag packet_boundary_flag = PacketBoundaryFlag::COMPLETE_PDU;
  BroadcastFlag broadcast_flag = BroadcastFlag::POINT_TO_POINT;
  auto acl_payload = std::make_unique<RawBuilder>();
  acl_payload->AddAddress(bd_addr);
  acl_payload->AddOctets2(handle);
  hal->callbacks->aclDataReceived(
      GetPacketBytes(AclPacketBuilder::Create(handle, packet_boundary_flag, broadcast_flag, std::move(acl_payload))));

  // Verify the ACL packet
  auto acl_view = upper->GetReceivedAcl();
  ASSERT_TRUE(acl_view.IsValid());
  ASSERT_EQ(sizeof(bd_addr) + sizeof(handle), acl_view.GetPayload().size());
  auto itr = acl_view.GetPayload().begin();
  ASSERT_EQ(bd_addr, itr.extract<Address>());
  ASSERT_EQ(handle, itr.extract<uint16_t>());

  // Send an ACL packet from DependsOnHci
  PacketBoundaryFlag packet_boundary_flag2 = PacketBoundaryFlag::COMPLETE_PDU;
  BroadcastFlag broadcast_flag2 = BroadcastFlag::POINT_TO_POINT;
  auto acl_payload2 = std::make_unique<RawBuilder>();
  acl_payload2->AddOctets2(handle);
  acl_payload2->AddAddress(bd_addr);
  upper->SendAclData(AclPacketBuilder::Create(handle, packet_boundary_flag2, broadcast_flag2, std::move(acl_payload2)));

  // Verify the ACL packet
  auto sent_acl = hal->GetSentAcl();
  ASSERT_LT(0, sent_acl.size());
  AclPacketView sent_acl_view = AclPacketView::Create(sent_acl);
  ASSERT_TRUE(sent_acl_view.IsValid());
  ASSERT_EQ(sizeof(bd_addr) + sizeof(handle), sent_acl_view.GetPayload().size());
  auto sent_itr = sent_acl_view.GetPayload().begin();
  ASSERT_EQ(handle, sent_itr.extract<uint16_t>());
  ASSERT_EQ(bd_addr, sent_itr.extract<Address>());
}

TEST_F(HciTest, receiveMultipleAclPacket) {
  common::Address bd_addr;
  ASSERT_TRUE(common::Address::FromString("A1:A2:A3:A4:A5:A6", bd_addr));
  uint16_t handle = 0x0001;
  PacketBoundaryFlag packet_boundary_flag = PacketBoundaryFlag::COMPLETE_PDU;
  BroadcastFlag broadcast_flag = BroadcastFlag::POINT_TO_POINT;
  for (int i = 0; i < 100; i++) {
    auto acl_payload = std::make_unique<RawBuilder>();
    acl_payload->AddAddress(bd_addr);
    acl_payload->AddOctets2(handle);
    hal->callbacks->aclDataReceived(
        GetPacketBytes(AclPacketBuilder::Create(handle, packet_boundary_flag, broadcast_flag, std::move(acl_payload))));
  }
}
}  // namespace hci
}  // namespace bluetooth
