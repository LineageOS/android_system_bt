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

#include "hci/controller.h"

#include <algorithm>
#include <chrono>
#include <future>
#include <map>

#include <gtest/gtest.h>

#include "common/address.h"
#include "common/bind.h"
#include "common/callback.h"
#include "hci/hci_layer.h"
#include "os/thread.h"
#include "packet/raw_builder.h"

namespace bluetooth {
namespace hci {
namespace {

using common::Address;
using common::BidiQueue;
using common::BidiQueueEnd;
using packet::kLittleEndian;
using packet::PacketView;
using packet::RawBuilder;

constexpr uint16_t kHandle1 = 0x123;
constexpr uint16_t kCredits1 = 0x78;
constexpr uint16_t kHandle2 = 0x456;
constexpr uint16_t kCredits2 = 0x9a;

PacketView<kLittleEndian> GetPacketView(std::unique_ptr<packet::BasePacketBuilder> packet) {
  auto bytes = std::make_shared<std::vector<uint8_t>>();
  BitInserter i(*bytes);
  bytes->reserve(packet->size());
  packet->Serialize(i);
  return packet::PacketView<packet::kLittleEndian>(bytes);
}

class TestHciLayer : public HciLayer {
 public:
  void EnqueueCommand(std::unique_ptr<CommandPacketBuilder> command,
                      common::OnceCallback<void(CommandCompleteView)> on_complete, os::Handler* handler) override {
    GetHandler()->Post(common::BindOnce(&TestHciLayer::HandleCommand, common::Unretained(this), std::move(command),
                                        std::move(on_complete), common::Unretained(handler)));
  }

  void EnqueueCommand(std::unique_ptr<CommandPacketBuilder> command,
                      common::OnceCallback<void(CommandStatusView)> on_status, os::Handler* handler) override {
    EXPECT_TRUE(false) << "Controller properties should not generate Command Status";
  }

  void HandleCommand(std::unique_ptr<CommandPacketBuilder> command_builder,
                     common::OnceCallback<void(CommandCompleteView)> on_complete, os::Handler* handler) {
    auto packet_view = GetPacketView(std::move(command_builder));
    CommandPacketView command = CommandPacketView::Create(packet_view);
    ASSERT(command.IsValid());

    uint8_t num_packets = 1;
    std::unique_ptr<packet::BasePacketBuilder> event_builder;
    switch (command.GetOpCode()) {
      case (OpCode::READ_BUFFER_SIZE): {
        event_builder = ReadBufferSizeCompleteBuilder::Create(
            num_packets, ErrorCode::SUCCESS, acl_data_packet_length, synchronous_data_packet_length,
            total_num_acl_data_packets, total_num_synchronous_data_packets);
      } break;
      case (OpCode::READ_BD_ADDR): {
        event_builder = ReadBdAddrCompleteBuilder::Create(num_packets, ErrorCode::SUCCESS, common::Address::kAny);
      } break;
      default:
        LOG_INFO("Dropping unhandled packet");
        return;
    }
    auto packet = GetPacketView(std::move(event_builder));
    EventPacketView event = EventPacketView::Create(packet);
    ASSERT(event.IsValid());
    CommandCompleteView command_complete = CommandCompleteView::Create(event);
    ASSERT(command_complete.IsValid());
    handler->Post(common::BindOnce(std::move(on_complete), std::move(command_complete)));
  }

  void RegisterEventHandler(EventCode event_code, common::Callback<void(EventPacketView)> event_handler,
                            os::Handler* handler) override {
    EXPECT_EQ(event_code, EventCode::NUMBER_OF_COMPLETED_PACKETS) << "Only NUMBER_OF_COMPLETED_PACKETS is needed";
    number_of_completed_packets_callback_ = event_handler;
    client_handler_ = handler;
  }

  void UnregisterEventHandler(EventCode event_code) override {
    EXPECT_EQ(event_code, EventCode::NUMBER_OF_COMPLETED_PACKETS) << "Only NUMBER_OF_COMPLETED_PACKETS is needed";
    number_of_completed_packets_callback_ = {};
    client_handler_ = nullptr;
  }

  void IncomingCredit() {
    std::vector<uint32_t> handles_and_completed_packets;
    handles_and_completed_packets.push_back(kCredits1 << 16 | kHandle1);
    handles_and_completed_packets.push_back(kCredits2 << 16 | kHandle2);
    auto event_builder = NumberOfCompletedPacketsBuilder::Create(handles_and_completed_packets);
    auto packet = GetPacketView(std::move(event_builder));
    EventPacketView event = EventPacketView::Create(packet);
    ASSERT(event.IsValid());
    client_handler_->Post(common::BindOnce(number_of_completed_packets_callback_, event));
  }

  void ListDependencies(ModuleList* list) override {}
  void Start() override {}
  void Stop() override {}

  constexpr static uint16_t acl_data_packet_length = 1024;
  constexpr static uint8_t synchronous_data_packet_length = 60;
  constexpr static uint16_t total_num_acl_data_packets = 10;
  constexpr static uint16_t total_num_synchronous_data_packets = 12;

 private:
  common::Callback<void(EventPacketView)> number_of_completed_packets_callback_;
  os::Handler* client_handler_;
};

class ControllerTest : public ::testing::Test {
 protected:
  void SetUp() override {
    test_hci_layer_ = new TestHciLayer;
    fake_registry_.InjectTestModule(&HciLayer::Factory, test_hci_layer_);
    client_handler_ = fake_registry_.GetTestModuleHandler(&HciLayer::Factory);
    fake_registry_.Start<Controller>(&thread_);
    controller_ = static_cast<Controller*>(fake_registry_.GetModuleUnderTest(&Controller::Factory));
  }

  void TearDown() override {
    fake_registry_.StopAll();
  }

  TestModuleRegistry fake_registry_;
  TestHciLayer* test_hci_layer_ = nullptr;
  os::Thread& thread_ = fake_registry_.GetTestThread();
  Controller* controller_ = nullptr;
  os::Handler* client_handler_ = nullptr;
};

TEST_F(ControllerTest, startup_teardown) {}

TEST_F(ControllerTest, read_controller_info) {
  std::promise<void> callback_completed;
  ASSERT_EQ(controller_->GetControllerAclPacketLength(), test_hci_layer_->acl_data_packet_length);
  ASSERT_EQ(controller_->GetControllerNumAclPacketBuffers(), test_hci_layer_->total_num_acl_data_packets);
  ASSERT_EQ(controller_->GetControllerScoPacketLength(), test_hci_layer_->synchronous_data_packet_length);
  ASSERT_EQ(controller_->GetControllerNumScoPacketBuffers(), test_hci_layer_->total_num_synchronous_data_packets);
  ASSERT_EQ(controller_->GetControllerMacAddress(), common::Address::kAny);
}

std::promise<void> credits1_set;
std::promise<void> credits2_set;

void CheckReceivedCredits(uint16_t handle, uint16_t credits) {
  switch (handle) {
    case (kHandle1):
      ASSERT_EQ(kCredits1, credits);
      credits1_set.set_value();
      break;
    case (kHandle2):
      ASSERT_EQ(kCredits2, credits);
      credits2_set.set_value();
      break;
    default:
      ASSERT_LOG(false, "Unknown handle 0x%0hx with 0x%0hx credits", handle, credits);
  }
}

TEST_F(ControllerTest, aclCreditCallbacksTest) {
  controller_->RegisterCompletedAclPacketsCallback(common::Bind(&CheckReceivedCredits), client_handler_);

  test_hci_layer_->IncomingCredit();

  credits1_set.get_future().wait();
  credits2_set.get_future().wait();
}
}  // namespace
}  // namespace hci
}  // namespace bluetooth
