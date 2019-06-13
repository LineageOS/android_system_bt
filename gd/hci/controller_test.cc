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
    last_command_ = std::move(command);
    last_command_handler_ = handler;
    last_command_on_complete_ = std::move(on_complete);
    last_command_on_status_ = common::OnceCallback<void(CommandStatusView)>();
    GetHandler()->Post(common::BindOnce(&TestHciLayer::HandleCommand, common::Unretained(this)));
  }

  void EnqueueCommand(std::unique_ptr<CommandPacketBuilder> command,
                      common::OnceCallback<void(CommandStatusView)> on_status, os::Handler* handler) override {
    last_command_ = std::move(command);
    last_command_handler_ = handler;
    last_command_on_complete_ = common::OnceCallback<void(CommandCompleteView)>();
    last_command_on_status_ = std::move(on_status);
    GetHandler()->Post(common::BindOnce(&TestHciLayer::HandleCommand, common::Unretained(this)));
  }

  void HandleCommand() {
    auto packet_view = GetPacketView(std::move(last_command_));
    CommandPacketView command = CommandPacketView::Create(packet_view);
    ASSERT(command.IsValid());

    uint8_t num_packets = 1;
    switch (command.GetOpCode()) {
      case (OpCode::READ_BUFFER_SIZE): {
        IncomingEvent(ReadBufferSizeCompleteBuilder::Create(
            num_packets, ErrorCode::SUCCESS, acl_data_packet_length_, synchronous_data_packet_length_,
            total_num_acl_data_packets_, total_num_synchronous_data_packets_));
      } break;
      default:
        LOG_INFO("Dropping unhandled packet");
    }
  }

  void RegisterEventHandler(EventCode event_code, common::Callback<void(EventPacketView)> event_handler,
                            os::Handler* handler) override {
    registered_events_[event_code] = std::move(event_handler);
    registered_event_handlers_[event_code] = handler;
  }

  void UnregisterEventHandler(EventCode event_code) override {
    registered_events_.erase(event_code);
    registered_event_handlers_.erase(event_code);
  }

  void IncomingEvent(std::unique_ptr<EventPacketBuilder> event_builder) {
    auto packet = GetPacketView(std::move(event_builder));
    EventPacketView event = EventPacketView::Create(packet);
    ASSERT(event.IsValid());
    EventCode event_code = event.GetEventCode();
    ASSERT_LOG(registered_events_.find(event_code) != registered_events_.end(), "Unhandled event 0x%0hhx %s",
               event_code, EventCodeText(event_code).c_str());
    registered_event_handlers_[event_code]->Post(common::BindOnce(registered_events_[event_code], event));
  }

  void HandleIncomingCommandComplete(EventPacketView event) {
    auto complete_event = CommandCompleteView::Create(event);
    ASSERT(complete_event.IsValid());
    last_command_handler_->Post(common::BindOnce(std::move(last_command_on_complete_), complete_event));
  }

  void IncomingCommandComplete(EventPacketView event) {
    last_command_handler_->Post(
        common::BindOnce(&TestHciLayer::HandleIncomingCommandComplete, common::Unretained(this), event));
  }

  void HandleIncomingCommandStatus(EventPacketView event) {
    auto status_event = CommandStatusView::Create(event);
    ASSERT(status_event.IsValid());
    last_command_handler_->Post(common::BindOnce(std::move(last_command_on_status_), status_event));
  }

  void IncomingCommandStatus(EventPacketView event) {
    last_command_handler_->Post(
        common::BindOnce(&TestHciLayer::HandleIncomingCommandStatus, common::Unretained(this), event));
  }
  void FakeStart(os::Handler* handler) {
    RegisterEventHandler(EventCode::COMMAND_COMPLETE,
                         common::Bind(&TestHciLayer::IncomingCommandComplete, common::Unretained(this)), handler);
    RegisterEventHandler(EventCode::COMMAND_STATUS,
                         common::Bind(&TestHciLayer::IncomingCommandStatus, common::Unretained(this)), handler);
  }

  void ListDependencies(ModuleList* list) override {}
  void Start() override {}
  void Stop() override {}

  uint16_t acl_data_packet_length_ = 1024;
  uint8_t synchronous_data_packet_length_ = 60;
  uint16_t total_num_acl_data_packets_ = 10;
  uint16_t total_num_synchronous_data_packets_ = 12;

 private:
  std::map<EventCode, common::Callback<void(EventPacketView)>> registered_events_;
  std::map<EventCode, os::Handler*> registered_event_handlers_;
  std::unique_ptr<CommandPacketBuilder> last_command_;
  os::Handler* last_command_handler_;
  common::OnceCallback<void(CommandStatusView)> last_command_on_status_;
  common::OnceCallback<void(CommandCompleteView)> last_command_on_complete_;
};

class ControllerTest : public ::testing::Test {
 protected:
  void SetUp() override {
    test_hci_layer_ = new TestHciLayer;
    fake_registry_.InjectTestModule(&HciLayer::Factory, test_hci_layer_);
    client_handler_ = fake_registry_.GetTestModuleHandler(&HciLayer::Factory);
    test_hci_layer_->FakeStart(client_handler_);
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
  ASSERT_EQ(controller_->ReadControllerAclPacketLength(), test_hci_layer_->acl_data_packet_length_);
  ASSERT_EQ(controller_->ReadControllerNumAclPacketBuffers(), test_hci_layer_->total_num_acl_data_packets_);
  ASSERT_EQ(controller_->ReadControllerScoPacketLength(), test_hci_layer_->synchronous_data_packet_length_);
  ASSERT_EQ(controller_->ReadControllerNumScoPacketBuffers(), test_hci_layer_->total_num_synchronous_data_packets_);
}

const uint16_t kHandle1 = 0x123;
const uint16_t kCredits1 = 0x78;
const uint16_t kHandle2 = 0x456;
const uint16_t kCredits2 = 0x9a;
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

  std::vector<uint32_t> handles_and_completed_packets;
  handles_and_completed_packets.push_back(kCredits1 << 16 | kHandle1);
  handles_and_completed_packets.push_back(kCredits2 << 16 | kHandle2);
  test_hci_layer_->IncomingEvent(NumberOfCompletedPacketsBuilder::Create(handles_and_completed_packets));

  credits1_set.get_future().wait();
  credits2_set.get_future().wait();
}
}  // namespace
}  // namespace hci
}  // namespace bluetooth
