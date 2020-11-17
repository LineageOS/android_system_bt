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

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <algorithm>
#include <chrono>
#include <future>
#include <map>

#include "common/bind.h"
#include "hci/acl_manager.h"
#include "hci/address.h"
#include "hci/controller.h"
#include "hci/hci_layer.h"
#include "hci/le_scanning_manager.h"
#include "os/thread.h"
#include "packet/raw_builder.h"

namespace bluetooth {
namespace hci {
namespace {

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

class TestController : public Controller {
 public:
  bool IsSupported(OpCode op_code) const override {
    return supported_opcodes_.count(op_code) == 1;
  }

  void AddSupported(OpCode op_code) {
    supported_opcodes_.insert(op_code);
  }

 protected:
  void Start() override {}
  void Stop() override {}
  void ListDependencies(ModuleList* list) override {}

 private:
  std::set<OpCode> supported_opcodes_{};
};

class TestHciLayer : public HciLayer {
 public:
  void EnqueueCommand(std::unique_ptr<CommandPacketBuilder> command,
                      common::ContextualOnceCallback<void(CommandStatusView)> on_status) override {
    command_queue_.push(std::move(command));
    command_status_callbacks.push_front(std::move(on_status));
    if (command_promise_ != nullptr) {
      command_promise_->set_value();
      command_promise_.reset();
    }
  }

  void EnqueueCommand(std::unique_ptr<CommandPacketBuilder> command,
                      common::ContextualOnceCallback<void(CommandCompleteView)> on_complete) override {
    command_queue_.push(std::move(command));
    command_complete_callbacks.push_front(std::move(on_complete));
    if (command_promise_ != nullptr) {
      command_promise_->set_value();
      command_promise_.reset();
    }
  }

  std::future<void> GetCommandFuture() {
    ASSERT_LOG(command_promise_ == nullptr, "Promises promises ... Only one at a time");
    command_promise_ = std::make_unique<std::promise<void>>();
    return command_promise_->get_future();
  }

  CommandPacketView GetLastCommand() {
    if (command_queue_.empty()) {
      return CommandPacketView::Create(GetPacketView(nullptr));
    } else {
      auto last = std::move(command_queue_.front());
      command_queue_.pop();
      return CommandPacketView::Create(GetPacketView(std::move(last)));
    }
  }

  ConnectionManagementCommandView GetCommandPacket(OpCode op_code) {
    CommandPacketView command_packet_view = GetLastCommand();
    auto command = ConnectionManagementCommandView::Create(AclCommandView::Create(command_packet_view));
    EXPECT_TRUE(command.IsValid());
    EXPECT_EQ(command.GetOpCode(), op_code);
    return command;
  }

  void RegisterEventHandler(EventCode event_code,
                            common::ContextualCallback<void(EventPacketView)> event_handler) override {
    registered_events_[event_code] = event_handler;
  }

  void RegisterLeEventHandler(SubeventCode subevent_code,
                              common::ContextualCallback<void(LeMetaEventView)> event_handler) override {
    registered_le_events_[subevent_code] = event_handler;
  }

  void IncomingEvent(std::unique_ptr<EventPacketBuilder> event_builder) {
    auto packet = GetPacketView(std::move(event_builder));
    EventPacketView event = EventPacketView::Create(packet);
    ASSERT_TRUE(event.IsValid());
    EventCode event_code = event.GetEventCode();
    ASSERT_NE(registered_events_.find(event_code), registered_events_.end()) << EventCodeText(event_code);
    registered_events_[event_code].Invoke(event);
  }

  void IncomingLeMetaEvent(std::unique_ptr<LeMetaEventBuilder> event_builder) {
    auto packet = GetPacketView(std::move(event_builder));
    EventPacketView event = EventPacketView::Create(packet);
    LeMetaEventView meta_event_view = LeMetaEventView::Create(event);
    ASSERT_TRUE(meta_event_view.IsValid());
    SubeventCode subevent_code = meta_event_view.GetSubeventCode();
    ASSERT_NE(registered_le_events_.find(subevent_code), registered_le_events_.end())
        << SubeventCodeText(subevent_code);
    registered_le_events_[subevent_code].Invoke(meta_event_view);
  }

  void CommandCompleteCallback(EventPacketView event) {
    CommandCompleteView complete_view = CommandCompleteView::Create(event);
    ASSERT_TRUE(complete_view.IsValid());
    std::move(command_complete_callbacks.front()).Invoke(complete_view);
    command_complete_callbacks.pop_front();
  }

  void CommandStatusCallback(EventPacketView event) {
    CommandStatusView status_view = CommandStatusView::Create(event);
    ASSERT_TRUE(status_view.IsValid());
    std::move(command_status_callbacks.front()).Invoke(status_view);
    command_status_callbacks.pop_front();
  }

  void ListDependencies(ModuleList* list) override {}
  void Start() override {
    RegisterEventHandler(EventCode::COMMAND_COMPLETE,
                         GetHandler()->BindOn(this, &TestHciLayer::CommandCompleteCallback));
    RegisterEventHandler(EventCode::COMMAND_STATUS, GetHandler()->BindOn(this, &TestHciLayer::CommandStatusCallback));
  }
  void Stop() override {}

 private:
  std::map<EventCode, common::ContextualCallback<void(EventPacketView)>> registered_events_;
  std::map<SubeventCode, common::ContextualCallback<void(LeMetaEventView)>> registered_le_events_;
  std::list<common::ContextualOnceCallback<void(CommandCompleteView)>> command_complete_callbacks;
  std::list<common::ContextualOnceCallback<void(CommandStatusView)>> command_status_callbacks;

  std::queue<std::unique_ptr<CommandPacketBuilder>> command_queue_;
  mutable std::mutex mutex_;
  std::unique_ptr<std::promise<void>> command_promise_{};
};

class TestLeAddressManager : public LeAddressManager {
 public:
  TestLeAddressManager(
      common::Callback<void(std::unique_ptr<CommandPacketBuilder>)> enqueue_command,
      os::Handler* handler,
      Address public_address,
      uint8_t connect_list_size,
      uint8_t resolving_list_size)
      : LeAddressManager(enqueue_command, handler, public_address, connect_list_size, resolving_list_size) {}

  AddressPolicy Register(LeAddressManagerCallback* callback) override {
    return AddressPolicy::USE_STATIC_ADDRESS;
  }

  void Unregister(LeAddressManagerCallback* callback) override {}
};

class TestAclManager : public AclManager {
 public:
  LeAddressManager* GetLeAddressManager() override {
    return test_le_address_manager_;
  }

 protected:
  void Start() override {
    thread_ = new os::Thread("thread", os::Thread::Priority::NORMAL);
    handler_ = new os::Handler(thread_);
    Address address({0x01, 0x02, 0x03, 0x04, 0x05, 0x06});
    test_le_address_manager_ = new TestLeAddressManager(
        common::Bind(&TestAclManager::enqueue_command, common::Unretained(this)), handler_, address, 0x3F, 0x3F);
  }

  void Stop() override {
    delete test_le_address_manager_;
    handler_->Clear();
    delete handler_;
    delete thread_;
  }

  void ListDependencies(ModuleList* list) override {}

  void SetRandomAddress(Address address) {}

  void enqueue_command(std::unique_ptr<CommandPacketBuilder> command_packet){};

  os::Thread* thread_;
  os::Handler* handler_;
  TestLeAddressManager* test_le_address_manager_;
};

class LeScanningManagerTest : public ::testing::Test {
 protected:
  void SetUp() override {
    test_hci_layer_ = new TestHciLayer;  // Ownership is transferred to registry
    test_controller_ = new TestController;
    test_controller_->AddSupported(param_opcode_);
    test_acl_manager_ = new TestAclManager;
    fake_registry_.InjectTestModule(&HciLayer::Factory, test_hci_layer_);
    fake_registry_.InjectTestModule(&Controller::Factory, test_controller_);
    fake_registry_.InjectTestModule(&AclManager::Factory, test_acl_manager_);
    client_handler_ = fake_registry_.GetTestModuleHandler(&HciLayer::Factory);
    ASSERT_NE(client_handler_, nullptr);
    mock_callbacks_.handler_ = client_handler_;
    std::future<void> config_future = test_hci_layer_->GetCommandFuture();
    fake_registry_.Start<LeScanningManager>(&thread_);
    le_scanning_manager =
        static_cast<LeScanningManager*>(fake_registry_.GetModuleUnderTest(&LeScanningManager::Factory));
    auto result = config_future.wait_for(std::chrono::duration(std::chrono::milliseconds(1000)));
    ASSERT_EQ(std::future_status::ready, result);
    HandleConfiguration();
  }

  void TearDown() override {
    fake_registry_.SynchronizeModuleHandler(&LeScanningManager::Factory, std::chrono::milliseconds(20));
    fake_registry_.StopAll();
  }

  virtual void HandleConfiguration() {
    auto packet = test_hci_layer_->GetCommandPacket(OpCode::LE_SET_SCAN_PARAMETERS);
    test_hci_layer_->IncomingEvent(LeSetScanParametersCompleteBuilder::Create(1, ErrorCode::SUCCESS));
  }

  TestModuleRegistry fake_registry_;
  TestHciLayer* test_hci_layer_ = nullptr;
  TestController* test_controller_ = nullptr;
  TestAclManager* test_acl_manager_ = nullptr;
  os::Thread& thread_ = fake_registry_.GetTestThread();
  LeScanningManager* le_scanning_manager = nullptr;
  os::Handler* client_handler_ = nullptr;

  class MockLeScanningManagerCallbacks : public LeScanningManagerCallbacks {
   public:
    MOCK_METHOD(void, on_advertisements, (std::vector<std::shared_ptr<LeReport>>), (override));
    MOCK_METHOD(void, on_timeout, (), (override));
    os::Handler* Handler() {
      return handler_;
    }
    os::Handler* handler_{nullptr};
  } mock_callbacks_;

  OpCode param_opcode_{OpCode::LE_SET_ADVERTISING_PARAMETERS};
};

class LeAndroidHciScanningManagerTest : public LeScanningManagerTest {
 protected:
  void SetUp() override {
    param_opcode_ = OpCode::LE_EXTENDED_SCAN_PARAMS;
    LeScanningManagerTest::SetUp();
  }

  void HandleConfiguration() override {
    auto packet = test_hci_layer_->GetCommandPacket(OpCode::LE_EXTENDED_SCAN_PARAMS);
    test_hci_layer_->IncomingEvent(LeExtendedScanParamsCompleteBuilder::Create(1, ErrorCode::SUCCESS));
  }
};

class LeExtendedScanningManagerTest : public LeScanningManagerTest {
 protected:
  void SetUp() override {
    param_opcode_ = OpCode::LE_SET_EXTENDED_SCAN_PARAMETERS;
    LeScanningManagerTest::SetUp();
  }

  void HandleConfiguration() override {
    auto packet = test_hci_layer_->GetCommandPacket(OpCode::LE_SET_EXTENDED_SCAN_PARAMETERS);
    test_hci_layer_->IncomingEvent(LeSetExtendedScanParametersCompleteBuilder::Create(1, ErrorCode::SUCCESS));
  }
};

TEST_F(LeScanningManagerTest, startup_teardown) {}

TEST_F(LeScanningManagerTest, start_scan_test) {
  auto next_command_future = test_hci_layer_->GetCommandFuture();
  le_scanning_manager->StartScan(&mock_callbacks_);

  auto result = next_command_future.wait_for(std::chrono::duration(std::chrono::milliseconds(100)));
  ASSERT_EQ(std::future_status::ready, result);
  test_hci_layer_->IncomingEvent(LeSetScanEnableCompleteBuilder::Create(uint8_t{1}, ErrorCode::SUCCESS));

  LeAdvertisingReport report{};
  report.event_type_ = AdvertisingEventType::ADV_IND;
  report.address_type_ = AddressType::PUBLIC_DEVICE_ADDRESS;
  Address::FromString("12:34:56:78:9a:bc", report.address_);
  std::vector<GapData> gap_data{};
  GapData data_item{};
  data_item.data_type_ = GapDataType::FLAGS;
  data_item.data_ = {0x34};
  gap_data.push_back(data_item);
  data_item.data_type_ = GapDataType::COMPLETE_LOCAL_NAME;
  data_item.data_ = {'r', 'a', 'n', 'd', 'o', 'm', ' ', 'd', 'e', 'v', 'i', 'c', 'e'};
  gap_data.push_back(data_item);
  report.advertising_data_ = gap_data;

  EXPECT_CALL(mock_callbacks_, on_advertisements);

  test_hci_layer_->IncomingLeMetaEvent(LeAdvertisingReportBuilder::Create({report}));
}

TEST_F(LeAndroidHciScanningManagerTest, start_scan_test) {
  auto next_command_future = test_hci_layer_->GetCommandFuture();
  le_scanning_manager->StartScan(&mock_callbacks_);

  auto result = next_command_future.wait_for(std::chrono::duration(std::chrono::milliseconds(100)));
  ASSERT_EQ(std::future_status::ready, result);
  test_hci_layer_->IncomingEvent(LeSetScanEnableCompleteBuilder::Create(uint8_t{1}, ErrorCode::SUCCESS));

  LeAdvertisingReport report{};
  report.event_type_ = AdvertisingEventType::ADV_IND;
  report.address_type_ = AddressType::PUBLIC_DEVICE_ADDRESS;
  Address::FromString("12:34:56:78:9a:bc", report.address_);
  std::vector<GapData> gap_data{};
  GapData data_item{};
  data_item.data_type_ = GapDataType::FLAGS;
  data_item.data_ = {0x34};
  gap_data.push_back(data_item);
  data_item.data_type_ = GapDataType::COMPLETE_LOCAL_NAME;
  data_item.data_ = {'r', 'a', 'n', 'd', 'o', 'm', ' ', 'd', 'e', 'v', 'i', 'c', 'e'};
  gap_data.push_back(data_item);
  report.advertising_data_ = gap_data;

  EXPECT_CALL(mock_callbacks_, on_advertisements);

  test_hci_layer_->IncomingLeMetaEvent(LeAdvertisingReportBuilder::Create({report}));
}

TEST_F(LeExtendedScanningManagerTest, start_scan_test) {
  auto next_command_future = test_hci_layer_->GetCommandFuture();
  le_scanning_manager->StartScan(&mock_callbacks_);

  auto result = next_command_future.wait_for(std::chrono::duration(std::chrono::milliseconds(100)));
  ASSERT_EQ(std::future_status::ready, result);
  auto packet = test_hci_layer_->GetCommandPacket(OpCode::LE_SET_EXTENDED_SCAN_ENABLE);

  test_hci_layer_->IncomingEvent(LeSetScanEnableCompleteBuilder::Create(uint8_t{1}, ErrorCode::SUCCESS));

  LeExtendedAdvertisingReport report{};
  report.connectable_ = 1;
  report.scannable_ = 1;
  report.address_type_ = DirectAdvertisingAddressType::PUBLIC_DEVICE_ADDRESS;
  Address::FromString("12:34:56:78:9a:bc", report.address_);
  std::vector<GapData> gap_data{};
  GapData data_item{};
  data_item.data_type_ = GapDataType::FLAGS;
  data_item.data_ = {0x34};
  gap_data.push_back(data_item);
  data_item.data_type_ = GapDataType::COMPLETE_LOCAL_NAME;
  data_item.data_ = {'r', 'a', 'n', 'd', 'o', 'm', ' ', 'd', 'e', 'v', 'i', 'c', 'e'};
  gap_data.push_back(data_item);
  report.advertising_data_ = gap_data;

  EXPECT_CALL(mock_callbacks_, on_advertisements);

  test_hci_layer_->IncomingLeMetaEvent(LeExtendedAdvertisingReportBuilder::Create({report}));
}

}  // namespace
}  // namespace hci
}  // namespace bluetooth
