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

#include "hci/le_advertising_manager.h"

#include <algorithm>
#include <chrono>
#include <future>
#include <map>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "common/bind.h"
#include "hci/acl_manager.h"
#include "hci/address.h"
#include "hci/controller.h"
#include "hci/hci_layer.h"
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

  uint8_t GetLeNumberOfSupportedAdverisingSets() const override {
    return num_advertisers;
  }

  uint16_t GetLeMaximumAdvertisingDataLength() const override {
    return 0x0672;
  }

  uint8_t num_advertisers{0};

 protected:
  void Start() override {}
  void Stop() override {}
  void ListDependencies(ModuleList* list) override {}

 private:
  std::set<OpCode> supported_opcodes_{};
};

class TestHciLayer : public HciLayer {
 public:
  void EnqueueCommand(
      std::unique_ptr<CommandBuilder> command,
      common::ContextualOnceCallback<void(CommandStatusView)> on_status) override {
    auto packet_view = CommandView::Create(GetPacketView(std::move(command)));
    ASSERT_TRUE(packet_view.IsValid());
    std::lock_guard<std::mutex> lock(mutex_);
    command_queue_.push_back(packet_view);
    command_status_callbacks.push_back(std::move(on_status));
    if (command_promise_ != nullptr &&
        (command_op_code_ == OpCode::NONE || command_op_code_ == packet_view.GetOpCode())) {
      if (command_op_code_ == OpCode::LE_MULTI_ADVT && command_sub_ocf_ != SubOcf::SET_ENABLE) {
        return;
      }
      command_promise_->set_value(command_queue_.size());
      command_promise_.reset();
    }
  }

  void EnqueueCommand(
      std::unique_ptr<CommandBuilder> command,
      common::ContextualOnceCallback<void(CommandCompleteView)> on_complete) override {
    auto packet_view = CommandView::Create(GetPacketView(std::move(command)));
    ASSERT_TRUE(packet_view.IsValid());
    std::lock_guard<std::mutex> lock(mutex_);
    command_queue_.push_back(packet_view);
    command_complete_callbacks.push_back(std::move(on_complete));
    if (command_promise_ != nullptr &&
        (command_op_code_ == OpCode::NONE || command_op_code_ == packet_view.GetOpCode())) {
      if (command_op_code_ == OpCode::LE_MULTI_ADVT) {
        auto sub_view = LeMultiAdvtView::Create(LeAdvertisingCommandView::Create(packet_view));
        ASSERT_TRUE(sub_view.IsValid());
        if (sub_view.GetSubCmd() != command_sub_ocf_) {
          return;
        }
      }
      command_promise_->set_value(command_queue_.size());
      command_promise_.reset();
    }
  }

  void SetCommandFuture(OpCode op_code = OpCode::NONE) {
    ASSERT_LOG(command_promise_ == nullptr, "Promises, Promises, ... Only one at a time.");
    command_op_code_ = op_code;
    command_promise_ = std::make_unique<std::promise<size_t>>();
    command_future_ = std::make_unique<std::future<size_t>>(command_promise_->get_future());
  }

  void ResetCommandFuture() {
    if (command_future_ != nullptr) {
      command_future_.reset();
      command_promise_.reset();
    }
  }

  void SetSubCommandFuture(SubOcf sub_ocf) {
    ASSERT_LOG(command_promise_ == nullptr, "Promises promises ... Only one at a time");
    command_op_code_ = OpCode::LE_MULTI_ADVT;
    command_sub_ocf_ = sub_ocf;
    command_promise_ = std::make_unique<std::promise<size_t>>();
    command_future_ = std::make_unique<std::future<size_t>>(command_promise_->get_future());
  }

  ConnectionManagementCommandView GetCommand(OpCode op_code) {
    if (!command_queue_.empty()) {
      std::lock_guard<std::mutex> lock(mutex_);
      if (command_future_ != nullptr) {
        command_future_.reset();
        command_promise_.reset();
      }
    } else if (command_future_ != nullptr) {
      auto result = command_future_->wait_for(std::chrono::milliseconds(1000));
      EXPECT_NE(std::future_status::timeout, result);
    }
    ASSERT_LOG(
        !command_queue_.empty(), "Expecting command %s but command queue was empty", OpCodeText(op_code).c_str());
    std::lock_guard<std::mutex> lock(mutex_);
    CommandView command_packet_view = CommandView::Create(command_queue_.front());
    command_queue_.pop_front();
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

  std::list<CommandView> command_queue_;
  mutable std::mutex mutex_;
  std::unique_ptr<std::promise<size_t>> command_promise_{};
  std::unique_ptr<std::future<size_t>> command_future_{};
  OpCode command_op_code_;
  SubOcf command_sub_ocf_;
};

class TestLeAddressManager : public LeAddressManager {
 public:
  TestLeAddressManager(
      common::Callback<void(std::unique_ptr<CommandBuilder>)> enqueue_command,
      os::Handler* handler,
      Address public_address,
      uint8_t connect_list_size,
      uint8_t resolving_list_size)
      : LeAddressManager(enqueue_command, handler, public_address, connect_list_size, resolving_list_size) {}

  AddressPolicy Register(LeAddressManagerCallback* callback) override {
    return AddressPolicy::USE_STATIC_ADDRESS;
  }

  void Unregister(LeAddressManagerCallback* callback) override {}

  AddressWithType GetAnotherAddress() override {
    hci::Address address;
    Address::FromString("05:04:03:02:01:00", address);
    auto random_address = AddressWithType(address, AddressType::RANDOM_DEVICE_ADDRESS);
    return random_address;
  }
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

  void enqueue_command(std::unique_ptr<CommandBuilder> command_packet){};

  os::Thread* thread_;
  os::Handler* handler_;
  TestLeAddressManager* test_le_address_manager_;
};

class LeAdvertisingManagerTest : public ::testing::Test {
 protected:
  void SetUp() override {
    test_hci_layer_ = new TestHciLayer;  // Ownership is transferred to registry
    test_controller_ = new TestController;
    test_acl_manager_ = new TestAclManager;
    test_controller_->AddSupported(param_opcode_);
    fake_registry_.InjectTestModule(&HciLayer::Factory, test_hci_layer_);
    fake_registry_.InjectTestModule(&Controller::Factory, test_controller_);
    fake_registry_.InjectTestModule(&AclManager::Factory, test_acl_manager_);
    client_handler_ = fake_registry_.GetTestModuleHandler(&HciLayer::Factory);
    ASSERT_NE(client_handler_, nullptr);
    test_controller_->num_advertisers = 1;
    le_advertising_manager_ = fake_registry_.Start<LeAdvertisingManager>(&thread_);
    le_advertising_manager_->RegisterAdvertisingCallback(&mock_advertising_callback_);
  }

  void TearDown() override {
    fake_registry_.SynchronizeModuleHandler(&LeAdvertisingManager::Factory, std::chrono::milliseconds(20));
    fake_registry_.StopAll();
  }

  TestModuleRegistry fake_registry_;
  TestHciLayer* test_hci_layer_ = nullptr;
  TestController* test_controller_ = nullptr;
  TestAclManager* test_acl_manager_ = nullptr;
  os::Thread& thread_ = fake_registry_.GetTestThread();
  LeAdvertisingManager* le_advertising_manager_ = nullptr;
  os::Handler* client_handler_ = nullptr;

  const common::Callback<void(Address, AddressType)> scan_callback =
      common::Bind(&LeAdvertisingManagerTest::on_scan, common::Unretained(this));
  const common::Callback<void(ErrorCode, uint8_t, uint8_t)> set_terminated_callback =
      common::Bind(&LeAdvertisingManagerTest::on_set_terminated, common::Unretained(this));

  std::future<Address> GetOnScanPromise() {
    ASSERT_LOG(address_promise_ == nullptr, "Promises promises ... Only one at a time");
    address_promise_ = std::make_unique<std::promise<Address>>();
    return address_promise_->get_future();
  }
  void on_scan(Address address, AddressType address_type) {
    if (address_promise_ == nullptr) {
      return;
    }
    address_promise_->set_value(address);
    address_promise_.reset();
  }

  std::future<ErrorCode> GetSetTerminatedPromise() {
    ASSERT_LOG(set_terminated_promise_ == nullptr, "Promises promises ... Only one at a time");
    set_terminated_promise_ = std::make_unique<std::promise<ErrorCode>>();
    return set_terminated_promise_->get_future();
  }
  void on_set_terminated(ErrorCode error_code, uint8_t, uint8_t) {
    if (set_terminated_promise_ != nullptr) {
      return;
    }
    set_terminated_promise_->set_value(error_code);
    set_terminated_promise_.reset();
  }

  void sync_client_handler() {
    std::promise<void> promise;
    auto future = promise.get_future();
    client_handler_->Call(common::BindOnce(&std::promise<void>::set_value, common::Unretained(&promise)));
    auto future_status = future.wait_for(std::chrono::seconds(1));
    ASSERT_EQ(future_status, std::future_status::ready);
  }

  std::unique_ptr<std::promise<Address>> address_promise_{};
  std::unique_ptr<std::promise<ErrorCode>> set_terminated_promise_{};

  OpCode param_opcode_{OpCode::LE_SET_ADVERTISING_PARAMETERS};

  class MockAdvertisingCallback : public AdvertisingCallback {
   public:
    MOCK_METHOD4(
        OnAdvertisingSetStarted, void(int reg_id, uint8_t advertiser_id, int8_t tx_power, AdvertisingStatus status));
    MOCK_METHOD3(OnAdvertisingEnabled, void(uint8_t advertiser_id, bool enable, uint8_t status));
    MOCK_METHOD2(OnAdvertisingDataSet, void(uint8_t advertiser_id, uint8_t status));
    MOCK_METHOD2(OnScanResponseDataSet, void(uint8_t advertiser_id, uint8_t status));
    MOCK_METHOD3(OnAdvertisingParametersUpdated, void(uint8_t advertiser_id, int8_t tx_power, uint8_t status));
    MOCK_METHOD2(OnPeriodicAdvertisingParametersUpdated, void(uint8_t advertiser_id, uint8_t status));
    MOCK_METHOD2(OnPeriodicAdvertisingDataSet, void(uint8_t advertiser_id, uint8_t status));
    MOCK_METHOD3(OnPeriodicAdvertisingEnabled, void(uint8_t advertiser_id, bool enable, uint8_t status));
  } mock_advertising_callback_;
};

class LeAdvertisingAPITest : public LeAdvertisingManagerTest {
 protected:
  void SetUp() override {
    LeAdvertisingManagerTest::SetUp();

    // start advertising set
    ExtendedAdvertisingConfig advertising_config{};
    advertising_config.advertising_type = AdvertisingType::ADV_IND;
    advertising_config.own_address_type = OwnAddressType::PUBLIC_DEVICE_ADDRESS;
    std::vector<GapData> gap_data{};
    GapData data_item{};
    data_item.data_type_ = GapDataType::FLAGS;
    data_item.data_ = {0x34};
    gap_data.push_back(data_item);
    data_item.data_type_ = GapDataType::COMPLETE_LOCAL_NAME;
    data_item.data_ = {'r', 'a', 'n', 'd', 'o', 'm', ' ', 'd', 'e', 'v', 'i', 'c', 'e'};
    gap_data.push_back(data_item);
    advertising_config.advertisement = gap_data;
    advertising_config.scan_response = gap_data;

    test_hci_layer_->SetCommandFuture();
    advertiser_id_ = le_advertising_manager_->ExtendedCreateAdvertiser(
        0x00, advertising_config, scan_callback, set_terminated_callback, client_handler_);
    ASSERT_NE(LeAdvertisingManager::kInvalidId, advertiser_id_);
    EXPECT_CALL(
        mock_advertising_callback_,
        OnAdvertisingSetStarted(0x00, advertiser_id_, 0x00, AdvertisingCallback::AdvertisingStatus::SUCCESS));
    std::vector<OpCode> adv_opcodes = {
        OpCode::LE_READ_ADVERTISING_PHYSICAL_CHANNEL_TX_POWER,
        OpCode::LE_SET_ADVERTISING_PARAMETERS,
        OpCode::LE_SET_SCAN_RESPONSE_DATA,
        OpCode::LE_SET_ADVERTISING_DATA,
        OpCode::LE_SET_ADVERTISING_ENABLE,
    };
    std::vector<uint8_t> success_vector{static_cast<uint8_t>(ErrorCode::SUCCESS)};
    for (size_t i = 0; i < adv_opcodes.size(); i++) {
      auto packet_view = test_hci_layer_->GetCommand(adv_opcodes[i]);
      CommandView command_packet_view = CommandView::Create(packet_view);
      if (adv_opcodes[i] == OpCode::LE_READ_ADVERTISING_PHYSICAL_CHANNEL_TX_POWER) {
        test_hci_layer_->IncomingEvent(
            LeReadAdvertisingPhysicalChannelTxPowerCompleteBuilder::Create(uint8_t{1}, ErrorCode::SUCCESS, 0x00));
      } else {
        test_hci_layer_->IncomingEvent(
            CommandCompleteBuilder::Create(uint8_t{1}, adv_opcodes[i], std::make_unique<RawBuilder>(success_vector)));
      }
      test_hci_layer_->SetCommandFuture();
    }
    sync_client_handler();
    test_hci_layer_->ResetCommandFuture();
  }

  AdvertiserId advertiser_id_;
};

class LeAndroidHciAdvertisingManagerTest : public LeAdvertisingManagerTest {
 protected:
  void SetUp() override {
    param_opcode_ = OpCode::LE_MULTI_ADVT;
    LeAdvertisingManagerTest::SetUp();
    test_controller_->num_advertisers = 3;
  }
};

class LeAndroidHciAdvertisingAPITest : public LeAndroidHciAdvertisingManagerTest {
 protected:
  void SetUp() override {
    LeAndroidHciAdvertisingManagerTest::SetUp();

    ExtendedAdvertisingConfig advertising_config{};
    advertising_config.advertising_type = AdvertisingType::ADV_IND;
    advertising_config.own_address_type = OwnAddressType::PUBLIC_DEVICE_ADDRESS;
    std::vector<GapData> gap_data{};
    GapData data_item{};
    data_item.data_type_ = GapDataType::FLAGS;
    data_item.data_ = {0x34};
    gap_data.push_back(data_item);
    data_item.data_type_ = GapDataType::COMPLETE_LOCAL_NAME;
    data_item.data_ = {'r', 'a', 'n', 'd', 'o', 'm', ' ', 'd', 'e', 'v', 'i', 'c', 'e'};
    gap_data.push_back(data_item);
    advertising_config.advertisement = gap_data;
    advertising_config.scan_response = gap_data;

    test_hci_layer_->SetSubCommandFuture(SubOcf::SET_PARAM);
    advertiser_id_ = le_advertising_manager_->ExtendedCreateAdvertiser(
        0x00, advertising_config, scan_callback, set_terminated_callback, client_handler_);
    ASSERT_NE(LeAdvertisingManager::kInvalidId, advertiser_id_);
    std::vector<SubOcf> sub_ocf = {
        SubOcf::SET_PARAM,
        SubOcf::SET_DATA,
        SubOcf::SET_SCAN_RESP,
        SubOcf::SET_RANDOM_ADDR,
        SubOcf::SET_ENABLE,
    };
    EXPECT_CALL(
        mock_advertising_callback_,
        OnAdvertisingSetStarted(0, advertiser_id_, 0, AdvertisingCallback::AdvertisingStatus::SUCCESS));
    for (size_t i = 0; i < sub_ocf.size(); i++) {
      auto packet = test_hci_layer_->GetCommand(OpCode::LE_MULTI_ADVT);
      auto sub_packet = LeMultiAdvtView::Create(LeAdvertisingCommandView::Create(packet));
      ASSERT_TRUE(sub_packet.IsValid());
      test_hci_layer_->IncomingEvent(LeMultiAdvtCompleteBuilder::Create(uint8_t{1}, ErrorCode::SUCCESS, sub_ocf[i]));
      if ((i + 1) < sub_ocf.size()) {
        test_hci_layer_->SetSubCommandFuture(sub_ocf[i + 1]);
      }
    }
    sync_client_handler();
  }

  AdvertiserId advertiser_id_;
};

class LeExtendedAdvertisingManagerTest : public LeAdvertisingManagerTest {
 protected:
  void SetUp() override {
    param_opcode_ = OpCode::LE_SET_EXTENDED_ADVERTISING_PARAMETERS;
    LeAdvertisingManagerTest::SetUp();
    test_controller_->num_advertisers = 5;
  }
};

class LeExtendedAdvertisingAPITest : public LeExtendedAdvertisingManagerTest {
 protected:
  void SetUp() override {
    LeExtendedAdvertisingManagerTest::SetUp();

    // start advertising set
    ExtendedAdvertisingConfig advertising_config{};
    advertising_config.advertising_type = AdvertisingType::ADV_IND;
    advertising_config.own_address_type = OwnAddressType::PUBLIC_DEVICE_ADDRESS;
    std::vector<GapData> gap_data{};
    GapData data_item{};
    data_item.data_type_ = GapDataType::FLAGS;
    data_item.data_ = {0x34};
    gap_data.push_back(data_item);
    data_item.data_type_ = GapDataType::COMPLETE_LOCAL_NAME;
    data_item.data_ = {'r', 'a', 'n', 'd', 'o', 'm', ' ', 'd', 'e', 'v', 'i', 'c', 'e'};
    gap_data.push_back(data_item);
    advertising_config.advertisement = gap_data;
    advertising_config.scan_response = gap_data;
    advertising_config.channel_map = 1;
    advertising_config.sid = 0x01;

    test_hci_layer_->SetCommandFuture();
    advertiser_id_ = le_advertising_manager_->ExtendedCreateAdvertiser(
        0x00, advertising_config, scan_callback, set_terminated_callback, client_handler_);
    ASSERT_NE(LeAdvertisingManager::kInvalidId, advertiser_id_);
    EXPECT_CALL(
        mock_advertising_callback_,
        OnAdvertisingSetStarted(0x00, advertiser_id_, -23, AdvertisingCallback::AdvertisingStatus::SUCCESS));
    std::vector<OpCode> adv_opcodes = {
        OpCode::LE_SET_EXTENDED_ADVERTISING_PARAMETERS,
        OpCode::LE_SET_EXTENDED_ADVERTISING_SCAN_RESPONSE,
        OpCode::LE_SET_EXTENDED_ADVERTISING_DATA,
        OpCode::LE_SET_EXTENDED_ADVERTISING_ENABLE,
    };
    std::vector<uint8_t> success_vector{static_cast<uint8_t>(ErrorCode::SUCCESS)};
    for (size_t i = 0; i < adv_opcodes.size(); i++) {
      auto packet_view = test_hci_layer_->GetCommand(adv_opcodes[i]);
      CommandView command_packet_view = CommandView::Create(packet_view);
      auto command = ConnectionManagementCommandView::Create(AclCommandView::Create(command_packet_view));
      if (adv_opcodes[i] == OpCode::LE_SET_EXTENDED_ADVERTISING_PARAMETERS) {
        test_hci_layer_->IncomingEvent(LeSetExtendedAdvertisingParametersCompleteBuilder::Create(
            uint8_t{1}, ErrorCode::SUCCESS, static_cast<uint8_t>(-23)));
      } else {
        test_hci_layer_->IncomingEvent(
            CommandCompleteBuilder::Create(uint8_t{1}, adv_opcodes[i], std::make_unique<RawBuilder>(success_vector)));
      }
      test_hci_layer_->SetCommandFuture();
    }
    sync_client_handler();
    test_hci_layer_->ResetCommandFuture();
  }

  AdvertiserId advertiser_id_;
};

TEST_F(LeAdvertisingManagerTest, startup_teardown) {}

TEST_F(LeAndroidHciAdvertisingManagerTest, startup_teardown) {}

TEST_F(LeExtendedAdvertisingManagerTest, startup_teardown) {}

TEST_F(LeAdvertisingManagerTest, create_advertiser_test) {
  ExtendedAdvertisingConfig advertising_config{};
  advertising_config.advertising_type = AdvertisingType::ADV_IND;
  advertising_config.own_address_type = OwnAddressType::PUBLIC_DEVICE_ADDRESS;
  std::vector<GapData> gap_data{};
  GapData data_item{};
  data_item.data_type_ = GapDataType::FLAGS;
  data_item.data_ = {0x34};
  gap_data.push_back(data_item);
  data_item.data_type_ = GapDataType::COMPLETE_LOCAL_NAME;
  data_item.data_ = {'r', 'a', 'n', 'd', 'o', 'm', ' ', 'd', 'e', 'v', 'i', 'c', 'e'};
  gap_data.push_back(data_item);
  advertising_config.advertisement = gap_data;
  advertising_config.scan_response = gap_data;

  test_hci_layer_->SetCommandFuture();
  auto id = le_advertising_manager_->ExtendedCreateAdvertiser(
      0x00, advertising_config, scan_callback, set_terminated_callback, client_handler_);
  ASSERT_NE(LeAdvertisingManager::kInvalidId, id);
  std::vector<OpCode> adv_opcodes = {
      OpCode::LE_READ_ADVERTISING_PHYSICAL_CHANNEL_TX_POWER,
      OpCode::LE_SET_ADVERTISING_PARAMETERS,
      OpCode::LE_SET_SCAN_RESPONSE_DATA,
      OpCode::LE_SET_ADVERTISING_DATA,
      OpCode::LE_SET_ADVERTISING_ENABLE,
  };
  EXPECT_CALL(
      mock_advertising_callback_,
      OnAdvertisingSetStarted(0x00, id, 0x00, AdvertisingCallback::AdvertisingStatus::SUCCESS));
  std::vector<uint8_t> success_vector{static_cast<uint8_t>(ErrorCode::SUCCESS)};
  for (size_t i = 0; i < adv_opcodes.size(); i++) {
    auto packet_view = test_hci_layer_->GetCommand(adv_opcodes[i]);
    CommandView command_packet_view = CommandView::Create(packet_view);
    auto command = ConnectionManagementCommandView::Create(AclCommandView::Create(command_packet_view));
    if (adv_opcodes[i] == OpCode::LE_READ_ADVERTISING_PHYSICAL_CHANNEL_TX_POWER) {
      test_hci_layer_->IncomingEvent(
          LeReadAdvertisingPhysicalChannelTxPowerCompleteBuilder::Create(uint8_t{1}, ErrorCode::SUCCESS, 0x00));
    } else {
      test_hci_layer_->IncomingEvent(
          CommandCompleteBuilder::Create(uint8_t{1}, adv_opcodes[i], std::make_unique<RawBuilder>(success_vector)));
    }
    test_hci_layer_->SetCommandFuture();
  }
  sync_client_handler();

  // Disable the advertiser
  le_advertising_manager_->RemoveAdvertiser(id);
  test_hci_layer_->GetCommand(OpCode::LE_SET_ADVERTISING_ENABLE);
  sync_client_handler();
}

TEST_F(LeAndroidHciAdvertisingManagerTest, create_advertiser_test) {
  ExtendedAdvertisingConfig advertising_config{};
  advertising_config.advertising_type = AdvertisingType::ADV_IND;
  advertising_config.own_address_type = OwnAddressType::PUBLIC_DEVICE_ADDRESS;
  std::vector<GapData> gap_data{};
  GapData data_item{};
  data_item.data_type_ = GapDataType::FLAGS;
  data_item.data_ = {0x34};
  gap_data.push_back(data_item);
  data_item.data_type_ = GapDataType::COMPLETE_LOCAL_NAME;
  data_item.data_ = {'r', 'a', 'n', 'd', 'o', 'm', ' ', 'd', 'e', 'v', 'i', 'c', 'e'};
  gap_data.push_back(data_item);
  advertising_config.advertisement = gap_data;
  advertising_config.scan_response = gap_data;

  test_hci_layer_->SetSubCommandFuture(SubOcf::SET_PARAM);
  auto id = le_advertising_manager_->ExtendedCreateAdvertiser(
      0x00, advertising_config, scan_callback, set_terminated_callback, client_handler_);
  ASSERT_NE(LeAdvertisingManager::kInvalidId, id);
  std::vector<SubOcf> sub_ocf = {
      SubOcf::SET_PARAM, SubOcf::SET_DATA, SubOcf::SET_SCAN_RESP, SubOcf::SET_RANDOM_ADDR, SubOcf::SET_ENABLE,
  };
  EXPECT_CALL(
      mock_advertising_callback_, OnAdvertisingSetStarted(0, id, 0, AdvertisingCallback::AdvertisingStatus::SUCCESS));
  for (size_t i = 0; i < sub_ocf.size(); i++) {
    auto packet = test_hci_layer_->GetCommand(OpCode::LE_MULTI_ADVT);
    auto sub_packet = LeMultiAdvtView::Create(LeAdvertisingCommandView::Create(packet));
    ASSERT_TRUE(sub_packet.IsValid());
    test_hci_layer_->IncomingEvent(LeMultiAdvtCompleteBuilder::Create(uint8_t{1}, ErrorCode::SUCCESS, sub_ocf[i]));
    if ((i + 1) < sub_ocf.size()) {
      test_hci_layer_->SetSubCommandFuture(sub_ocf[i + 1]);
    }
  }
  sync_client_handler();

  // Disable the advertiser
  test_hci_layer_->SetSubCommandFuture(SubOcf::SET_ENABLE);
  le_advertising_manager_->RemoveAdvertiser(id);
  test_hci_layer_->GetCommand(OpCode::LE_MULTI_ADVT);
  test_hci_layer_->IncomingEvent(LeMultiAdvtSetEnableCompleteBuilder::Create(uint8_t{1}, ErrorCode::SUCCESS));
  sync_client_handler();
}

TEST_F(LeExtendedAdvertisingManagerTest, create_advertiser_test) {
  ExtendedAdvertisingConfig advertising_config{};
  advertising_config.advertising_type = AdvertisingType::ADV_IND;
  advertising_config.own_address_type = OwnAddressType::PUBLIC_DEVICE_ADDRESS;
  std::vector<GapData> gap_data{};
  GapData data_item{};
  data_item.data_type_ = GapDataType::FLAGS;
  data_item.data_ = {0x34};
  gap_data.push_back(data_item);
  data_item.data_type_ = GapDataType::COMPLETE_LOCAL_NAME;
  data_item.data_ = {'r', 'a', 'n', 'd', 'o', 'm', ' ', 'd', 'e', 'v', 'i', 'c', 'e'};
  gap_data.push_back(data_item);
  advertising_config.advertisement = gap_data;
  advertising_config.scan_response = gap_data;
  advertising_config.channel_map = 1;
  advertising_config.sid = 0x01;

  test_hci_layer_->SetCommandFuture();
  auto id = le_advertising_manager_->ExtendedCreateAdvertiser(
      0x00, advertising_config, scan_callback, set_terminated_callback, client_handler_);
  ASSERT_NE(LeAdvertisingManager::kInvalidId, id);
  EXPECT_CALL(
      mock_advertising_callback_,
      OnAdvertisingSetStarted(0x00, id, -23, AdvertisingCallback::AdvertisingStatus::SUCCESS));
  std::vector<OpCode> adv_opcodes = {
      OpCode::LE_SET_EXTENDED_ADVERTISING_PARAMETERS,
      OpCode::LE_SET_EXTENDED_ADVERTISING_SCAN_RESPONSE,
      OpCode::LE_SET_EXTENDED_ADVERTISING_DATA,
      OpCode::LE_SET_EXTENDED_ADVERTISING_ENABLE,
  };
  std::vector<uint8_t> success_vector{static_cast<uint8_t>(ErrorCode::SUCCESS)};
  for (size_t i = 0; i < adv_opcodes.size(); i++) {
    auto packet_view = test_hci_layer_->GetCommand(adv_opcodes[i]);
    CommandView command_packet_view = CommandView::Create(packet_view);
    auto command = ConnectionManagementCommandView::Create(AclCommandView::Create(command_packet_view));
    if (adv_opcodes[i] == OpCode::LE_SET_EXTENDED_ADVERTISING_PARAMETERS) {
      test_hci_layer_->IncomingEvent(LeSetExtendedAdvertisingParametersCompleteBuilder::Create(
          uint8_t{1}, ErrorCode::SUCCESS, static_cast<uint8_t>(-23)));
    } else {
      test_hci_layer_->IncomingEvent(
          CommandCompleteBuilder::Create(uint8_t{1}, adv_opcodes[i], std::make_unique<RawBuilder>(success_vector)));
    }
    test_hci_layer_->SetCommandFuture();
  }
  sync_client_handler();

  // Remove the advertiser
  le_advertising_manager_->RemoveAdvertiser(id);
  test_hci_layer_->GetCommand(OpCode::LE_SET_EXTENDED_ADVERTISING_ENABLE);
  test_hci_layer_->SetCommandFuture();
  test_hci_layer_->GetCommand(OpCode::LE_SET_PERIODIC_ADVERTISING_ENABLE);
  test_hci_layer_->SetCommandFuture();
  test_hci_layer_->GetCommand(OpCode::LE_REMOVE_ADVERTISING_SET);
  sync_client_handler();
}

TEST_F(LeAdvertisingAPITest, startup_teardown) {}

TEST_F(LeAndroidHciAdvertisingAPITest, startup_teardown) {}

TEST_F(LeExtendedAdvertisingAPITest, startup_teardown) {}

TEST_F(LeAdvertisingAPITest, set_parameter) {
  ExtendedAdvertisingConfig advertising_config{};
  advertising_config.advertising_type = AdvertisingType::ADV_IND;
  advertising_config.own_address_type = OwnAddressType::PUBLIC_DEVICE_ADDRESS;
  std::vector<GapData> gap_data{};
  GapData data_item{};
  data_item.data_type_ = GapDataType::COMPLETE_LOCAL_NAME;
  data_item.data_ = {'r', 'a', 'n', 'd', 'o', 'm', ' ', 'd', 'e', 'v', 'i', 'c', 'e'};
  gap_data.push_back(data_item);
  advertising_config.advertisement = gap_data;
  advertising_config.channel_map = 1;
  test_hci_layer_->SetCommandFuture();
  le_advertising_manager_->SetParameters(advertiser_id_, advertising_config);
  test_hci_layer_->GetCommand(OpCode::LE_SET_ADVERTISING_PARAMETERS);
  EXPECT_CALL(
      mock_advertising_callback_,
      OnAdvertisingParametersUpdated(advertiser_id_, 0x00, AdvertisingCallback::AdvertisingStatus::SUCCESS));
  test_hci_layer_->IncomingEvent(LeSetAdvertisingParametersCompleteBuilder::Create(uint8_t{1}, ErrorCode::SUCCESS));
  sync_client_handler();
}

TEST_F(LeAndroidHciAdvertisingAPITest, set_parameter) {
  ExtendedAdvertisingConfig advertising_config{};
  advertising_config.advertising_type = AdvertisingType::ADV_IND;
  advertising_config.own_address_type = OwnAddressType::PUBLIC_DEVICE_ADDRESS;
  std::vector<GapData> gap_data{};
  GapData data_item{};
  data_item.data_type_ = GapDataType::COMPLETE_LOCAL_NAME;
  data_item.data_ = {'r', 'a', 'n', 'd', 'o', 'm', ' ', 'd', 'e', 'v', 'i', 'c', 'e'};
  gap_data.push_back(data_item);
  advertising_config.advertisement = gap_data;
  advertising_config.channel_map = 1;
  test_hci_layer_->SetSubCommandFuture(SubOcf::SET_PARAM);
  le_advertising_manager_->SetParameters(advertiser_id_, advertising_config);
  test_hci_layer_->GetCommand(OpCode::LE_MULTI_ADVT);
  EXPECT_CALL(
      mock_advertising_callback_,
      OnAdvertisingParametersUpdated(advertiser_id_, 0x00, AdvertisingCallback::AdvertisingStatus::SUCCESS));
  test_hci_layer_->IncomingEvent(LeMultiAdvtCompleteBuilder::Create(uint8_t{1}, ErrorCode::SUCCESS, SubOcf::SET_PARAM));
  sync_client_handler();
}

TEST_F(LeExtendedAdvertisingAPITest, set_parameter) {
  ExtendedAdvertisingConfig advertising_config{};
  advertising_config.advertising_type = AdvertisingType::ADV_IND;
  advertising_config.own_address_type = OwnAddressType::PUBLIC_DEVICE_ADDRESS;
  std::vector<GapData> gap_data{};
  GapData data_item{};
  data_item.data_type_ = GapDataType::COMPLETE_LOCAL_NAME;
  data_item.data_ = {'r', 'a', 'n', 'd', 'o', 'm', ' ', 'd', 'e', 'v', 'i', 'c', 'e'};
  gap_data.push_back(data_item);
  advertising_config.advertisement = gap_data;
  advertising_config.channel_map = 1;
  advertising_config.sid = 0x01;
  advertising_config.tx_power = 0x08;
  test_hci_layer_->SetCommandFuture();
  le_advertising_manager_->SetParameters(advertiser_id_, advertising_config);
  test_hci_layer_->GetCommand(OpCode::LE_SET_EXTENDED_ADVERTISING_PARAMETERS);
  EXPECT_CALL(
      mock_advertising_callback_,
      OnAdvertisingParametersUpdated(advertiser_id_, 0x08, AdvertisingCallback::AdvertisingStatus::SUCCESS));
  test_hci_layer_->IncomingEvent(
      LeSetExtendedAdvertisingParametersCompleteBuilder::Create(uint8_t{1}, ErrorCode::SUCCESS, 0x08));
  sync_client_handler();
}

TEST_F(LeAdvertisingAPITest, set_data_test) {
  // Set advertising data
  std::vector<GapData> advertising_data{};
  GapData data_item{};
  data_item.data_type_ = GapDataType::TX_POWER_LEVEL;
  data_item.data_ = {0x00};
  advertising_data.push_back(data_item);
  test_hci_layer_->SetCommandFuture();
  le_advertising_manager_->SetData(advertiser_id_, false, advertising_data);
  test_hci_layer_->GetCommand(OpCode::LE_SET_ADVERTISING_DATA);
  EXPECT_CALL(
      mock_advertising_callback_,
      OnAdvertisingDataSet(advertiser_id_, AdvertisingCallback::AdvertisingStatus::SUCCESS));
  test_hci_layer_->IncomingEvent(LeSetAdvertisingDataCompleteBuilder::Create(uint8_t{1}, ErrorCode::SUCCESS));
  sync_client_handler();

  // Set scan response data
  std::vector<GapData> response_data{};
  GapData data_item2{};
  data_item2.data_type_ = GapDataType::COMPLETE_LOCAL_NAME;
  data_item2.data_ = {'t', 'e', 's', 't', ' ', 'd', 'e', 'v', 'i', 'c', 'e'};
  response_data.push_back(data_item2);
  test_hci_layer_->SetCommandFuture();
  le_advertising_manager_->SetData(advertiser_id_, true, response_data);
  test_hci_layer_->GetCommand(OpCode::LE_SET_SCAN_RESPONSE_DATA);
  EXPECT_CALL(
      mock_advertising_callback_,
      OnScanResponseDataSet(advertiser_id_, AdvertisingCallback::AdvertisingStatus::SUCCESS));
  test_hci_layer_->IncomingEvent(LeSetScanResponseDataCompleteBuilder::Create(uint8_t{1}, ErrorCode::SUCCESS));
  sync_client_handler();
}

TEST_F(LeExtendedAdvertisingAPITest, set_data_test) {
  // Set advertising data
  std::vector<GapData> advertising_data{};
  GapData data_item{};
  data_item.data_type_ = GapDataType::TX_POWER_LEVEL;
  data_item.data_ = {0x00};
  advertising_data.push_back(data_item);
  test_hci_layer_->SetCommandFuture();
  le_advertising_manager_->SetData(advertiser_id_, false, advertising_data);
  test_hci_layer_->GetCommand(OpCode::LE_SET_EXTENDED_ADVERTISING_DATA);
  EXPECT_CALL(
      mock_advertising_callback_,
      OnAdvertisingDataSet(advertiser_id_, AdvertisingCallback::AdvertisingStatus::SUCCESS));
  test_hci_layer_->IncomingEvent(LeSetExtendedAdvertisingDataCompleteBuilder::Create(uint8_t{1}, ErrorCode::SUCCESS));
  sync_client_handler();

  // Set scan response data
  std::vector<GapData> response_data{};
  GapData data_item2{};
  data_item2.data_type_ = GapDataType::COMPLETE_LOCAL_NAME;
  data_item2.data_ = {'t', 'e', 's', 't', ' ', 'd', 'e', 'v', 'i', 'c', 'e'};
  response_data.push_back(data_item2);
  test_hci_layer_->SetCommandFuture();
  le_advertising_manager_->SetData(advertiser_id_, true, response_data);
  test_hci_layer_->GetCommand(OpCode::LE_SET_EXTENDED_ADVERTISING_SCAN_RESPONSE);
  EXPECT_CALL(
      mock_advertising_callback_,
      OnScanResponseDataSet(advertiser_id_, AdvertisingCallback::AdvertisingStatus::SUCCESS));
  test_hci_layer_->IncomingEvent(
      LeSetExtendedAdvertisingScanResponseCompleteBuilder::Create(uint8_t{1}, ErrorCode::SUCCESS));
  sync_client_handler();
}

TEST_F(LeAndroidHciAdvertisingAPITest, set_data_test) {
  // Set advertising data
  std::vector<GapData> advertising_data{};
  GapData data_item{};
  data_item.data_type_ = GapDataType::TX_POWER_LEVEL;
  data_item.data_ = {0x00};
  advertising_data.push_back(data_item);
  test_hci_layer_->SetSubCommandFuture(SubOcf::SET_DATA);
  le_advertising_manager_->SetData(advertiser_id_, false, advertising_data);
  test_hci_layer_->GetCommand(OpCode::LE_MULTI_ADVT);
  EXPECT_CALL(
      mock_advertising_callback_,
      OnAdvertisingDataSet(advertiser_id_, AdvertisingCallback::AdvertisingStatus::SUCCESS));
  test_hci_layer_->IncomingEvent(LeMultiAdvtCompleteBuilder::Create(uint8_t{1}, ErrorCode::SUCCESS, SubOcf::SET_DATA));
  sync_client_handler();

  // Set scan response data
  std::vector<GapData> response_data{};
  GapData data_item2{};
  data_item2.data_type_ = GapDataType::COMPLETE_LOCAL_NAME;
  data_item2.data_ = {'t', 'e', 's', 't', ' ', 'd', 'e', 'v', 'i', 'c', 'e'};
  response_data.push_back(data_item2);
  test_hci_layer_->SetSubCommandFuture(SubOcf::SET_SCAN_RESP);
  le_advertising_manager_->SetData(advertiser_id_, true, response_data);
  test_hci_layer_->GetCommand(OpCode::LE_MULTI_ADVT);
  EXPECT_CALL(
      mock_advertising_callback_,
      OnScanResponseDataSet(advertiser_id_, AdvertisingCallback::AdvertisingStatus::SUCCESS));
  test_hci_layer_->IncomingEvent(
      LeMultiAdvtCompleteBuilder::Create(uint8_t{1}, ErrorCode::SUCCESS, SubOcf::SET_SCAN_RESP));
  sync_client_handler();
}

TEST_F(LeExtendedAdvertisingAPITest, set_data_fragments_test) {
  // Set advertising data
  std::vector<GapData> advertising_data{};
  for (uint8_t i = 0; i < 3; i++) {
    GapData data_item{};
    data_item.data_.push_back(0xda);
    data_item.data_type_ = GapDataType::SERVICE_DATA_128_BIT_UUIDS;
    uint8_t uuid[16] = {0xf0, 0x34, 0x9b, 0x5f, 0x80, 0x00, 0x00, 0x80, 0x00, 0x10, 0x00, 0x00, 0x00, 0x10, 0x00, i};
    std::copy_n(uuid, 16, std::back_inserter(data_item.data_));
    uint8_t service_data[200];
    std::copy_n(service_data, 200, std::back_inserter(data_item.data_));
    advertising_data.push_back(data_item);
  }
  le_advertising_manager_->SetData(advertiser_id_, false, advertising_data);

  // First fragment
  test_hci_layer_->SetCommandFuture();
  test_hci_layer_->GetCommand(OpCode::LE_SET_EXTENDED_ADVERTISING_DATA);

  // Intermediate fragment
  test_hci_layer_->SetCommandFuture();
  test_hci_layer_->GetCommand(OpCode::LE_SET_EXTENDED_ADVERTISING_DATA);

  // Last fragment
  test_hci_layer_->SetCommandFuture();
  test_hci_layer_->GetCommand(OpCode::LE_SET_EXTENDED_ADVERTISING_DATA);

  EXPECT_CALL(
      mock_advertising_callback_,
      OnAdvertisingDataSet(advertiser_id_, AdvertisingCallback::AdvertisingStatus::SUCCESS));
  test_hci_layer_->IncomingEvent(LeSetExtendedAdvertisingDataCompleteBuilder::Create(uint8_t{1}, ErrorCode::SUCCESS));
  test_hci_layer_->IncomingEvent(LeSetExtendedAdvertisingDataCompleteBuilder::Create(uint8_t{1}, ErrorCode::SUCCESS));
  test_hci_layer_->IncomingEvent(LeSetExtendedAdvertisingDataCompleteBuilder::Create(uint8_t{1}, ErrorCode::SUCCESS));

  sync_client_handler();
}

TEST_F(LeExtendedAdvertisingAPITest, set_scan_response_fragments_test) {
  // Set advertising data
  std::vector<GapData> advertising_data{};
  for (uint8_t i = 0; i < 3; i++) {
    GapData data_item{};
    data_item.data_.push_back(0xfa);
    data_item.data_type_ = GapDataType::SERVICE_DATA_128_BIT_UUIDS;
    uint8_t uuid[16] = {0xf0, 0x34, 0x9b, 0x5f, 0x80, 0x00, 0x00, 0x80, 0x00, 0x10, 0x00, 0x00, 0x00, 0x10, 0x00, i};
    std::copy_n(uuid, 16, std::back_inserter(data_item.data_));
    uint8_t service_data[232];
    std::copy_n(service_data, 232, std::back_inserter(data_item.data_));
    advertising_data.push_back(data_item);
  }
  le_advertising_manager_->SetData(advertiser_id_, true, advertising_data);

  // First fragment
  test_hci_layer_->SetCommandFuture();
  test_hci_layer_->GetCommand(OpCode::LE_SET_EXTENDED_ADVERTISING_SCAN_RESPONSE);

  // Intermediate fragment
  test_hci_layer_->SetCommandFuture();
  test_hci_layer_->GetCommand(OpCode::LE_SET_EXTENDED_ADVERTISING_SCAN_RESPONSE);

  // Last fragment
  test_hci_layer_->SetCommandFuture();
  test_hci_layer_->GetCommand(OpCode::LE_SET_EXTENDED_ADVERTISING_SCAN_RESPONSE);

  EXPECT_CALL(
      mock_advertising_callback_,
      OnScanResponseDataSet(advertiser_id_, AdvertisingCallback::AdvertisingStatus::SUCCESS));
  test_hci_layer_->IncomingEvent(
      LeSetExtendedAdvertisingScanResponseCompleteBuilder::Create(uint8_t{1}, ErrorCode::SUCCESS));
  test_hci_layer_->IncomingEvent(
      LeSetExtendedAdvertisingScanResponseCompleteBuilder::Create(uint8_t{1}, ErrorCode::SUCCESS));
  test_hci_layer_->IncomingEvent(
      LeSetExtendedAdvertisingScanResponseCompleteBuilder::Create(uint8_t{1}, ErrorCode::SUCCESS));

  sync_client_handler();
}

TEST_F(LeExtendedAdvertisingAPITest, set_data_with_invalid_ad_structure) {
  // Set advertising data with AD structure that length greater than 251
  std::vector<GapData> advertising_data{};
  GapData data_item{};
  data_item.data_.push_back(0xfb);
  data_item.data_type_ = GapDataType::SERVICE_DATA_128_BIT_UUIDS;
  uint8_t uuid[16] = {0xf0, 0x34, 0x9b, 0x5f, 0x80, 0x00, 0x00, 0x80, 0x00, 0x10, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00};
  std::copy_n(uuid, 16, std::back_inserter(data_item.data_));
  uint8_t service_data[233];
  std::copy_n(service_data, 233, std::back_inserter(data_item.data_));
  advertising_data.push_back(data_item);

  EXPECT_CALL(
      mock_advertising_callback_,
      OnAdvertisingDataSet(advertiser_id_, AdvertisingCallback::AdvertisingStatus::INTERNAL_ERROR));

  le_advertising_manager_->SetData(advertiser_id_, false, advertising_data);

  EXPECT_CALL(
      mock_advertising_callback_,
      OnScanResponseDataSet(advertiser_id_, AdvertisingCallback::AdvertisingStatus::INTERNAL_ERROR));
  le_advertising_manager_->SetData(advertiser_id_, true, advertising_data);

  sync_client_handler();
}

TEST_F(LeExtendedAdvertisingAPITest, set_data_with_invalid_length) {
  // Set advertising data with data that greater than le_maximum_advertising_data_length_
  std::vector<GapData> advertising_data{};
  for (uint8_t i = 0; i < 10; i++) {
    GapData data_item{};
    data_item.data_.push_back(0xfb);
    data_item.data_type_ = GapDataType::SERVICE_DATA_128_BIT_UUIDS;
    uint8_t uuid[16] = {0xf0, 0x34, 0x9b, 0x5f, 0x80, 0x00, 0x00, 0x80, 0x00, 0x10, 0x00, 0x00, 0x00, 0x10, 0x00, i};
    std::copy_n(uuid, 16, std::back_inserter(data_item.data_));
    uint8_t service_data[200];
    std::copy_n(service_data, 200, std::back_inserter(data_item.data_));
    advertising_data.push_back(data_item);
  }

  EXPECT_CALL(
      mock_advertising_callback_,
      OnAdvertisingDataSet(advertiser_id_, AdvertisingCallback::AdvertisingStatus::DATA_TOO_LARGE));
  le_advertising_manager_->SetData(advertiser_id_, false, advertising_data);

  EXPECT_CALL(
      mock_advertising_callback_,
      OnScanResponseDataSet(advertiser_id_, AdvertisingCallback::AdvertisingStatus::DATA_TOO_LARGE));
  le_advertising_manager_->SetData(advertiser_id_, true, advertising_data);

  sync_client_handler();
}

TEST_F(LeAdvertisingAPITest, disable_enable_advertiser_test) {
  // disable advertiser
  test_hci_layer_->SetCommandFuture();
  le_advertising_manager_->EnableAdvertiser(advertiser_id_, false, 0x00, 0x00);
  test_hci_layer_->GetCommand(OpCode::LE_SET_ADVERTISING_ENABLE);
  EXPECT_CALL(
      mock_advertising_callback_,
      OnAdvertisingEnabled(advertiser_id_, false, AdvertisingCallback::AdvertisingStatus::SUCCESS));
  test_hci_layer_->IncomingEvent(LeSetAdvertisingEnableCompleteBuilder::Create(uint8_t{1}, ErrorCode::SUCCESS));
  sync_client_handler();

  // enable advertiser
  test_hci_layer_->SetCommandFuture();
  le_advertising_manager_->EnableAdvertiser(advertiser_id_, true, 0x00, 0x00);
  test_hci_layer_->GetCommand(OpCode::LE_SET_ADVERTISING_ENABLE);
  EXPECT_CALL(
      mock_advertising_callback_,
      OnAdvertisingEnabled(advertiser_id_, true, AdvertisingCallback::AdvertisingStatus::SUCCESS));
  test_hci_layer_->IncomingEvent(LeSetAdvertisingEnableCompleteBuilder::Create(uint8_t{1}, ErrorCode::SUCCESS));
  sync_client_handler();
}

TEST_F(LeAndroidHciAdvertisingAPITest, disable_enable_advertiser_test) {
  // disable advertiser
  test_hci_layer_->SetSubCommandFuture(SubOcf::SET_ENABLE);
  le_advertising_manager_->EnableAdvertiser(advertiser_id_, false, 0x00, 0x00);
  test_hci_layer_->GetCommand(OpCode::LE_MULTI_ADVT);
  EXPECT_CALL(
      mock_advertising_callback_,
      OnAdvertisingEnabled(advertiser_id_, false, AdvertisingCallback::AdvertisingStatus::SUCCESS));
  test_hci_layer_->IncomingEvent(
      LeMultiAdvtCompleteBuilder::Create(uint8_t{1}, ErrorCode::SUCCESS, SubOcf::SET_ENABLE));
  sync_client_handler();

  // enable advertiser
  test_hci_layer_->SetSubCommandFuture(SubOcf::SET_ENABLE);
  le_advertising_manager_->EnableAdvertiser(advertiser_id_, true, 0x00, 0x00);
  test_hci_layer_->GetCommand(OpCode::LE_MULTI_ADVT);
  EXPECT_CALL(
      mock_advertising_callback_,
      OnAdvertisingEnabled(advertiser_id_, true, AdvertisingCallback::AdvertisingStatus::SUCCESS));
  test_hci_layer_->IncomingEvent(
      LeMultiAdvtCompleteBuilder::Create(uint8_t{1}, ErrorCode::SUCCESS, SubOcf::SET_ENABLE));
  sync_client_handler();
}

TEST_F(LeExtendedAdvertisingAPITest, disable_enable_advertiser_test) {
  // disable advertiser
  test_hci_layer_->SetCommandFuture();
  le_advertising_manager_->EnableAdvertiser(advertiser_id_, false, 0x00, 0x00);
  test_hci_layer_->GetCommand(OpCode::LE_SET_EXTENDED_ADVERTISING_ENABLE);
  EXPECT_CALL(
      mock_advertising_callback_,
      OnAdvertisingEnabled(advertiser_id_, false, AdvertisingCallback::AdvertisingStatus::SUCCESS));
  test_hci_layer_->IncomingEvent(LeSetExtendedAdvertisingEnableCompleteBuilder::Create(uint8_t{1}, ErrorCode::SUCCESS));
  sync_client_handler();

  // enable advertiser
  test_hci_layer_->SetCommandFuture();
  le_advertising_manager_->EnableAdvertiser(advertiser_id_, true, 0x00, 0x00);
  test_hci_layer_->GetCommand(OpCode::LE_SET_EXTENDED_ADVERTISING_ENABLE);
  EXPECT_CALL(
      mock_advertising_callback_,
      OnAdvertisingEnabled(advertiser_id_, true, AdvertisingCallback::AdvertisingStatus::SUCCESS));
  test_hci_layer_->IncomingEvent(LeSetExtendedAdvertisingEnableCompleteBuilder::Create(uint8_t{1}, ErrorCode::SUCCESS));
  sync_client_handler();
}

TEST_F(LeExtendedAdvertisingAPITest, set_periodic_parameter) {
  PeriodicAdvertisingParameters advertising_config{};
  advertising_config.max_interval = 0x1000;
  advertising_config.min_interval = 0x0006;
  test_hci_layer_->SetCommandFuture();
  le_advertising_manager_->SetPeriodicParameters(advertiser_id_, advertising_config);
  test_hci_layer_->GetCommand(OpCode::LE_SET_PERIODIC_ADVERTISING_PARAM);
  EXPECT_CALL(
      mock_advertising_callback_,
      OnPeriodicAdvertisingParametersUpdated(advertiser_id_, AdvertisingCallback::AdvertisingStatus::SUCCESS));
  test_hci_layer_->IncomingEvent(LeSetPeriodicAdvertisingParamCompleteBuilder::Create(uint8_t{1}, ErrorCode::SUCCESS));
  sync_client_handler();
}

TEST_F(LeExtendedAdvertisingAPITest, set_periodic_data_test) {
  // Set advertising data
  std::vector<GapData> advertising_data{};
  GapData data_item{};
  data_item.data_type_ = GapDataType::TX_POWER_LEVEL;
  data_item.data_ = {0x00};
  advertising_data.push_back(data_item);
  test_hci_layer_->SetCommandFuture();
  le_advertising_manager_->SetPeriodicData(advertiser_id_, advertising_data);
  test_hci_layer_->GetCommand(OpCode::LE_SET_PERIODIC_ADVERTISING_DATA);
  EXPECT_CALL(
      mock_advertising_callback_,
      OnPeriodicAdvertisingDataSet(advertiser_id_, AdvertisingCallback::AdvertisingStatus::SUCCESS));
  test_hci_layer_->IncomingEvent(LeSetPeriodicAdvertisingDataCompleteBuilder::Create(uint8_t{1}, ErrorCode::SUCCESS));
  sync_client_handler();
}

TEST_F(LeExtendedAdvertisingAPITest, set_periodic_data_fragments_test) {
  // Set advertising data
  std::vector<GapData> advertising_data{};
  for (uint8_t i = 0; i < 3; i++) {
    GapData data_item{};
    data_item.data_.push_back(0xfa);
    data_item.data_type_ = GapDataType::SERVICE_DATA_128_BIT_UUIDS;
    uint8_t uuid[16] = {0xf0, 0x34, 0x9b, 0x5f, 0x80, 0x00, 0x00, 0x80, 0x00, 0x10, 0x00, 0x00, 0x00, 0x10, 0x00, i};
    std::copy_n(uuid, 16, std::back_inserter(data_item.data_));
    uint8_t service_data[232];
    std::copy_n(service_data, 232, std::back_inserter(data_item.data_));
    advertising_data.push_back(data_item);
  }
  le_advertising_manager_->SetPeriodicData(advertiser_id_, advertising_data);

  // First fragment
  test_hci_layer_->SetCommandFuture();
  test_hci_layer_->GetCommand(OpCode::LE_SET_PERIODIC_ADVERTISING_DATA);

  // Intermediate fragment
  test_hci_layer_->SetCommandFuture();
  test_hci_layer_->GetCommand(OpCode::LE_SET_PERIODIC_ADVERTISING_DATA);

  // Last fragment
  test_hci_layer_->SetCommandFuture();
  test_hci_layer_->GetCommand(OpCode::LE_SET_PERIODIC_ADVERTISING_DATA);

  EXPECT_CALL(
      mock_advertising_callback_,
      OnPeriodicAdvertisingDataSet(advertiser_id_, AdvertisingCallback::AdvertisingStatus::SUCCESS));
  test_hci_layer_->IncomingEvent(LeSetPeriodicAdvertisingDataCompleteBuilder::Create(uint8_t{1}, ErrorCode::SUCCESS));
  test_hci_layer_->IncomingEvent(LeSetPeriodicAdvertisingDataCompleteBuilder::Create(uint8_t{1}, ErrorCode::SUCCESS));
  test_hci_layer_->IncomingEvent(LeSetPeriodicAdvertisingDataCompleteBuilder::Create(uint8_t{1}, ErrorCode::SUCCESS));

  sync_client_handler();
}

TEST_F(LeExtendedAdvertisingAPITest, set_perodic_data_with_invalid_ad_structure) {
  // Set advertising data with AD structure that length greater than 251
  std::vector<GapData> advertising_data{};
  GapData data_item{};
  data_item.data_.push_back(0xfb);
  data_item.data_type_ = GapDataType::SERVICE_DATA_128_BIT_UUIDS;
  uint8_t uuid[16] = {0xf0, 0x34, 0x9b, 0x5f, 0x80, 0x00, 0x00, 0x80, 0x00, 0x10, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00};
  std::copy_n(uuid, 16, std::back_inserter(data_item.data_));
  uint8_t service_data[233];
  std::copy_n(service_data, 233, std::back_inserter(data_item.data_));
  advertising_data.push_back(data_item);

  EXPECT_CALL(
      mock_advertising_callback_,
      OnPeriodicAdvertisingDataSet(advertiser_id_, AdvertisingCallback::AdvertisingStatus::INTERNAL_ERROR));

  le_advertising_manager_->SetPeriodicData(advertiser_id_, advertising_data);

  sync_client_handler();
}

TEST_F(LeExtendedAdvertisingAPITest, set_perodic_data_with_invalid_length) {
  // Set advertising data with data that greater than le_maximum_advertising_data_length_
  std::vector<GapData> advertising_data{};
  for (uint8_t i = 0; i < 10; i++) {
    GapData data_item{};
    data_item.data_.push_back(0xfb);
    data_item.data_type_ = GapDataType::SERVICE_DATA_128_BIT_UUIDS;
    uint8_t uuid[16] = {0xf0, 0x34, 0x9b, 0x5f, 0x80, 0x00, 0x00, 0x80, 0x00, 0x10, 0x00, 0x00, 0x00, 0x10, 0x00, i};
    std::copy_n(uuid, 16, std::back_inserter(data_item.data_));
    uint8_t service_data[200];
    std::copy_n(service_data, 200, std::back_inserter(data_item.data_));
    advertising_data.push_back(data_item);
  }

  EXPECT_CALL(
      mock_advertising_callback_,
      OnPeriodicAdvertisingDataSet(advertiser_id_, AdvertisingCallback::AdvertisingStatus::DATA_TOO_LARGE));
  le_advertising_manager_->SetPeriodicData(advertiser_id_, advertising_data);

  sync_client_handler();
}

TEST_F(LeExtendedAdvertisingAPITest, disable_enable_periodic_advertiser_test) {
  // disable advertiser
  test_hci_layer_->SetCommandFuture();
  le_advertising_manager_->EnablePeriodicAdvertising(advertiser_id_, false);
  test_hci_layer_->GetCommand(OpCode::LE_SET_PERIODIC_ADVERTISING_ENABLE);
  EXPECT_CALL(
      mock_advertising_callback_,
      OnPeriodicAdvertisingEnabled(advertiser_id_, false, AdvertisingCallback::AdvertisingStatus::SUCCESS));
  test_hci_layer_->IncomingEvent(LeSetPeriodicAdvertisingEnableCompleteBuilder::Create(uint8_t{1}, ErrorCode::SUCCESS));
  sync_client_handler();

  // enable advertiser
  test_hci_layer_->SetCommandFuture();
  le_advertising_manager_->EnablePeriodicAdvertising(advertiser_id_, true);
  test_hci_layer_->GetCommand(OpCode::LE_SET_PERIODIC_ADVERTISING_ENABLE);
  EXPECT_CALL(
      mock_advertising_callback_,
      OnPeriodicAdvertisingEnabled(advertiser_id_, true, AdvertisingCallback::AdvertisingStatus::SUCCESS));
  test_hci_layer_->IncomingEvent(LeSetPeriodicAdvertisingEnableCompleteBuilder::Create(uint8_t{1}, ErrorCode::SUCCESS));
  sync_client_handler();
}

}  // namespace
}  // namespace hci
}  // namespace bluetooth
