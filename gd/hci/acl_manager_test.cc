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

#include "hci/acl_manager.h"

#include <algorithm>
#include <chrono>
#include <future>
#include <map>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "common/bind.h"
#include "hci/address.h"
#include "hci/class_of_device.h"
#include "hci/controller.h"
#include "hci/hci_layer.h"
#include "os/thread.h"
#include "packet/raw_builder.h"

namespace bluetooth {
namespace hci {
namespace acl_manager {
namespace {

using common::BidiQueue;
using common::BidiQueueEnd;
using packet::kLittleEndian;
using packet::PacketView;
using packet::RawBuilder;

constexpr std::chrono::seconds kTimeout = std::chrono::seconds(2);
constexpr uint16_t kScanIntervalFast = 0x0060;
constexpr uint16_t kScanWindowFast = 0x0030;
constexpr uint16_t kScanIntervalSlow = 0x0800;
constexpr uint16_t kScanWindowSlow = 0x0030;
const AddressWithType empty_address_with_type = hci::AddressWithType();

PacketView<kLittleEndian> GetPacketView(std::unique_ptr<packet::BasePacketBuilder> packet) {
  auto bytes = std::make_shared<std::vector<uint8_t>>();
  BitInserter i(*bytes);
  bytes->reserve(packet->size());
  packet->Serialize(i);
  return packet::PacketView<packet::kLittleEndian>(bytes);
}

std::unique_ptr<BasePacketBuilder> NextPayload(uint16_t handle) {
  static uint32_t packet_number = 1;
  auto payload = std::make_unique<RawBuilder>();
  payload->AddOctets2(6);  // L2CAP PDU size
  payload->AddOctets2(2);  // L2CAP CID
  payload->AddOctets2(handle);
  payload->AddOctets4(packet_number++);
  return std::move(payload);
}

std::unique_ptr<AclBuilder> NextAclPacket(uint16_t handle) {
  PacketBoundaryFlag packet_boundary_flag = PacketBoundaryFlag::FIRST_AUTOMATICALLY_FLUSHABLE;
  BroadcastFlag broadcast_flag = BroadcastFlag::POINT_TO_POINT;
  return AclBuilder::Create(handle, packet_boundary_flag, broadcast_flag, NextPayload(handle));
}

class TestController : public Controller {
 public:
  void RegisterCompletedAclPacketsCallback(
      common::ContextualCallback<void(uint16_t /* handle */, uint16_t /* packets */)> cb) override {
    acl_cb_ = cb;
  }

  void UnregisterCompletedAclPacketsCallback() override {
    acl_cb_ = {};
  }

  uint16_t GetAclPacketLength() const override {
    return acl_buffer_length_;
  }

  uint16_t GetNumAclPacketBuffers() const override {
    return total_acl_buffers_;
  }

  bool IsSupported(bluetooth::hci::OpCode op_code) const override {
    return false;
  }

  LeBufferSize GetLeBufferSize() const override {
    LeBufferSize le_buffer_size;
    le_buffer_size.total_num_le_packets_ = 2;
    le_buffer_size.le_data_packet_length_ = 32;
    return le_buffer_size;
  }

  void CompletePackets(uint16_t handle, uint16_t packets) {
    acl_cb_.Invoke(handle, packets);
  }

  uint16_t acl_buffer_length_ = 1024;
  uint16_t total_acl_buffers_ = 2;
  common::ContextualCallback<void(uint16_t /* handle */, uint16_t /* packets */)> acl_cb_;

 protected:
  void Start() override {}
  void Stop() override {}
  void ListDependencies(ModuleList* list) override {}
};

class TestHciLayer : public HciLayer {
 public:
  void EnqueueCommand(
      std::unique_ptr<CommandBuilder> command,
      common::ContextualOnceCallback<void(CommandStatusView)> on_status) override {
    command_queue_.push(std::move(command));
    command_status_callbacks.push_back(std::move(on_status));
    if (command_promise_ != nullptr) {
      command_promise_->set_value();
      command_promise_.reset();
    }
  }

  void EnqueueCommand(
      std::unique_ptr<CommandBuilder> command,
      common::ContextualOnceCallback<void(CommandCompleteView)> on_complete) override {
    command_queue_.push(std::move(command));
    command_complete_callbacks.push_back(std::move(on_complete));
    if (command_promise_ != nullptr) {
      command_promise_->set_value();
      command_promise_.reset();
    }
  }

  void SetCommandFuture() {
    ASSERT_LOG(command_promise_ == nullptr, "Promises, Promises, ... Only one at a time.");
    command_promise_ = std::make_unique<std::promise<void>>();
    command_future_ = std::make_unique<std::future<void>>(command_promise_->get_future());
  }

  CommandView GetLastCommand() {
    if (command_queue_.size() == 0) {
      return CommandView::Create(PacketView<kLittleEndian>(std::make_shared<std::vector<uint8_t>>()));
    }
    auto last = std::move(command_queue_.front());
    command_queue_.pop();
    return CommandView::Create(GetPacketView(std::move(last)));
  }

  ConnectionManagementCommandView GetCommand(OpCode op_code) {
    if (command_future_ != nullptr) {
      auto result = command_future_->wait_for(std::chrono::milliseconds(1000));
      EXPECT_NE(std::future_status::timeout, result);
    }
    if (command_queue_.empty()) {
      return ConnectionManagementCommandView::Create(AclCommandView::Create(
          CommandView::Create(PacketView<kLittleEndian>(std::make_shared<std::vector<uint8_t>>()))));
    }
    CommandView command_packet_view = GetLastCommand();
    ConnectionManagementCommandView command =
        ConnectionManagementCommandView::Create(AclCommandView::Create(command_packet_view));
    EXPECT_TRUE(command.IsValid());
    EXPECT_EQ(command.GetOpCode(), op_code);

    return command;
  }

  ConnectionManagementCommandView GetLastCommand(OpCode op_code) {
    if (!command_queue_.empty() && command_future_ != nullptr) {
      command_future_.reset();
      command_promise_.reset();
    } else if (command_future_ != nullptr) {
      auto result = command_future_->wait_for(std::chrono::milliseconds(1000));
      EXPECT_NE(std::future_status::timeout, result);
    }
    if (command_queue_.empty()) {
      return ConnectionManagementCommandView::Create(AclCommandView::Create(
          CommandView::Create(PacketView<kLittleEndian>(std::make_shared<std::vector<uint8_t>>()))));
    }
    CommandView command_packet_view = GetLastCommand();
    ConnectionManagementCommandView command =
        ConnectionManagementCommandView::Create(AclCommandView::Create(command_packet_view));
    EXPECT_TRUE(command.IsValid());
    EXPECT_EQ(command.GetOpCode(), op_code);

    return command;
  }

  void RegisterEventHandler(EventCode event_code, common::ContextualCallback<void(EventView)> event_handler) override {
    registered_events_[event_code] = event_handler;
  }

  void UnregisterEventHandler(EventCode event_code) override {
    registered_events_.erase(event_code);
  }

  void RegisterLeEventHandler(SubeventCode subevent_code,
                              common::ContextualCallback<void(LeMetaEventView)> event_handler) override {
    registered_le_events_[subevent_code] = event_handler;
  }

  void UnregisterLeEventHandler(SubeventCode subevent_code) override {
    registered_le_events_.erase(subevent_code);
  }

  void IncomingEvent(std::unique_ptr<EventBuilder> event_builder) {
    auto packet = GetPacketView(std::move(event_builder));
    EventView event = EventView::Create(packet);
    ASSERT_TRUE(event.IsValid());
    EventCode event_code = event.GetEventCode();
    ASSERT_NE(registered_events_.find(event_code), registered_events_.end()) << EventCodeText(event_code);
    registered_events_[event_code].Invoke(event);
  }

  void IncomingLeMetaEvent(std::unique_ptr<LeMetaEventBuilder> event_builder) {
    auto packet = GetPacketView(std::move(event_builder));
    EventView event = EventView::Create(packet);
    LeMetaEventView meta_event_view = LeMetaEventView::Create(event);
    EXPECT_TRUE(meta_event_view.IsValid());
    SubeventCode subevent_code = meta_event_view.GetSubeventCode();
    EXPECT_TRUE(registered_le_events_.find(subevent_code) != registered_le_events_.end());
    registered_le_events_[subevent_code].Invoke(meta_event_view);
  }

  void IncomingAclData(uint16_t handle) {
    os::Handler* hci_handler = GetHandler();
    auto* queue_end = acl_queue_.GetDownEnd();
    std::promise<void> promise;
    auto future = promise.get_future();
    queue_end->RegisterEnqueue(hci_handler,
                               common::Bind(
                                   [](decltype(queue_end) queue_end, uint16_t handle, std::promise<void> promise) {
                                     auto packet = GetPacketView(NextAclPacket(handle));
                                     AclView acl2 = AclView::Create(packet);
                                     queue_end->UnregisterEnqueue();
                                     promise.set_value();
                                     return std::make_unique<AclView>(acl2);
                                   },
                                   queue_end, handle, common::Passed(std::move(promise))));
    auto status = future.wait_for(kTimeout);
    ASSERT_EQ(status, std::future_status::ready);
  }

  void AssertNoOutgoingAclData() {
    auto queue_end = acl_queue_.GetDownEnd();
    EXPECT_EQ(queue_end->TryDequeue(), nullptr);
  }

  void CommandCompleteCallback(EventView event) {
    CommandCompleteView complete_view = CommandCompleteView::Create(event);
    ASSERT_TRUE(complete_view.IsValid());
    std::move(command_complete_callbacks.front()).Invoke(complete_view);
    command_complete_callbacks.pop_front();
  }

  void CommandStatusCallback(EventView event) {
    CommandStatusView status_view = CommandStatusView::Create(event);
    ASSERT_TRUE(status_view.IsValid());
    std::move(command_status_callbacks.front()).Invoke(status_view);
    command_status_callbacks.pop_front();
  }

  PacketView<kLittleEndian> OutgoingAclData() {
    auto queue_end = acl_queue_.GetDownEnd();
    std::unique_ptr<AclBuilder> received;
    do {
      received = queue_end->TryDequeue();
    } while (received == nullptr);

    return GetPacketView(std::move(received));
  }

  BidiQueueEnd<AclBuilder, AclView>* GetAclQueueEnd() override {
    return acl_queue_.GetUpEnd();
  }

  void ListDependencies(ModuleList* list) override {}
  void Start() override {
    RegisterEventHandler(EventCode::COMMAND_COMPLETE,
                         GetHandler()->BindOn(this, &TestHciLayer::CommandCompleteCallback));
    RegisterEventHandler(EventCode::COMMAND_STATUS, GetHandler()->BindOn(this, &TestHciLayer::CommandStatusCallback));
  }
  void Stop() override {}

  void Disconnect(uint16_t handle, ErrorCode reason) override {
    GetHandler()->Post(common::BindOnce(&TestHciLayer::do_disconnect, common::Unretained(this), handle, reason));
  }

 private:
  std::map<EventCode, common::ContextualCallback<void(EventView)>> registered_events_;
  std::map<SubeventCode, common::ContextualCallback<void(LeMetaEventView)>> registered_le_events_;
  std::list<common::ContextualOnceCallback<void(CommandCompleteView)>> command_complete_callbacks;
  std::list<common::ContextualOnceCallback<void(CommandStatusView)>> command_status_callbacks;
  BidiQueue<AclView, AclBuilder> acl_queue_{3 /* TODO: Set queue depth */};

  std::queue<std::unique_ptr<CommandBuilder>> command_queue_;
  std::unique_ptr<std::promise<void>> command_promise_;
  std::unique_ptr<std::future<void>> command_future_;

  void do_disconnect(uint16_t handle, ErrorCode reason) {
    HciLayer::Disconnect(handle, reason);
  }
};

class AclManagerNoCallbacksTest : public ::testing::Test {
 protected:
  void SetUp() override {
    test_hci_layer_ = new TestHciLayer;  // Ownership is transferred to registry
    test_controller_ = new TestController;
    fake_registry_.InjectTestModule(&HciLayer::Factory, test_hci_layer_);
    fake_registry_.InjectTestModule(&Controller::Factory, test_controller_);
    client_handler_ = fake_registry_.GetTestModuleHandler(&HciLayer::Factory);
    ASSERT_NE(client_handler_, nullptr);
    test_hci_layer_->SetCommandFuture();
    fake_registry_.Start<AclManager>(&thread_);
    acl_manager_ = static_cast<AclManager*>(fake_registry_.GetModuleUnderTest(&AclManager::Factory));
    Address::FromString("A1:A2:A3:A4:A5:A6", remote);

    hci::Address address;
    Address::FromString("D0:05:04:03:02:01", address);
    hci::AddressWithType address_with_type(address, hci::AddressType::RANDOM_DEVICE_ADDRESS);
    auto minimum_rotation_time = std::chrono::milliseconds(7 * 60 * 1000);
    auto maximum_rotation_time = std::chrono::milliseconds(15 * 60 * 1000);
    acl_manager_->SetPrivacyPolicyForInitiatorAddress(
        LeAddressManager::AddressPolicy::USE_STATIC_ADDRESS,
        address_with_type,
        minimum_rotation_time,
        maximum_rotation_time);

    auto set_random_address_packet = LeSetRandomAddressView::Create(
        LeAdvertisingCommandView::Create(test_hci_layer_->GetCommand(OpCode::LE_SET_RANDOM_ADDRESS)));
    ASSERT_TRUE(set_random_address_packet.IsValid());
    my_initiating_address =
        AddressWithType(set_random_address_packet.GetRandomAddress(), AddressType::RANDOM_DEVICE_ADDRESS);
    // Verify LE Set Random Address was sent during setup
    test_hci_layer_->GetLastCommand(OpCode::LE_SET_RANDOM_ADDRESS);
    test_hci_layer_->IncomingEvent(LeSetRandomAddressCompleteBuilder::Create(0x01, ErrorCode::SUCCESS));
  }

  void TearDown() override {
    fake_registry_.SynchronizeModuleHandler(&AclManager::Factory, std::chrono::milliseconds(20));
    fake_registry_.StopAll();
  }

  TestModuleRegistry fake_registry_;
  TestHciLayer* test_hci_layer_ = nullptr;
  TestController* test_controller_ = nullptr;
  os::Thread& thread_ = fake_registry_.GetTestThread();
  AclManager* acl_manager_ = nullptr;
  os::Handler* client_handler_ = nullptr;
  Address remote;
  AddressWithType my_initiating_address;
  const bool use_connect_list_ = true;  // gd currently only supports connect list

  std::future<void> GetConnectionFuture() {
    ASSERT_LOG(mock_connection_callback_.connection_promise_ == nullptr, "Promises promises ... Only one at a time");
    mock_connection_callback_.connection_promise_ = std::make_unique<std::promise<void>>();
    return mock_connection_callback_.connection_promise_->get_future();
  }

  std::future<void> GetLeConnectionFuture() {
    ASSERT_LOG(mock_le_connection_callbacks_.le_connection_promise_ == nullptr,
               "Promises promises ... Only one at a time");
    mock_le_connection_callbacks_.le_connection_promise_ = std::make_unique<std::promise<void>>();
    return mock_le_connection_callbacks_.le_connection_promise_->get_future();
  }

  std::shared_ptr<ClassicAclConnection> GetLastConnection() {
    return mock_connection_callback_.connections_.back();
  }

  std::shared_ptr<LeAclConnection> GetLastLeConnection() {
    return mock_le_connection_callbacks_.le_connections_.back();
  }

  void SendAclData(uint16_t handle, AclConnection::QueueUpEnd* queue_end) {
    std::promise<void> promise;
    auto future = promise.get_future();
    queue_end->RegisterEnqueue(client_handler_,
                               common::Bind(
                                   [](decltype(queue_end) queue_end, uint16_t handle, std::promise<void> promise) {
                                     queue_end->UnregisterEnqueue();
                                     promise.set_value();
                                     return NextPayload(handle);
                                   },
                                   queue_end, handle, common::Passed(std::move(promise))));
    auto status = future.wait_for(kTimeout);
    ASSERT_EQ(status, std::future_status::ready);
  }

  class MockConnectionCallback : public ConnectionCallbacks {
   public:
    void OnConnectSuccess(std::unique_ptr<ClassicAclConnection> connection) override {
      // Convert to std::shared_ptr during push_back()
      connections_.push_back(std::move(connection));
      if (connection_promise_ != nullptr) {
        connection_promise_->set_value();
        connection_promise_.reset();
      }
    }
    MOCK_METHOD(void, OnConnectFail, (Address, ErrorCode reason), (override));

    MOCK_METHOD(void, HACK_OnEscoConnectRequest, (Address, ClassOfDevice), (override));
    MOCK_METHOD(void, HACK_OnScoConnectRequest, (Address, ClassOfDevice), (override));

    std::list<std::shared_ptr<ClassicAclConnection>> connections_;
    std::unique_ptr<std::promise<void>> connection_promise_;
  } mock_connection_callback_;

  class MockLeConnectionCallbacks : public LeConnectionCallbacks {
   public:
    void OnLeConnectSuccess(AddressWithType address_with_type, std::unique_ptr<LeAclConnection> connection) override {
      le_connections_.push_back(std::move(connection));
      if (le_connection_promise_ != nullptr) {
        le_connection_promise_->set_value();
        le_connection_promise_.reset();
      }
    }
    MOCK_METHOD(void, OnLeConnectFail, (AddressWithType, ErrorCode reason), (override));

    std::list<std::shared_ptr<LeAclConnection>> le_connections_;
    std::unique_ptr<std::promise<void>> le_connection_promise_;
  } mock_le_connection_callbacks_;
};

class AclManagerTest : public AclManagerNoCallbacksTest {
 protected:
  void SetUp() override {
    AclManagerNoCallbacksTest::SetUp();
    acl_manager_->RegisterCallbacks(&mock_connection_callback_, client_handler_);
    acl_manager_->RegisterLeCallbacks(&mock_le_connection_callbacks_, client_handler_);
  }
};

class AclManagerWithConnectionTest : public AclManagerTest {
 protected:
  void SetUp() override {
    AclManagerTest::SetUp();

    handle_ = 0x123;
    acl_manager_->CreateConnection(remote);

    // Wait for the connection request
    auto last_command = test_hci_layer_->GetCommand(OpCode::CREATE_CONNECTION);
    while (!last_command.IsValid()) {
      last_command = test_hci_layer_->GetCommand(OpCode::CREATE_CONNECTION);
    }

    EXPECT_CALL(mock_connection_management_callbacks_, OnRoleChange(hci::ErrorCode::SUCCESS, Role::CENTRAL));

    auto first_connection = GetConnectionFuture();
    test_hci_layer_->IncomingEvent(
        ConnectionCompleteBuilder::Create(ErrorCode::SUCCESS, handle_, remote, LinkType::ACL, Enable::DISABLED));

    auto first_connection_status = first_connection.wait_for(kTimeout);
    ASSERT_EQ(first_connection_status, std::future_status::ready);

    connection_ = GetLastConnection();
    connection_->RegisterCallbacks(&mock_connection_management_callbacks_, client_handler_);
  }

  void TearDown() override {
    fake_registry_.SynchronizeModuleHandler(&HciLayer::Factory, std::chrono::milliseconds(20));
    fake_registry_.SynchronizeModuleHandler(&AclManager::Factory, std::chrono::milliseconds(20));
    fake_registry_.StopAll();
  }

  void sync_client_handler() {
    std::promise<void> promise;
    auto future = promise.get_future();
    client_handler_->Post(common::BindOnce(&std::promise<void>::set_value, common::Unretained(&promise)));
    auto future_status = future.wait_for(std::chrono::seconds(1));
    EXPECT_EQ(future_status, std::future_status::ready);
  }

  uint16_t handle_;
  std::shared_ptr<ClassicAclConnection> connection_;

  class MockConnectionManagementCallbacks : public ConnectionManagementCallbacks {
   public:
    MOCK_METHOD1(OnConnectionPacketTypeChanged, void(uint16_t packet_type));
    MOCK_METHOD1(OnAuthenticationComplete, void(hci::ErrorCode hci_status));
    MOCK_METHOD1(OnEncryptionChange, void(EncryptionEnabled enabled));
    MOCK_METHOD0(OnChangeConnectionLinkKeyComplete, void());
    MOCK_METHOD1(OnReadClockOffsetComplete, void(uint16_t clock_offse));
    MOCK_METHOD3(OnModeChange, void(ErrorCode status, Mode current_mode, uint16_t interval));
    MOCK_METHOD5(
        OnSniffSubrating,
        void(
            ErrorCode status,
            uint16_t maximum_transmit_latency,
            uint16_t maximum_receive_latency,
            uint16_t minimum_remote_timeout,
            uint16_t minimum_local_timeout));
    MOCK_METHOD5(OnQosSetupComplete, void(ServiceType service_type, uint32_t token_rate, uint32_t peak_bandwidth,
                                          uint32_t latency, uint32_t delay_variation));
    MOCK_METHOD6(OnFlowSpecificationComplete,
                 void(FlowDirection flow_direction, ServiceType service_type, uint32_t token_rate,
                      uint32_t token_bucket_size, uint32_t peak_bandwidth, uint32_t access_latency));
    MOCK_METHOD0(OnFlushOccurred, void());
    MOCK_METHOD1(OnRoleDiscoveryComplete, void(Role current_role));
    MOCK_METHOD1(OnReadLinkPolicySettingsComplete, void(uint16_t link_policy_settings));
    MOCK_METHOD1(OnReadAutomaticFlushTimeoutComplete, void(uint16_t flush_timeout));
    MOCK_METHOD1(OnReadTransmitPowerLevelComplete, void(uint8_t transmit_power_level));
    MOCK_METHOD1(OnReadLinkSupervisionTimeoutComplete, void(uint16_t link_supervision_timeout));
    MOCK_METHOD1(OnReadFailedContactCounterComplete, void(uint16_t failed_contact_counter));
    MOCK_METHOD1(OnReadLinkQualityComplete, void(uint8_t link_quality));
    MOCK_METHOD2(OnReadAfhChannelMapComplete, void(AfhMode afh_mode, std::array<uint8_t, 10> afh_channel_map));
    MOCK_METHOD1(OnReadRssiComplete, void(uint8_t rssi));
    MOCK_METHOD2(OnReadClockComplete, void(uint32_t clock, uint16_t accuracy));
    MOCK_METHOD1(OnCentralLinkKeyComplete, void(KeyFlag flag));
    MOCK_METHOD2(OnRoleChange, void(ErrorCode hci_status, Role new_role));
    MOCK_METHOD1(OnDisconnection, void(ErrorCode reason));
    MOCK_METHOD4(
        OnReadRemoteVersionInformationComplete,
        void(hci::ErrorCode hci_status, uint8_t lmp_version, uint16_t manufacturer_name, uint16_t sub_version));
    MOCK_METHOD1(OnReadRemoteSupportedFeaturesComplete, void(uint64_t features));
    MOCK_METHOD3(
        OnReadRemoteExtendedFeaturesComplete, void(uint8_t page_number, uint8_t max_page_number, uint64_t features));
  } mock_connection_management_callbacks_;
};

TEST_F(AclManagerTest, startup_teardown) {}

TEST_F(AclManagerNoCallbacksTest, acl_connection_before_registered_callbacks) {
  ClassOfDevice class_of_device;

  test_hci_layer_->IncomingEvent(
      ConnectionRequestBuilder::Create(remote, class_of_device, ConnectionRequestLinkType::ACL));
  fake_registry_.SynchronizeModuleHandler(&HciLayer::Factory, std::chrono::milliseconds(20));
  fake_registry_.SynchronizeModuleHandler(&AclManager::Factory, std::chrono::milliseconds(20));
  fake_registry_.SynchronizeModuleHandler(&HciLayer::Factory, std::chrono::milliseconds(20));
  CommandView command = CommandView::Create(test_hci_layer_->GetLastCommand());
  EXPECT_TRUE(command.IsValid());
  OpCode op_code = command.GetOpCode();
  EXPECT_EQ(op_code, OpCode::REJECT_CONNECTION_REQUEST);
}

TEST_F(AclManagerTest, invoke_registered_callback_connection_complete_success) {
  uint16_t handle = 1;

  test_hci_layer_->SetCommandFuture();
  acl_manager_->CreateConnection(remote);

  // Wait for the connection request
  auto last_command = test_hci_layer_->GetCommand(OpCode::CREATE_CONNECTION);
  while (!last_command.IsValid()) {
    last_command = test_hci_layer_->GetCommand(OpCode::CREATE_CONNECTION);
  }

  auto first_connection = GetConnectionFuture();

  test_hci_layer_->IncomingEvent(
      ConnectionCompleteBuilder::Create(ErrorCode::SUCCESS, handle, remote, LinkType::ACL, Enable::DISABLED));

  auto first_connection_status = first_connection.wait_for(kTimeout);
  ASSERT_EQ(first_connection_status, std::future_status::ready);

  auto connection = GetLastConnection();
  ASSERT_EQ(connection->GetAddress(), remote);
}

TEST_F(AclManagerTest, invoke_registered_callback_connection_complete_fail) {
  uint16_t handle = 0x123;

  test_hci_layer_->SetCommandFuture();
  acl_manager_->CreateConnection(remote);

  // Wait for the connection request
  auto last_command = test_hci_layer_->GetCommand(OpCode::CREATE_CONNECTION);
  while (!last_command.IsValid()) {
    last_command = test_hci_layer_->GetCommand(OpCode::CREATE_CONNECTION);
  }

  EXPECT_CALL(mock_connection_callback_, OnConnectFail(remote, ErrorCode::PAGE_TIMEOUT));
  test_hci_layer_->IncomingEvent(
      ConnectionCompleteBuilder::Create(ErrorCode::PAGE_TIMEOUT, handle, remote, LinkType::ACL, Enable::DISABLED));
  fake_registry_.SynchronizeModuleHandler(&HciLayer::Factory, std::chrono::milliseconds(20));
  fake_registry_.SynchronizeModuleHandler(&AclManager::Factory, std::chrono::milliseconds(20));
  fake_registry_.SynchronizeModuleHandler(&HciLayer::Factory, std::chrono::milliseconds(20));
}

class AclManagerWithLeConnectionTest : public AclManagerTest {
 protected:
  void SetUp() override {
    AclManagerTest::SetUp();

    remote_with_type_ = AddressWithType(remote, AddressType::PUBLIC_DEVICE_ADDRESS);
    test_hci_layer_->SetCommandFuture();
    acl_manager_->CreateLeConnection(remote_with_type_, true);
    test_hci_layer_->GetCommand(OpCode::LE_ADD_DEVICE_TO_CONNECT_LIST);
    test_hci_layer_->IncomingEvent(LeAddDeviceToConnectListCompleteBuilder::Create(0x01, ErrorCode::SUCCESS));
    test_hci_layer_->SetCommandFuture();
    auto packet = test_hci_layer_->GetCommand(OpCode::LE_CREATE_CONNECTION);
    auto le_connection_management_command_view =
        LeConnectionManagementCommandView::Create(AclCommandView::Create(packet));
    auto command_view = LeCreateConnectionView::Create(le_connection_management_command_view);
    ASSERT_TRUE(command_view.IsValid());
    if (use_connect_list_) {
      ASSERT_EQ(command_view.GetPeerAddress(), empty_address_with_type.GetAddress());
      ASSERT_EQ(command_view.GetPeerAddressType(), empty_address_with_type.GetAddressType());
    } else {
      ASSERT_EQ(command_view.GetPeerAddress(), remote);
      ASSERT_EQ(command_view.GetPeerAddressType(), AddressType::PUBLIC_DEVICE_ADDRESS);
    }

    test_hci_layer_->IncomingEvent(LeCreateConnectionStatusBuilder::Create(ErrorCode::SUCCESS, 0x01));

    auto first_connection = GetLeConnectionFuture();

    test_hci_layer_->IncomingLeMetaEvent(LeConnectionCompleteBuilder::Create(
        ErrorCode::SUCCESS,
        handle_,
        Role::PERIPHERAL,
        AddressType::PUBLIC_DEVICE_ADDRESS,
        remote,
        0x0100,
        0x0010,
        0x0C80,
        ClockAccuracy::PPM_30));

    test_hci_layer_->SetCommandFuture();
    test_hci_layer_->GetCommand(OpCode::LE_REMOVE_DEVICE_FROM_CONNECT_LIST);
    test_hci_layer_->IncomingEvent(LeRemoveDeviceFromConnectListCompleteBuilder::Create(0x01, ErrorCode::SUCCESS));

    auto first_connection_status = first_connection.wait_for(kTimeout);
    ASSERT_EQ(first_connection_status, std::future_status::ready);

    connection_ = GetLastLeConnection();
  }

  void TearDown() override {
    fake_registry_.SynchronizeModuleHandler(&HciLayer::Factory, std::chrono::milliseconds(20));
    fake_registry_.SynchronizeModuleHandler(&AclManager::Factory, std::chrono::milliseconds(20));
    fake_registry_.StopAll();
  }

  void sync_client_handler() {
    std::promise<void> promise;
    auto future = promise.get_future();
    client_handler_->Post(common::BindOnce(&std::promise<void>::set_value, common::Unretained(&promise)));
    auto future_status = future.wait_for(std::chrono::seconds(1));
    EXPECT_EQ(future_status, std::future_status::ready);
  }

  uint16_t handle_ = 0x123;
  std::shared_ptr<LeAclConnection> connection_;
  AddressWithType remote_with_type_;

  class MockLeConnectionManagementCallbacks : public LeConnectionManagementCallbacks {
   public:
    MOCK_METHOD1(OnDisconnection, void(ErrorCode reason));
    MOCK_METHOD4(
        OnConnectionUpdate,
        void(
            hci::ErrorCode hci_status,
            uint16_t connection_interval,
            uint16_t connection_latency,
            uint16_t supervision_timeout));
    MOCK_METHOD4(OnDataLengthChange, void(uint16_t tx_octets, uint16_t tx_time, uint16_t rx_octets, uint16_t rx_time));
    MOCK_METHOD4(
        OnReadRemoteVersionInformationComplete,
        void(hci::ErrorCode hci_status, uint8_t version, uint16_t manufacturer_name, uint16_t sub_version));
    MOCK_METHOD3(OnPhyUpdate, void(hci::ErrorCode hci_status, uint8_t tx_phy, uint8_t rx_phy));
    MOCK_METHOD1(OnLocalAddressUpdate, void(AddressWithType address_with_type));
  } mock_le_connection_management_callbacks_;
};

// TODO: implement version of this test where controller supports Extended Advertising Feature in
// GetLeLocalSupportedFeatures, and LE Extended Create Connection is used
TEST_F(AclManagerWithLeConnectionTest, invoke_registered_callback_le_connection_complete_success) {
  ASSERT_EQ(connection_->GetLocalAddress(), my_initiating_address);
  ASSERT_EQ(connection_->GetRemoteAddress(), remote_with_type_);
}

TEST_F(AclManagerTest, invoke_registered_callback_le_connection_complete_fail) {
  AddressWithType remote_with_type(remote, AddressType::PUBLIC_DEVICE_ADDRESS);
  test_hci_layer_->SetCommandFuture();
  acl_manager_->CreateLeConnection(remote_with_type, true);
  test_hci_layer_->GetLastCommand(OpCode::LE_ADD_DEVICE_TO_CONNECT_LIST);
  test_hci_layer_->IncomingEvent(LeAddDeviceToConnectListCompleteBuilder::Create(0x01, ErrorCode::SUCCESS));
  test_hci_layer_->SetCommandFuture();
  auto packet = test_hci_layer_->GetLastCommand(OpCode::LE_CREATE_CONNECTION);
  auto le_connection_management_command_view =
      LeConnectionManagementCommandView::Create(AclCommandView::Create(packet));
  auto command_view = LeCreateConnectionView::Create(le_connection_management_command_view);
  ASSERT_TRUE(command_view.IsValid());
  if (use_connect_list_) {
    ASSERT_EQ(command_view.GetPeerAddress(), hci::Address::kEmpty);
  } else {
    ASSERT_EQ(command_view.GetPeerAddress(), remote);
  }
  EXPECT_EQ(command_view.GetPeerAddressType(), AddressType::PUBLIC_DEVICE_ADDRESS);

  test_hci_layer_->IncomingEvent(LeCreateConnectionStatusBuilder::Create(ErrorCode::SUCCESS, 0x01));

  EXPECT_CALL(mock_le_connection_callbacks_,
              OnLeConnectFail(remote_with_type, ErrorCode::CONNECTION_REJECTED_LIMITED_RESOURCES));
  test_hci_layer_->IncomingLeMetaEvent(LeConnectionCompleteBuilder::Create(
      ErrorCode::CONNECTION_REJECTED_LIMITED_RESOURCES,
      0x123,
      Role::PERIPHERAL,
      AddressType::PUBLIC_DEVICE_ADDRESS,
      remote,
      0x0100,
      0x0010,
      0x0011,
      ClockAccuracy::PPM_30));

  test_hci_layer_->SetCommandFuture();
  packet = test_hci_layer_->GetLastCommand(OpCode::LE_REMOVE_DEVICE_FROM_CONNECT_LIST);
  le_connection_management_command_view = LeConnectionManagementCommandView::Create(AclCommandView::Create(packet));
  auto remove_command_view = LeRemoveDeviceFromConnectListView::Create(le_connection_management_command_view);
  ASSERT_TRUE(remove_command_view.IsValid());
  test_hci_layer_->IncomingEvent(LeRemoveDeviceFromConnectListCompleteBuilder::Create(0x01, ErrorCode::SUCCESS));
}

TEST_F(AclManagerTest, cancel_le_connection) {
  AddressWithType remote_with_type(remote, AddressType::PUBLIC_DEVICE_ADDRESS);
  test_hci_layer_->SetCommandFuture();
  acl_manager_->CreateLeConnection(remote_with_type, true);
  test_hci_layer_->GetLastCommand(OpCode::LE_ADD_DEVICE_TO_CONNECT_LIST);
  test_hci_layer_->IncomingEvent(LeAddDeviceToConnectListCompleteBuilder::Create(0x01, ErrorCode::SUCCESS));
  test_hci_layer_->SetCommandFuture();
  test_hci_layer_->GetLastCommand(OpCode::LE_CREATE_CONNECTION);

  test_hci_layer_->SetCommandFuture();
  acl_manager_->CancelLeConnect(remote_with_type);
  auto packet = test_hci_layer_->GetLastCommand(OpCode::LE_CREATE_CONNECTION_CANCEL);
  auto le_connection_management_command_view =
      LeConnectionManagementCommandView::Create(AclCommandView::Create(packet));
  auto command_view = LeCreateConnectionCancelView::Create(le_connection_management_command_view);
  ASSERT_TRUE(command_view.IsValid());

  test_hci_layer_->IncomingEvent(LeCreateConnectionCancelCompleteBuilder::Create(0x01, ErrorCode::SUCCESS));
  test_hci_layer_->IncomingLeMetaEvent(LeConnectionCompleteBuilder::Create(
      ErrorCode::UNKNOWN_CONNECTION,
      0x123,
      Role::PERIPHERAL,
      AddressType::PUBLIC_DEVICE_ADDRESS,
      remote,
      0x0100,
      0x0010,
      0x0011,
      ClockAccuracy::PPM_30));

  test_hci_layer_->SetCommandFuture();
  packet = test_hci_layer_->GetLastCommand(OpCode::LE_REMOVE_DEVICE_FROM_CONNECT_LIST);
  le_connection_management_command_view = LeConnectionManagementCommandView::Create(AclCommandView::Create(packet));
  auto remove_command_view = LeRemoveDeviceFromConnectListView::Create(le_connection_management_command_view);
  ASSERT_TRUE(remove_command_view.IsValid());

  test_hci_layer_->IncomingEvent(LeRemoveDeviceFromConnectListCompleteBuilder::Create(0x01, ErrorCode::SUCCESS));
}

TEST_F(AclManagerTest, create_connection_with_fast_mode) {
  AddressWithType remote_with_type(remote, AddressType::PUBLIC_DEVICE_ADDRESS);
  test_hci_layer_->SetCommandFuture();
  acl_manager_->CreateLeConnection(remote_with_type, true);
  test_hci_layer_->GetLastCommand(OpCode::LE_ADD_DEVICE_TO_CONNECT_LIST);
  test_hci_layer_->IncomingEvent(LeAddDeviceToConnectListCompleteBuilder::Create(0x01, ErrorCode::SUCCESS));
  test_hci_layer_->SetCommandFuture();
  auto packet = test_hci_layer_->GetLastCommand(OpCode::LE_CREATE_CONNECTION);
  auto command_view =
      LeCreateConnectionView::Create(LeConnectionManagementCommandView::Create(AclCommandView::Create(packet)));
  ASSERT_TRUE(command_view.IsValid());
  ASSERT_EQ(command_view.GetLeScanInterval(), kScanIntervalFast);
  ASSERT_EQ(command_view.GetLeScanWindow(), kScanWindowFast);
  test_hci_layer_->IncomingEvent(LeCreateConnectionStatusBuilder::Create(ErrorCode::SUCCESS, 0x01));
  auto first_connection = GetLeConnectionFuture();
  test_hci_layer_->IncomingLeMetaEvent(LeConnectionCompleteBuilder::Create(
      ErrorCode::SUCCESS,
      0x00,
      Role::PERIPHERAL,
      AddressType::PUBLIC_DEVICE_ADDRESS,
      remote,
      0x0100,
      0x0010,
      0x0C80,
      ClockAccuracy::PPM_30));
  test_hci_layer_->SetCommandFuture();
  test_hci_layer_->GetCommand(OpCode::LE_REMOVE_DEVICE_FROM_CONNECT_LIST);
  test_hci_layer_->IncomingEvent(LeRemoveDeviceFromConnectListCompleteBuilder::Create(0x01, ErrorCode::SUCCESS));
  auto first_connection_status = first_connection.wait_for(kTimeout);
  ASSERT_EQ(first_connection_status, std::future_status::ready);
}

TEST_F(AclManagerTest, create_connection_with_slow_mode) {
  AddressWithType remote_with_type(remote, AddressType::PUBLIC_DEVICE_ADDRESS);
  test_hci_layer_->SetCommandFuture();
  acl_manager_->CreateLeConnection(remote_with_type, false);
  test_hci_layer_->GetLastCommand(OpCode::LE_ADD_DEVICE_TO_CONNECT_LIST);
  test_hci_layer_->IncomingEvent(LeAddDeviceToConnectListCompleteBuilder::Create(0x01, ErrorCode::SUCCESS));
  test_hci_layer_->SetCommandFuture();
  auto packet = test_hci_layer_->GetLastCommand(OpCode::LE_CREATE_CONNECTION);
  auto command_view =
      LeCreateConnectionView::Create(LeConnectionManagementCommandView::Create(AclCommandView::Create(packet)));
  ASSERT_TRUE(command_view.IsValid());
  ASSERT_EQ(command_view.GetLeScanInterval(), kScanIntervalSlow);
  ASSERT_EQ(command_view.GetLeScanWindow(), kScanWindowSlow);
  test_hci_layer_->IncomingEvent(LeCreateConnectionStatusBuilder::Create(ErrorCode::SUCCESS, 0x01));
  auto first_connection = GetLeConnectionFuture();
  test_hci_layer_->IncomingLeMetaEvent(LeConnectionCompleteBuilder::Create(
      ErrorCode::SUCCESS,
      0x00,
      Role::PERIPHERAL,
      AddressType::PUBLIC_DEVICE_ADDRESS,
      remote,
      0x0100,
      0x0010,
      0x0C80,
      ClockAccuracy::PPM_30));
  test_hci_layer_->SetCommandFuture();
  test_hci_layer_->GetCommand(OpCode::LE_REMOVE_DEVICE_FROM_CONNECT_LIST);
  test_hci_layer_->IncomingEvent(LeRemoveDeviceFromConnectListCompleteBuilder::Create(0x01, ErrorCode::SUCCESS));
  auto first_connection_status = first_connection.wait_for(kTimeout);
  ASSERT_EQ(first_connection_status, std::future_status::ready);
}

TEST_F(AclManagerWithLeConnectionTest, acl_send_data_one_le_connection) {
  ASSERT_EQ(connection_->GetRemoteAddress(), remote_with_type_);
  ASSERT_EQ(connection_->GetHandle(), handle_);

  // Send a packet from HCI
  test_hci_layer_->IncomingAclData(handle_);
  auto queue_end = connection_->GetAclQueueEnd();

  std::unique_ptr<PacketView<kLittleEndian>> received;
  do {
    received = queue_end->TryDequeue();
  } while (received == nullptr);

  PacketView<kLittleEndian> received_packet = *received;

  // Send a packet from the connection
  SendAclData(handle_, connection_->GetAclQueueEnd());

  auto sent_packet = test_hci_layer_->OutgoingAclData();

  // Send another packet from the connection
  SendAclData(handle_, connection_->GetAclQueueEnd());

  sent_packet = test_hci_layer_->OutgoingAclData();
}

TEST_F(AclManagerWithLeConnectionTest, invoke_registered_callback_le_connection_update_success) {
  ASSERT_EQ(connection_->GetLocalAddress(), my_initiating_address);
  ASSERT_EQ(connection_->GetRemoteAddress(), remote_with_type_);
  ASSERT_EQ(connection_->GetHandle(), handle_);
  connection_->RegisterCallbacks(&mock_le_connection_management_callbacks_, client_handler_);

  std::promise<ErrorCode> promise;
  ErrorCode hci_status = hci::ErrorCode::SUCCESS;
  uint16_t connection_interval_min = 0x0012;
  uint16_t connection_interval_max = 0x0080;
  uint16_t connection_interval = (connection_interval_max + connection_interval_min) / 2;
  uint16_t connection_latency = 0x0001;
  uint16_t supervision_timeout = 0x0A00;
  test_hci_layer_->SetCommandFuture();
  connection_->LeConnectionUpdate(connection_interval_min, connection_interval_max, connection_latency,
                                  supervision_timeout, 0x10, 0x20);
  auto update_packet = test_hci_layer_->GetCommand(OpCode::LE_CONNECTION_UPDATE);
  auto update_view =
      LeConnectionUpdateView::Create(LeConnectionManagementCommandView::Create(AclCommandView::Create(update_packet)));
  ASSERT_TRUE(update_view.IsValid());
  EXPECT_EQ(update_view.GetConnectionHandle(), handle_);
  EXPECT_CALL(
      mock_le_connection_management_callbacks_,
      OnConnectionUpdate(hci_status, connection_interval, connection_latency, supervision_timeout));
  test_hci_layer_->IncomingLeMetaEvent(LeConnectionUpdateCompleteBuilder::Create(
      ErrorCode::SUCCESS, handle_, connection_interval, connection_latency, supervision_timeout));
}

TEST_F(AclManagerWithLeConnectionTest, invoke_registered_callback_le_disconnect) {
  ASSERT_EQ(connection_->GetRemoteAddress(), remote_with_type_);
  ASSERT_EQ(connection_->GetHandle(), handle_);
  connection_->RegisterCallbacks(&mock_le_connection_management_callbacks_, client_handler_);

  auto reason = ErrorCode::REMOTE_USER_TERMINATED_CONNECTION;
  EXPECT_CALL(mock_le_connection_management_callbacks_, OnDisconnection(reason));
  test_hci_layer_->Disconnect(handle_, reason);
}

TEST_F(AclManagerWithLeConnectionTest, DISABLED_invoke_registered_callback_le_disconnect_data_race) {
  ASSERT_EQ(connection_->GetRemoteAddress(), remote_with_type_);
  ASSERT_EQ(connection_->GetHandle(), handle_);
  connection_->RegisterCallbacks(&mock_le_connection_management_callbacks_, client_handler_);

  test_hci_layer_->IncomingAclData(handle_);
  auto reason = ErrorCode::REMOTE_USER_TERMINATED_CONNECTION;
  EXPECT_CALL(mock_le_connection_management_callbacks_, OnDisconnection(reason));
  test_hci_layer_->Disconnect(handle_, reason);
}

TEST_F(AclManagerWithLeConnectionTest, invoke_registered_callback_le_queue_disconnect) {
  auto reason = ErrorCode::REMOTE_USER_TERMINATED_CONNECTION;
  test_hci_layer_->Disconnect(handle_, reason);
  fake_registry_.SynchronizeModuleHandler(&HciLayer::Factory, std::chrono::milliseconds(20));
  fake_registry_.SynchronizeModuleHandler(&AclManager::Factory, std::chrono::milliseconds(20));

  EXPECT_CALL(mock_le_connection_management_callbacks_, OnDisconnection(reason));
  connection_->RegisterCallbacks(&mock_le_connection_management_callbacks_, client_handler_);
  sync_client_handler();
}

TEST_F(AclManagerWithConnectionTest, invoke_registered_callback_disconnection_complete) {
  auto reason = ErrorCode::REMOTE_USER_TERMINATED_CONNECTION;
  EXPECT_CALL(mock_connection_management_callbacks_, OnDisconnection(reason));
  test_hci_layer_->Disconnect(handle_, reason);
}

TEST_F(AclManagerWithConnectionTest, acl_send_data_one_connection) {
  // Send a packet from HCI
  test_hci_layer_->IncomingAclData(handle_);
  auto queue_end = connection_->GetAclQueueEnd();

  std::unique_ptr<PacketView<kLittleEndian>> received;
  do {
    received = queue_end->TryDequeue();
  } while (received == nullptr);

  PacketView<kLittleEndian> received_packet = *received;

  // Send a packet from the connection
  SendAclData(handle_, connection_->GetAclQueueEnd());

  auto sent_packet = test_hci_layer_->OutgoingAclData();

  // Send another packet from the connection
  SendAclData(handle_, connection_->GetAclQueueEnd());

  sent_packet = test_hci_layer_->OutgoingAclData();
  test_hci_layer_->SetCommandFuture();
  auto reason = ErrorCode::AUTHENTICATION_FAILURE;
  EXPECT_CALL(mock_connection_management_callbacks_, OnDisconnection(reason));
  connection_->Disconnect(DisconnectReason::AUTHENTICATION_FAILURE);
  auto packet = test_hci_layer_->GetCommand(OpCode::DISCONNECT);
  auto command_view = DisconnectView::Create(packet);
  ASSERT_TRUE(command_view.IsValid());
  ASSERT_EQ(command_view.GetConnectionHandle(), handle_);
  test_hci_layer_->Disconnect(handle_, reason);
}

TEST_F(AclManagerWithConnectionTest, acl_send_data_credits) {
  // Use all the credits
  for (uint16_t credits = 0; credits < test_controller_->total_acl_buffers_; credits++) {
    // Send a packet from the connection
    SendAclData(handle_, connection_->GetAclQueueEnd());

    auto sent_packet = test_hci_layer_->OutgoingAclData();
  }

  // Send another packet from the connection
  SendAclData(handle_, connection_->GetAclQueueEnd());

  test_hci_layer_->AssertNoOutgoingAclData();

  test_controller_->CompletePackets(handle_, 1);

  auto after_credits_sent_packet = test_hci_layer_->OutgoingAclData();
}

TEST_F(AclManagerWithConnectionTest, send_switch_role) {
  test_hci_layer_->SetCommandFuture();
  acl_manager_->SwitchRole(connection_->GetAddress(), Role::PERIPHERAL);
  auto packet = test_hci_layer_->GetCommand(OpCode::SWITCH_ROLE);
  auto command_view = SwitchRoleView::Create(packet);
  ASSERT_TRUE(command_view.IsValid());
  ASSERT_EQ(command_view.GetBdAddr(), connection_->GetAddress());
  ASSERT_EQ(command_view.GetRole(), Role::PERIPHERAL);

  EXPECT_CALL(mock_connection_management_callbacks_, OnRoleChange(hci::ErrorCode::SUCCESS, Role::PERIPHERAL));
  test_hci_layer_->IncomingEvent(
      RoleChangeBuilder::Create(ErrorCode::SUCCESS, connection_->GetAddress(), Role::PERIPHERAL));
}

TEST_F(AclManagerWithConnectionTest, send_write_default_link_policy_settings) {
  test_hci_layer_->SetCommandFuture();
  uint16_t link_policy_settings = 0x05;
  acl_manager_->WriteDefaultLinkPolicySettings(link_policy_settings);
  auto packet = test_hci_layer_->GetCommand(OpCode::WRITE_DEFAULT_LINK_POLICY_SETTINGS);
  auto command_view = WriteDefaultLinkPolicySettingsView::Create(packet);
  ASSERT_TRUE(command_view.IsValid());
  ASSERT_EQ(command_view.GetDefaultLinkPolicySettings(), 0x05);

  uint8_t num_packets = 1;
  test_hci_layer_->IncomingEvent(
      WriteDefaultLinkPolicySettingsCompleteBuilder::Create(num_packets, ErrorCode::SUCCESS));

  ASSERT_EQ(link_policy_settings, acl_manager_->ReadDefaultLinkPolicySettings());
}

TEST_F(AclManagerWithConnectionTest, send_authentication_requested) {
  test_hci_layer_->SetCommandFuture();
  connection_->AuthenticationRequested();
  auto packet = test_hci_layer_->GetCommand(OpCode::AUTHENTICATION_REQUESTED);
  auto command_view = AuthenticationRequestedView::Create(packet);
  ASSERT_TRUE(command_view.IsValid());

  EXPECT_CALL(mock_connection_management_callbacks_, OnAuthenticationComplete);
  test_hci_layer_->IncomingEvent(AuthenticationCompleteBuilder::Create(ErrorCode::SUCCESS, handle_));
}

TEST_F(AclManagerWithConnectionTest, send_read_clock_offset) {
  test_hci_layer_->SetCommandFuture();
  connection_->ReadClockOffset();
  auto packet = test_hci_layer_->GetCommand(OpCode::READ_CLOCK_OFFSET);
  auto command_view = ReadClockOffsetView::Create(packet);
  ASSERT_TRUE(command_view.IsValid());

  EXPECT_CALL(mock_connection_management_callbacks_, OnReadClockOffsetComplete(0x0123));
  test_hci_layer_->IncomingEvent(ReadClockOffsetCompleteBuilder::Create(ErrorCode::SUCCESS, handle_, 0x0123));
}

TEST_F(AclManagerWithConnectionTest, send_hold_mode) {
  test_hci_layer_->SetCommandFuture();
  connection_->HoldMode(0x0500, 0x0020);
  auto packet = test_hci_layer_->GetCommand(OpCode::HOLD_MODE);
  auto command_view = HoldModeView::Create(packet);
  ASSERT_TRUE(command_view.IsValid());
  ASSERT_EQ(command_view.GetHoldModeMaxInterval(), 0x0500);
  ASSERT_EQ(command_view.GetHoldModeMinInterval(), 0x0020);

  EXPECT_CALL(mock_connection_management_callbacks_, OnModeChange(ErrorCode::SUCCESS, Mode::HOLD, 0x0020));
  test_hci_layer_->IncomingEvent(ModeChangeBuilder::Create(ErrorCode::SUCCESS, handle_, Mode::HOLD, 0x0020));
}

TEST_F(AclManagerWithConnectionTest, send_sniff_mode) {
  test_hci_layer_->SetCommandFuture();
  connection_->SniffMode(0x0500, 0x0020, 0x0040, 0x0014);
  auto packet = test_hci_layer_->GetCommand(OpCode::SNIFF_MODE);
  auto command_view = SniffModeView::Create(packet);
  ASSERT_TRUE(command_view.IsValid());
  ASSERT_EQ(command_view.GetSniffMaxInterval(), 0x0500);
  ASSERT_EQ(command_view.GetSniffMinInterval(), 0x0020);
  ASSERT_EQ(command_view.GetSniffAttempt(), 0x0040);
  ASSERT_EQ(command_view.GetSniffTimeout(), 0x0014);

  EXPECT_CALL(mock_connection_management_callbacks_, OnModeChange(ErrorCode::SUCCESS, Mode::SNIFF, 0x0028));
  test_hci_layer_->IncomingEvent(ModeChangeBuilder::Create(ErrorCode::SUCCESS, handle_, Mode::SNIFF, 0x0028));
}

TEST_F(AclManagerWithConnectionTest, send_exit_sniff_mode) {
  test_hci_layer_->SetCommandFuture();
  connection_->ExitSniffMode();
  auto packet = test_hci_layer_->GetCommand(OpCode::EXIT_SNIFF_MODE);
  auto command_view = ExitSniffModeView::Create(packet);
  ASSERT_TRUE(command_view.IsValid());

  EXPECT_CALL(mock_connection_management_callbacks_, OnModeChange(ErrorCode::SUCCESS, Mode::ACTIVE, 0x00));
  test_hci_layer_->IncomingEvent(ModeChangeBuilder::Create(ErrorCode::SUCCESS, handle_, Mode::ACTIVE, 0x00));
}

TEST_F(AclManagerWithConnectionTest, send_qos_setup) {
  test_hci_layer_->SetCommandFuture();
  connection_->QosSetup(ServiceType::BEST_EFFORT, 0x1234, 0x1233, 0x1232, 0x1231);
  auto packet = test_hci_layer_->GetCommand(OpCode::QOS_SETUP);
  auto command_view = QosSetupView::Create(packet);
  ASSERT_TRUE(command_view.IsValid());
  ASSERT_EQ(command_view.GetServiceType(), ServiceType::BEST_EFFORT);
  ASSERT_EQ(command_view.GetTokenRate(), 0x1234);
  ASSERT_EQ(command_view.GetPeakBandwidth(), 0x1233);
  ASSERT_EQ(command_view.GetLatency(), 0x1232);
  ASSERT_EQ(command_view.GetDelayVariation(), 0x1231);

  EXPECT_CALL(mock_connection_management_callbacks_,
              OnQosSetupComplete(ServiceType::BEST_EFFORT, 0x1234, 0x1233, 0x1232, 0x1231));
  test_hci_layer_->IncomingEvent(QosSetupCompleteBuilder::Create(ErrorCode::SUCCESS, handle_, ServiceType::BEST_EFFORT,
                                                                 0x1234, 0x1233, 0x1232, 0x1231));
}

TEST_F(AclManagerWithConnectionTest, send_flow_specification) {
  test_hci_layer_->SetCommandFuture();
  connection_->FlowSpecification(FlowDirection::OUTGOING_FLOW, ServiceType::BEST_EFFORT, 0x1234, 0x1233, 0x1232,
                                 0x1231);
  auto packet = test_hci_layer_->GetCommand(OpCode::FLOW_SPECIFICATION);
  auto command_view = FlowSpecificationView::Create(packet);
  ASSERT_TRUE(command_view.IsValid());
  ASSERT_EQ(command_view.GetFlowDirection(), FlowDirection::OUTGOING_FLOW);
  ASSERT_EQ(command_view.GetServiceType(), ServiceType::BEST_EFFORT);
  ASSERT_EQ(command_view.GetTokenRate(), 0x1234);
  ASSERT_EQ(command_view.GetTokenBucketSize(), 0x1233);
  ASSERT_EQ(command_view.GetPeakBandwidth(), 0x1232);
  ASSERT_EQ(command_view.GetAccessLatency(), 0x1231);

  EXPECT_CALL(mock_connection_management_callbacks_,
              OnFlowSpecificationComplete(FlowDirection::OUTGOING_FLOW, ServiceType::BEST_EFFORT, 0x1234, 0x1233,
                                          0x1232, 0x1231));
  test_hci_layer_->IncomingEvent(
      FlowSpecificationCompleteBuilder::Create(ErrorCode::SUCCESS, handle_, FlowDirection::OUTGOING_FLOW,
                                               ServiceType::BEST_EFFORT, 0x1234, 0x1233, 0x1232, 0x1231));
}

TEST_F(AclManagerWithConnectionTest, send_flush) {
  test_hci_layer_->SetCommandFuture();
  connection_->Flush();
  auto packet = test_hci_layer_->GetCommand(OpCode::FLUSH);
  auto command_view = FlushView::Create(packet);
  ASSERT_TRUE(command_view.IsValid());

  EXPECT_CALL(mock_connection_management_callbacks_, OnFlushOccurred());
  test_hci_layer_->IncomingEvent(FlushOccurredBuilder::Create(handle_));
}

TEST_F(AclManagerWithConnectionTest, send_role_discovery) {
  test_hci_layer_->SetCommandFuture();
  connection_->RoleDiscovery();
  auto packet = test_hci_layer_->GetCommand(OpCode::ROLE_DISCOVERY);
  auto command_view = RoleDiscoveryView::Create(packet);
  ASSERT_TRUE(command_view.IsValid());

  EXPECT_CALL(mock_connection_management_callbacks_, OnRoleDiscoveryComplete(Role::CENTRAL));
  uint8_t num_packets = 1;
  test_hci_layer_->IncomingEvent(
      RoleDiscoveryCompleteBuilder::Create(num_packets, ErrorCode::SUCCESS, handle_, Role::CENTRAL));
}

TEST_F(AclManagerWithConnectionTest, send_read_link_policy_settings) {
  test_hci_layer_->SetCommandFuture();
  connection_->ReadLinkPolicySettings();
  auto packet = test_hci_layer_->GetCommand(OpCode::READ_LINK_POLICY_SETTINGS);
  auto command_view = ReadLinkPolicySettingsView::Create(packet);
  ASSERT_TRUE(command_view.IsValid());

  EXPECT_CALL(mock_connection_management_callbacks_, OnReadLinkPolicySettingsComplete(0x07));
  uint8_t num_packets = 1;
  test_hci_layer_->IncomingEvent(
      ReadLinkPolicySettingsCompleteBuilder::Create(num_packets, ErrorCode::SUCCESS, handle_, 0x07));
}

TEST_F(AclManagerWithConnectionTest, send_write_link_policy_settings) {
  test_hci_layer_->SetCommandFuture();
  connection_->WriteLinkPolicySettings(0x05);
  auto packet = test_hci_layer_->GetCommand(OpCode::WRITE_LINK_POLICY_SETTINGS);
  auto command_view = WriteLinkPolicySettingsView::Create(packet);
  ASSERT_TRUE(command_view.IsValid());
  ASSERT_EQ(command_view.GetLinkPolicySettings(), 0x05);

  uint8_t num_packets = 1;
  test_hci_layer_->IncomingEvent(
      WriteLinkPolicySettingsCompleteBuilder::Create(num_packets, ErrorCode::SUCCESS, handle_));
}

TEST_F(AclManagerWithConnectionTest, send_sniff_subrating) {
  test_hci_layer_->SetCommandFuture();
  connection_->SniffSubrating(0x1234, 0x1235, 0x1236);
  auto packet = test_hci_layer_->GetCommand(OpCode::SNIFF_SUBRATING);
  auto command_view = SniffSubratingView::Create(packet);
  ASSERT_TRUE(command_view.IsValid());
  ASSERT_EQ(command_view.GetMaximumLatency(), 0x1234);
  ASSERT_EQ(command_view.GetMinimumRemoteTimeout(), 0x1235);
  ASSERT_EQ(command_view.GetMinimumLocalTimeout(), 0x1236);

  uint8_t num_packets = 1;
  test_hci_layer_->IncomingEvent(SniffSubratingCompleteBuilder::Create(num_packets, ErrorCode::SUCCESS, handle_));
}

TEST_F(AclManagerWithConnectionTest, send_read_automatic_flush_timeout) {
  test_hci_layer_->SetCommandFuture();
  connection_->ReadAutomaticFlushTimeout();
  auto packet = test_hci_layer_->GetCommand(OpCode::READ_AUTOMATIC_FLUSH_TIMEOUT);
  auto command_view = ReadAutomaticFlushTimeoutView::Create(packet);
  ASSERT_TRUE(command_view.IsValid());

  EXPECT_CALL(mock_connection_management_callbacks_, OnReadAutomaticFlushTimeoutComplete(0x07ff));
  uint8_t num_packets = 1;
  test_hci_layer_->IncomingEvent(
      ReadAutomaticFlushTimeoutCompleteBuilder::Create(num_packets, ErrorCode::SUCCESS, handle_, 0x07ff));
}

TEST_F(AclManagerWithConnectionTest, send_write_automatic_flush_timeout) {
  test_hci_layer_->SetCommandFuture();
  connection_->WriteAutomaticFlushTimeout(0x07FF);
  auto packet = test_hci_layer_->GetCommand(OpCode::WRITE_AUTOMATIC_FLUSH_TIMEOUT);
  auto command_view = WriteAutomaticFlushTimeoutView::Create(packet);
  ASSERT_TRUE(command_view.IsValid());
  ASSERT_EQ(command_view.GetFlushTimeout(), 0x07FF);

  uint8_t num_packets = 1;
  test_hci_layer_->IncomingEvent(
      WriteAutomaticFlushTimeoutCompleteBuilder::Create(num_packets, ErrorCode::SUCCESS, handle_));
}

TEST_F(AclManagerWithConnectionTest, send_read_transmit_power_level) {
  test_hci_layer_->SetCommandFuture();
  connection_->ReadTransmitPowerLevel(TransmitPowerLevelType::CURRENT);
  auto packet = test_hci_layer_->GetCommand(OpCode::READ_TRANSMIT_POWER_LEVEL);
  auto command_view = ReadTransmitPowerLevelView::Create(packet);
  ASSERT_TRUE(command_view.IsValid());
  ASSERT_EQ(command_view.GetTransmitPowerLevelType(), TransmitPowerLevelType::CURRENT);

  EXPECT_CALL(mock_connection_management_callbacks_, OnReadTransmitPowerLevelComplete(0x07));
  uint8_t num_packets = 1;
  test_hci_layer_->IncomingEvent(
      ReadTransmitPowerLevelCompleteBuilder::Create(num_packets, ErrorCode::SUCCESS, handle_, 0x07));
}

TEST_F(AclManagerWithConnectionTest, send_read_link_supervision_timeout) {
  test_hci_layer_->SetCommandFuture();
  connection_->ReadLinkSupervisionTimeout();
  auto packet = test_hci_layer_->GetCommand(OpCode::READ_LINK_SUPERVISION_TIMEOUT);
  auto command_view = ReadLinkSupervisionTimeoutView::Create(packet);
  ASSERT_TRUE(command_view.IsValid());

  EXPECT_CALL(mock_connection_management_callbacks_, OnReadLinkSupervisionTimeoutComplete(0x5677));
  uint8_t num_packets = 1;
  test_hci_layer_->IncomingEvent(
      ReadLinkSupervisionTimeoutCompleteBuilder::Create(num_packets, ErrorCode::SUCCESS, handle_, 0x5677));
}

TEST_F(AclManagerWithConnectionTest, send_write_link_supervision_timeout) {
  test_hci_layer_->SetCommandFuture();
  connection_->WriteLinkSupervisionTimeout(0x5678);
  auto packet = test_hci_layer_->GetCommand(OpCode::WRITE_LINK_SUPERVISION_TIMEOUT);
  auto command_view = WriteLinkSupervisionTimeoutView::Create(packet);
  ASSERT_TRUE(command_view.IsValid());
  ASSERT_EQ(command_view.GetLinkSupervisionTimeout(), 0x5678);

  uint8_t num_packets = 1;
  test_hci_layer_->IncomingEvent(
      WriteLinkSupervisionTimeoutCompleteBuilder::Create(num_packets, ErrorCode::SUCCESS, handle_));
}

TEST_F(AclManagerWithConnectionTest, send_read_failed_contact_counter) {
  test_hci_layer_->SetCommandFuture();
  connection_->ReadFailedContactCounter();
  auto packet = test_hci_layer_->GetCommand(OpCode::READ_FAILED_CONTACT_COUNTER);
  auto command_view = ReadFailedContactCounterView::Create(packet);
  ASSERT_TRUE(command_view.IsValid());

  EXPECT_CALL(mock_connection_management_callbacks_, OnReadFailedContactCounterComplete(0x00));
  uint8_t num_packets = 1;
  test_hci_layer_->IncomingEvent(
      ReadFailedContactCounterCompleteBuilder::Create(num_packets, ErrorCode::SUCCESS, handle_, 0x00));
}

TEST_F(AclManagerWithConnectionTest, send_reset_failed_contact_counter) {
  test_hci_layer_->SetCommandFuture();
  connection_->ResetFailedContactCounter();
  auto packet = test_hci_layer_->GetCommand(OpCode::RESET_FAILED_CONTACT_COUNTER);
  auto command_view = ResetFailedContactCounterView::Create(packet);
  ASSERT_TRUE(command_view.IsValid());

  uint8_t num_packets = 1;
  test_hci_layer_->IncomingEvent(
      ResetFailedContactCounterCompleteBuilder::Create(num_packets, ErrorCode::SUCCESS, handle_));
}

TEST_F(AclManagerWithConnectionTest, send_read_link_quality) {
  test_hci_layer_->SetCommandFuture();
  connection_->ReadLinkQuality();
  auto packet = test_hci_layer_->GetCommand(OpCode::READ_LINK_QUALITY);
  auto command_view = ReadLinkQualityView::Create(packet);
  ASSERT_TRUE(command_view.IsValid());

  EXPECT_CALL(mock_connection_management_callbacks_, OnReadLinkQualityComplete(0xa9));
  uint8_t num_packets = 1;
  test_hci_layer_->IncomingEvent(
      ReadLinkQualityCompleteBuilder::Create(num_packets, ErrorCode::SUCCESS, handle_, 0xa9));
}

TEST_F(AclManagerWithConnectionTest, send_read_afh_channel_map) {
  test_hci_layer_->SetCommandFuture();
  connection_->ReadAfhChannelMap();
  auto packet = test_hci_layer_->GetCommand(OpCode::READ_AFH_CHANNEL_MAP);
  auto command_view = ReadAfhChannelMapView::Create(packet);
  ASSERT_TRUE(command_view.IsValid());
  std::array<uint8_t, 10> afh_channel_map = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09};

  EXPECT_CALL(mock_connection_management_callbacks_,
              OnReadAfhChannelMapComplete(AfhMode::AFH_ENABLED, afh_channel_map));
  uint8_t num_packets = 1;
  test_hci_layer_->IncomingEvent(ReadAfhChannelMapCompleteBuilder::Create(num_packets, ErrorCode::SUCCESS, handle_,
                                                                          AfhMode::AFH_ENABLED, afh_channel_map));
}

TEST_F(AclManagerWithConnectionTest, send_read_rssi) {
  test_hci_layer_->SetCommandFuture();
  connection_->ReadRssi();
  auto packet = test_hci_layer_->GetCommand(OpCode::READ_RSSI);
  auto command_view = ReadRssiView::Create(packet);
  ASSERT_TRUE(command_view.IsValid());
  sync_client_handler();
  EXPECT_CALL(mock_connection_management_callbacks_, OnReadRssiComplete(0x00));
  uint8_t num_packets = 1;
  test_hci_layer_->IncomingEvent(ReadRssiCompleteBuilder::Create(num_packets, ErrorCode::SUCCESS, handle_, 0x00));
}

TEST_F(AclManagerWithConnectionTest, send_read_clock) {
  test_hci_layer_->SetCommandFuture();
  connection_->ReadClock(WhichClock::LOCAL);
  auto packet = test_hci_layer_->GetCommand(OpCode::READ_CLOCK);
  auto command_view = ReadClockView::Create(packet);
  ASSERT_TRUE(command_view.IsValid());
  ASSERT_EQ(command_view.GetWhichClock(), WhichClock::LOCAL);

  EXPECT_CALL(mock_connection_management_callbacks_, OnReadClockComplete(0x00002e6a, 0x0000));
  uint8_t num_packets = 1;
  test_hci_layer_->IncomingEvent(
      ReadClockCompleteBuilder::Create(num_packets, ErrorCode::SUCCESS, handle_, 0x00002e6a, 0x0000));
}

class AclManagerWithResolvableAddressTest : public AclManagerNoCallbacksTest {
 protected:
  void SetUp() override {
    test_hci_layer_ = new TestHciLayer;  // Ownership is transferred to registry
    test_controller_ = new TestController;
    fake_registry_.InjectTestModule(&HciLayer::Factory, test_hci_layer_);
    fake_registry_.InjectTestModule(&Controller::Factory, test_controller_);
    client_handler_ = fake_registry_.GetTestModuleHandler(&HciLayer::Factory);
    ASSERT_NE(client_handler_, nullptr);
    test_hci_layer_->SetCommandFuture();
    fake_registry_.Start<AclManager>(&thread_);
    acl_manager_ = static_cast<AclManager*>(fake_registry_.GetModuleUnderTest(&AclManager::Factory));
    Address::FromString("A1:A2:A3:A4:A5:A6", remote);

    hci::Address address;
    Address::FromString("D0:05:04:03:02:01", address);
    hci::AddressWithType address_with_type(address, hci::AddressType::RANDOM_DEVICE_ADDRESS);
    acl_manager_->RegisterCallbacks(&mock_connection_callback_, client_handler_);
    acl_manager_->RegisterLeCallbacks(&mock_le_connection_callbacks_, client_handler_);
    auto minimum_rotation_time = std::chrono::milliseconds(7 * 60 * 1000);
    auto maximum_rotation_time = std::chrono::milliseconds(15 * 60 * 1000);
    acl_manager_->SetPrivacyPolicyForInitiatorAddress(
        LeAddressManager::AddressPolicy::USE_RESOLVABLE_ADDRESS,
        address_with_type,
        minimum_rotation_time,
        maximum_rotation_time);

    test_hci_layer_->GetLastCommand(OpCode::LE_SET_RANDOM_ADDRESS);
    test_hci_layer_->IncomingEvent(LeSetRandomAddressCompleteBuilder::Create(0x01, ErrorCode::SUCCESS));
  }
};

TEST_F(AclManagerWithResolvableAddressTest, create_connection_cancel_fail) {
  auto remote_with_type_ = AddressWithType(remote, AddressType::PUBLIC_DEVICE_ADDRESS);
  test_hci_layer_->SetCommandFuture();
  acl_manager_->CreateLeConnection(remote_with_type_, true);

  // Set random address
  test_hci_layer_->GetLastCommand(OpCode::LE_SET_RANDOM_ADDRESS);
  test_hci_layer_->SetCommandFuture();
  test_hci_layer_->IncomingEvent(LeSetRandomAddressCompleteBuilder::Create(0x01, ErrorCode::SUCCESS));

  // Add device to connect list
  test_hci_layer_->GetLastCommand(OpCode::LE_ADD_DEVICE_TO_CONNECT_LIST);
  test_hci_layer_->SetCommandFuture();
  test_hci_layer_->IncomingEvent(LeAddDeviceToConnectListCompleteBuilder::Create(0x01, ErrorCode::SUCCESS));

  // send create connection command
  test_hci_layer_->GetLastCommand(OpCode::LE_CREATE_CONNECTION);
  test_hci_layer_->IncomingEvent(LeCreateConnectionStatusBuilder::Create(ErrorCode::SUCCESS, 0x01));

  fake_registry_.SynchronizeModuleHandler(&HciLayer::Factory, std::chrono::milliseconds(20));
  fake_registry_.SynchronizeModuleHandler(&AclManager::Factory, std::chrono::milliseconds(20));

  Address remote2;
  Address::FromString("A1:A2:A3:A4:A5:A7", remote2);
  auto remote_with_type2 = AddressWithType(remote2, AddressType::PUBLIC_DEVICE_ADDRESS);

  // create another connection
  test_hci_layer_->SetCommandFuture();
  acl_manager_->CreateLeConnection(remote_with_type2, true);

  // cancel previous connection
  test_hci_layer_->GetLastCommand(OpCode::LE_CREATE_CONNECTION_CANCEL);

  // receive connection complete of first device
  test_hci_layer_->IncomingLeMetaEvent(LeConnectionCompleteBuilder::Create(
      ErrorCode::SUCCESS,
      0x123,
      Role::PERIPHERAL,
      AddressType::PUBLIC_DEVICE_ADDRESS,
      remote,
      0x0100,
      0x0010,
      0x0011,
      ClockAccuracy::PPM_30));

  // receive create connection cancel complete with ErrorCode::CONNECTION_ALREADY_EXISTS
  test_hci_layer_->SetCommandFuture();
  test_hci_layer_->IncomingEvent(
      LeCreateConnectionCancelCompleteBuilder::Create(0x01, ErrorCode::CONNECTION_ALREADY_EXISTS));

  // Add another device to connect list
  test_hci_layer_->GetLastCommand(OpCode::LE_ADD_DEVICE_TO_CONNECT_LIST);
  test_hci_layer_->IncomingEvent(LeAddDeviceToConnectListCompleteBuilder::Create(0x01, ErrorCode::SUCCESS));
}

class AclManagerLifeCycleTest : public AclManagerNoCallbacksTest {
 protected:
  void SetUp() override {
    AclManagerNoCallbacksTest::SetUp();
    acl_manager_->RegisterCallbacks(&mock_connection_callback_, client_handler_);
    acl_manager_->RegisterLeCallbacks(&mock_le_connection_callbacks_, client_handler_);
  }

  AddressWithType remote_with_type_;
  uint16_t handle_{0x123};
};

TEST_F(AclManagerLifeCycleTest, unregister_classic_after_create_connection) {
  // Inject create connection
  test_hci_layer_->SetCommandFuture();
  acl_manager_->CreateConnection(remote);
  auto connection_command = test_hci_layer_->GetCommand(OpCode::CREATE_CONNECTION);

  // Unregister callbacks after sending connection request
  auto promise = std::promise<void>();
  auto future = promise.get_future();
  acl_manager_->UnregisterCallbacks(&mock_connection_callback_, std::move(promise));
  future.get();

  // Inject peer sending connection complete
  auto connection_future = GetConnectionFuture();
  test_hci_layer_->IncomingEvent(
      ConnectionCompleteBuilder::Create(ErrorCode::SUCCESS, handle_, remote, LinkType::ACL, Enable::DISABLED));
  auto connection_future_status = connection_future.wait_for(kTimeout);
  ASSERT_NE(connection_future_status, std::future_status::ready);
}

TEST_F(AclManagerLifeCycleTest, unregister_classic_before_connection_request) {
  ClassOfDevice class_of_device;

  // Unregister callbacks before receiving connection request
  auto promise = std::promise<void>();
  auto future = promise.get_future();
  acl_manager_->UnregisterCallbacks(&mock_connection_callback_, std::move(promise));
  future.get();

  // Inject peer sending connection request
  auto connection_future = GetConnectionFuture();
  test_hci_layer_->IncomingEvent(
      ConnectionRequestBuilder::Create(remote, class_of_device, ConnectionRequestLinkType::ACL));
  auto connection_future_status = connection_future.wait_for(kTimeout);
  ASSERT_NE(connection_future_status, std::future_status::ready);

  test_hci_layer_->GetLastCommand(OpCode::REJECT_CONNECTION_REQUEST);
}

TEST_F(AclManagerLifeCycleTest, unregister_le_before_connection_complete) {
  AddressWithType remote_with_type(remote, AddressType::PUBLIC_DEVICE_ADDRESS);
  test_hci_layer_->SetCommandFuture();
  acl_manager_->CreateLeConnection(remote_with_type, true);
  test_hci_layer_->GetLastCommand(OpCode::LE_ADD_DEVICE_TO_CONNECT_LIST);
  test_hci_layer_->IncomingEvent(LeAddDeviceToConnectListCompleteBuilder::Create(0x01, ErrorCode::SUCCESS));

  test_hci_layer_->SetCommandFuture();
  auto packet = test_hci_layer_->GetLastCommand(OpCode::LE_CREATE_CONNECTION);
  auto le_connection_management_command_view =
      LeConnectionManagementCommandView::Create(AclCommandView::Create(packet));
  auto command_view = LeCreateConnectionView::Create(le_connection_management_command_view);
  ASSERT_TRUE(command_view.IsValid());
  if (use_connect_list_) {
    ASSERT_EQ(command_view.GetPeerAddress(), hci::Address::kEmpty);
  } else {
    ASSERT_EQ(command_view.GetPeerAddress(), remote);
  }
  ASSERT_EQ(command_view.GetPeerAddressType(), AddressType::PUBLIC_DEVICE_ADDRESS);

  // Unregister callbacks after sending connection request
  auto promise = std::promise<void>();
  auto future = promise.get_future();
  acl_manager_->UnregisterLeCallbacks(&mock_le_connection_callbacks_, std::move(promise));
  future.get();

  auto connection_future = GetLeConnectionFuture();
  test_hci_layer_->IncomingLeMetaEvent(LeConnectionCompleteBuilder::Create(
      ErrorCode::SUCCESS,
      0x123,
      Role::PERIPHERAL,
      AddressType::PUBLIC_DEVICE_ADDRESS,
      remote,
      0x0100,
      0x0010,
      0x0500,
      ClockAccuracy::PPM_30));

  auto connection_future_status = connection_future.wait_for(kTimeout);
  ASSERT_NE(connection_future_status, std::future_status::ready);
}

TEST_F(AclManagerLifeCycleTest, unregister_le_before_enhanced_connection_complete) {
  AddressWithType remote_with_type(remote, AddressType::PUBLIC_DEVICE_ADDRESS);
  test_hci_layer_->SetCommandFuture();
  acl_manager_->CreateLeConnection(remote_with_type, true);
  test_hci_layer_->GetLastCommand(OpCode::LE_ADD_DEVICE_TO_CONNECT_LIST);
  test_hci_layer_->IncomingEvent(LeAddDeviceToConnectListCompleteBuilder::Create(0x01, ErrorCode::SUCCESS));

  test_hci_layer_->SetCommandFuture();
  auto packet = test_hci_layer_->GetLastCommand(OpCode::LE_CREATE_CONNECTION);
  auto le_connection_management_command_view =
      LeConnectionManagementCommandView::Create(AclCommandView::Create(packet));
  auto command_view = LeCreateConnectionView::Create(le_connection_management_command_view);
  ASSERT_TRUE(command_view.IsValid());
  if (use_connect_list_) {
    ASSERT_EQ(command_view.GetPeerAddress(), hci::Address::kEmpty);
  } else {
    ASSERT_EQ(command_view.GetPeerAddress(), remote);
  }
  ASSERT_EQ(command_view.GetPeerAddressType(), AddressType::PUBLIC_DEVICE_ADDRESS);

  // Unregister callbacks after sending connection request
  auto promise = std::promise<void>();
  auto future = promise.get_future();
  acl_manager_->UnregisterLeCallbacks(&mock_le_connection_callbacks_, std::move(promise));
  future.get();

  auto connection_future = GetLeConnectionFuture();
  test_hci_layer_->IncomingLeMetaEvent(LeEnhancedConnectionCompleteBuilder::Create(
      ErrorCode::SUCCESS,
      0x123,
      Role::PERIPHERAL,
      AddressType::PUBLIC_DEVICE_ADDRESS,
      remote,
      Address::kEmpty,
      Address::kEmpty,
      0x0100,
      0x0010,
      0x0500,
      ClockAccuracy::PPM_30));

  auto connection_future_status = connection_future.wait_for(kTimeout);
  ASSERT_NE(connection_future_status, std::future_status::ready);
}

TEST_F(AclManagerWithConnectionTest, remote_sco_connect_request) {
  ClassOfDevice class_of_device;

  EXPECT_CALL(mock_connection_callback_, HACK_OnScoConnectRequest(remote, class_of_device));

  test_hci_layer_->IncomingEvent(
      ConnectionRequestBuilder::Create(remote, class_of_device, ConnectionRequestLinkType::SCO));
  fake_registry_.SynchronizeModuleHandler(&HciLayer::Factory, std::chrono::milliseconds(20));
  fake_registry_.SynchronizeModuleHandler(&AclManager::Factory, std::chrono::milliseconds(20));
  fake_registry_.SynchronizeModuleHandler(&HciLayer::Factory, std::chrono::milliseconds(20));
}

TEST_F(AclManagerWithConnectionTest, remote_esco_connect_request) {
  ClassOfDevice class_of_device;

  EXPECT_CALL(mock_connection_callback_, HACK_OnEscoConnectRequest(remote, class_of_device));

  test_hci_layer_->IncomingEvent(
      ConnectionRequestBuilder::Create(remote, class_of_device, ConnectionRequestLinkType::ESCO));
  fake_registry_.SynchronizeModuleHandler(&HciLayer::Factory, std::chrono::milliseconds(20));
  fake_registry_.SynchronizeModuleHandler(&AclManager::Factory, std::chrono::milliseconds(20));
  fake_registry_.SynchronizeModuleHandler(&HciLayer::Factory, std::chrono::milliseconds(20));
}

}  // namespace
}  // namespace acl_manager
}  // namespace hci
}  // namespace bluetooth
