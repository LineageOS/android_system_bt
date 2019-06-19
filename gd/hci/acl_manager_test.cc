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

#include "common/address.h"
#include "common/bind.h"
#include "hci/controller.h"
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

std::unique_ptr<BasePacketBuilder> NextPayload(uint16_t handle) {
  static uint32_t packet_number = 1;
  auto payload = std::make_unique<RawBuilder>();
  payload->AddOctets2(handle);
  payload->AddOctets4(packet_number++);
  return std::move(payload);
}

std::unique_ptr<AclPacketBuilder> NextAclPacket(uint16_t handle) {
  PacketBoundaryFlag packet_boundary_flag = PacketBoundaryFlag::FIRST_AUTOMATICALLY_FLUSHABLE;
  BroadcastFlag broadcast_flag = BroadcastFlag::ACTIVE_SLAVE_BROADCAST;
  return AclPacketBuilder::Create(handle, packet_boundary_flag, broadcast_flag, NextPayload(handle));
}

class TestController : public Controller {
 public:
  void RegisterCompletedAclPacketsCallback(common::Callback<void(uint16_t /* handle */, uint16_t /* packets */)> cb,
                                           os::Handler* handler) override {
    acl_cb_ = cb;
    acl_cb_handler_ = handler;
  }

  uint16_t ReadControllerAclPacketLength() override {
    return acl_buffer_length_;
  }

  uint16_t ReadControllerNumAclPacketBuffers() override {
    return total_acl_buffers_;
  }

  void CompletePackets(uint16_t handle, uint16_t packets) {
    acl_cb_handler_->Post(common::BindOnce(acl_cb_, handle, packets));
  }

  uint16_t acl_buffer_length_ = 1024;
  uint16_t total_acl_buffers_ = 2;
  common::Callback<void(uint16_t /* handle */, uint16_t /* packets */)> acl_cb_;
  os::Handler* acl_cb_handler_ = nullptr;

 protected:
  void Start() override {}
  void Stop() override {}
  void ListDependencies(ModuleList* list) override {}
};

class TestHciLayer : public HciLayer {
 public:
  void EnqueueCommand(std::unique_ptr<CommandPacketBuilder> command,
                      common::OnceCallback<void(CommandStatusView)> on_status, os::Handler* handler) override {
    command_queue_.push(std::move(command));
  }

  void EnqueueCommand(std::unique_ptr<CommandPacketBuilder> command,
                      common::OnceCallback<void(CommandCompleteView)> on_complete, os::Handler* handler) override {
    command_queue_.push(std::move(command));
  }

  std::unique_ptr<CommandPacketBuilder> GetLastCommand() {
    auto last = std::move(command_queue_.front());
    command_queue_.pop();
    return last;
  }

  void RegisterEventHandler(EventCode event_code, common::Callback<void(EventPacketView)> event_handler,
                            os::Handler* handler) override {
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

  void IncomingAclData(uint16_t handle) {
    os::Handler* hci_handler = GetHandler();
    auto* queue_end = acl_queue_.GetDownEnd();
    std::promise<void> promise;
    auto future = promise.get_future();
    queue_end->RegisterEnqueue(hci_handler,
                               common::Bind(
                                   [](decltype(queue_end) queue_end, uint16_t handle, std::promise<void> promise) {
                                     auto packet = GetPacketView(NextAclPacket(handle));
                                     AclPacketView acl2 = AclPacketView::Create(packet);
                                     queue_end->UnregisterEnqueue();
                                     promise.set_value();
                                     return std::make_unique<AclPacketView>(acl2);
                                   },
                                   queue_end, handle, common::Passed(std::move(promise))));
    future.wait();
  }

  void AssertNoOutgoingAclData() {
    auto queue_end = acl_queue_.GetDownEnd();
    EXPECT_EQ(queue_end->TryDequeue(), nullptr);
  }

  PacketView<kLittleEndian> OutgoingAclData() {
    auto queue_end = acl_queue_.GetDownEnd();
    std::unique_ptr<AclPacketBuilder> received;
    do {
      received = queue_end->TryDequeue();
    } while (received == nullptr);

    return GetPacketView(std::move(received));
  }

  BidiQueueEnd<AclPacketBuilder, AclPacketView>* GetAclQueueEnd() override {
    return acl_queue_.GetUpEnd();
  }

  void ListDependencies(ModuleList* list) override {}
  void Start() override {}
  void Stop() override {}

 private:
  std::map<EventCode, common::Callback<void(EventPacketView)>> registered_events_;
  BidiQueue<AclPacketView, AclPacketBuilder> acl_queue_{3 /* TODO: Set queue depth */};

  std::queue<std::unique_ptr<CommandPacketBuilder>> command_queue_;
};

class AclManagerNoCallbacksTest : public ::testing::Test {
 protected:
  void SetUp() override {
    test_hci_layer_ = new TestHciLayer;  // Ownership is transferred to registry
    test_controller_ = new TestController;
    fake_registry_.InjectTestModule(&HciLayer::Factory, test_hci_layer_);
    fake_registry_.InjectTestModule(&Controller::Factory, test_controller_);
    client_handler_ = fake_registry_.GetTestModuleHandler(&HciLayer::Factory);
    EXPECT_NE(client_handler_, nullptr);
    fake_registry_.Start<AclManager>(&thread_);
    acl_manager_ = static_cast<AclManager*>(fake_registry_.GetModuleUnderTest(&AclManager::Factory));
    Address::FromString("A1:A2:A3:A4:A5:A6", remote);
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

  size_t GetNumConnections() {
    return mock_connection_callback_.connections_.size();
  }

  AclConnection& GetLastConnection() {
    return mock_connection_callback_.connections_.back();
  }

  void SendAclData(uint16_t handle, AclConnection connection) {
    auto queue_end = connection.GetAclQueueEnd();
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
    future.wait();
  }

  class MockConnectionCallback : public ConnectionCallbacks {
   public:
    void OnConnectSuccess(AclConnection connection) override {
      connections_.push_back(connection);
    }
    MOCK_METHOD2(OnConnectFail, void(Address, ErrorCode reason));

    std::list<AclConnection> connections_;

  } mock_connection_callback_;
};

class AclManagerTest : public AclManagerNoCallbacksTest {
 protected:
  void SetUp() override {
    AclManagerNoCallbacksTest::SetUp();
    acl_manager_->RegisterCallbacks(&mock_connection_callback_, client_handler_);
  }
};

TEST_F(AclManagerTest, startup_teardown) {}

TEST_F(AclManagerNoCallbacksTest, acl_connection_before_registered_callbacks) {
  common::ClassOfDevice class_of_device;

  test_hci_layer_->IncomingEvent(
      ConnectionRequestBuilder::Create(remote, class_of_device, ConnectionRequestLinkType::ACL));
  fake_registry_.SynchronizeModuleHandler(&HciLayer::Factory, std::chrono::milliseconds(20));
  fake_registry_.SynchronizeModuleHandler(&AclManager::Factory, std::chrono::milliseconds(20));
  fake_registry_.SynchronizeModuleHandler(&HciLayer::Factory, std::chrono::milliseconds(20));
  auto last_command = test_hci_layer_->GetLastCommand();
  auto packet = GetPacketView(std::move(last_command));
  CommandPacketView command = CommandPacketView::Create(packet);
  EXPECT_TRUE(command.IsValid());
  OpCode op_code = command.GetOpCode();
  EXPECT_EQ(op_code, OpCode::REJECT_CONNECTION_REQUEST);
}

TEST_F(AclManagerTest, invoke_registered_callback_connection_complete_success) {
  uint16_t handle = 1;

  acl_manager_->CreateConnection(remote);

  size_t num_connections = GetNumConnections();
  test_hci_layer_->IncomingEvent(
      ConnectionCompleteBuilder::Create(ErrorCode::SUCCESS, handle, remote, LinkType::ACL, Enable::DISABLED));

  while (GetNumConnections() == num_connections)
    ;
  AclConnection& connection = GetLastConnection();
  ASSERT_EQ(connection.GetAddress(), remote);
}

TEST_F(AclManagerTest, invoke_registered_callback_connection_complete_fail) {
  uint16_t handle = 0x123;

  acl_manager_->CreateConnection(remote);

  EXPECT_CALL(mock_connection_callback_, OnConnectFail(remote, ErrorCode::PAGE_TIMEOUT));
  test_hci_layer_->IncomingEvent(
      ConnectionCompleteBuilder::Create(ErrorCode::PAGE_TIMEOUT, handle, remote, LinkType::ACL, Enable::DISABLED));
  fake_registry_.SynchronizeModuleHandler(&HciLayer::Factory, std::chrono::milliseconds(20));
  fake_registry_.SynchronizeModuleHandler(&AclManager::Factory, std::chrono::milliseconds(20));
  fake_registry_.SynchronizeModuleHandler(&HciLayer::Factory, std::chrono::milliseconds(20));
}

TEST_F(AclManagerTest, invoke_registered_callback_disconnection_complete) {
  uint16_t handle = 0x123;

  acl_manager_->CreateConnection(remote);

  size_t num_connections = GetNumConnections();
  test_hci_layer_->IncomingEvent(
      ConnectionCompleteBuilder::Create(ErrorCode::SUCCESS, handle, remote, LinkType::ACL, Enable::DISABLED));

  while (GetNumConnections() == num_connections)
    ;

  AclConnection& connection = GetLastConnection();

  // Register the disconnect handler
  std::promise<ErrorCode> promise;
  auto future = promise.get_future();
  connection.RegisterDisconnectCallback(
      common::BindOnce([](std::promise<ErrorCode> promise, ErrorCode reason) { promise.set_value(reason); },
                       std::move(promise)),
      client_handler_);

  test_hci_layer_->IncomingEvent(
      DisconnectionCompleteBuilder::Create(ErrorCode::SUCCESS, handle, ErrorCode::REMOTE_USER_TERMINATED_CONNECTION));

  future.wait();
  ASSERT_EQ(ErrorCode::REMOTE_USER_TERMINATED_CONNECTION, future.get());

  fake_registry_.SynchronizeModuleHandler(&HciLayer::Factory, std::chrono::milliseconds(20));
}

TEST_F(AclManagerTest, acl_connection_finish_after_disconnected) {
  uint16_t handle = 0x123;

  acl_manager_->CreateConnection(remote);

  size_t num_connections = GetNumConnections();
  test_hci_layer_->IncomingEvent(
      ConnectionCompleteBuilder::Create(ErrorCode::SUCCESS, handle, remote, LinkType::ACL, Enable::DISABLED));

  while (GetNumConnections() == num_connections)
    ;

  AclConnection& connection = GetLastConnection();

  // Register the disconnect handler
  std::promise<ErrorCode> promise;
  auto future = promise.get_future();
  connection.RegisterDisconnectCallback(
      common::BindOnce([](std::promise<ErrorCode> promise, ErrorCode reason) { promise.set_value(reason); },
                       std::move(promise)),
      client_handler_);

  test_hci_layer_->IncomingEvent(DisconnectionCompleteBuilder::Create(
      ErrorCode::SUCCESS, handle, ErrorCode::REMOTE_DEVICE_TERMINATED_CONNECTION_POWER_OFF));

  future.wait();
  ASSERT_EQ(ErrorCode::REMOTE_DEVICE_TERMINATED_CONNECTION_POWER_OFF, future.get());

  connection.Finish();
}

TEST_F(AclManagerTest, acl_send_data_one_connection) {
  uint16_t handle = 0x123;

  acl_manager_->CreateConnection(remote);

  size_t num_connections = GetNumConnections();
  test_hci_layer_->IncomingEvent(
      ConnectionCompleteBuilder::Create(ErrorCode::SUCCESS, handle, remote, LinkType::ACL, Enable::DISABLED));

  while (GetNumConnections() == num_connections)
    ;

  AclConnection& connection = GetLastConnection();

  // Register the disconnect handler
  connection.RegisterDisconnectCallback(common::Bind([](AclConnection conn, ErrorCode) { conn.Finish(); }, connection),
                                        client_handler_);

  // Send a packet from HCI
  test_hci_layer_->IncomingAclData(handle);
  auto queue_end = connection.GetAclQueueEnd();

  std::unique_ptr<PacketView<kLittleEndian>> received;
  do {
    received = queue_end->TryDequeue();
  } while (received == nullptr);

  PacketView<kLittleEndian> received_packet = *received;

  // Send a packet from the connection
  SendAclData(handle, connection);

  auto sent_packet = test_hci_layer_->OutgoingAclData();

  // Send another packet from the connection
  SendAclData(handle, connection);

  sent_packet = test_hci_layer_->OutgoingAclData();
  connection.Disconnect(DisconnectReason::AUTHENTICATION_FAILURE);
}

TEST_F(AclManagerTest, acl_send_data_credits) {
  uint16_t handle = 0x123;

  acl_manager_->CreateConnection(remote);

  size_t num_connections = GetNumConnections();
  test_hci_layer_->IncomingEvent(
      ConnectionCompleteBuilder::Create(ErrorCode::SUCCESS, handle, remote, LinkType::ACL, Enable::DISABLED));

  while (GetNumConnections() == num_connections)
    ;

  AclConnection& connection = GetLastConnection();

  // Register the disconnect handler
  connection.RegisterDisconnectCallback(
      common::BindOnce([](AclConnection conn, ErrorCode) { conn.Finish(); }, std::move(connection)), client_handler_);

  // Use all the credits
  for (uint16_t credits = 0; credits < test_controller_->total_acl_buffers_; credits++) {
    // Send a packet from the connection
    SendAclData(handle, connection);

    auto sent_packet = test_hci_layer_->OutgoingAclData();
  }

  // Send another packet from the connection
  SendAclData(handle, connection);

  test_hci_layer_->AssertNoOutgoingAclData();

  test_controller_->CompletePackets(handle, 1);

  auto after_credits_sent_packet = test_hci_layer_->OutgoingAclData();

  connection.Disconnect(DisconnectReason::AUTHENTICATION_FAILURE);
}

}  // namespace
}  // namespace hci
}  // namespace bluetooth
