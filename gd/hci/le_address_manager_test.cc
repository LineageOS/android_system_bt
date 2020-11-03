/*
 * Copyright 2020 The Android Open Source Project
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

#include "hci/le_address_manager.h"

#include <gtest/gtest.h>

#include "os/log.h"
#include "packet/raw_builder.h"

using ::bluetooth::crypto_toolbox::Octet16;
using ::bluetooth::os::Handler;
using ::bluetooth::os::Thread;

namespace bluetooth {
namespace hci {

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
  void EnqueueCommand(
      std::unique_ptr<CommandPacketBuilder> command,
      common::ContextualOnceCallback<void(CommandCompleteView)> on_complete) override {
    command_queue_.push(std::move(command));
    command_complete_callbacks.push_front(std::move(on_complete));
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

  CommandPacketView GetLastCommand() {
    if (command_queue_.size() == 0) {
      return CommandPacketView::Create(PacketView<kLittleEndian>(std::make_shared<std::vector<uint8_t>>()));
    }
    auto last = std::move(command_queue_.front());
    command_queue_.pop();
    return CommandPacketView::Create(GetPacketView(std::move(last)));
  }

  CommandPacketView GetCommandPacket(OpCode op_code) {
    if (!command_queue_.empty() && command_future_ != nullptr) {
      command_promise_.reset();
      command_future_.reset();
    } else if (command_future_ != nullptr) {
      auto result = command_future_->wait_for(std::chrono::milliseconds(1000));
      EXPECT_NE(std::future_status::timeout, result);
    }
    ASSERT_LOG(
        !command_queue_.empty(), "Expecting command %s but command queue was empty", OpCodeText(op_code).c_str());
    CommandPacketView command_packet_view = GetLastCommand();
    EXPECT_TRUE(command_packet_view.IsValid());
    EXPECT_EQ(command_packet_view.GetOpCode(), op_code);
    return command_packet_view;
  }

  void IncomingEvent(std::unique_ptr<EventPacketBuilder> event_builder) {
    auto packet = GetPacketView(std::move(event_builder));
    EventPacketView event = EventPacketView::Create(packet);
    ASSERT_TRUE(event.IsValid());
    CommandCompleteCallback(event);
  }

  void CommandCompleteCallback(EventPacketView event) {
    CommandCompleteView complete_view = CommandCompleteView::Create(event);
    ASSERT_TRUE(complete_view.IsValid());
    std::move(command_complete_callbacks.front()).Invoke(complete_view);
    command_complete_callbacks.pop_front();
  }

  void ListDependencies(ModuleList* list) override {}
  void Start() override {}
  void Stop() override {}

 private:
  std::list<common::ContextualOnceCallback<void(CommandCompleteView)>> command_complete_callbacks;
  std::queue<std::unique_ptr<CommandPacketBuilder>> command_queue_;
  std::unique_ptr<std::promise<void>> command_promise_;
  std::unique_ptr<std::future<void>> command_future_;
};

class RotatorClient : public LeAddressManagerCallback {
 public:
  RotatorClient(LeAddressManager* le_address_manager, size_t id) : le_address_manager_(le_address_manager), id_(id){};

  void OnPause() {
    paused = true;
    le_address_manager_->AckPause(this);
  }

  void OnResume() {
    paused = false;
    le_address_manager_->AckResume(this);
    if (resume_promise_ != nullptr) {
      resume_promise_->set_value();
      resume_promise_.reset();
    }
  }

  void WaitForResume() {
    if (paused) {
      resume_promise_ = std::make_unique<std::promise<void>>();
      auto resume_future = resume_promise_->get_future();
      auto result = resume_future.wait_for(std::chrono::milliseconds(1000));
      EXPECT_NE(std::future_status::timeout, result);
    }
  }

  bool paused{false};
  LeAddressManager* le_address_manager_;
  size_t id_;
  std::unique_ptr<std::promise<void>> resume_promise_;
};

class LeAddressManagerTest : public ::testing::Test {
 public:
  void SetUp() override {
    thread_ = new Thread("thread", Thread::Priority::NORMAL);
    handler_ = new Handler(thread_);
    test_hci_layer_ = new TestHciLayer;
    Address address({0x01, 0x02, 0x03, 0x04, 0x05, 0x06});
    le_address_manager_ = new LeAddressManager(
        common::Bind(&LeAddressManagerTest::enqueue_command, common::Unretained(this)), handler_, address, 0x3F, 0x3F);
    AllocateClients(1);
  }

  void sync_handler(os::Handler* handler) {
    std::promise<void> promise;
    auto future = promise.get_future();
    handler_->Post(common::BindOnce(&std::promise<void>::set_value, common::Unretained(&promise)));
    auto future_status = future.wait_for(std::chrono::seconds(1));
    EXPECT_EQ(future_status, std::future_status::ready);
  }

  void TearDown() override {
    sync_handler(handler_);
    delete le_address_manager_;
    delete test_hci_layer_;
    handler_->Clear();
    delete handler_;
    delete thread_;
  }

  void AllocateClients(size_t num_clients) {
    size_t first_id = clients.size();
    for (size_t i = 0; i < num_clients; i++) {
      clients.emplace_back(std::make_unique<RotatorClient>(le_address_manager_, first_id + i));
    }
  }

  void enqueue_command(std::unique_ptr<CommandPacketBuilder> command_packet) {
    test_hci_layer_->EnqueueCommand(
        std::move(command_packet),
        handler_->BindOnce(&LeAddressManager::OnCommandComplete, common::Unretained(le_address_manager_)));
  }

  Thread* thread_;
  Handler* handler_;
  TestHciLayer* test_hci_layer_ = nullptr;
  LeAddressManager* le_address_manager_;
  std::vector<std::unique_ptr<RotatorClient>> clients;
};

TEST_F(LeAddressManagerTest, startup_teardown) {}

TEST_F(LeAddressManagerTest, register_unregister_callback) {
  le_address_manager_->Register(clients[0].get());
  sync_handler(handler_);
  le_address_manager_->Unregister(clients[0].get());
  sync_handler(handler_);
}

TEST_F(LeAddressManagerTest, rotator_address_for_single_client) {
  Octet16 irk = {0xec, 0x02, 0x34, 0xa3, 0x57, 0xc8, 0xad, 0x05, 0x34, 0x10, 0x10, 0xa6, 0x0a, 0x39, 0x7d, 0x9b};
  auto minimum_rotation_time = std::chrono::milliseconds(1000);
  auto maximum_rotation_time = std::chrono::milliseconds(3000);
  AddressWithType remote_address(Address::kEmpty, AddressType::RANDOM_DEVICE_ADDRESS);
  le_address_manager_->SetPrivacyPolicyForInitiatorAddress(
      LeAddressManager::AddressPolicy::USE_RESOLVABLE_ADDRESS,
      remote_address,
      irk,
      minimum_rotation_time,
      maximum_rotation_time);

  test_hci_layer_->SetCommandFuture();
  le_address_manager_->Register(clients[0].get());
  sync_handler(handler_);
  test_hci_layer_->GetCommandPacket(OpCode::LE_SET_RANDOM_ADDRESS);
  test_hci_layer_->IncomingEvent(LeSetRandomAddressCompleteBuilder::Create(0x01, ErrorCode::SUCCESS));
  clients[0].get()->WaitForResume();
  le_address_manager_->Unregister(clients[0].get());
  sync_handler(handler_);
}

TEST_F(LeAddressManagerTest, rotator_non_resolvable_address_for_single_client) {
  Octet16 irk = {};
  auto minimum_rotation_time = std::chrono::milliseconds(1000);
  auto maximum_rotation_time = std::chrono::milliseconds(3000);
  AddressWithType remote_address(Address::kEmpty, AddressType::RANDOM_DEVICE_ADDRESS);
  le_address_manager_->SetPrivacyPolicyForInitiatorAddress(
      LeAddressManager::AddressPolicy::USE_NON_RESOLVABLE_ADDRESS,
      remote_address,
      irk,
      minimum_rotation_time,
      maximum_rotation_time);

  test_hci_layer_->SetCommandFuture();
  le_address_manager_->Register(clients[0].get());
  sync_handler(handler_);
  test_hci_layer_->GetCommandPacket(OpCode::LE_SET_RANDOM_ADDRESS);
  test_hci_layer_->IncomingEvent(LeSetRandomAddressCompleteBuilder::Create(0x01, ErrorCode::SUCCESS));
  clients[0].get()->WaitForResume();
  le_address_manager_->Unregister(clients[0].get());
  sync_handler(handler_);
}

// TODO handle the case "register during rotate_random_address" and enable this
TEST_F(LeAddressManagerTest, DISABLED_rotator_address_for_multiple_clients) {
  AllocateClients(2);
  Octet16 irk = {0xec, 0x02, 0x34, 0xa3, 0x57, 0xc8, 0xad, 0x05, 0x34, 0x10, 0x10, 0xa6, 0x0a, 0x39, 0x7d, 0x9b};
  auto minimum_rotation_time = std::chrono::milliseconds(1000);
  auto maximum_rotation_time = std::chrono::milliseconds(3000);
  AddressWithType remote_address(Address::kEmpty, AddressType::RANDOM_DEVICE_ADDRESS);
  le_address_manager_->SetPrivacyPolicyForInitiatorAddress(
      LeAddressManager::AddressPolicy::USE_RESOLVABLE_ADDRESS,
      remote_address,
      irk,
      minimum_rotation_time,
      maximum_rotation_time);
  le_address_manager_->Register(clients[0].get());
  le_address_manager_->Register(clients[1].get());
  le_address_manager_->Register(clients[2].get());
  sync_handler(handler_);

  le_address_manager_->Unregister(clients[0].get());
  le_address_manager_->Unregister(clients[1].get());
  le_address_manager_->Unregister(clients[2].get());
  sync_handler(handler_);
}

class LeAddressManagerWithSingleClientTest : public LeAddressManagerTest {
 public:
  void SetUp() override {
    thread_ = new Thread("thread", Thread::Priority::NORMAL);
    handler_ = new Handler(thread_);
    test_hci_layer_ = new TestHciLayer;
    Address address({0x01, 0x02, 0x03, 0x04, 0x05, 0x06});
    le_address_manager_ = new LeAddressManager(
        common::Bind(&LeAddressManagerWithSingleClientTest::enqueue_command, common::Unretained(this)),
        handler_,
        address,
        0x3F,
        0x3F);
    AllocateClients(1);

    Octet16 irk = {0xec, 0x02, 0x34, 0xa3, 0x57, 0xc8, 0xad, 0x05, 0x34, 0x10, 0x10, 0xa6, 0x0a, 0x39, 0x7d, 0x9b};
    auto minimum_rotation_time = std::chrono::milliseconds(1000);
    auto maximum_rotation_time = std::chrono::milliseconds(3000);
    AddressWithType remote_address(Address::kEmpty, AddressType::RANDOM_DEVICE_ADDRESS);
    le_address_manager_->SetPrivacyPolicyForInitiatorAddress(
        LeAddressManager::AddressPolicy::USE_RESOLVABLE_ADDRESS,
        remote_address,
        irk,
        minimum_rotation_time,
        maximum_rotation_time);

    test_hci_layer_->SetCommandFuture();
    le_address_manager_->Register(clients[0].get());
    sync_handler(handler_);
    test_hci_layer_->GetCommandPacket(OpCode::LE_SET_RANDOM_ADDRESS);
    test_hci_layer_->IncomingEvent(LeSetRandomAddressCompleteBuilder::Create(0x01, ErrorCode::SUCCESS));
  }

  void enqueue_command(std::unique_ptr<CommandPacketBuilder> command_packet) {
    test_hci_layer_->EnqueueCommand(
        std::move(command_packet),
        handler_->BindOnce(&LeAddressManager::OnCommandComplete, common::Unretained(le_address_manager_)));
  }

  void TearDown() override {
    le_address_manager_->Unregister(clients[0].get());
    sync_handler(handler_);
    delete le_address_manager_;
    delete test_hci_layer_;
    handler_->Clear();
    delete handler_;
    delete thread_;
  }
};

TEST_F(LeAddressManagerWithSingleClientTest, add_device_to_connect_list) {
  Address address;
  Address::FromString("01:02:03:04:05:06", address);
  test_hci_layer_->SetCommandFuture();
  le_address_manager_->AddDeviceToConnectList(ConnectListAddressType::RANDOM, address);
  auto packet = test_hci_layer_->GetCommandPacket(OpCode::LE_ADD_DEVICE_TO_CONNECT_LIST);
  auto packet_view = LeAddDeviceToConnectListView::Create(LeConnectionManagementCommandView::Create(packet));
  ASSERT_TRUE(packet_view.IsValid());
  ASSERT_EQ(ConnectListAddressType::RANDOM, packet_view.GetAddressType());
  ASSERT_EQ(address, packet_view.GetAddress());

  test_hci_layer_->IncomingEvent(LeAddDeviceToConnectListCompleteBuilder::Create(0x01, ErrorCode::SUCCESS));
  clients[0].get()->WaitForResume();
}

TEST_F(LeAddressManagerWithSingleClientTest, remove_device_from_connect_list) {
  Address address;
  Address::FromString("01:02:03:04:05:06", address);
  test_hci_layer_->SetCommandFuture();
  le_address_manager_->AddDeviceToConnectList(ConnectListAddressType::RANDOM, address);
  test_hci_layer_->GetCommandPacket(OpCode::LE_ADD_DEVICE_TO_CONNECT_LIST);
  test_hci_layer_->IncomingEvent(LeAddDeviceToConnectListCompleteBuilder::Create(0x01, ErrorCode::SUCCESS));

  test_hci_layer_->SetCommandFuture();
  le_address_manager_->RemoveDeviceFromConnectList(ConnectListAddressType::RANDOM, address);
  auto packet = test_hci_layer_->GetCommandPacket(OpCode::LE_REMOVE_DEVICE_FROM_CONNECT_LIST);
  auto packet_view = LeRemoveDeviceFromConnectListView::Create(LeConnectionManagementCommandView::Create(packet));
  ASSERT_TRUE(packet_view.IsValid());
  ASSERT_EQ(ConnectListAddressType::RANDOM, packet_view.GetAddressType());
  ASSERT_EQ(address, packet_view.GetAddress());
  test_hci_layer_->IncomingEvent(LeRemoveDeviceFromConnectListCompleteBuilder::Create(0x01, ErrorCode::SUCCESS));
  clients[0].get()->WaitForResume();
}

TEST_F(LeAddressManagerWithSingleClientTest, clear_connect_list) {
  Address address;
  Address::FromString("01:02:03:04:05:06", address);
  test_hci_layer_->SetCommandFuture();
  le_address_manager_->AddDeviceToConnectList(ConnectListAddressType::RANDOM, address);
  test_hci_layer_->GetCommandPacket(OpCode::LE_ADD_DEVICE_TO_CONNECT_LIST);
  test_hci_layer_->IncomingEvent(LeAddDeviceToConnectListCompleteBuilder::Create(0x01, ErrorCode::SUCCESS));

  test_hci_layer_->SetCommandFuture();
  le_address_manager_->ClearConnectList();
  test_hci_layer_->GetCommandPacket(OpCode::LE_CLEAR_CONNECT_LIST);
  test_hci_layer_->IncomingEvent(LeClearConnectListCompleteBuilder::Create(0x01, ErrorCode::SUCCESS));
  clients[0].get()->WaitForResume();
}

TEST_F(LeAddressManagerWithSingleClientTest, add_device_to_resolving_list) {
  Address address;
  Address::FromString("01:02:03:04:05:06", address);
  Octet16 peer_irk = {0xec, 0x02, 0x34, 0xa3, 0x57, 0xc8, 0xad, 0x05, 0x34, 0x10, 0x10, 0xa6, 0x0a, 0x39, 0x7d, 0x9b};
  Octet16 local_irk = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};
  test_hci_layer_->SetCommandFuture();
  le_address_manager_->AddDeviceToResolvingList(
      PeerAddressType::RANDOM_DEVICE_OR_IDENTITY_ADDRESS, address, peer_irk, local_irk);
  auto packet = test_hci_layer_->GetCommandPacket(OpCode::LE_ADD_DEVICE_TO_RESOLVING_LIST);
  auto packet_view = LeAddDeviceToResolvingListView::Create(LeSecurityCommandView::Create(packet));
  ASSERT_TRUE(packet_view.IsValid());
  ASSERT_EQ(PeerAddressType::RANDOM_DEVICE_OR_IDENTITY_ADDRESS, packet_view.GetPeerIdentityAddressType());
  ASSERT_EQ(address, packet_view.GetPeerIdentityAddress());
  ASSERT_EQ(peer_irk, packet_view.GetPeerIrk());
  ASSERT_EQ(local_irk, packet_view.GetLocalIrk());

  test_hci_layer_->IncomingEvent(LeAddDeviceToResolvingListCompleteBuilder::Create(0x01, ErrorCode::SUCCESS));
  clients[0].get()->WaitForResume();
}

TEST_F(LeAddressManagerWithSingleClientTest, remove_device_from_resolving_list) {
  Address address;
  Address::FromString("01:02:03:04:05:06", address);
  Octet16 peer_irk = {0xec, 0x02, 0x34, 0xa3, 0x57, 0xc8, 0xad, 0x05, 0x34, 0x10, 0x10, 0xa6, 0x0a, 0x39, 0x7d, 0x9b};
  Octet16 local_irk = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};
  test_hci_layer_->SetCommandFuture();
  le_address_manager_->AddDeviceToResolvingList(
      PeerAddressType::RANDOM_DEVICE_OR_IDENTITY_ADDRESS, address, peer_irk, local_irk);
  test_hci_layer_->GetCommandPacket(OpCode::LE_ADD_DEVICE_TO_RESOLVING_LIST);
  test_hci_layer_->IncomingEvent(LeAddDeviceToResolvingListCompleteBuilder::Create(0x01, ErrorCode::SUCCESS));

  test_hci_layer_->SetCommandFuture();
  le_address_manager_->RemoveDeviceFromResolvingList(PeerAddressType::RANDOM_DEVICE_OR_IDENTITY_ADDRESS, address);
  auto packet = test_hci_layer_->GetCommandPacket(OpCode::LE_REMOVE_DEVICE_FROM_RESOLVING_LIST);
  auto packet_view = LeRemoveDeviceFromResolvingListView::Create(LeSecurityCommandView::Create(packet));
  ASSERT_TRUE(packet_view.IsValid());
  ASSERT_EQ(PeerAddressType::RANDOM_DEVICE_OR_IDENTITY_ADDRESS, packet_view.GetPeerIdentityAddressType());
  ASSERT_EQ(address, packet_view.GetPeerIdentityAddress());
  test_hci_layer_->IncomingEvent(LeRemoveDeviceFromResolvingListCompleteBuilder::Create(0x01, ErrorCode::SUCCESS));
  clients[0].get()->WaitForResume();
}

TEST_F(LeAddressManagerWithSingleClientTest, clear_resolving_list) {
  Address address;
  Address::FromString("01:02:03:04:05:06", address);
  Octet16 peer_irk = {0xec, 0x02, 0x34, 0xa3, 0x57, 0xc8, 0xad, 0x05, 0x34, 0x10, 0x10, 0xa6, 0x0a, 0x39, 0x7d, 0x9b};
  Octet16 local_irk = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};
  test_hci_layer_->SetCommandFuture();
  le_address_manager_->AddDeviceToResolvingList(
      PeerAddressType::RANDOM_DEVICE_OR_IDENTITY_ADDRESS, address, peer_irk, local_irk);
  test_hci_layer_->GetCommandPacket(OpCode::LE_ADD_DEVICE_TO_RESOLVING_LIST);
  test_hci_layer_->IncomingEvent(LeAddDeviceToResolvingListCompleteBuilder::Create(0x01, ErrorCode::SUCCESS));

  test_hci_layer_->SetCommandFuture();
  le_address_manager_->ClearResolvingList();
  auto packet = test_hci_layer_->GetCommandPacket(OpCode::LE_CLEAR_RESOLVING_LIST);
  auto packet_view = LeClearResolvingListView::Create(LeSecurityCommandView::Create(packet));
  ASSERT_TRUE(packet_view.IsValid());
  test_hci_layer_->IncomingEvent(LeClearResolvingListCompleteBuilder::Create(0x01, ErrorCode::SUCCESS));
  clients[0].get()->WaitForResume();
}

TEST_F(LeAddressManagerWithSingleClientTest, register_during_command_complete) {
  Address address;
  Address::FromString("01:02:03:04:05:06", address);
  test_hci_layer_->SetCommandFuture();
  le_address_manager_->AddDeviceToConnectList(ConnectListAddressType::RANDOM, address);
  auto packet = test_hci_layer_->GetCommandPacket(OpCode::LE_ADD_DEVICE_TO_CONNECT_LIST);
  auto packet_view = LeAddDeviceToConnectListView::Create(LeConnectionManagementCommandView::Create(packet));
  ASSERT_TRUE(packet_view.IsValid());
  ASSERT_EQ(ConnectListAddressType::RANDOM, packet_view.GetAddressType());
  ASSERT_EQ(address, packet_view.GetAddress());
  test_hci_layer_->IncomingEvent(LeAddDeviceToConnectListCompleteBuilder::Create(0x01, ErrorCode::SUCCESS));

  AllocateClients(1);
  test_hci_layer_->SetCommandFuture();
  le_address_manager_->Register(clients[1].get());
  test_hci_layer_->GetCommandPacket(OpCode::LE_SET_RANDOM_ADDRESS);
  test_hci_layer_->IncomingEvent(LeSetRandomAddressCompleteBuilder::Create(0x01, ErrorCode::SUCCESS));
  clients[0].get()->WaitForResume();
  clients[1].get()->WaitForResume();
}

}  // namespace hci
}  // namespace bluetooth
