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

#include "l2cap/classic/internal/signalling_manager.h"

#include "l2cap/classic/internal/dynamic_channel_service_manager_impl_mock.h"
#include "l2cap/classic/internal/fixed_channel_service_manager_impl_mock.h"
#include "l2cap/classic/internal/link_mock.h"
#include "l2cap/internal/parameter_provider_mock.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

using ::testing::_;
using ::testing::Return;

namespace bluetooth {
namespace l2cap {
namespace classic {
namespace internal {
namespace {

class L2capClassicSignallingManagerTest : public ::testing::Test {
 public:
  static void SyncHandler(os::Handler* handler) {
    std::promise<void> promise;
    auto future = promise.get_future();
    handler->Post(common::BindOnce(&std::promise<void>::set_value, common::Unretained(&promise)));
    future.wait_for(std::chrono::milliseconds(3));
  }

 protected:
  void SetUp() override {
    thread_ = new os::Thread("test_thread", os::Thread::Priority::NORMAL);
    l2cap_handler_ = new os::Handler(thread_);
  }

  void TearDown() override {
    l2cap_handler_->Clear();
    delete l2cap_handler_;
    delete thread_;
  }

  os::Thread* thread_ = nullptr;
  os::Handler* l2cap_handler_ = nullptr;
};

PacketView<kLittleEndian> GetPacketView(std::unique_ptr<packet::BasePacketBuilder> packet) {
  auto bytes = std::make_shared<std::vector<uint8_t>>();
  BitInserter i(*bytes);
  bytes->reserve(packet->size());
  packet->Serialize(i);
  return packet::PacketView<packet::kLittleEndian>(bytes);
}

TEST_F(L2capClassicSignallingManagerTest, handle_connection_request) {
  l2cap::internal::testing::MockParameterProvider parameter_provider;
  testing::MockDynamicChannelServiceManagerImpl dynamic_service_manager_;
  testing::MockFixedChannelServiceManagerImpl fixed_service_manager_;
  testing::MockLink link{l2cap_handler_, &parameter_provider};
  std::shared_ptr<FixedChannelImpl> signalling_channel = std::make_shared<FixedChannelImpl>(1, &link, l2cap_handler_);
  EXPECT_CALL(link, AllocateFixedChannel(_, _)).WillRepeatedly(Return(signalling_channel));
  auto service_psm = 0x1;
  EXPECT_CALL(dynamic_service_manager_, IsServiceRegistered(service_psm)).WillRepeatedly(Return(true));
  DynamicChannelAllocator channel_allocator{&link, l2cap_handler_};
  ClassicSignallingManager signalling_manager{l2cap_handler_, &link, &dynamic_service_manager_, &channel_allocator,
                                              &fixed_service_manager_};
  auto* down_end = signalling_channel->GetQueueDownEnd();
  os::EnqueueBuffer<packet::PacketView<kLittleEndian>> enqueue_buffer{down_end};
  auto dcid = 0x101;
  auto builder = ConnectionRequestBuilder::Create(1, service_psm, dcid);
  enqueue_buffer.Enqueue(std::make_unique<PacketView<kLittleEndian>>(GetPacketView(std::move(builder))),
                         l2cap_handler_);
  SyncHandler(l2cap_handler_);
  EXPECT_CALL(link, AllocateDynamicChannel(_, dcid, _));
  SyncHandler(l2cap_handler_);
}

}  // namespace
}  // namespace internal
}  // namespace classic
}  // namespace l2cap
}  // namespace bluetooth
