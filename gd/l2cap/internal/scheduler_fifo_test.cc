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

#include "l2cap/internal/scheduler_fifo.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <future>

#include "l2cap/internal/channel_impl_mock.h"
#include "os/handler.h"
#include "os/queue.h"
#include "os/thread.h"
#include "packet/raw_builder.h"

namespace bluetooth {
namespace l2cap {
namespace internal {
namespace {

using ::testing::Return;

void sync_handler(os::Handler* handler) {
  std::promise<void> promise;
  auto future = promise.get_future();
  handler->Post(common::BindOnce(&std::promise<void>::set_value, common::Unretained(&promise)));
  auto status = future.wait_for(std::chrono::milliseconds(300));
  EXPECT_EQ(status, std::future_status::ready);
}

class L2capSchedulerFifoTest : public ::testing::Test {
 protected:
  void SetUp() override {
    thread_ = new os::Thread("test_thread", os::Thread::Priority::NORMAL);
    user_handler_ = new os::Handler(thread_);
    queue_handler_ = new os::Handler(thread_);
    fifo_ = new Fifo(link_queue_.GetUpEnd(), queue_handler_);
  }

  void TearDown() override {
    delete fifo_;
    queue_handler_->Clear();
    user_handler_->Clear();
    delete queue_handler_;
    delete user_handler_;
    delete thread_;
  }

  os::Thread* thread_ = nullptr;
  os::Handler* user_handler_ = nullptr;
  os::Handler* queue_handler_ = nullptr;
  common::BidiQueue<Scheduler::LowerDequeue, Scheduler::LowerEnqueue> link_queue_{10};
  Fifo* fifo_ = nullptr;
};

TEST_F(L2capSchedulerFifoTest, send_packet) {
  common::BidiQueue<Scheduler::UpperEnqueue, Scheduler::UpperDequeue> channel_one_queue_{10};
  common::BidiQueue<Scheduler::UpperEnqueue, Scheduler::UpperDequeue> channel_two_queue_{10};

  auto mock_channel_1 = std::make_shared<testing::MockChannelImpl>();
  EXPECT_CALL(*mock_channel_1, GetQueueDownEnd()).WillRepeatedly(Return(channel_one_queue_.GetDownEnd()));
  EXPECT_CALL(*mock_channel_1, GetChannelMode())
      .WillRepeatedly(Return(RetransmissionAndFlowControlModeOption::L2CAP_BASIC));
  EXPECT_CALL(*mock_channel_1, GetCid()).WillRepeatedly(Return(1));
  EXPECT_CALL(*mock_channel_1, GetRemoteCid()).WillRepeatedly(Return(1));
  auto mock_channel_2 = std::make_shared<testing::MockChannelImpl>();
  EXPECT_CALL(*mock_channel_2, GetQueueDownEnd()).WillRepeatedly(Return(channel_two_queue_.GetDownEnd()));
  EXPECT_CALL(*mock_channel_2, GetChannelMode())
      .WillRepeatedly(Return(RetransmissionAndFlowControlModeOption::L2CAP_BASIC));
  EXPECT_CALL(*mock_channel_2, GetCid()).WillRepeatedly(Return(2));
  EXPECT_CALL(*mock_channel_2, GetRemoteCid()).WillRepeatedly(Return(2));
  fifo_->AttachChannel(1, mock_channel_1);
  fifo_->AttachChannel(2, mock_channel_2);
  os::EnqueueBuffer<Scheduler::UpperDequeue> channel_one_enqueue_buffer{channel_one_queue_.GetUpEnd()};
  os::EnqueueBuffer<Scheduler::UpperDequeue> channel_two_enqueue_buffer{channel_two_queue_.GetUpEnd()};
  auto packet_one = std::make_unique<packet::RawBuilder>();
  packet_one->AddOctets({1, 2, 3});
  auto packet_two = std::make_unique<packet::RawBuilder>();
  packet_two->AddOctets({4, 5, 6, 7});
  channel_one_enqueue_buffer.Enqueue(std::move(packet_one), user_handler_);
  channel_two_enqueue_buffer.Enqueue(std::move(packet_two), user_handler_);
  sync_handler(user_handler_);
  sync_handler(queue_handler_);
  sync_handler(user_handler_);
  auto packet = link_queue_.GetDownEnd()->TryDequeue();
  EXPECT_NE(packet, nullptr);
  EXPECT_EQ(packet->size(), 7);
  packet = link_queue_.GetDownEnd()->TryDequeue();
  EXPECT_NE(packet, nullptr);
  EXPECT_EQ(packet->size(), 8);
  fifo_->DetachChannel(1);
  fifo_->DetachChannel(2);
}

}  // namespace
}  // namespace internal
}  // namespace l2cap
}  // namespace bluetooth
