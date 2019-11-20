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

#include "l2cap/internal/sender.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <future>

#include "l2cap/internal/channel_impl_mock.h"
#include "l2cap/internal/scheduler.h"
#include "os/handler.h"
#include "os/queue.h"
#include "os/thread.h"
#include "packet/raw_builder.h"

namespace bluetooth {
namespace l2cap {
namespace internal {
namespace {

using ::testing::Return;

std::unique_ptr<packet::BasePacketBuilder> CreateSdu(std::vector<uint8_t> payload) {
  auto raw_builder = std::make_unique<packet::RawBuilder>();
  raw_builder->AddOctets(payload);
  return raw_builder;
}

class FakeScheduler : public Scheduler {
 public:
  void OnPacketsReady(Cid cid, int number_packets) override {
    on_packets_ready_(cid, number_packets);
  }

  void SetOnPacketsReady(std::function<void(Cid cid, int number_packets)> callback) {
    on_packets_ready_ = callback;
  }
  std::function<void(Cid cid, int number_packets)> on_packets_ready_;
};

class L2capSegmenterTest : public ::testing::Test {
 public:
  std::unique_ptr<Sender::UpperDequeue> enqueue_callback() {
    auto packet_one = CreateSdu({1, 2, 3});
    channel_queue_.GetUpEnd()->UnregisterEnqueue();
    return packet_one;
  }

 protected:
  void SetUp() override {
    thread_ = new os::Thread("test_thread", os::Thread::Priority::NORMAL);
    user_handler_ = new os::Handler(thread_);
    queue_handler_ = new os::Handler(thread_);
    mock_channel_ = std::make_shared<testing::MockChannelImpl>();
    EXPECT_CALL(*mock_channel_, GetQueueDownEnd()).WillRepeatedly(Return(channel_queue_.GetDownEnd()));
    EXPECT_CALL(*mock_channel_, GetChannelMode())
        .WillRepeatedly(Return(RetransmissionAndFlowControlModeOption::L2CAP_BASIC));
    EXPECT_CALL(*mock_channel_, GetCid()).WillRepeatedly(Return(0x41));
    EXPECT_CALL(*mock_channel_, GetRemoteCid()).WillRepeatedly(Return(0x41));
    sender_ = new Sender(queue_handler_, &scheduler_, mock_channel_);
  }

  void TearDown() override {
    delete sender_;
    queue_handler_->Clear();
    user_handler_->Clear();
    delete queue_handler_;
    delete user_handler_;
    delete thread_;
  }

  os::Thread* thread_ = nullptr;
  os::Handler* user_handler_ = nullptr;
  os::Handler* queue_handler_ = nullptr;
  common::BidiQueue<Sender::UpperEnqueue, Sender::UpperDequeue> channel_queue_{10};
  std::shared_ptr<testing::MockChannelImpl> mock_channel_;
  Sender* sender_ = nullptr;
  FakeScheduler scheduler_;
};

TEST_F(L2capSegmenterTest, send_packet) {
  auto packet_one = CreateSdu({1, 2, 3});
  std::promise<void> promise;
  auto future = promise.get_future();
  scheduler_.SetOnPacketsReady([&promise](Cid cid, int number_packets) { promise.set_value(); });
  channel_queue_.GetUpEnd()->RegisterEnqueue(
      queue_handler_, common::Bind(&L2capSegmenterTest::enqueue_callback, common::Unretained(this)));
  auto status = future.wait_for(std::chrono::milliseconds(3));
  EXPECT_EQ(status, std::future_status::ready);
  auto packet = sender_->GetNextPacket();
  EXPECT_NE(packet, nullptr);
}

}  // namespace
}  // namespace internal
}  // namespace l2cap
}  // namespace bluetooth
