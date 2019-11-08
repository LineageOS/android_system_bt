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

#include <gtest/gtest.h>
#include <future>

#include "l2cap/l2cap_packets.h"
#include "os/handler.h"
#include "os/queue.h"
#include "os/thread.h"
#include "packet/raw_builder.h"

namespace bluetooth {
namespace l2cap {
namespace internal {

std::unique_ptr<BasicFrameBuilder> CreateSampleL2capPacket(Cid cid, std::vector<uint8_t> payload) {
  auto raw_builder = std::make_unique<packet::RawBuilder>();
  raw_builder->AddOctets(payload);
  return BasicFrameBuilder::Create(cid, std::move(raw_builder));
}

PacketView<kLittleEndian> GetPacketView(std::unique_ptr<packet::BasePacketBuilder> packet) {
  auto bytes = std::make_shared<std::vector<uint8_t>>();
  BitInserter i(*bytes);
  bytes->reserve(packet->size());
  packet->Serialize(i);
  return packet::PacketView<packet::kLittleEndian>(bytes);
}
void sync_handler(os::Handler* handler) {
  std::promise<void> promise;
  auto future = promise.get_future();
  handler->Post(common::BindOnce(&std::promise<void>::set_value, common::Unretained(&promise)));
  auto status = future.wait_for(std::chrono::milliseconds(3));
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

TEST_F(L2capSchedulerFifoTest, receive_packet) {
  common::BidiQueue<Scheduler::UpperEnqueue, Scheduler::UpperDequeue> channel_one_queue_{10};
  common::BidiQueue<Scheduler::UpperEnqueue, Scheduler::UpperDequeue> channel_two_queue_{10};
  fifo_->AttachChannel(1, channel_one_queue_.GetDownEnd(), 1);
  fifo_->AttachChannel(2, channel_two_queue_.GetDownEnd(), 2);
  os::EnqueueBuffer<Scheduler::UpperEnqueue> link_queue_enqueue_buffer{link_queue_.GetDownEnd()};
  auto packet_one = CreateSampleL2capPacket(1, {1, 2, 3});
  auto packet_two = CreateSampleL2capPacket(2, {4, 5, 6, 7});
  auto packet_one_view = GetPacketView(std::move(packet_one));
  auto packet_two_view = GetPacketView(std::move(packet_two));
  link_queue_enqueue_buffer.Enqueue(std::make_unique<Scheduler::UpperEnqueue>(packet_one_view), queue_handler_);
  link_queue_enqueue_buffer.Enqueue(std::make_unique<Scheduler::UpperEnqueue>(packet_two_view), queue_handler_);
  sync_handler(queue_handler_);
  sync_handler(user_handler_);
  sync_handler(queue_handler_);
  auto packet = channel_one_queue_.GetUpEnd()->TryDequeue();
  EXPECT_NE(packet, nullptr);
  EXPECT_EQ(packet->size(), 3);
  packet = channel_two_queue_.GetUpEnd()->TryDequeue();
  EXPECT_NE(packet, nullptr);
  EXPECT_EQ(packet->size(), 4);
  fifo_->DetachChannel(1);
  fifo_->DetachChannel(2);
}

TEST_F(L2capSchedulerFifoTest, send_packet) {
  common::BidiQueue<Scheduler::UpperEnqueue, Scheduler::UpperDequeue> channel_one_queue_{10};
  common::BidiQueue<Scheduler::UpperEnqueue, Scheduler::UpperDequeue> channel_two_queue_{10};
  fifo_->AttachChannel(1, channel_one_queue_.GetDownEnd(), 1);
  fifo_->AttachChannel(2, channel_two_queue_.GetDownEnd(), 2);
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

}  // namespace internal
}  // namespace l2cap
}  // namespace bluetooth
