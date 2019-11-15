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

#include "l2cap/internal/reassembler.h"

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
namespace {
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

class L2capClassicReassemblerTest : public ::testing::Test {
 protected:
  void SetUp() override {
    thread_ = new os::Thread("test_thread", os::Thread::Priority::NORMAL);
    user_handler_ = new os::Handler(thread_);
    queue_handler_ = new os::Handler(thread_);
    reassembler_ = new Reassembler(link_queue_.GetUpEnd(), queue_handler_);
  }

  void TearDown() override {
    delete reassembler_;
    queue_handler_->Clear();
    user_handler_->Clear();
    delete queue_handler_;
    delete user_handler_;
    delete thread_;
  }

  os::Thread* thread_ = nullptr;
  os::Handler* user_handler_ = nullptr;
  os::Handler* queue_handler_ = nullptr;
  common::BidiQueue<Reassembler::LowerDequeue, Reassembler::LowerEnqueue> link_queue_{10};
  Reassembler* reassembler_ = nullptr;
};

TEST_F(L2capClassicReassemblerTest, receive_basic_mode_packet_for_fixed_channel) {
  common::BidiQueue<Reassembler::UpperEnqueue, Reassembler::UpperDequeue> channel_one_queue_{10};
  common::BidiQueue<Reassembler::UpperEnqueue, Reassembler::UpperDequeue> channel_two_queue_{10};
  reassembler_->AttachChannel(1, channel_one_queue_.GetDownEnd(), nullptr);
  reassembler_->AttachChannel(2, channel_two_queue_.GetDownEnd(), nullptr);
  os::EnqueueBuffer<Reassembler::UpperEnqueue> link_queue_enqueue_buffer{link_queue_.GetDownEnd()};
  auto packet_one = CreateSampleL2capPacket(1, {1, 2, 3});
  auto packet_two = CreateSampleL2capPacket(2, {4, 5, 6, 7});
  auto packet_one_view = GetPacketView(std::move(packet_one));
  auto packet_two_view = GetPacketView(std::move(packet_two));
  link_queue_enqueue_buffer.Enqueue(std::make_unique<Reassembler::UpperEnqueue>(packet_one_view), queue_handler_);
  link_queue_enqueue_buffer.Enqueue(std::make_unique<Reassembler::UpperEnqueue>(packet_two_view), queue_handler_);
  sync_handler(queue_handler_);
  sync_handler(user_handler_);
  sync_handler(queue_handler_);
  auto packet = channel_one_queue_.GetUpEnd()->TryDequeue();
  EXPECT_NE(packet, nullptr);
  EXPECT_EQ(packet->size(), 3);
  packet = channel_two_queue_.GetUpEnd()->TryDequeue();
  EXPECT_NE(packet, nullptr);
  EXPECT_EQ(packet->size(), 4);
  reassembler_->DetachChannel(1);
  reassembler_->DetachChannel(2);
}

}  // namespace
}  // namespace internal
}  // namespace l2cap
}  // namespace bluetooth
