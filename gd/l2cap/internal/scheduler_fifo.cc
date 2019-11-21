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

#include "l2cap/classic/internal/dynamic_channel_impl.h"
#include "l2cap/l2cap_packets.h"
#include "os/log.h"

namespace bluetooth {
namespace l2cap {
namespace internal {

Fifo::Fifo(LowerQueueUpEnd* link_queue_up_end, os::Handler* handler)
    : link_queue_up_end_(link_queue_up_end), handler_(handler) {
  ASSERT(link_queue_up_end_ != nullptr && handler_ != nullptr);
}

Fifo::~Fifo() {
  sender_map_.clear();
  if (link_queue_enqueue_registered_) {
    link_queue_up_end_->UnregisterEnqueue();
  }
}

void Fifo::AttachChannel(Cid cid, std::shared_ptr<ChannelImpl> channel) {
  ASSERT(sender_map_.find(cid) == sender_map_.end());
  sender_map_.emplace(std::piecewise_construct, std::forward_as_tuple(cid),
                      std::forward_as_tuple(handler_, this, channel));
}

void Fifo::DetachChannel(Cid cid) {
  ASSERT(sender_map_.find(cid) != sender_map_.end());
  sender_map_.erase(cid);
}

void Fifo::OnPacketsReady(Cid cid, int number_packets) {
  next_to_dequeue_and_num_packets.push(std::make_pair(cid, number_packets));
  try_register_link_queue_enqueue();
}

std::unique_ptr<Fifo::UpperDequeue> Fifo::link_queue_enqueue_callback() {
  ASSERT(!next_to_dequeue_and_num_packets.empty());
  auto& channel_id_and_number_packets = next_to_dequeue_and_num_packets.front();
  auto channel_id = channel_id_and_number_packets.first;
  channel_id_and_number_packets.second--;
  if (channel_id_and_number_packets.second == 0) {
    next_to_dequeue_and_num_packets.pop();
  }
  auto packet = sender_map_.find(channel_id)->second.GetNextPacket();

  sender_map_.find(channel_id)->second.OnPacketSent();
  if (next_to_dequeue_and_num_packets.empty()) {
    link_queue_up_end_->UnregisterEnqueue();
    link_queue_enqueue_registered_ = false;
  }
  return packet;
}

void Fifo::try_register_link_queue_enqueue() {
  if (link_queue_enqueue_registered_) {
    return;
  }
  link_queue_up_end_->RegisterEnqueue(handler_,
                                      common::Bind(&Fifo::link_queue_enqueue_callback, common::Unretained(this)));
  link_queue_enqueue_registered_ = true;
}

void Fifo::SetChannelRetransmissionFlowControlMode(Cid cid, RetransmissionAndFlowControlModeOption mode) {
  ASSERT(sender_map_.find(cid) != sender_map_.end());
  sender_map_.find(cid)->second.SetChannelRetransmissionFlowControlMode(mode);
}

DataController* Fifo::GetDataController(Cid cid) {
  if (sender_map_.find(cid) == sender_map_.end()) {
    return nullptr;
  }
  return sender_map_.find(cid)->second.GetDataController();
}

}  // namespace internal
}  // namespace l2cap
}  // namespace bluetooth
