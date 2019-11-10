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
#include "l2cap/l2cap_packets.h"
#include "os/log.h"

namespace bluetooth {
namespace l2cap {
namespace internal {

Fifo::~Fifo() {
  channel_queue_end_map_.clear();
  link_queue_up_end_->UnregisterDequeue();
  if (link_queue_enqueue_registered_) {
    link_queue_up_end_->UnregisterEnqueue();
  }
}

void Fifo::AttachChannel(Cid cid, UpperQueueDownEnd* channel_down_end, Cid remote_cid) {
  ASSERT(channel_queue_end_map_.find(cid) == channel_queue_end_map_.end());
  channel_queue_end_map_.emplace(std::piecewise_construct, std::forward_as_tuple(cid),
                                 std::forward_as_tuple(handler_, channel_down_end, this, cid, remote_cid));
}

void Fifo::DetachChannel(Cid cid) {
  ASSERT(channel_queue_end_map_.find(cid) != channel_queue_end_map_.end());
  channel_queue_end_map_.erase(cid);
}

std::unique_ptr<Fifo::UpperDequeue> Fifo::link_queue_enqueue_callback() {
  ASSERT(!next_to_dequeue_.empty());
  auto channel_id = next_to_dequeue_.front();
  next_to_dequeue_.pop();
  auto& dequeue_buffer = channel_queue_end_map_.find(channel_id)->second.dequeue_buffer_;
  auto packet = std::move(dequeue_buffer.front());
  dequeue_buffer.pop();
  if (dequeue_buffer.size() < ChannelQueueEndAndBuffer::kBufferSize) {
    channel_queue_end_map_.find(channel_id)->second.try_register_dequeue();
  }
  if (next_to_dequeue_.empty()) {
    link_queue_up_end_->UnregisterEnqueue();
    link_queue_enqueue_registered_ = false;
  }
  Cid remote_channel_id = channel_queue_end_map_.find(channel_id)->second.remote_channel_id_;
  return BasicFrameBuilder::Create(remote_channel_id, std::move(packet));
}

void Fifo::try_register_link_queue_enqueue() {
  if (link_queue_enqueue_registered_) {
    return;
  }
  link_queue_up_end_->RegisterEnqueue(handler_,
                                      common::Bind(&Fifo::link_queue_enqueue_callback, common::Unretained(this)));
  link_queue_enqueue_registered_ = true;
}

void Fifo::link_queue_dequeue_callback() {
  auto packet = link_queue_up_end_->TryDequeue();
  auto base_frame_view = BasicFrameView::Create(*packet);
  if (!base_frame_view.IsValid()) {
    return;
  }
  Cid cid = static_cast<Cid>(base_frame_view.GetChannelId());
  auto channel = channel_queue_end_map_.find(cid);
  if (channel == channel_queue_end_map_.end()) {
    return;  // Channel is not attached to scheduler
  }
  auto& queue_end_and_buffer = channel->second;

  queue_end_and_buffer.enqueue_buffer_.Enqueue(
      std::make_unique<PacketView<kLittleEndian>>(base_frame_view.GetPayload()), handler_);
}

void Fifo::ChannelQueueEndAndBuffer::try_register_dequeue() {
  if (is_dequeue_registered_) {
    return;
  }
  queue_end_->RegisterDequeue(
      handler_, common::Bind(&Fifo::ChannelQueueEndAndBuffer::dequeue_callback, common::Unretained(this)));
  is_dequeue_registered_ = true;
}

void Fifo::ChannelQueueEndAndBuffer::dequeue_callback() {
  auto packet = queue_end_->TryDequeue();
  ASSERT(packet != nullptr);
  dequeue_buffer_.emplace(std::move(packet));
  if (dequeue_buffer_.size() >= kBufferSize) {
    queue_end_->UnregisterDequeue();
    is_dequeue_registered_ = false;
  }
  scheduler_->next_to_dequeue_.push(channel_id_);
  scheduler_->try_register_link_queue_enqueue();
}

Fifo::ChannelQueueEndAndBuffer::~ChannelQueueEndAndBuffer() {
  if (is_dequeue_registered_) {
    queue_end_->UnregisterDequeue();
  }
}

}  // namespace internal
}  // namespace l2cap
}  // namespace bluetooth
