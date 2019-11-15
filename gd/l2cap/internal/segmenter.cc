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

#include <string>
#include <unordered_map>

#include "common/bind.h"
#include "l2cap/cid.h"
#include "l2cap/internal/scheduler.h"
#include "l2cap/internal/segmenter.h"
#include "os/handler.h"
#include "os/log.h"
#include "os/queue.h"
#include "packet/base_packet_builder.h"

namespace bluetooth {
namespace l2cap {
namespace internal {

Segmenter::Segmenter(os::Handler* handler, UpperQueueDownEnd* queue_end, Scheduler* scheduler, Cid channel_id,
                     Cid remote_channel_id)
    : handler_(handler), queue_end_(queue_end), scheduler_(scheduler), channel_id_(channel_id),
      remote_channel_id_(remote_channel_id) {
  try_register_dequeue();
}

Segmenter::~Segmenter() {
  if (is_dequeue_registered_) {
    queue_end_->UnregisterDequeue();
  }
}

void Segmenter::NotifyPacketSent() {
  try_register_dequeue();
}

std::unique_ptr<Segmenter::UpperDequeue> Segmenter::GetNextPacket() {
  ASSERT_LOG(!pdu_buffer_.empty(), "No packet is available");
  auto packet = std::move(pdu_buffer_.front());
  pdu_buffer_.pop();
  return packet;
}

void Segmenter::try_register_dequeue() {
  if (is_dequeue_registered_) {
    return;
  }
  queue_end_->RegisterDequeue(handler_, common::Bind(&Segmenter::dequeue_callback, common::Unretained(this)));
  is_dequeue_registered_ = true;
}

void Segmenter::dequeue_callback() {
  auto packet = queue_end_->TryDequeue();
  ASSERT(packet != nullptr);
  // TODO(hsz): Construct PDU(s) according to channel mode.
  auto pdu = BasicFrameBuilder::Create(remote_channel_id_, std::move(packet));
  pdu_buffer_.emplace(std::move(pdu));
  queue_end_->UnregisterDequeue();
  is_dequeue_registered_ = false;
  scheduler_->NotifyPacketsReady(channel_id_, 1);
}

}  // namespace internal
}  // namespace l2cap
}  // namespace bluetooth
