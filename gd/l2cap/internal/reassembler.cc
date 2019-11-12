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
#include "common/bidi_queue.h"
#include "l2cap/cid.h"
#include "l2cap/l2cap_packets.h"
#include "packet/base_packet_builder.h"
#include "packet/packet_view.h"
#

namespace bluetooth {
namespace l2cap {
namespace internal {
Reassembler::Reassembler(LowerQueueUpEnd* link_queue_up_end, os::Handler* handler)
    : link_queue_up_end_(link_queue_up_end), handler_(handler) {
  ASSERT(link_queue_up_end_ != nullptr && handler_ != nullptr);
  link_queue_up_end_->RegisterDequeue(
      handler_, common::Bind(&Reassembler::link_queue_dequeue_callback, common::Unretained(this)));
}

Reassembler::~Reassembler() {
  link_queue_up_end_->UnregisterDequeue();
}

void Reassembler::AttachChannel(Cid cid, Reassembler::UpperQueueDownEnd* channel_down_end,
                                Reassembler::ChannelConfigurationOptions options) {
  ASSERT_LOG(channel_map_.find(cid) == channel_map_.end(), "Channel is already attached");
  auto pair = ChannelBufferAndOptions(channel_down_end, options);
  channel_map_.emplace(std::piecewise_construct, std::forward_as_tuple(cid),
                       std::forward_as_tuple(channel_down_end, options));
}

void Reassembler::DetachChannel(Cid cid) {
  ASSERT_LOG(channel_map_.find(cid) != channel_map_.end(), "Channel is not attached");
  channel_map_.erase(cid);
}

void Reassembler::link_queue_dequeue_callback() {
  auto packet = link_queue_up_end_->TryDequeue();
  auto basic_frame_view = BasicFrameView::Create(*packet);
  if (!basic_frame_view.IsValid()) {
    LOG_WARN("Received an invalid basic frame");
    return;
  }
  Cid cid = static_cast<Cid>(basic_frame_view.GetChannelId());
  auto channel = channel_map_.find(cid);
  if (channel == channel_map_.end()) {
    LOG_WARN("Received a packet with invalid cid: %d", cid);
    return;  // Channel is not attached to scheduler
  }

  auto channel_mode = channel->second.options_.mode_;
  switch (channel_mode) {
    case RetransmissionAndFlowControlModeOption::L2CAP_BASIC:
      handle_basic_mode_packet(cid, basic_frame_view);
      break;
    case RetransmissionAndFlowControlModeOption::ENHANCED_RETRANSMISSION:
      handle_enhanced_retransmission_mode_packet(cid, std::move(basic_frame_view));
      break;
    default:
      LOG_WARN("channel mode is not supported: %d", static_cast<int>(channel_mode));
  }
}

void Reassembler::handle_basic_mode_packet(Cid cid, const BasicFrameView& view) {
  auto channel = channel_map_.find(cid);
  auto& enqueue_buffer = channel->second.enqueue_buffer_;

  enqueue_buffer.Enqueue(std::make_unique<PacketView<kLittleEndian>>(view.GetPayload()), handler_);
}

void Reassembler::handle_enhanced_retransmission_mode_packet(Cid cid, BasicFrameView view) {
  LOG_ERROR("Enhanced retransmission mode is not implemented");
}

}  // namespace internal
}  // namespace l2cap
}  // namespace bluetooth
