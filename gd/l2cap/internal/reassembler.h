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

#pragma once

#include <unordered_map>
#include <utility>

#include "common/bidi_queue.h"
#include "l2cap/cid.h"
#include "l2cap/l2cap_packets.h"
#include "l2cap/mtu.h"
#include "os/queue.h"
#include "packet/base_packet_builder.h"
#include "packet/packet_view.h"

namespace bluetooth {
namespace l2cap {
namespace internal {

/**
 * Handle the reassembly of L2CAP SDU from PDU.
 * Dequeue incoming packets from LinkQueueUpEnd, and enqueue it to ChannelQueueDownEnd. Note: If a channel
 * cannot dequeue from ChannelQueueDownEnd so that the buffer for incoming packet is full, further incoming packets will
 * be dropped.
 * The Reassembler keeps the reference to ChannelImpl objects, because it needs to check channel mode and parameters.
 */
class Reassembler {
 public:
  using UpperEnqueue = packet::PacketView<packet::kLittleEndian>;
  using UpperDequeue = packet::BasePacketBuilder;
  using UpperQueueDownEnd = common::BidiQueueEnd<UpperEnqueue, UpperDequeue>;
  using LowerEnqueue = UpperDequeue;
  using LowerDequeue = UpperEnqueue;
  using LowerQueueUpEnd = common::BidiQueueEnd<LowerEnqueue, LowerDequeue>;

  Reassembler(LowerQueueUpEnd* link_queue_up_end, os::Handler* handler);
  ~Reassembler();

  struct ChannelConfigurationOptions {
    Mtu incoming_mtu_ = kDefaultClassicMtu;
    RetransmissionAndFlowControlModeOption mode_ = RetransmissionAndFlowControlModeOption::L2CAP_BASIC;
    // TODO: Add all RetransmissionAndFlowControlConfigurationOptions
    FcsType fcs_type_ = FcsType::NO_FCS;
  };

  /**
   * Attach a channel for packet reassembly.
   * If the channel is reconfigured, signalling manager should detach channel and attach channel again.
   */
  void AttachChannel(Cid cid, UpperQueueDownEnd* channel_down_end, ChannelConfigurationOptions options);

  /**
   * Detach a channel for packet reassembly. Incoming packets won't be delivered to the specified cid.
   */
  void DetachChannel(Cid cid);

 private:
  struct ChannelBufferAndOptions {
    ChannelBufferAndOptions(UpperQueueDownEnd* queue_end, ChannelConfigurationOptions options)
        : enqueue_buffer_(queue_end), options_(std::move(options)) {}
    os::EnqueueBuffer<UpperEnqueue> enqueue_buffer_;
    ChannelConfigurationOptions options_;
  };

  LowerQueueUpEnd* link_queue_up_end_;
  os::Handler* handler_;
  std::unordered_map<Cid, ChannelBufferAndOptions> channel_map_;

  void link_queue_dequeue_callback();
  void handle_basic_mode_packet(Cid cid, const BasicFrameView& view);
  void handle_enhanced_retransmission_mode_packet(Cid cid, BasicFrameView view);
};

}  // namespace internal
}  // namespace l2cap
}  // namespace bluetooth
