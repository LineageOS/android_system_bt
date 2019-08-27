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

#include "common/bidi_queue.h"
#include "l2cap/cid.h"
#include "l2cap/l2cap_packets.h"
#include "packet/base_packet_builder.h"
#include "packet/packet_view.h"

namespace bluetooth {
namespace l2cap {
namespace internal {

/**
 * Handle the scheduling of packets through the l2cap stack.
 * For each attached channel, dequeue its outgoing packets and enqueue it to the given LinkQueueUpEnd, according to some
 * policy (cid). Dequeue incoming packets from LinkQueueUpEnd, and enqueue it to ChannelQueueDownEnd. Note: If a channel
 * cannot dequeue from ChannelQueueDownEnd so that the buffer for incoming packet is full, further incoming packets will
 * be dropped.
 */
class Scheduler {
 public:
  using UpperEnqueue = packet::PacketView<packet::kLittleEndian>;
  using UpperDequeue = packet::BasePacketBuilder;
  using UpperQueueDownEnd = common::BidiQueueEnd<UpperEnqueue, UpperDequeue>;
  using LowerEnqueue = UpperDequeue;
  using LowerDequeue = UpperEnqueue;
  using LowerQueueUpEnd = common::BidiQueueEnd<LowerEnqueue, LowerDequeue>;
  using DemuxPolicy = common::Callback<Cid(const UpperEnqueue&)>;

  /**
   * Attach the channel with the specified ChannelQueueDownEnd into the scheduler.
   *
   * @param cid The channel to attach to the scheduler.
   * @param channel_down_end The ChannelQueueDownEnd associated with the channel to attach to the scheduler.
   */
  virtual void AttachChannel(Cid cid, UpperQueueDownEnd* channel_down_end) {}

  /**
   * Detach the channel from the scheduler.
   *
   * @param cid The channel to detach to the scheduler.
   */
  virtual void DetachChannel(Cid cid) {}

  /**
   * Return the lower queue up end, which can be used to enqueue or dequeue.
   */
  virtual LowerQueueUpEnd* GetLowerQueueUpEnd() const = 0;

  virtual ~Scheduler() = default;
};

}  // namespace internal
}  // namespace l2cap
}  // namespace bluetooth
