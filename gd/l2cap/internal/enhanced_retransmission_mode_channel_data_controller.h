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

#include <memory>
#include <unordered_map>
#include <utility>

#include "common/bidi_queue.h"
#include "l2cap/cid.h"
#include "l2cap/internal/channel_impl.h"
#include "l2cap/internal/data_controller.h"
#include "l2cap/internal/scheduler.h"
#include "l2cap/l2cap_packets.h"
#include "l2cap/mtu.h"
#include "os/handler.h"
#include "os/queue.h"
#include "packet/base_packet_builder.h"
#include "packet/packet_view.h"

namespace bluetooth {
namespace l2cap {
namespace internal {

class ErtmController : public DataController {
 public:
  using UpperEnqueue = packet::PacketView<packet::kLittleEndian>;
  using UpperDequeue = packet::BasePacketBuilder;
  using UpperQueueDownEnd = common::BidiQueueEnd<UpperEnqueue, UpperDequeue>;
  ErtmController(Cid cid, Cid remote_cid, UpperQueueDownEnd* channel_queue_end, os::Handler* handler,
                 Scheduler* scheduler);
  ~ErtmController();
  // Segmentation is handled here
  void OnSdu(std::unique_ptr<packet::BasePacketBuilder> sdu) override;
  void OnPdu(BasicFrameView pdu) override;
  std::unique_ptr<BasicFrameBuilder> GetNextPacket() override;

 private:
  [[maybe_unused]] Cid cid_;
  [[maybe_unused]] Cid remote_cid_;
  [[maybe_unused]] os::EnqueueBuffer<UpperEnqueue> enqueue_buffer_;
  [[maybe_unused]] os::Handler* handler_;
  std::queue<std::unique_ptr<BasicFrameBuilder>> pdu_queue_;
  [[maybe_unused]] Scheduler* scheduler_;
  // TODO: Support FCS
  [[maybe_unused]] FcsType fcs_type_ = FcsType::NO_FCS;

  class PacketViewForReassembly : public packet::PacketView<kLittleEndian> {
   public:
    PacketViewForReassembly(const PacketView& packetView) : PacketView(packetView) {}
    PacketViewForReassembly(nullptr_t) : PacketView(nullptr) {}
    void AppendPacketView(packet::PacketView<kLittleEndian> to_append) {
      Append(to_append);
    }
  };

  class CopyablePacketBuilder : public packet::BasePacketBuilder {
   public:
    CopyablePacketBuilder(std::unique_ptr<packet::BasePacketBuilder> builder) : builder_(builder.release()) {}

    void Serialize(BitInserter& it) const override;

    size_t size() const override;

    std::unique_ptr<packet::BasePacketBuilder> Create();

   private:
    std::shared_ptr<packet::BasePacketBuilder> builder_;
  };

  PacketViewForReassembly reassembly_stage_{nullptr};
  SegmentationAndReassembly sar_state_ = SegmentationAndReassembly::END;

  void stage_for_reassembly(SegmentationAndReassembly sar, const packet::PacketView<kLittleEndian>& payload);
  void send_pdu(std::unique_ptr<BasicFrameBuilder> pdu);

  void close_channel();

  // Configuration options
  // TODO: Configure these number
  [[maybe_unused]] uint16_t local_tx_window_ = 10;
  [[maybe_unused]] uint16_t local_max_transmit_ = 20;
  [[maybe_unused]] uint16_t local_retransmit_timeout_ms_ = 2000;
  [[maybe_unused]] uint16_t local_monitor_timeout_ms_ = 12000;
  [[maybe_unused]] uint16_t local_mps_ = 1010;

  [[maybe_unused]] uint16_t remote_tx_window_ = 10;
  [[maybe_unused]] uint16_t remote_max_transmit_ = 20;
  [[maybe_unused]] uint16_t remote_retransmit_timeout_ms_ = 2000;
  [[maybe_unused]] uint16_t remote_monitor_timeout_ms_ = 12000;
  [[maybe_unused]] uint16_t remote_mps_ = 1010;

  struct impl;
  std::unique_ptr<impl> pimpl_;
};

}  // namespace internal
}  // namespace l2cap
}  // namespace bluetooth
