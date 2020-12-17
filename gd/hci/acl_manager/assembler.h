/*
 * Copyright 2020 The Android Open Source Project
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

namespace bluetooth {
namespace hci {
namespace acl_manager {

namespace {
class PacketViewForRecombination : public packet::PacketView<kLittleEndian> {
 public:
  PacketViewForRecombination(const PacketView& packetView) : PacketView(packetView) {}
  void AppendPacketView(packet::PacketView<kLittleEndian> to_append) {
    Append(to_append);
  }
};

constexpr size_t kMaxQueuedPacketsPerConnection = 10;
constexpr int kL2capBasicFrameHeaderSize = 4;

// Per spec 5.1 Vol 2 Part B 5.3, ACL link shall carry L2CAP data. Therefore, an ACL packet shall contain L2CAP PDU.
// This function returns the PDU size of the L2CAP data if it's a starting packet. Returns 0 if it's invalid.
uint16_t GetL2capPduSize(AclView packet) {
  auto l2cap_payload = packet.GetPayload();
  if (l2cap_payload.size() < kL2capBasicFrameHeaderSize) {
    LOG_ERROR("Controller sent an invalid L2CAP starting packet!");
    return 0;
  }
  return (l2cap_payload.at(1) << 8u) + l2cap_payload.at(0);
}

}  // namespace

struct assembler {
  assembler(AddressWithType address_with_type, AclConnection::QueueDownEnd* down_end, os::Handler* handler)
      : address_with_type_(address_with_type), down_end_(down_end), handler_(handler) {}
  AddressWithType address_with_type_;
  AclConnection::QueueDownEnd* down_end_;
  os::Handler* handler_;
  PacketViewForRecombination recombination_stage_{PacketView<kLittleEndian>(std::make_shared<std::vector<uint8_t>>())};
  int remaining_sdu_continuation_packet_size_ = 0;
  std::shared_ptr<std::atomic_bool> enqueue_registered_ = std::make_shared<std::atomic_bool>(false);
  std::queue<packet::PacketView<kLittleEndian>> incoming_queue_;

  ~assembler() {
    if (enqueue_registered_->exchange(false)) {
      down_end_->UnregisterEnqueue();
    }
  }

  // Invoked from some external Queue Reactable context
  std::unique_ptr<packet::PacketView<kLittleEndian>> on_le_incoming_data_ready() {
    auto packet = incoming_queue_.front();
    incoming_queue_.pop();
    if (incoming_queue_.empty() && enqueue_registered_->exchange(false)) {
      down_end_->UnregisterEnqueue();
    }
    return std::make_unique<PacketView<kLittleEndian>>(packet);
  }

  void on_incoming_packet(AclView packet) {
    PacketView<kLittleEndian> payload = packet.GetPayload();
    auto payload_size = payload.size();
    auto broadcast_flag = packet.GetBroadcastFlag();
    if (broadcast_flag == BroadcastFlag::ACTIVE_PERIPHERAL_BROADCAST) {
      LOG_WARN("Dropping broadcast from remote");
      return;
    }
    auto packet_boundary_flag = packet.GetPacketBoundaryFlag();
    if (packet_boundary_flag == PacketBoundaryFlag::FIRST_NON_AUTOMATICALLY_FLUSHABLE) {
      LOG_ERROR("Controller is not allowed to send FIRST_NON_AUTOMATICALLY_FLUSHABLE to host except loopback mode");
      return;
    }
    if (packet_boundary_flag == PacketBoundaryFlag::CONTINUING_FRAGMENT) {
      if (remaining_sdu_continuation_packet_size_ < payload_size) {
        LOG_WARN("Remote sent unexpected L2CAP PDU. Drop the entire L2CAP PDU");
        recombination_stage_ =
            PacketViewForRecombination(PacketView<kLittleEndian>(std::make_shared<std::vector<uint8_t>>()));
        remaining_sdu_continuation_packet_size_ = 0;
        return;
      }
      remaining_sdu_continuation_packet_size_ -= payload_size;
      recombination_stage_.AppendPacketView(payload);
      if (remaining_sdu_continuation_packet_size_ != 0) {
        return;
      } else {
        payload = recombination_stage_;
        recombination_stage_ =
            PacketViewForRecombination(PacketView<kLittleEndian>(std::make_shared<std::vector<uint8_t>>()));
      }
    } else if (packet_boundary_flag == PacketBoundaryFlag::FIRST_AUTOMATICALLY_FLUSHABLE) {
      if (recombination_stage_.size() > 0) {
        LOG_ERROR("Controller sent a starting packet without finishing previous packet. Drop previous one.");
      }
      auto l2cap_pdu_size = GetL2capPduSize(packet);
      remaining_sdu_continuation_packet_size_ = l2cap_pdu_size - (payload_size - kL2capBasicFrameHeaderSize);
      if (remaining_sdu_continuation_packet_size_ > 0) {
        recombination_stage_ = payload;
        return;
      }
    }
    if (incoming_queue_.size() > kMaxQueuedPacketsPerConnection) {
      LOG_ERROR("Dropping packet from %s due to congestion", address_with_type_.ToString().c_str());
      return;
    }

    incoming_queue_.push(payload);
    if (!enqueue_registered_->exchange(true)) {
      down_end_->RegisterEnqueue(handler_,
                                 common::Bind(&assembler::on_le_incoming_data_ready, common::Unretained(this)));
    }
  }
};

}  // namespace acl_manager
}  // namespace hci
}  // namespace bluetooth
