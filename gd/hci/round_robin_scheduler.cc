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

#include "hci/round_robin_scheduler.h"
#include "hci/acl_fragmenter.h"

namespace bluetooth {
namespace hci {

RoundRobinScheduler::RoundRobinScheduler(os::Handler* handler, Controller* controller,
                                         common::BidiQueueEnd<AclPacketBuilder, AclPacketView>* hci_queue_end)
    : handler_(handler), controller_(controller), hci_queue_end_(hci_queue_end) {
  max_acl_packet_credits_ = controller_->GetControllerNumAclPacketBuffers();
  acl_packet_credits_ = max_acl_packet_credits_;
  hci_mtu_ = controller_->GetControllerAclPacketLength();
  controller_->RegisterCompletedAclPacketsCallback(
      common::Bind(&RoundRobinScheduler::IncomingAclCredits, common::Unretained(this)), handler_);
}

RoundRobinScheduler::~RoundRobinScheduler() {
  UnregisterAllConnections();
  controller_->UnregisterCompletedAclPacketsCallback();
}

void RoundRobinScheduler::Register(uint16_t handle, AclConnection::QueueDownEnd* queue_down_end) {
  acl_queue_handler acl_queue_handler = {queue_down_end, false, 0, false};
  acl_queue_handlers_.insert(std::pair<uint16_t, RoundRobinScheduler::acl_queue_handler>(handle, acl_queue_handler));
  if (fragments_to_send_.size() == 0) {
    StartRoundRobin();
  }
}

void RoundRobinScheduler::Unregister(uint16_t handle) {
  ASSERT(acl_queue_handlers_.count(handle) == 1);
  auto acl_queue_handler = acl_queue_handlers_.find(handle)->second;
  if (acl_queue_handler.dequeue_is_registered_) {
    acl_queue_handler.dequeue_is_registered_ = false;
    acl_queue_handler.queue_down_end_->UnregisterDequeue();
  }
  acl_queue_handlers_.erase(handle);
  starting_point_ = acl_queue_handlers_.begin();
}

void RoundRobinScheduler::SetDisconnect(uint16_t handle) {
  auto acl_queue_handler = acl_queue_handlers_.find(handle)->second;
  acl_queue_handler.is_disconnected_ = true;
  // Reclaim outstanding packets
  acl_packet_credits_ += acl_queue_handler.number_of_sent_packets_;
  acl_queue_handler.number_of_sent_packets_ = 0;
}

void RoundRobinScheduler::StartRoundRobin() {
  if (acl_packet_credits_ == 0) {
    return;
  }
  if (!fragments_to_send_.empty()) {
    SendNextFragment();
    return;
  }

  if (acl_queue_handlers_.size() == 1 || starting_point_ == acl_queue_handlers_.end()) {
    starting_point_ = acl_queue_handlers_.begin();
  }
  size_t count = acl_queue_handlers_.size();

  for (auto acl_queue_handler = starting_point_; count > 0; count--) {
    if (!acl_queue_handler->second.dequeue_is_registered_) {
      acl_queue_handler->second.dequeue_is_registered_ = true;
      acl_queue_handler->second.queue_down_end_->RegisterDequeue(
          handler_, common::Bind(&RoundRobinScheduler::BufferPacket, common::Unretained(this), acl_queue_handler));
    }
    acl_queue_handler = std::next(acl_queue_handler);
    if (acl_queue_handler == acl_queue_handlers_.end()) {
      acl_queue_handler = acl_queue_handlers_.begin();
    }
  }

  starting_point_ = std::next(starting_point_);
}

void RoundRobinScheduler::BufferPacket(std::map<uint16_t, acl_queue_handler>::iterator acl_queue_handler) {
  BroadcastFlag broadcast_flag = BroadcastFlag::POINT_TO_POINT;
  //   Wrap packet and enqueue it
  uint16_t handle = acl_queue_handler->first;
  auto packet = acl_queue_handler->second.queue_down_end_->TryDequeue();
  ASSERT(packet != nullptr);

  if (packet->size() <= hci_mtu_) {
    fragments_to_send_.push(AclPacketBuilder::Create(handle, PacketBoundaryFlag::FIRST_AUTOMATICALLY_FLUSHABLE,
                                                     broadcast_flag, std::move(packet)));
  } else {
    auto fragments = AclFragmenter(hci_mtu_, std::move(packet)).GetFragments();
    PacketBoundaryFlag packet_boundary_flag = PacketBoundaryFlag::FIRST_AUTOMATICALLY_FLUSHABLE;
    for (size_t i = 0; i < fragments.size(); i++) {
      fragments_to_send_.push(
          AclPacketBuilder::Create(handle, packet_boundary_flag, broadcast_flag, std::move(fragments[i])));
      packet_boundary_flag = PacketBoundaryFlag::CONTINUING_FRAGMENT;
    }
  }
  ASSERT(fragments_to_send_.size() > 0);
  UnregisterAllConnections();

  acl_queue_handler->second.number_of_sent_packets_ += fragments_to_send_.size();
  SendNextFragment();
}

void RoundRobinScheduler::UnregisterAllConnections() {
  for (auto acl_queue_handler = acl_queue_handlers_.begin(); acl_queue_handler != acl_queue_handlers_.end();
       acl_queue_handler = std::next(acl_queue_handler)) {
    if (acl_queue_handler->second.dequeue_is_registered_) {
      acl_queue_handler->second.dequeue_is_registered_ = false;
      acl_queue_handler->second.queue_down_end_->UnregisterDequeue();
    }
  }
}

void RoundRobinScheduler::SendNextFragment() {
  if (!enqueue_registered_.exchange(true)) {
    hci_queue_end_->RegisterEnqueue(
        handler_, common::Bind(&RoundRobinScheduler::HandleEnqueueNextFragment, common::Unretained(this)));
  }
}

// Invoked from some external Queue Reactable context 1
std::unique_ptr<AclPacketBuilder> RoundRobinScheduler::HandleEnqueueNextFragment() {
  ASSERT(acl_packet_credits_ > 0);
  if (acl_packet_credits_ == 1 || fragments_to_send_.size() == 1) {
    if (enqueue_registered_.exchange(false)) {
      hci_queue_end_->UnregisterEnqueue();
    }
  }
  ASSERT(fragments_to_send_.size() > 0);
  auto raw_pointer = fragments_to_send_.front().release();
  acl_packet_credits_ -= 1;
  fragments_to_send_.pop();
  if (fragments_to_send_.empty()) {
    handler_->Post(common::BindOnce(&RoundRobinScheduler::StartRoundRobin, common::Unretained(this)));
  }
  return std::unique_ptr<AclPacketBuilder>(raw_pointer);
}

void RoundRobinScheduler::IncomingAclCredits(uint16_t handle, uint16_t credits) {
  auto acl_queue_handler = acl_queue_handlers_.find(handle);
  if (acl_queue_handler == acl_queue_handlers_.end()) {
    LOG_INFO("Dropping %hx received credits to unknown connection 0x%0hx", credits, handle);
    return;
  }
  if (acl_queue_handler->second.is_disconnected_) {
    LOG_INFO("Dropping %hx received credits to disconnected connection 0x%0hx", credits, handle);
    return;
  }
  acl_queue_handler->second.number_of_sent_packets_ -= credits;
  acl_packet_credits_ += credits;
  ASSERT(acl_packet_credits_ <= max_acl_packet_credits_);
  if (acl_packet_credits_ == credits) {
    StartRoundRobin();
  }
}

}  // namespace hci
}  // namespace bluetooth