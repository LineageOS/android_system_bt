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

#include "l2cap/internal/enhanced_retransmission_mode_channel_data_controller.h"

namespace bluetooth {
namespace l2cap {
namespace internal {
ErtmController::ErtmController(Cid cid, Cid remote_cid, UpperQueueDownEnd* channel_queue_end, os::Handler* handler,
                               Scheduler* scheduler)
    : cid_(cid), enqueue_buffer_(channel_queue_end), handler_(handler), scheduler_(scheduler) {}

void ErtmController::OnSdu(std::unique_ptr<packet::BasePacketBuilder> sdu) {
  LOG_ERROR("Not implemented");
}

void ErtmController::OnPdu(BasicFrameView pdu) {
  LOG_ERROR("Not implemented");
}

std::unique_ptr<BasicFrameBuilder> ErtmController::GetNextPacket() {
  auto next = std::move(pdu_queue_.front());
  pdu_queue_.pop();
  return next;
}

}  // namespace internal
}  // namespace l2cap
}  // namespace bluetooth
