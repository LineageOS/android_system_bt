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
#include "l2cap/classic/internal/dynamic_channel_impl.h"
#include "l2cap/internal/basic_mode_channel_data_controller.h"
#include "l2cap/internal/enhanced_retransmission_mode_channel_data_controller.h"
#include "l2cap/internal/scheduler.h"
#include "l2cap/internal/sender.h"
#include "os/handler.h"
#include "os/log.h"
#include "os/queue.h"
#include "packet/base_packet_builder.h"

namespace bluetooth {
namespace l2cap {
namespace internal {

Sender::Sender(os::Handler* handler, Scheduler* scheduler, std::shared_ptr<ChannelImpl> channel)
    : handler_(handler), queue_end_(channel->GetQueueDownEnd()), scheduler_(scheduler), channel_id_(channel->GetCid()),
      remote_channel_id_(channel->GetRemoteCid()),
      data_controller_(std::make_unique<BasicModeDataController>(channel_id_, remote_channel_id_, queue_end_, handler_,
                                                                 scheduler_)) {
  try_register_dequeue();
}

Sender::~Sender() {
  if (is_dequeue_registered_) {
    queue_end_->UnregisterDequeue();
  }
}

void Sender::OnPacketSent() {
  try_register_dequeue();
}

std::unique_ptr<Sender::UpperDequeue> Sender::GetNextPacket() {
  return data_controller_->GetNextPacket();
}

void Sender::SetChannelRetransmissionFlowControlMode(RetransmissionAndFlowControlModeOption mode) {
  if (mode_ == mode) {
    return;
  }
  if (mode_ == RetransmissionAndFlowControlModeOption::L2CAP_BASIC) {
    data_controller_ =
        std::make_unique<BasicModeDataController>(channel_id_, remote_channel_id_, queue_end_, handler_, scheduler_);
    return;
  }
  if (mode == RetransmissionAndFlowControlModeOption::ENHANCED_RETRANSMISSION) {
    data_controller_ =
        std::make_unique<ErtmController>(channel_id_, remote_channel_id_, queue_end_, handler_, scheduler_);
    return;
  }
}

DataController* Sender::GetDataController() {
  return data_controller_.get();
}

void Sender::try_register_dequeue() {
  if (is_dequeue_registered_) {
    return;
  }
  queue_end_->RegisterDequeue(handler_, common::Bind(&Sender::dequeue_callback, common::Unretained(this)));
  is_dequeue_registered_ = true;
}

void Sender::dequeue_callback() {
  auto packet = queue_end_->TryDequeue();
  ASSERT(packet != nullptr);
  data_controller_->OnSdu(std::move(packet));
  queue_end_->UnregisterDequeue();
  is_dequeue_registered_ = false;
}

}  // namespace internal
}  // namespace l2cap
}  // namespace bluetooth
