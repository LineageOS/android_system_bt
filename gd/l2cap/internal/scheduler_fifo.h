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

#include <string>
#include <unordered_map>

#include "common/bidi_queue.h"
#include "common/bind.h"
#include "l2cap/cid.h"
#include "l2cap/internal/scheduler.h"
#include "os/handler.h"
#include "os/queue.h"
#include "packet/base_packet_builder.h"
#include "packet/packet_view.h"

namespace bluetooth {
namespace l2cap {
namespace internal {

class Fifo : public Scheduler {
 public:
  Fifo(LowerQueueUpEnd* link_queue_up_end, os::Handler* handler)
      : link_queue_up_end_(link_queue_up_end), handler_(handler) {
    ASSERT(link_queue_up_end_ != nullptr && handler_ != nullptr);
    link_queue_up_end_->RegisterDequeue(handler_,
                                        common::Bind(&Fifo::link_queue_dequeue_callback, common::Unretained(this)));
  }

  ~Fifo() override;
  void AttachChannel(Cid cid, UpperQueueDownEnd* channel_down_end) override;
  void DetachChannel(Cid cid) override;
  LowerQueueUpEnd* GetLowerQueueUpEnd() const override {
    return link_queue_up_end_;
  }

 private:
  LowerQueueUpEnd* link_queue_up_end_;
  os::Handler* handler_;

  struct ChannelQueueEndAndBuffer {
    ChannelQueueEndAndBuffer(os::Handler* handler, UpperQueueDownEnd* queue_end, Fifo* scheduler, Cid channel_id)
        : handler_(handler), queue_end_(queue_end), enqueue_buffer_(queue_end), scheduler_(scheduler),
          channel_id_(channel_id) {
      try_register_dequeue();
    }
    os::Handler* handler_;
    UpperQueueDownEnd* queue_end_;
    os::EnqueueBuffer<UpperEnqueue> enqueue_buffer_;
    constexpr static int kBufferSize = 1;
    std::queue<std::unique_ptr<UpperDequeue>> dequeue_buffer_;
    Fifo* scheduler_;
    Cid channel_id_;
    bool is_dequeue_registered_ = false;

    void try_register_dequeue();
    void dequeue_callback();
    ~ChannelQueueEndAndBuffer();
  };

  std::unordered_map<Cid, ChannelQueueEndAndBuffer> channel_queue_end_map_;
  std::queue<Cid> next_to_dequeue_;
  void link_queue_dequeue_callback();

  bool link_queue_enqueue_registered_ = false;
  void try_register_link_queue_enqueue();
  std::unique_ptr<LowerEnqueue> link_queue_enqueue_callback();
};

}  // namespace internal
}  // namespace l2cap
}  // namespace bluetooth
