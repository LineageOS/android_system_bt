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
#include "hci/address.h"
#include "l2cap/cid.h"
#include "l2cap/classic/dynamic_channel.h"
#include "l2cap/psm.h"
#include "os/handler.h"
#include "os/log.h"

namespace bluetooth {
namespace l2cap {
namespace classic {
namespace internal {

class Link;

class DynamicChannelImpl {
 public:
  DynamicChannelImpl(Psm psm, Cid cid, Cid remote_cid, Link* link, os::Handler* l2cap_handler);

  virtual ~DynamicChannelImpl() = default;

  hci::Address GetDevice() const;

  virtual void RegisterOnCloseCallback(os::Handler* user_handler, DynamicChannel::OnCloseCallback on_close_callback);

  virtual void Close();
  virtual void OnClosed(hci::ErrorCode status);
  virtual std::string ToString();

  common::BidiQueueEnd<packet::BasePacketBuilder, packet::PacketView<packet::kLittleEndian>>* GetQueueUpEnd() {
    return channel_queue_.GetUpEnd();
  }

  common::BidiQueueEnd<packet::PacketView<packet::kLittleEndian>, packet::BasePacketBuilder>* GetQueueDownEnd() {
    return channel_queue_.GetDownEnd();
  }

  virtual Cid GetCid() const {
    return cid_;
  }

  virtual Cid GetRemoteCid() const {
    return remote_cid_;
  }

  virtual Psm GetPsm() const {
    return psm_;
  }

 private:
  const Psm psm_;
  const Cid cid_;
  const Cid remote_cid_;
  Link* link_;
  os::Handler* l2cap_handler_;
  const hci::Address device_;

  // User supported states
  os::Handler* user_handler_ = nullptr;
  DynamicChannel::OnCloseCallback on_close_callback_{};

  // Internal states
  bool closed_ = false;
  hci::ErrorCode close_reason_ = hci::ErrorCode::SUCCESS;
  static constexpr size_t kChannelQueueSize = 10;
  common::BidiQueue<packet::PacketView<packet::kLittleEndian>, packet::BasePacketBuilder> channel_queue_{
      kChannelQueueSize};

  DISALLOW_COPY_AND_ASSIGN(DynamicChannelImpl);
};

}  // namespace internal
}  // namespace classic
}  // namespace l2cap
}  // namespace bluetooth
