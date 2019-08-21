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
#include "common/callback.h"
#include "os/handler.h"
#include "packet/base_packet_builder.h"
#include "packet/packet_view.h"

namespace bluetooth {
namespace l2cap {

namespace internal {
class ClassicFixedChannelImpl;
}  // namespace internal

/**
 * L2CAP fixed channel object. When a new object is created, it must be
 * acquired through calling {@link FixedChannel#Acquire()} within X seconds.
 * Otherwise, {@link FixeChannel#Release()} will be called automatically.
 *
 */
class ClassicFixedChannel {
 public:
  using OnCloseCallback = common::Callback<void()>;

  /**
   * Register close callback. If close callback is registered, when a channel is closed, the channel's resource will
   * only be freed after on_close callback is invoked. Otherwise, if no on_close callback is registered, the channel's
   * resource will be freed immediately after closing.
   *
   * @param on_close The callback invoked upon channel closing.
   */
  void RegisterOnCloseCallback(os::Handler* handler, OnCloseCallback on_close);

  /**
   * Indicate that this Fixed Channel is being used. This will prevent ACL
   * connection from being disconnected.
   */
  void Acquire();

  /**
   * Indicate that this Fixed Channel is no longer being used. ACL connection
   * will be disconnected after X seconds if no other DynamicChannel is connected
   * or no other Fixed Channel is using this ACL connection. However a module can
   * still receive data on this channel as long as it remains open.
   */
  void Release();

  /**
   * This method will retrieve the data channel queue to send and receive packets.
   *
   * {@see BidiQueueEnd}
   *
   * @return The upper end of a bi-directional queue.
   */
  common::BidiQueueEnd<packet::PacketView<packet::kLittleEndian>, packet::BasePacketBuilder>* GetQueueUpEnd() const;

  friend class internal::ClassicFixedChannelImpl;

 private:
  ClassicFixedChannel(os::Handler* l2cap_handler, internal::ClassicFixedChannelImpl* classic_fixed_channel_impl)
      : l2cap_handler_(l2cap_handler), classic_fixed_channel_impl_(classic_fixed_channel_impl) {}
  os::Handler* l2cap_handler_;
  internal::ClassicFixedChannelImpl* classic_fixed_channel_impl_;
  DISALLOW_COPY_AND_ASSIGN(ClassicFixedChannel);
};

}  // namespace l2cap
}  // namespace bluetooth
