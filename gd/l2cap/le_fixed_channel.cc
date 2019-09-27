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

#include "l2cap/le_fixed_channel.h"
#include "common/bind.h"
#include "l2cap/internal/le_fixed_channel_impl.h"

namespace bluetooth {
namespace l2cap {

hci::Address LeFixedChannel::GetDevice() const {
  return impl_->GetDevice();
}

void LeFixedChannel::RegisterOnCloseCallback(os::Handler* user_handler,
                                             LeFixedChannel::OnCloseCallback on_close_callback) {
  l2cap_handler_->Post(common::BindOnce(&internal::LeFixedChannelImpl::RegisterOnCloseCallback, impl_, user_handler,
                                        std::move(on_close_callback)));
}

void LeFixedChannel::Acquire() {
  l2cap_handler_->Post(common::BindOnce(&internal::LeFixedChannelImpl::Acquire, impl_));
}

void LeFixedChannel::Release() {
  l2cap_handler_->Post(common::BindOnce(&internal::LeFixedChannelImpl::Release, impl_));
}

common::BidiQueueEnd<packet::BasePacketBuilder, packet::PacketView<packet::kLittleEndian>>*
LeFixedChannel::GetQueueUpEnd() const {
  return impl_->GetQueueUpEnd();
}
}  // namespace l2cap
}  // namespace bluetooth