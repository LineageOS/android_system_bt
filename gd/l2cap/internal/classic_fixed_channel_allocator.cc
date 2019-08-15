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

#include <unordered_map>

#include "classic_fixed_channel_allocator.h"
#include "l2cap/cid.h"
#include "l2cap/internal/classic_fixed_channel_allocator.h"
#include "l2cap/security_policy.h"
#include "os/handler.h"
#include "os/log.h"

namespace bluetooth {
namespace l2cap {
namespace internal {

ClassicFixedChannelImpl* ClassicFixedChannelAllocator::AllocateChannel(Cid cid, SecurityPolicy security_policy) {
  ASSERT_LOG(!IsChannelInUse((cid)), "Cid %d is already in use", cid);
  ASSERT_LOG(cid >= kFirstFixedChannel && cid <= kLastFixedChannel, "Cid %d out of bound", cid);
  channels_.try_emplace(cid, cid, handler_);
  return &channels_.find(cid)->second;
}

bool ClassicFixedChannelAllocator::FreeChannel(Cid cid) {
  ASSERT_LOG(IsChannelInUse(cid), "Channel is not in use: cid %d", cid);
  channels_.erase(cid);
  return true;
}

bool ClassicFixedChannelAllocator::IsChannelInUse(Cid cid) const {
  return channels_.find(cid) != channels_.end();
}

ClassicFixedChannelImpl* ClassicFixedChannelAllocator::FindChannel(Cid cid) {
  ASSERT_LOG(IsChannelInUse(cid), "Channel is not in use: cid %d", cid);
  return &channels_.find(cid)->second;
}
size_t ClassicFixedChannelAllocator::NumberOfChannels() const {
  return channels_.size();
}
}  // namespace internal
}  // namespace l2cap
}  // namespace bluetooth
