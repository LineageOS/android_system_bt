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

#include "l2cap/cid.h"
#include "l2cap/internal/le_fixed_channel_allocator.h"
#include "l2cap/internal/le_link.h"
#include "l2cap/security_policy.h"
#include "le_fixed_channel_allocator.h"
#include "os/handler.h"
#include "os/log.h"

namespace bluetooth {
namespace l2cap {
namespace internal {

std::shared_ptr<LeFixedChannelImpl> LeFixedChannelAllocator::AllocateChannel(Cid cid, SecurityPolicy security_policy) {
  ASSERT_LOG(!IsChannelAllocated((cid)), "Cid 0x%x for device %s is already in use", cid,
             link_->GetDevice().ToString().c_str());
  ASSERT_LOG(cid >= kFirstFixedChannel && cid <= kLastFixedChannel, "Cid %d out of bound", cid);
  auto elem = channels_.try_emplace(cid, std::make_shared<LeFixedChannelImpl>(cid, link_, l2cap_handler_));
  ASSERT_LOG(elem.second, "Failed to create channel for cid 0x%x device %s", cid,
             link_->GetDevice().ToString().c_str());
  ASSERT(elem.first->second != nullptr);
  return elem.first->second;
}

void LeFixedChannelAllocator::FreeChannel(Cid cid) {
  ASSERT_LOG(IsChannelAllocated(cid), "Channel is not in use: cid %d, device %s", cid,
             link_->GetDevice().ToString().c_str());
  channels_.erase(cid);
}

bool LeFixedChannelAllocator::IsChannelAllocated(Cid cid) const {
  return channels_.find(cid) != channels_.end();
}

std::shared_ptr<LeFixedChannelImpl> LeFixedChannelAllocator::FindChannel(Cid cid) {
  ASSERT_LOG(IsChannelAllocated(cid), "Channel is not in use: cid %d, device %s", cid,
             link_->GetDevice().ToString().c_str());
  return channels_.find(cid)->second;
}

size_t LeFixedChannelAllocator::NumberOfChannels() const {
  return channels_.size();
}

void LeFixedChannelAllocator::OnAclDisconnected(hci::ErrorCode reason) {
  for (auto& elem : channels_) {
    elem.second->OnClosed(reason);
  }
}

int LeFixedChannelAllocator::GetRefCount() {
  int ref_count = 0;
  for (auto& elem : channels_) {
    if (elem.second->IsAcquired()) {
      ref_count++;
    }
  }
  return ref_count;
}

}  // namespace internal
}  // namespace l2cap
}  // namespace bluetooth
