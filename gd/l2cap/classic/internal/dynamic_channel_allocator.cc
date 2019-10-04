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
#include "l2cap/classic/internal/dynamic_channel_allocator.h"
#include "l2cap/classic/internal/link.h"
#include "l2cap/security_policy.h"
#include "os/handler.h"
#include "os/log.h"

namespace bluetooth {
namespace l2cap {
namespace classic {
namespace internal {

std::shared_ptr<DynamicChannelImpl> DynamicChannelAllocator::AllocateChannel(Psm psm, Cid remote_cid,
                                                                             SecurityPolicy security_policy) {
  if (IsChannelAllocated((psm))) {
    LOG_INFO("Psm 0x%x for device %s is already in use", psm, link_->GetDevice().ToString().c_str());
    return nullptr;
  }
  if (!IsPsmValid(psm)) {
    LOG_INFO("Psm 0x%x is invalid", psm);
    return nullptr;
  }
  if (used_remote_cid_.find(remote_cid) != used_remote_cid_.end()) {
    LOG_INFO("Remote cid 0x%x is used", remote_cid);
    return nullptr;
  }
  Cid cid = kFirstDynamicChannel;
  for (; cid <= kLastDynamicChannel; cid++) {
    LOG_INFO();
    if (used_cid_.count(cid) == 0) break;
  }
  if (cid > kLastDynamicChannel) {
    LOG_WARN("All cid are used");
    return nullptr;
  }
  auto elem =
      channels_.try_emplace(psm, std::make_shared<DynamicChannelImpl>(psm, cid, remote_cid, link_, l2cap_handler_));
  ASSERT_LOG(elem.second, "Failed to create channel for psm 0x%x device %s", psm,
             link_->GetDevice().ToString().c_str());
  ASSERT(elem.first->second != nullptr);
  used_cid_.insert(cid);
  used_remote_cid_.insert(remote_cid);
  return elem.first->second;
}

void DynamicChannelAllocator::FreeChannel(Psm psm) {
  ASSERT_LOG(IsChannelAllocated(psm), "Channel is not in use: psm %d, device %s", psm,
             link_->GetDevice().ToString().c_str());
  channels_.erase(psm);
}

bool DynamicChannelAllocator::IsChannelAllocated(Psm psm) const {
  return channels_.find(psm) != channels_.end();
}

std::shared_ptr<DynamicChannelImpl> DynamicChannelAllocator::FindChannel(Psm psm) {
  ASSERT_LOG(IsChannelAllocated(psm), "Channel is not in use: psm %d, device %s", psm,
             link_->GetDevice().ToString().c_str());
  return channels_.find(psm)->second;
}

size_t DynamicChannelAllocator::NumberOfChannels() const {
  return channels_.size();
}

void DynamicChannelAllocator::OnAclDisconnected(hci::ErrorCode reason) {
  for (auto& elem : channels_) {
    elem.second->OnClosed(reason);
  }
}

}  // namespace internal
}  // namespace classic
}  // namespace l2cap
}  // namespace bluetooth
