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

#include <hci/hci_packets.h>
#include <unordered_map>

#include "l2cap/cid.h"
#include "l2cap/internal/le_fixed_channel_impl.h"
#include "l2cap/security_policy.h"
#include "os/handler.h"
#include "os/log.h"

namespace bluetooth {
namespace l2cap {
namespace internal {

class LeLink;

// Helper class for keeping channels in a Link. It allocates and frees Channel object, and supports querying whether a
// channel is in use
class LeFixedChannelAllocator {
 public:
  LeFixedChannelAllocator(LeLink* link, os::Handler* l2cap_handler) : link_(link), l2cap_handler_(l2cap_handler) {
    ASSERT(link_ != nullptr);
    ASSERT(l2cap_handler_ != nullptr);
  }

  // Allocates a channel. If cid is used, return nullptr. NOTE: The returned LeFixedChannelImpl object is still
  // owned by the channel allocator, NOT the client.
  std::shared_ptr<LeFixedChannelImpl> AllocateChannel(Cid cid, SecurityPolicy security_policy);

  // Frees a channel. If cid doesn't exist, it will crash
  void FreeChannel(Cid cid);

  bool IsChannelAllocated(Cid cid) const;

  std::shared_ptr<LeFixedChannelImpl> FindChannel(Cid cid);

  size_t NumberOfChannels() const;

  void OnAclDisconnected(hci::ErrorCode hci_status);

  int GetRefCount();

 private:
  LeLink* link_;
  os::Handler* l2cap_handler_;
  std::unordered_map<Cid, std::shared_ptr<LeFixedChannelImpl>> channels_;
};

}  // namespace internal
}  // namespace l2cap
}  // namespace bluetooth
