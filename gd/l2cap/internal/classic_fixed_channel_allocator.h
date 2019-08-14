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

#include <unordered_map>

#include "l2cap/cid.h"
#include "l2cap/internal/classic_fixed_channel_impl.h"
#include "l2cap/security_policy.h"
#include "os/handler.h"
#include "os/log.h"

namespace bluetooth {
namespace l2cap {
namespace internal {

// Helper class for keeping channels in a Link. It allocates and frees Channel object, and supports querying whether a
// channel is in use
class ClassicFixedChannelAllocator {
 public:
  explicit ClassicFixedChannelAllocator(os::Handler* handler) : handler_(handler) {
    ASSERT(handler_ != nullptr);
  }

  // Allocates a channel. If cid is used, return nullptr. NOTE: The returned ClassicFixedChannelImpl object is still
  // owned by the channel cllocator, NOT the client.
  ClassicFixedChannelImpl* AllocateChannel(Cid cid, SecurityPolicy security_policy);

  // Frees a channel. If cid doesn't exist, return false
  bool FreeChannel(Cid cid);

  bool IsChannelInUse(Cid cid) const;

  ClassicFixedChannelImpl* FindChannel(Cid cid);

  size_t NumberOfChannels() const;

 private:
  os::Handler* handler_ = nullptr;
  std::unordered_map<Cid, ClassicFixedChannelImpl> channels_;
};

}  // namespace internal
}  // namespace l2cap
}  // namespace bluetooth
