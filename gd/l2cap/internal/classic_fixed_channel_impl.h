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

#include "l2cap/cid.h"
#include "os/handler.h"
#include "os/log.h"

namespace bluetooth {
namespace l2cap {
namespace internal {

class ClassicFixedChannelImpl {
 public:
  ClassicFixedChannelImpl(Cid cid, os::Handler* handler) : cid_(cid), handler_(handler) {
    ASSERT_LOG(cid_ >= kFirstFixedChannel && cid_ <= kLastFixedChannel, "Invalid cid: %d", cid_);
    ASSERT(handler_ != nullptr);
  }

 private:
  Cid cid_;
  os::Handler* handler_;
};

}  // namespace internal
}  // namespace l2cap
}  // namespace bluetooth
