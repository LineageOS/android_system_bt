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

#include <memory>

#include "hci/acl_manager.h"
#include "l2cap/internal/classic_fixed_channel_allocator.h"
#include "l2cap/internal/scheduler.h"

namespace bluetooth {
namespace l2cap {
namespace internal {

class ClassicLink {
 public:
  ClassicLink(os::Handler* l2cap_layer_handler, std::unique_ptr<hci::AclConnection> acl_connection,
              std::unique_ptr<Scheduler> scheduler)
      : handler_(l2cap_layer_handler), acl_connection_(std::move(acl_connection)), scheduler_(std::move(scheduler)) {}

  friend class ClassicLinkManager;

 private:
  os::Handler* handler_;
  ClassicFixedChannelAllocator fixed_channel_allocator_{handler_};
  std::unique_ptr<hci::AclConnection> acl_connection_;
  std::unique_ptr<Scheduler> scheduler_;
  DISALLOW_COPY_AND_ASSIGN(ClassicLink);
};

}  // namespace internal
}  // namespace l2cap
}  // namespace bluetooth
