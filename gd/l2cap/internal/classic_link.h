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
#include "l2cap/internal/classic_dynamic_channel_allocator.h"
#include "l2cap/internal/classic_dynamic_channel_impl.h"
#include "l2cap/internal/classic_fixed_channel_impl.h"
#include "l2cap/internal/fixed_channel_allocator.h"
#include "l2cap/internal/parameter_provider.h"
#include "l2cap/internal/scheduler.h"
#include "os/alarm.h"

namespace bluetooth {
namespace l2cap {
namespace internal {

class ClassicLink {
 public:
  ClassicLink(os::Handler* l2cap_handler, std::unique_ptr<hci::AclConnection> acl_connection,
              std::unique_ptr<Scheduler> scheduler, ParameterProvider* parameter_provider);

  virtual ~ClassicLink() = default;

  virtual hci::Address GetDevice() {
    return acl_connection_->GetAddress();
  }

  // ACL methods

  virtual void OnAclDisconnected(hci::ErrorCode status);

  virtual void Disconnect();

  // ClassicFixedChannel methods

  virtual std::shared_ptr<ClassicFixedChannelImpl> AllocateFixedChannel(Cid cid, SecurityPolicy security_policy);

  virtual bool IsFixedChannelAllocated(Cid cid);

  // ClassicDynamicChannel methods

  virtual std::shared_ptr<ClassicDynamicChannelImpl> AllocateDynamicChannel(Psm psm, Cid remote_cid,
                                                                            SecurityPolicy security_policy);

  virtual void FreeDynamicChannel(Cid cid);

  // Check how many channels are acquired or in use, if zero, start tear down timer, if non-zero, cancel tear down timer
  virtual void RefreshRefCount();

 private:
  os::Handler* l2cap_handler_;
  FixedChannelAllocator<ClassicFixedChannelImpl, ClassicLink> fixed_channel_allocator_{this, l2cap_handler_};
  ClassicDynamicChannelAllocator dynamic_channel_allocator_{this, l2cap_handler_};
  std::unique_ptr<hci::AclConnection> acl_connection_;
  std::unique_ptr<Scheduler> scheduler_;
  ParameterProvider* parameter_provider_;
  os::Alarm link_idle_disconnect_alarm_{l2cap_handler_};
  DISALLOW_COPY_AND_ASSIGN(ClassicLink);
};

}  // namespace internal
}  // namespace l2cap
}  // namespace bluetooth
