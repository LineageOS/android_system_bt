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

#include <chrono>
#include <memory>

#include "hci/acl_manager.h"
#include "l2cap/internal/classic_fixed_channel_allocator.h"
#include "l2cap/internal/classic_fixed_channel_impl.h"
#include "l2cap/internal/parameter_provider.h"
#include "l2cap/internal/scheduler.h"
#include "os/alarm.h"

namespace bluetooth {
namespace l2cap {
namespace internal {

class ClassicLink {
 public:
  ClassicLink(os::Handler* l2cap_handler, std::unique_ptr<hci::AclConnection> acl_connection,
              std::unique_ptr<Scheduler> scheduler, ParameterProvider* parameter_provider)
      : l2cap_handler_(l2cap_handler), acl_connection_(std::move(acl_connection)), scheduler_(std::move(scheduler)),
        parameter_provider_(parameter_provider) {
    ASSERT(l2cap_handler_ != nullptr);
    ASSERT(acl_connection_ != nullptr);
    ASSERT(scheduler_ != nullptr);
    ASSERT(parameter_provider_ != nullptr);
    acl_connection_->RegisterDisconnectCallback(
        common::BindOnce(&ClassicLink::OnAclDisconnected, common::Unretained(this)), l2cap_handler_);
    link_idle_disconnect_alarm_.Schedule(common::BindOnce(&ClassicLink::Disconnect, common::Unretained(this)),
                                         parameter_provider_->GetClassicLinkIdleDisconnectTimeout());
  }

  virtual ~ClassicLink() = default;

  inline virtual hci::Address GetDevice() {
    return acl_connection_->GetAddress();
  }

  // ACL methods

  virtual void OnAclDisconnected(hci::ErrorCode status) {
    fixed_channel_allocator_.OnAclDisconnected(status);
  }

  virtual void Disconnect() {
    acl_connection_->Disconnect(hci::DisconnectReason::REMOTE_USER_TERMINATED_CONNECTION);
  }

  // ClassicFixedChannel methods

  virtual std::shared_ptr<ClassicFixedChannelImpl> AllocateFixedChannel(Cid cid, SecurityPolicy security_policy) {
    auto channel = fixed_channel_allocator_.AllocateChannel(cid, security_policy);
    scheduler_->AttachChannel(cid, channel->GetQueueDownEnd());
    return channel;
  }

  virtual bool IsFixedChannelAllocated(Cid cid) {
    return fixed_channel_allocator_.IsChannelAllocated(cid);
  }

  // Check how many channels are acquired or in use, if zero, start tear down timer, if non-zero, cancel tear down timer
  virtual void RefreshRefCount() {
    int ref_count = 0;
    ref_count += fixed_channel_allocator_.GetRefCount();
    ASSERT_LOG(ref_count >= 0, "ref_count %d is less than 0", ref_count);
    if (ref_count > 0) {
      link_idle_disconnect_alarm_.Cancel();
    } else {
      link_idle_disconnect_alarm_.Schedule(common::BindOnce(&ClassicLink::Disconnect, common::Unretained(this)),
                                           parameter_provider_->GetClassicLinkIdleDisconnectTimeout());
    }
  }

 private:
  os::Handler* l2cap_handler_;
  ClassicFixedChannelAllocator fixed_channel_allocator_{this, l2cap_handler_};
  std::unique_ptr<hci::AclConnection> acl_connection_;
  std::unique_ptr<Scheduler> scheduler_;
  ParameterProvider* parameter_provider_;
  os::Alarm link_idle_disconnect_alarm_{l2cap_handler_};
  DISALLOW_COPY_AND_ASSIGN(ClassicLink);
};

}  // namespace internal
}  // namespace l2cap
}  // namespace bluetooth
