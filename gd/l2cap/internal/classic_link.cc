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

#include "l2cap/internal/classic_link.h"

#include <chrono>
#include <memory>

#include "hci/acl_manager.h"
#include "l2cap/internal/classic_fixed_channel_impl.h"
#include "l2cap/internal/parameter_provider.h"
#include "l2cap/internal/scheduler.h"
#include "os/alarm.h"

namespace bluetooth {
namespace l2cap {
namespace internal {

ClassicLink::ClassicLink(os::Handler* l2cap_handler, std::unique_ptr<hci::AclConnection> acl_connection,
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

void ClassicLink::OnAclDisconnected(hci::ErrorCode status) {
  fixed_channel_allocator_.OnAclDisconnected(status);
  // TODO hsz: add dynamic channel part
}

void ClassicLink::Disconnect() {
  acl_connection_->Disconnect(hci::DisconnectReason::REMOTE_USER_TERMINATED_CONNECTION);
}

std::shared_ptr<ClassicFixedChannelImpl> ClassicLink::AllocateFixedChannel(Cid cid, SecurityPolicy security_policy) {
  auto channel = fixed_channel_allocator_.AllocateChannel(cid, security_policy);
  scheduler_->AttachChannel(cid, channel->GetQueueDownEnd());
  return channel;
}

bool ClassicLink::IsFixedChannelAllocated(Cid cid) {
  return fixed_channel_allocator_.IsChannelAllocated(cid);
}

std::shared_ptr<ClassicDynamicChannelImpl> ClassicLink::AllocateDynamicChannel(Psm psm, Cid remote_cid,
                                                                               SecurityPolicy security_policy) {
  auto channel = dynamic_channel_allocator_.AllocateChannel(psm, remote_cid, security_policy);
  scheduler_->AttachChannel(channel->GetCid(), channel->GetQueueDownEnd());
  return channel;
}

void ClassicLink::FreeDynamicChannel(Cid cid) {}

void ClassicLink::RefreshRefCount() {
  int ref_count = 0;
  ref_count += fixed_channel_allocator_.GetRefCount();
  ref_count += dynamic_channel_allocator_.NumberOfChannels();
  ASSERT_LOG(ref_count >= 0, "ref_count %d is less than 0", ref_count);
  if (ref_count > 0) {
    link_idle_disconnect_alarm_.Cancel();
  } else {
    link_idle_disconnect_alarm_.Schedule(common::BindOnce(&ClassicLink::Disconnect, common::Unretained(this)),
                                         parameter_provider_->GetClassicLinkIdleDisconnectTimeout());
  }
}

}  // namespace internal
}  // namespace l2cap
}  // namespace bluetooth
