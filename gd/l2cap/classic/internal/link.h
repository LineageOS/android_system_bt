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
#include <unordered_map>

#include "hci/acl_manager.h"
#include "l2cap/classic/internal/dynamic_channel_allocator.h"
#include "l2cap/classic/internal/dynamic_channel_impl.h"
#include "l2cap/classic/internal/dynamic_channel_service_manager_impl.h"
#include "l2cap/classic/internal/fixed_channel_impl.h"
#include "l2cap/classic/internal/fixed_channel_service_manager_impl.h"
#include "l2cap/internal/fixed_channel_allocator.h"
#include "l2cap/internal/parameter_provider.h"
#include "l2cap/internal/receiver.h"
#include "l2cap/internal/scheduler.h"
#include "os/alarm.h"
#include "os/handler.h"
#include "signalling_manager.h"

namespace bluetooth {
namespace l2cap {
namespace classic {
namespace internal {

class Link {
 public:
  Link(os::Handler* l2cap_handler, std::unique_ptr<hci::AclConnection> acl_connection,
       std::unique_ptr<l2cap::internal::Scheduler> scheduler, l2cap::internal::ParameterProvider* parameter_provider,
       DynamicChannelServiceManagerImpl* dynamic_service_manager,
       FixedChannelServiceManagerImpl* fixed_service_manager);

  virtual ~Link() = default;

  virtual hci::Address GetDevice() {
    return acl_connection_->GetAddress();
  }

  struct PendingDynamicChannelConnection {
    os::Handler* handler_;
    DynamicChannelManager::OnConnectionOpenCallback on_open_callback_;
    DynamicChannelManager::OnConnectionFailureCallback on_fail_callback_;
  };

  // ACL methods

  virtual void OnAclDisconnected(hci::ErrorCode status);

  virtual void Disconnect();

  // FixedChannel methods

  std::shared_ptr<FixedChannelImpl> AllocateFixedChannel(Cid cid, SecurityPolicy security_policy);

  virtual bool IsFixedChannelAllocated(Cid cid);

  // DynamicChannel methods

  virtual Cid ReserveDynamicChannel();

  virtual void SendConnectionRequest(Psm psm, Cid local_cid);
  virtual void SendConnectionRequest(Psm psm, Cid local_cid,
                                     PendingDynamicChannelConnection pending_dynamic_channel_connection);

  virtual void SendInformationRequest(InformationRequestInfoType type);

  virtual void SendDisconnectionRequest(Cid local_cid, Cid remote_cid);

  virtual std::shared_ptr<DynamicChannelImpl> AllocateDynamicChannel(Psm psm, Cid remote_cid,
                                                                     SecurityPolicy security_policy);

  virtual std::shared_ptr<DynamicChannelImpl> AllocateReservedDynamicChannel(Cid reserved_cid, Psm psm, Cid remote_cid,
                                                                             SecurityPolicy security_policy);

  virtual void SetChannelRetransmissionFlowControlMode(Cid cid, RetransmissionAndFlowControlModeOption mode);

  virtual void FreeDynamicChannel(Cid cid);

  // Check how many channels are acquired or in use, if zero, start tear down timer, if non-zero, cancel tear down timer
  virtual void RefreshRefCount();

  virtual void NotifyChannelCreation(Cid cid, std::unique_ptr<DynamicChannel> channel);
  virtual void NotifyChannelFail(Cid cid);

 private:
  os::Handler* l2cap_handler_;
  l2cap::internal::FixedChannelAllocator<FixedChannelImpl, Link> fixed_channel_allocator_{this, l2cap_handler_};
  DynamicChannelAllocator dynamic_channel_allocator_{this, l2cap_handler_};
  std::unique_ptr<hci::AclConnection> acl_connection_;
  std::unique_ptr<l2cap::internal::Scheduler> scheduler_;
  l2cap::internal::Receiver receiver_;
  l2cap::internal::ParameterProvider* parameter_provider_;
  DynamicChannelServiceManagerImpl* dynamic_service_manager_;
  FixedChannelServiceManagerImpl* fixed_service_manager_;
  ClassicSignallingManager signalling_manager_;
  std::unordered_map<Cid, PendingDynamicChannelConnection> local_cid_to_pending_dynamic_channel_connection_map_;
  os::Alarm link_idle_disconnect_alarm_{l2cap_handler_};
  DISALLOW_COPY_AND_ASSIGN(Link);
};

}  // namespace internal
}  // namespace classic
}  // namespace l2cap
}  // namespace bluetooth
