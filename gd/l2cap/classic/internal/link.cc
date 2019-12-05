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

#include <chrono>
#include <memory>

#include "hci/acl_manager.h"
#include "l2cap/classic/dynamic_channel_manager.h"
#include "l2cap/classic/internal/fixed_channel_impl.h"
#include "l2cap/classic/internal/link.h"
#include "l2cap/internal/parameter_provider.h"
#include "os/alarm.h"

namespace bluetooth {
namespace l2cap {
namespace classic {
namespace internal {

Link::Link(os::Handler* l2cap_handler, std::unique_ptr<hci::AclConnection> acl_connection,
           l2cap::internal::ParameterProvider* parameter_provider,
           DynamicChannelServiceManagerImpl* dynamic_service_manager,
           FixedChannelServiceManagerImpl* fixed_service_manager)
    : l2cap_handler_(l2cap_handler), acl_connection_(std::move(acl_connection)),
      data_pipeline_manager_(l2cap_handler, this, acl_connection_->GetAclQueueEnd()),
      parameter_provider_(parameter_provider), dynamic_service_manager_(dynamic_service_manager),
      fixed_service_manager_(fixed_service_manager),
      signalling_manager_(l2cap_handler_, this, &data_pipeline_manager_, dynamic_service_manager_,
                          &dynamic_channel_allocator_, fixed_service_manager_) {
  ASSERT(l2cap_handler_ != nullptr);
  ASSERT(acl_connection_ != nullptr);
  ASSERT(parameter_provider_ != nullptr);
  link_idle_disconnect_alarm_.Schedule(common::BindOnce(&Link::Disconnect, common::Unretained(this)),
                                       parameter_provider_->GetClassicLinkIdleDisconnectTimeout());
}

void Link::OnAclDisconnected(hci::ErrorCode status) {
  fixed_channel_allocator_.OnAclDisconnected(status);
  dynamic_channel_allocator_.OnAclDisconnected(status);
}

void Link::Disconnect() {
  acl_connection_->Disconnect(hci::DisconnectReason::REMOTE_USER_TERMINATED_CONNECTION);
}

std::shared_ptr<FixedChannelImpl> Link::AllocateFixedChannel(Cid cid, SecurityPolicy security_policy) {
  auto channel = fixed_channel_allocator_.AllocateChannel(cid, security_policy);
  data_pipeline_manager_.AttachChannel(cid, channel, l2cap::internal::DataPipelineManager::ChannelMode::BASIC);
  return channel;
}

bool Link::IsFixedChannelAllocated(Cid cid) {
  return fixed_channel_allocator_.IsChannelAllocated(cid);
}

Cid Link::ReserveDynamicChannel() {
  return dynamic_channel_allocator_.ReserveChannel();
}

void Link::SendConnectionRequest(Psm psm, Cid local_cid) {
  signalling_manager_.SendConnectionRequest(psm, local_cid);
}

void Link::SendConnectionRequest(Psm psm, Cid local_cid,
                                 PendingDynamicChannelConnection pending_dynamic_channel_connection) {
  local_cid_to_pending_dynamic_channel_connection_map_[local_cid] = std::move(pending_dynamic_channel_connection);
  signalling_manager_.SendConnectionRequest(psm, local_cid);
}

void Link::OnOutgoingConnectionRequestFail(Cid local_cid) {
  local_cid_to_pending_dynamic_channel_connection_map_.erase(local_cid);
  dynamic_channel_allocator_.FreeChannel(local_cid);
}

void Link::SendDisconnectionRequest(Cid local_cid, Cid remote_cid) {
  signalling_manager_.SendDisconnectionRequest(local_cid, remote_cid);
}

void Link::SendInformationRequest(InformationRequestInfoType type) {
  signalling_manager_.SendInformationRequest(type);
}

std::shared_ptr<l2cap::internal::DynamicChannelImpl> Link::AllocateDynamicChannel(Psm psm, Cid remote_cid,
                                                                                  SecurityPolicy security_policy) {
  auto channel = dynamic_channel_allocator_.AllocateChannel(psm, remote_cid, security_policy);
  if (channel != nullptr) {
    data_pipeline_manager_.AttachChannel(channel->GetCid(), channel,
                                         l2cap::internal::DataPipelineManager::ChannelMode::BASIC);
    RefreshRefCount();
  }
  channel->local_initiated_ = false;
  return channel;
}

std::shared_ptr<l2cap::internal::DynamicChannelImpl> Link::AllocateReservedDynamicChannel(
    Cid reserved_cid, Psm psm, Cid remote_cid, SecurityPolicy security_policy) {
  auto channel = dynamic_channel_allocator_.AllocateReservedChannel(reserved_cid, psm, remote_cid, security_policy);
  if (channel != nullptr) {
    data_pipeline_manager_.AttachChannel(channel->GetCid(), channel,
                                         l2cap::internal::DataPipelineManager::ChannelMode::BASIC);
    RefreshRefCount();
  }
  channel->local_initiated_ = true;
  return channel;
}

classic::DynamicChannelConfigurationOption Link::GetConfigurationForInitialConfiguration(Cid cid) {
  ASSERT(local_cid_to_pending_dynamic_channel_connection_map_.find(cid) !=
         local_cid_to_pending_dynamic_channel_connection_map_.end());
  return local_cid_to_pending_dynamic_channel_connection_map_[cid].configuration_;
}

void Link::FreeDynamicChannel(Cid cid) {
  if (dynamic_channel_allocator_.FindChannelByCid(cid) == nullptr) {
    return;
  }
  data_pipeline_manager_.DetachChannel(cid);
  dynamic_channel_allocator_.FreeChannel(cid);
  RefreshRefCount();
}

void Link::RefreshRefCount() {
  int ref_count = 0;
  ref_count += fixed_channel_allocator_.GetRefCount();
  ref_count += dynamic_channel_allocator_.NumberOfChannels();
  ASSERT_LOG(ref_count >= 0, "ref_count %d is less than 0", ref_count);
  if (ref_count > 0) {
    link_idle_disconnect_alarm_.Cancel();
  } else {
    link_idle_disconnect_alarm_.Schedule(common::BindOnce(&Link::Disconnect, common::Unretained(this)),
                                         parameter_provider_->GetClassicLinkIdleDisconnectTimeout());
  }
}

void Link::NotifyChannelCreation(Cid cid, std::unique_ptr<DynamicChannel> user_channel) {
  ASSERT(local_cid_to_pending_dynamic_channel_connection_map_.find(cid) !=
         local_cid_to_pending_dynamic_channel_connection_map_.end());
  auto& pending_dynamic_channel_connection = local_cid_to_pending_dynamic_channel_connection_map_[cid];
  pending_dynamic_channel_connection.handler_->Post(
      common::BindOnce(std::move(pending_dynamic_channel_connection.on_open_callback_), std::move(user_channel)));
  local_cid_to_pending_dynamic_channel_connection_map_.erase(cid);
}

void Link::NotifyChannelFail(Cid cid) {
  ASSERT(local_cid_to_pending_dynamic_channel_connection_map_.find(cid) !=
         local_cid_to_pending_dynamic_channel_connection_map_.end());
  auto& pending_dynamic_channel_connection = local_cid_to_pending_dynamic_channel_connection_map_[cid];
  // TODO(cmanton) Pass proper connection falure result to user
  DynamicChannelManager::ConnectionResult result;
  pending_dynamic_channel_connection.handler_->Post(
      common::BindOnce(std::move(pending_dynamic_channel_connection.on_fail_callback_), result));
  local_cid_to_pending_dynamic_channel_connection_map_.erase(cid);
}

void Link::SetRemoteConnectionlessMtu(Mtu mtu) {
  remote_connectionless_mtu_ = mtu;
}

Mtu Link::GetRemoteConnectionlessMtu() const {
  return remote_connectionless_mtu_;
}

void Link::SetRemoteSupportsErtm(bool supported) {
  remote_supports_ertm_ = supported;
}

bool Link::GetRemoteSupportsErtm() const {
  return remote_supports_ertm_;
}

void Link::SetRemoteSupportsFcs(bool supported) {
  remote_supports_fcs_ = supported;
}

bool Link::GetRemoteSupportsFcs() const {
  return remote_supports_fcs_;
}

}  // namespace internal
}  // namespace classic
}  // namespace l2cap
}  // namespace bluetooth
