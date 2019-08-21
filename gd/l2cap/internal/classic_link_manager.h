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

#include "os/handler.h"

#include "l2cap/classic_fixed_channel_manager.h"
#include "l2cap/internal/classic_fixed_channel_service_impl.h"
#include "l2cap/internal/classic_fixed_channel_service_manager_impl.h"
#include "l2cap/internal/classic_link.h"
#include "l2cap/internal/scheduler.h"

#include "hci/acl_manager.h"

namespace bluetooth {
namespace l2cap {
namespace internal {

class ClassicLinkManager : public hci::ConnectionCallbacks {
 public:
  ClassicLinkManager(os::Handler* l2cap_layer_handler, hci::AclManager* acl_manager,
                     ClassicFixedChannelServiceManagerImpl* service_manager)
      : handler_(l2cap_layer_handler), acl_manager_(acl_manager), service_manager_(service_manager) {
    acl_manager_->RegisterCallbacks(this, handler_);
  }

  struct PendingFixedChannelConnection {
    os::Handler* handler_;
    ClassicFixedChannelManager::OnConnectionFailureCallback on_fail_callback_;
  };

  struct PendingLink {
    std::vector<PendingFixedChannelConnection> pending_fixed_channel_connections_;
  };

  void ConnectFixedChannelServices(common::Address device,
                                   PendingFixedChannelConnection pending_fixed_channel_connection);

  ClassicLink* GetLink(common::Address device);
  void OnConnectSuccess(std::unique_ptr<hci::AclConnection> acl_connection) override;
  void OnConnectFail(common::Address device, hci::ErrorCode reason) override;

 private:
  // Dependencies
  os::Handler* handler_;
  hci::AclManager* acl_manager_;
  ClassicFixedChannelServiceManagerImpl* service_manager_;

  // Internal states
  std::unordered_map<common::Address, PendingLink> pending_links_;
  std::unordered_map<common::Address, ClassicLink> links_;
  DISALLOW_COPY_AND_ASSIGN(ClassicLinkManager);
};

}  // namespace internal
}  // namespace l2cap
}  // namespace bluetooth