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

#include "l2cap/le_fixed_channel_manager.h"
#include "l2cap/internal/le_fixed_channel_service_impl.h"
#include "l2cap/internal/le_fixed_channel_service_manager_impl.h"
#include "l2cap/internal/le_link_manager.h"

namespace bluetooth {
namespace l2cap {

bool LeFixedChannelManager::ConnectServices(hci::Address device, hci::AddressType address_type,
                                            OnConnectionFailureCallback on_fail_callback, os::Handler* handler) {
  internal::LeLinkManager::PendingFixedChannelConnection pending_fixed_channel_connection{
      .on_fail_callback_ = std::move(on_fail_callback), .handler_ = handler};
  l2cap_layer_handler_->Post(common::BindOnce(&internal::LeLinkManager::ConnectFixedChannelServices,
                                              common::Unretained(link_manager_), device, address_type,
                                              std::move(pending_fixed_channel_connection)));
  return true;
}

bool LeFixedChannelManager::RegisterService(Cid cid, const SecurityPolicy& security_policy,
                                            OnRegistrationCompleteCallback on_registration_complete,
                                            OnConnectionOpenCallback on_connection_open, os::Handler* handler) {
  internal::LeFixedChannelServiceImpl::PendingRegistration pending_registration{
      .user_handler_ = handler,
      .on_registration_complete_callback_ = std::move(on_registration_complete),
      .on_connection_open_callback_ = std::move(on_connection_open)};
  l2cap_layer_handler_->Post(common::BindOnce(&internal::LeFixedChannelServiceManagerImpl::Register,
                                              common::Unretained(service_manager_), cid,
                                              std::move(pending_registration)));
  return true;
}

}  // namespace l2cap
}  // namespace bluetooth
