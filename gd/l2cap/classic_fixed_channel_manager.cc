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

#include "l2cap/classic_fixed_channel_manager.h"
#include "l2cap/internal/classic_fixed_channel_service.h"
#include "l2cap/internal/classic_fixed_channel_service_manager_impl.h"

namespace bluetooth {
namespace l2cap {

bool ClassicFixedChannelManager::ConnectServices(common::Address device,
                                                 OnConnectionFailureCallback on_connection_failure,
                                                 os::Handler* handler) {
  return false;
}

bool ClassicFixedChannelManager::RegisterService(Cid cid, const SecurityPolicy& security_policy,
                                                 OnRegistrationCompleteCallback on_registration_complete,
                                                 OnConnectionOpenCallback on_connection_open, os::Handler* handler) {
  internal::ClassicFixedChannelServiceImpl::Builder builder;
  builder.SetUserHandler(handler)
      .SetOnRegister(std::move(on_registration_complete))
      .SetOnChannelOpen(std::move(on_connection_open));

  l2cap_layer_handler_->Post(common::BindOnce(&internal::ClassicFixedChannelServiceManagerImpl::Register,
                                              common::Unretained(manager_), cid, std::move(builder)));
  return true;
}

}  // namespace l2cap
}  // namespace bluetooth