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

#include "l2cap/internal/classic_fixed_channel_service_manager_impl.h"

#include "common/bind.h"
#include "l2cap/cid.h"
#include "l2cap/internal/classic_fixed_channel_service.h"
#include "os/log.h"

namespace bluetooth {
namespace l2cap {
namespace internal {

void ClassicFixedChannelServiceManagerImpl::Register(Cid cid, ClassicFixedChannelServiceImpl::Builder builder) {
  if (cid < kFirstFixedChannel || cid > kLastFixedChannel || cid == kClassicSignallingCid || IsServiceRegistered(cid)) {
    ClassicFixedChannelService invalid_service;
    builder.user_handler_->Post(common::BindOnce(std::move(builder.on_registration_complete_callback_),
                                                 ClassicFixedChannelManager::RegistrationResult::FAIL,
                                                 invalid_service));
  } else {
    auto service = builder.Build();
    service_map_.emplace(cid, std::move(service));
    ClassicFixedChannelService user_service{cid, this, l2cap_layer_handler_};
    builder.user_handler_->Post(common::BindOnce(std::move(builder.on_registration_complete_callback_),
                                                 ClassicFixedChannelManager::RegistrationResult::SUCCESS,
                                                 user_service));
  }
}

void ClassicFixedChannelServiceManagerImpl::Unregister(Cid cid,
                                                       ClassicFixedChannelService::OnUnregisteredCallback callback,
                                                       os::Handler* handler) {
  if (IsServiceRegistered(cid)) {
    service_map_.erase(cid);
    handler->Post(std::move(callback));
  } else {
    LOG_ERROR("service not registered cid:%d", cid);
  }
}

bool ClassicFixedChannelServiceManagerImpl::IsServiceRegistered(Cid cid) const {
  return service_map_.find(cid) != service_map_.end();
}

ClassicFixedChannelServiceImpl* ClassicFixedChannelServiceManagerImpl::GetService(Cid cid) {
  ASSERT(IsServiceRegistered(cid));
  return &service_map_.find(cid)->second;
}

}  // namespace internal
}  // namespace l2cap
}  // namespace bluetooth
