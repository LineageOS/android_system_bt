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

#include "l2cap/internal/le_fixed_channel_service_manager_impl.h"

#include "common/bind.h"
#include "l2cap/cid.h"
#include "l2cap/internal/le_fixed_channel_service_impl.h"
#include "os/log.h"

namespace bluetooth {
namespace l2cap {
namespace internal {

void LeFixedChannelServiceManagerImpl::Register(Cid cid,
                                                LeFixedChannelServiceImpl::PendingRegistration pending_registration) {
  if (cid < kFirstFixedChannel || cid > kLastFixedChannel || cid == kLeSignallingCid) {
    std::unique_ptr<LeFixedChannelService> invalid_service(new LeFixedChannelService());
    pending_registration.user_handler_->Post(
        common::BindOnce(std::move(pending_registration.on_registration_complete_callback_),
                         LeFixedChannelManager::RegistrationResult::FAIL_INVALID_SERVICE, std::move(invalid_service)));
  } else if (IsServiceRegistered(cid)) {
    std::unique_ptr<LeFixedChannelService> invalid_service(new LeFixedChannelService());
    pending_registration.user_handler_->Post(common::BindOnce(
        std::move(pending_registration.on_registration_complete_callback_),
        LeFixedChannelManager::RegistrationResult::FAIL_DUPLICATE_SERVICE, std::move(invalid_service)));
  } else {
    service_map_.try_emplace(cid,
                             LeFixedChannelServiceImpl(pending_registration.user_handler_,
                                                       std::move(pending_registration.on_connection_open_callback_)));
    std::unique_ptr<LeFixedChannelService> user_service(new LeFixedChannelService(cid, this, l2cap_layer_handler_));
    pending_registration.user_handler_->Post(
        common::BindOnce(std::move(pending_registration.on_registration_complete_callback_),
                         LeFixedChannelManager::RegistrationResult::SUCCESS, std::move(user_service)));
  }
}

void LeFixedChannelServiceManagerImpl::Unregister(Cid cid, LeFixedChannelService::OnUnregisteredCallback callback,
                                                  os::Handler* handler) {
  if (IsServiceRegistered(cid)) {
    service_map_.erase(cid);
    handler->Post(std::move(callback));
  } else {
    LOG_ERROR("service not registered cid:%d", cid);
  }
}

bool LeFixedChannelServiceManagerImpl::IsServiceRegistered(Cid cid) const {
  return service_map_.find(cid) != service_map_.end();
}

LeFixedChannelServiceImpl* LeFixedChannelServiceManagerImpl::GetService(Cid cid) {
  ASSERT(IsServiceRegistered(cid));
  return &service_map_.find(cid)->second;
}

std::vector<std::pair<Cid, LeFixedChannelServiceImpl*>> LeFixedChannelServiceManagerImpl::GetRegisteredServices() {
  std::vector<std::pair<Cid, LeFixedChannelServiceImpl*>> results;
  for (auto& elem : service_map_) {
    results.emplace_back(elem.first, &elem.second);
  }
  return results;
}

}  // namespace internal
}  // namespace l2cap
}  // namespace bluetooth
