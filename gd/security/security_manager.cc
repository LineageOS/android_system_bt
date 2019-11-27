/*
 *
 *  Copyright 2019 The Android Open Source Project
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at:
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */
#include "security_manager.h"

#include "os/log.h"

using namespace bluetooth::security;

// Definition of Pure Virtual Destructor
ISecurityManagerListener::~ISecurityManagerListener() {}

void SecurityManager::Init() {
  security_handler_->Post(
      common::BindOnce(&internal::SecurityManagerImpl::Init, common::Unretained(security_manager_impl_)));
}

void SecurityManager::CreateBond(hci::AddressWithType device) {
  security_handler_->Post(common::BindOnce(&internal::SecurityManagerImpl::CreateBond,
                                           common::Unretained(security_manager_impl_),
                                           std::forward<hci::AddressWithType>(device)));
}

void SecurityManager::CancelBond(hci::AddressWithType device) {
  security_handler_->Post(common::BindOnce(&internal::SecurityManagerImpl::CancelBond,
                                           common::Unretained(security_manager_impl_),
                                           std::forward<hci::AddressWithType>(device)));
}

void SecurityManager::RemoveBond(hci::AddressWithType device) {
  security_handler_->Post(common::BindOnce(&internal::SecurityManagerImpl::RemoveBond,
                                           common::Unretained(security_manager_impl_),
                                           std::forward<hci::AddressWithType>(device)));
}

void SecurityManager::RegisterCallbackListener(ISecurityManagerListener* listener, os::Handler* handler) {
  security_handler_->Post(common::BindOnce(&internal::SecurityManagerImpl::RegisterCallbackListener,
                                           common::Unretained(security_manager_impl_), listener, handler));
}

void SecurityManager::UnregisterCallbackListener(ISecurityManagerListener* listener) {
  security_handler_->Post(common::BindOnce(&internal::SecurityManagerImpl::UnregisterCallbackListener,
                                           common::Unretained(security_manager_impl_), listener));
}
