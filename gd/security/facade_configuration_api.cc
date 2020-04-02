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
#include "facade_configuration_api.h"

#include "os/log.h"

namespace bluetooth {
namespace security {

void FacadeConfigurationApi::SetIoCapabilities(hci::IoCapability io_capability) {
  security_handler_->Post(common::BindOnce(&internal::SecurityManagerImpl::SetIoCapabilities,
                                           common::Unretained(security_manager_impl_), io_capability));
}

void FacadeConfigurationApi::SetAuthenticationRequirements(hci::AuthenticationRequirements authentication_requirement) {
  security_handler_->Post(common::BindOnce(&internal::SecurityManagerImpl::SetAuthenticationRequirements,
                                           common::Unretained(security_manager_impl_), authentication_requirement));
}

void FacadeConfigurationApi::SetOobData(hci::OobDataPresent data_present) {
  security_handler_->Post(common::BindOnce(&internal::SecurityManagerImpl::SetOobDataPresent,
                                           common::Unretained(security_manager_impl_), data_present));
}
}  // namespace security
}  // namespace bluetooth
