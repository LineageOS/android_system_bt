/******************************************************************************
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
 ******************************************************************************/

#pragma once

#include "security/internal/security_manager_impl.h"

namespace bluetooth {
namespace security {

class SecurityManager {
 public:
  // TODO: put SMP API methods here

  friend class SecurityModule;

 private:
  SecurityManager(os::Handler* security_handler, internal::SecurityManagerImpl* security_manager_impl)
      : security_handler_(security_handler), security_manager_impl_(security_manager_impl) {}

  os::Handler* security_handler_ = nullptr;
  internal::SecurityManagerImpl* security_manager_impl_;
  DISALLOW_COPY_AND_ASSIGN(SecurityManager);
};

}  // namespace security
}  // namespace bluetooth