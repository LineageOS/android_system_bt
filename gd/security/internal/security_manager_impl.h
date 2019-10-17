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

#include "l2cap/classic/l2cap_classic_module.h"
#include "l2cap/le/l2cap_le_module.h"
#include "os/handler.h"

namespace bluetooth {
namespace security {
namespace internal {

class SecurityManagerImpl {
 public:
  explicit SecurityManagerImpl(os::Handler* security_handler, l2cap::le::L2capLeModule* l2cap_le_module,
                               l2cap::classic::L2capClassicModule* l2cap_classic_module)
      : security_handler_(security_handler), l2cap_le_module_(l2cap_le_module),
        l2cap_classic_module_(l2cap_classic_module) {}
  virtual ~SecurityManagerImpl() = default;

  // All APIs must be invoked in L2CAP layer handler

  // TODO: put all API methods here

 private:
  os::Handler* security_handler_ __attribute__((unused));
  l2cap::le::L2capLeModule* l2cap_le_module_ __attribute__((unused));
  l2cap::classic::L2capClassicModule* l2cap_classic_module_ __attribute__((unused));
};
}  // namespace internal
}  // namespace security
}  // namespace bluetooth
