/*
 * Copyright 2020 The Android Open Source Project
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

namespace bluetooth {
namespace l2cap {
namespace le {

// Security Policy for LE Security Mode 1, used by COC and GATT. Defined in Core 5.2, 3, C 10.2.1
class SecurityPolicy {
 public:
  enum class Level {
    NO_SECURITY,
    UNAUTHENTICATED_PAIRING_WITH_ENCRYPTION,
    AUTHENTICATED_PAIRING_WITH_ENCRYPTION,
    AUTHENTICATED_PAIRING_WITH_128_BYTE_KEY,
  };
  Level security_level_ = Level::NO_SECURITY;

  bool RequiresAuthentication() const {
    return security_level_ != SecurityPolicy::Level::NO_SECURITY;
  }
};

}  // namespace le
}  // namespace l2cap
}  // namespace bluetooth
