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

#include "l2cap/classic_dynamic_channel_manager.h"
#include "l2cap/internal/classic_link_manager.h"

namespace bluetooth {
namespace l2cap {

bool ClassicDynamicChannelManager::ConnectChannel(hci::Address device, Psm psm,
                                                  OnConnectionOpenCallback on_connection_open,
                                                  OnConnectionFailureCallback on_fail_callback, os::Handler* handler) {
  // TODO impl me when there is no link, and when there is link
  return false;
}

bool ClassicDynamicChannelManager::RegisterService(Psm psm, const SecurityPolicy& security_policy,
                                                   OnRegistrationCompleteCallback on_registration_complete,
                                                   OnConnectionOpenCallback on_connection_open, os::Handler* handler) {
  return false;
}

}  // namespace l2cap
}  // namespace bluetooth
