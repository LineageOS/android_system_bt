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

#include "l2cap/classic_fixed_channel.h"
#include "l2cap/classic_fixed_channel_manager.h"
#include "l2cap/classic_fixed_channel_service.h"

namespace bluetooth {
namespace l2cap {
namespace internal {

class ClassicFixedChannelServiceImpl {
 public:
  struct Builder {
    Builder& SetUserHandler(os::Handler* handler) {
      user_handler_ = handler;
      return *this;
    }

    Builder& SetOnChannelOpen(ClassicFixedChannelManager::OnConnectionOpenCallback on_connection_open_callback) {
      on_connection_open_callback_ = on_connection_open_callback;
      return *this;
    }

    Builder& SetOnChannelClose(ClassicFixedChannel::OnCloseCallback on_close_callback) {
      on_close_callback_ = on_close_callback;
      return *this;
    }

    Builder& SetOnChannelFail(ClassicFixedChannelManager::OnConnectionFailureCallback on_connection_failure_callback) {
      on_connection_failure_callback_ = on_connection_failure_callback;
      return *this;
    }

    Builder& SetOnRegister(
        ClassicFixedChannelManager::OnRegistrationCompleteCallback on_registration_complete_callback) {
      on_registration_complete_callback_ = std::move(on_registration_complete_callback);
      return *this;
    }

    ClassicFixedChannelServiceImpl Build() {
      ASSERT(user_handler_ != nullptr);
      ASSERT(!on_registration_complete_callback_.is_null());
      ClassicFixedChannelServiceImpl service;
      service.user_handler_ = user_handler_;
      service.on_connection_failure_callback_ = on_connection_failure_callback_;
      service.on_connection_open_callback_ = on_connection_open_callback_;
      service.on_close_callback_ = on_close_callback_;
      return service;
    }

    os::Handler* user_handler_ = nullptr;
    ClassicFixedChannelManager::OnConnectionFailureCallback on_connection_failure_callback_;
    ClassicFixedChannelManager::OnConnectionOpenCallback on_connection_open_callback_;
    ClassicFixedChannel::OnCloseCallback on_close_callback_;
    ClassicFixedChannelManager::OnRegistrationCompleteCallback on_registration_complete_callback_;
  };

 private:
  os::Handler* user_handler_ = nullptr;
  ClassicFixedChannelManager::OnConnectionFailureCallback on_connection_failure_callback_;
  ClassicFixedChannelManager::OnConnectionOpenCallback on_connection_open_callback_;
  ClassicFixedChannel::OnCloseCallback on_close_callback_;
};

}  // namespace internal
}  // namespace l2cap
}  // namespace bluetooth
