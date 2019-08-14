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

#include <string>

#include "common/address.h"
#include "l2cap/cid.h"
#include "l2cap/classic_fixed_channel.h"
#include "l2cap/classic_fixed_channel_service.h"
#include "l2cap/security_policy.h"
#include "os/handler.h"

namespace bluetooth {
namespace l2cap {

namespace internal {
class ClassicFixedChannelServiceManagerImpl;
}

class ClassicFixedChannelManager {
 public:
  /**
   * OnConnectionFailureCallback(std::string failure_reason);
   */
  using OnConnectionFailureCallback = common::Callback<void(std::string)>;

  /**
   * OnConnectionOpenCallback(ClassicFixedChannel channel);
   */
  using OnConnectionOpenCallback = common::Callback<void(ClassicFixedChannel)>;

  enum class RegistrationResult { SUCCESS, FAIL };

  /**
   * OnRegistrationFailureCallback(RegistrationResult result, ClassicFixedChannelService service);
   */
  using OnRegistrationCompleteCallback = common::OnceCallback<void(RegistrationResult, ClassicFixedChannelService)>;

  /**
   * Connect to ALL fixed channels on a remote device
   *
   * - This method is asynchronous
   * - When false is returned, the connection fails immediately
   * - When true is returned, method caller should wait for on_fail_callback or on_open_callback registered through
   *   RegisterService() API.
   * - If an ACL connection does not exist, this method will create an ACL connection. As a result, on_open_callback
   *   supplied through RegisterService() will be triggered to provide the actual ClassicFixedChannel objects
   * - If fixed channel on a remote device is already reported as connected via on_open_callback and has been acquired
   *   via ClassicFixedChannel#Acquire() API, it won't be reported again
   * - If no service is registered, this call is a no-op and on on_fail_callback will be triggered
   *
   * NOTE:
   * This call will initiate an effort to connect all fixed channel services on a remote device.
   * Due to the connectionless nature of fixed channels, all fixed channels will be connected together.
   * If a fixed channel service does not need a particular fixed channel. It should release the received
   * channel immediately after receiving on_open_callback via ClassicFixedChannel#Release()
   *
   * A module calling ConnectServices() must have called RegisterService() before.
   * The callback will come back from on_open_callback in the service that is registered
   *
   * @param device: Remote device to make this connection.
   * @param on_fail_callback: A callback to indicate connection failure along with a status code.
   * @param handler: The handler context in which to execute the @callback parameters.
   *
   * Returns: true if connection was able to be initiated, false otherwise.
   */
  bool ConnectServices(common::Address device, OnConnectionFailureCallback on_fail_callback, os::Handler* handler);

  /**
   * Register a service to receive incoming connections bound to a specific channel.
   *
   * - This method is asynchronous.
   * - When false is returned, the registration fails immediately.
   * - When true is returned, method caller should wait for on_service_registered callback that contains a
   *   ClassicFixedChannelService object. The registered service can be managed from that object.
   * - If a CID is already registered or some other error happens,
   * - After a service is registered, any classic ACL connection will create a ClassicFixedChannel object that is
   *   delivered through on_open_callback
   * - on_open_callback, if any, must be triggered after on_service_registered callback
   *
   * @param cid: Classic cid used to receive incoming connections
   * @param security_policy: The security policy used for the connection.
   * @param on_registration_complete: A callback to indicate the service setup has completed. If the return status is
   *        not SUCCESS, it means service is not registered due to reasons like CID already take
   * @param on_open_callback: A callback to indicate success of a connection initiated from a remote device.
   * @param handler: The handler context in which to execute the @callback parameter.
   */
  bool RegisterService(Cid cid, const SecurityPolicy& security_policy,
                       OnRegistrationCompleteCallback on_registration_complete,
                       OnConnectionOpenCallback on_connection_open, os::Handler* handler);

  // The constructor is not to be used by user code
  ClassicFixedChannelManager(internal::ClassicFixedChannelServiceManagerImpl* manager, os::Handler* l2cap_layer_handler)
      : manager_(manager), l2cap_layer_handler_(l2cap_layer_handler) {}

 private:
  internal::ClassicFixedChannelServiceManagerImpl* manager_ = nullptr;
  os::Handler* l2cap_layer_handler_ = nullptr;
};

}  // namespace l2cap
}  // namespace bluetooth