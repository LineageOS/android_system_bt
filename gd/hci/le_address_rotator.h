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

#include <map>
#include <mutex>
#include <set>

#include "common/callback.h"
#include "hci/address_with_type.h"
#include "os/alarm.h"

namespace bluetooth {
namespace hci {

class LeAddressRotatorCallback {
 public:
  virtual ~LeAddressRotatorCallback() = default;
  virtual void OnPause() = 0;
  virtual void OnResume() = 0;
};

class LeAddressRotator {
 public:
  LeAddressRotator(common::Callback<void(Address address)> set_random_address, os::Handler* handler,
                   Address pulic_address);
  virtual ~LeAddressRotator();

  enum AddressPolicy {
    POLICY_NOT_SET,
    USE_PUBLIC_ADDRESS,
    USE_STATIC_ADDRESS,
    USE_NON_RESOLVABLE_ADDRESS,
    USE_RESOLVABLE_ADDRESS
  };

  // Aborts if called more than once
  void SetPrivacyPolicyForInitiatorAddress(AddressPolicy address_policy, AddressWithType fixed_address,
                                           crypto_toolbox::Octet16 rotation_irk,
                                           std::chrono::milliseconds minimum_rotation_time,
                                           std::chrono::milliseconds maximum_rotation_time);
  void AckPause(LeAddressRotatorCallback* callback);
  void AckResume(LeAddressRotatorCallback* callback);
  virtual void Register(LeAddressRotatorCallback* callback);
  virtual void Unregister(LeAddressRotatorCallback* callback);
  void OnLeSetRandomAddressComplete(bool success);
  AddressWithType GetCurrentAddress();  // What was set in SetRandomAddress()
  AddressWithType GetAnotherAddress();  // A new random address without rotating.
  void SetAddress(AddressWithType address_with_type);

 private:
  void pause_registered_clients();
  void resume_registered_clients();
  void rotate_random_address();
  hci::Address generate_rpa(const crypto_toolbox::Octet16& irk, std::array<uint8_t, 8> prand);
  hci::Address generate_nrpa();
  std::chrono::milliseconds get_next_private_address_interval_ms();
  common::Callback<void(Address address)> set_random_address_;

  enum ClientState {
    WAITING_FOR_PAUSE,
    PAUSED,
    WAITING_FOR_RESUME,
    RESUMED,
  };

  os::Handler* handler_;
  std::map<LeAddressRotatorCallback*, ClientState> registered_clients_;
  mutable std::mutex mutex_;

  AddressPolicy address_policy_ = AddressPolicy::POLICY_NOT_SET;
  bool use_address_from_set_address = false;
  AddressWithType public_address_;
  AddressWithType fixed_address_;
  AddressWithType le_random_address_;
  std::unique_ptr<os::Alarm> address_rotation_alarm_;
  crypto_toolbox::Octet16 rotation_irk_;
  std::chrono::milliseconds minimum_rotation_time_;
  std::chrono::milliseconds maximum_rotation_time_;
};

}  // namespace hci
}  // namespace bluetooth
