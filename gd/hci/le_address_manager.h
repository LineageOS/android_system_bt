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
#include "hci/hci_layer.h"
#include "os/alarm.h"

namespace bluetooth {
namespace hci {

class LeAddressManagerCallback {
 public:
  virtual ~LeAddressManagerCallback() = default;
  virtual void OnPause() = 0;
  virtual void OnResume() = 0;
};

class LeAddressManager {
 public:
  LeAddressManager(
      common::Callback<void(std::unique_ptr<CommandPacketBuilder>)> enqueue_command,
      os::Handler* handler,
      Address public_address,
      uint8_t connect_list_size,
      uint8_t resolving_list_size);
  virtual ~LeAddressManager();

  enum AddressPolicy {
    POLICY_NOT_SET,
    USE_PUBLIC_ADDRESS,
    USE_STATIC_ADDRESS,
    USE_NON_RESOLVABLE_ADDRESS,
    USE_RESOLVABLE_ADDRESS
  };

  // Aborts if called more than once
  void SetPrivacyPolicyForInitiatorAddress(
      AddressPolicy address_policy,
      AddressWithType fixed_address,
      crypto_toolbox::Octet16 rotation_irk,
      std::chrono::milliseconds minimum_rotation_time,
      std::chrono::milliseconds maximum_rotation_time);
  // TODO(jpawlowski): remove once we have config file abstraction in cert tests
  void SetPrivacyPolicyForInitiatorAddressForTest(
      AddressPolicy address_policy,
      AddressWithType fixed_address,
      crypto_toolbox::Octet16 rotation_irk,
      std::chrono::milliseconds minimum_rotation_time,
      std::chrono::milliseconds maximum_rotation_time);
  void AckPause(LeAddressManagerCallback* callback);
  void AckResume(LeAddressManagerCallback* callback);
  virtual AddressPolicy Register(LeAddressManagerCallback* callback);
  virtual void Unregister(LeAddressManagerCallback* callback);
  AddressWithType GetCurrentAddress();          // What was set in SetRandomAddress()
  virtual AddressWithType GetAnotherAddress();  // A new random address without rotating.

  uint8_t GetConnectListSize();
  uint8_t GetResolvingListSize();
  void AddDeviceToConnectList(ConnectListAddressType connect_list_address_type, Address address);
  void AddDeviceToResolvingList(
      PeerAddressType peer_identity_address_type,
      Address peer_identity_address,
      const std::array<uint8_t, 16>& peer_irk,
      const std::array<uint8_t, 16>& local_irk);
  void RemoveDeviceFromConnectList(ConnectListAddressType connect_list_address_type, Address address);
  void RemoveDeviceFromResolvingList(PeerAddressType peer_identity_address_type, Address peer_identity_address);
  void ClearConnectList();
  void ClearResolvingList();
  void OnCommandComplete(CommandCompleteView view);

 private:
  void pause_registered_clients();
  void ack_pause(LeAddressManagerCallback* callback);
  void resume_registered_clients();
  void ack_resume(LeAddressManagerCallback* callback);
  void register_client(LeAddressManagerCallback* callback);
  void unregister_client(LeAddressManagerCallback* callback);
  void prepare_to_rotate();
  void rotate_random_address();
  void schedule_rotate_random_address();
  void set_random_address();
  hci::Address generate_rpa();
  hci::Address generate_nrpa();
  std::chrono::milliseconds get_next_private_address_interval_ms();
  void handle_next_command();

  enum ClientState {
    WAITING_FOR_PAUSE,
    PAUSED,
    WAITING_FOR_RESUME,
    RESUMED,
  };

  enum CommandType {
    ROTATE_RANDOM_ADDRESS,
    ADD_DEVICE_TO_CONNECT_LIST,
    REMOVE_DEVICE_FROM_CONNECT_LIST,
    CLEAR_CONNECT_LIST,
    ADD_DEVICE_TO_RESOLVING_LIST,
    REMOVE_DEVICE_FROM_RESOLVING_LIST,
    CLEAR_RESOLVING_LIST
  };

  struct Command {
    CommandType command_type;
    std::unique_ptr<CommandPacketBuilder> command_packet;
  };

  common::Callback<void(std::unique_ptr<CommandPacketBuilder>)> enqueue_command_;
  os::Handler* handler_;
  std::map<LeAddressManagerCallback*, ClientState> registered_clients_;

  AddressPolicy address_policy_ = AddressPolicy::POLICY_NOT_SET;
  AddressWithType le_address_;
  Address public_address_;
  std::unique_ptr<os::Alarm> address_rotation_alarm_;
  crypto_toolbox::Octet16 rotation_irk_;
  std::chrono::milliseconds minimum_rotation_time_;
  std::chrono::milliseconds maximum_rotation_time_;
  uint8_t connect_list_size_;
  uint8_t resolving_list_size_;
  std::queue<Command> cached_commands_;
};

}  // namespace hci
}  // namespace bluetooth
