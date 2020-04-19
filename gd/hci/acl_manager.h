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

#include <memory>

#include "common/bidi_queue.h"
#include "common/callback.h"
#include "hci/address.h"
#include "hci/address_with_type.h"
#include "hci/hci_layer.h"
#include "hci/hci_packets.h"
#include "module.h"
#include "os/handler.h"

namespace bluetooth {

namespace security {
class SecurityModule;
}

namespace hci {

class AclManager;

class ConnectionManagementCallbacks {
 public:
  virtual ~ConnectionManagementCallbacks() = default;
  // Invoked when controller sends Connection Packet Type Changed event with Success error code
  virtual void OnConnectionPacketTypeChanged(uint16_t packet_type) = 0;
  // Invoked when controller sends Authentication Complete event with Success error code
  virtual void OnAuthenticationComplete() = 0;
  // Invoked when controller sends Encryption Change event with Success error code
  virtual void OnEncryptionChange(EncryptionEnabled enabled) = 0;
  // Invoked when controller sends Change Connection Link Key Complete event with Success error code
  virtual void OnChangeConnectionLinkKeyComplete() = 0;
  // Invoked when controller sends Read Clock Offset Complete event with Success error code
  virtual void OnReadClockOffsetComplete(uint16_t clock_offset) = 0;
  // Invoked when controller sends Mode Change event with Success error code
  virtual void OnModeChange(Mode current_mode, uint16_t interval) = 0;
  // Invoked when controller sends QoS Setup Complete event with Success error code
  virtual void OnQosSetupComplete(ServiceType service_type, uint32_t token_rate, uint32_t peak_bandwidth,
                                  uint32_t latency, uint32_t delay_variation) = 0;
  // Invoked when controller sends Flow Specification Complete event with Success error code
  virtual void OnFlowSpecificationComplete(FlowDirection flow_direction, ServiceType service_type, uint32_t token_rate,
                                           uint32_t token_bucket_size, uint32_t peak_bandwidth,
                                           uint32_t access_latency) = 0;
  // Invoked when controller sends Flush Occurred event
  virtual void OnFlushOccurred() = 0;
  // Invoked when controller sends Command Complete event for Role Discovery command with Success error code
  virtual void OnRoleDiscoveryComplete(Role current_role) = 0;
  // Invoked when controller sends Command Complete event for Read Link Policy Settings command with Success error code
  virtual void OnReadLinkPolicySettingsComplete(uint16_t link_policy_settings) = 0;
  // Invoked when controller sends Command Complete event for Read Automatic Flush Timeout command with Success error
  // code
  virtual void OnReadAutomaticFlushTimeoutComplete(uint16_t flush_timeout) = 0;
  // Invoked when controller sends Command Complete event for Read Transmit Power Level command with Success error code
  virtual void OnReadTransmitPowerLevelComplete(uint8_t transmit_power_level) = 0;
  // Invoked when controller sends Command Complete event for Read Link Supervision Time out command with Success error
  // code
  virtual void OnReadLinkSupervisionTimeoutComplete(uint16_t link_supervision_timeout) = 0;
  // Invoked when controller sends Command Complete event for Read Failed Contact Counter command with Success error
  // code
  virtual void OnReadFailedContactCounterComplete(uint16_t failed_contact_counter) = 0;
  // Invoked when controller sends Command Complete event for Read Link Quality command with Success error code
  virtual void OnReadLinkQualityComplete(uint8_t link_quality) = 0;
  // Invoked when controller sends Command Complete event for Read AFH Channel Map command with Success error code
  virtual void OnReadAfhChannelMapComplete(AfhMode afh_mode, std::array<uint8_t, 10> afh_channel_map) = 0;
  // Invoked when controller sends Command Complete event for Read RSSI command with Success error code
  virtual void OnReadRssiComplete(uint8_t rssi) = 0;
  // Invoked when controller sends Command Complete event for Read Clock command with Success error code
  virtual void OnReadClockComplete(uint32_t clock, uint16_t accuracy) = 0;
  // Invoked when controller sends Master Link Key Complete event
  virtual void OnMasterLinkKeyComplete(KeyFlag key_flag) = 0;
  // Invoked when controller sends Role Change event
  virtual void OnRoleChange(Role new_role) = 0;
};

class LeConnectionManagementCallbacks {
 public:
  virtual ~LeConnectionManagementCallbacks() = default;
  virtual void OnConnectionUpdate(uint16_t connection_interval, uint16_t connection_latency,
                                  uint16_t supervision_timeout) = 0;
};

class AclConnection {
 public:
  AclConnection() : manager_(nullptr), queue_up_end_(nullptr), handle_(0), role_(Role::MASTER){};
  virtual ~AclConnection() = default;

  uint16_t GetHandle() const {
    return handle_;
  }

  Role GetRole() const {
    return role_;
  }

  using Queue = common::BidiQueue<PacketView<kLittleEndian>, BasePacketBuilder>;
  using QueueUpEnd = common::BidiQueueEnd<BasePacketBuilder, PacketView<kLittleEndian>>;
  using QueueDownEnd = common::BidiQueueEnd<PacketView<kLittleEndian>, BasePacketBuilder>;
  virtual QueueUpEnd* GetAclQueueEnd() const;

  // Ask AclManager to clean me up. Must invoke after on_disconnect is called
  virtual void Finish();

  // TODO: API to change link settings ... ?

 protected:
  friend AclManager;
  AclConnection(const AclManager* acl_manager, QueueUpEnd* queue_up_end, uint16_t handle, Role role)
      : manager_(acl_manager), queue_up_end_(queue_up_end), handle_(handle), role_(role) {}
  const AclManager* manager_;
  QueueUpEnd* queue_up_end_;
  uint16_t handle_;
  Role role_;
  DISALLOW_COPY_AND_ASSIGN(AclConnection);
};

class ClassicAclConnection : public AclConnection {
 public:
  ClassicAclConnection() : AclConnection(), address_(Address::kEmpty) {}

  virtual Address GetAddress() const {
    return address_;
  }

  virtual void RegisterCallbacks(ConnectionManagementCallbacks* callbacks, os::Handler* handler);
  virtual void UnregisterCallbacks(ConnectionManagementCallbacks* callbacks);
  virtual void RegisterDisconnectCallback(common::OnceCallback<void(ErrorCode)> on_disconnect, os::Handler* handler);
  virtual bool Disconnect(DisconnectReason reason);
  virtual bool ChangeConnectionPacketType(uint16_t packet_type);
  virtual bool AuthenticationRequested();
  virtual bool SetConnectionEncryption(Enable enable);
  virtual bool ChangeConnectionLinkKey();
  virtual bool ReadClockOffset();
  virtual bool HoldMode(uint16_t max_interval, uint16_t min_interval);
  virtual bool SniffMode(uint16_t max_interval, uint16_t min_interval, uint16_t attempt, uint16_t timeout);
  virtual bool ExitSniffMode();
  virtual bool QosSetup(ServiceType service_type, uint32_t token_rate, uint32_t peak_bandwidth, uint32_t latency,
                        uint32_t delay_variation);
  virtual bool RoleDiscovery();
  virtual bool ReadLinkPolicySettings();
  virtual bool WriteLinkPolicySettings(uint16_t link_policy_settings);
  virtual bool FlowSpecification(FlowDirection flow_direction, ServiceType service_type, uint32_t token_rate,
                                 uint32_t token_bucket_size, uint32_t peak_bandwidth, uint32_t access_latency);
  virtual bool SniffSubrating(uint16_t maximum_latency, uint16_t minimum_remote_timeout,
                              uint16_t minimum_local_timeout);
  virtual bool Flush();
  virtual bool ReadAutomaticFlushTimeout();
  virtual bool WriteAutomaticFlushTimeout(uint16_t flush_timeout);
  virtual bool ReadTransmitPowerLevel(TransmitPowerLevelType type);
  virtual bool ReadLinkSupervisionTimeout();
  virtual bool WriteLinkSupervisionTimeout(uint16_t link_supervision_timeout);
  virtual bool ReadFailedContactCounter();
  virtual bool ResetFailedContactCounter();
  virtual bool ReadLinkQuality();
  virtual bool ReadAfhChannelMap();
  virtual bool ReadRssi();
  virtual bool ReadClock(WhichClock which_clock);
  virtual bool ReadRemoteVersionInformation();
  virtual bool ReadRemoteSupportedFeatures();
  virtual bool ReadRemoteExtendedFeatures();

 private:
  friend AclManager;
  ClassicAclConnection(const AclManager* acl_manager, QueueUpEnd* queue_up_end,
                       AclConnectionInterface* acl_connection_interface, uint16_t handle, Address address, Role role)
      : AclConnection(acl_manager, queue_up_end, handle, Role::MASTER),
        acl_connection_interface_(acl_connection_interface), address_(address) {}
  AclConnectionInterface* acl_connection_interface_;
  Address address_;
  DISALLOW_COPY_AND_ASSIGN(ClassicAclConnection);
};

class LeAclConnection : public AclConnection {
 public:
  LeAclConnection()
      : AclConnection(), le_acl_connection_interface_(nullptr),
        local_address_(Address::kEmpty, AddressType::PUBLIC_DEVICE_ADDRESS),
        remote_address_(Address::kEmpty, AddressType::PUBLIC_DEVICE_ADDRESS){};

  virtual AddressWithType GetLocalAddress() const {
    return local_address_;
  }

  virtual AddressWithType GetRemoteAddress() const {
    return remote_address_;
  }

  virtual void RegisterCallbacks(LeConnectionManagementCallbacks* callbacks, os::Handler* handler);
  virtual void RegisterDisconnectCallback(common::OnceCallback<void(ErrorCode)> on_disconnect, os::Handler* handler);
  virtual bool Disconnect(DisconnectReason reason);

  virtual bool LeConnectionUpdate(uint16_t conn_interval_min, uint16_t conn_interval_max, uint16_t conn_latency,
                                  uint16_t supervision_timeout, uint16_t min_ce_length, uint16_t max_ce_length,
                                  common::OnceCallback<void(ErrorCode)> done_callback, os::Handler* handler);

  // TODO: API to change link settings ... ?

 private:
  friend AclManager;
  LeAclConnection(const AclManager* acl_manager, QueueUpEnd* queue_up_end,
                  LeAclConnectionInterface* le_acl_connection_interface, uint16_t handle, AddressWithType local_address,
                  AddressWithType remote_address, Role role)
      : AclConnection(acl_manager, queue_up_end, handle, role),
        le_acl_connection_interface_(le_acl_connection_interface), local_address_(local_address),
        remote_address_(remote_address) {}
  LeAclConnectionInterface* le_acl_connection_interface_;
  AddressWithType local_address_;
  AddressWithType remote_address_;
  DISALLOW_COPY_AND_ASSIGN(LeAclConnection);
};

class ConnectionCallbacks {
 public:
  virtual ~ConnectionCallbacks() = default;
  // Invoked when controller sends Connection Complete event with Success error code
  virtual void OnConnectSuccess(std::unique_ptr<ClassicAclConnection>) = 0;
  // Invoked when controller sends Connection Complete event with non-Success error code
  virtual void OnConnectFail(Address, ErrorCode reason) = 0;
};

class LeConnectionCallbacks {
 public:
  virtual ~LeConnectionCallbacks() = default;
  // Invoked when controller sends Connection Complete event with Success error code
  // AddressWithType is always equal to the object used in AclManager#CreateLeConnection
  virtual void OnLeConnectSuccess(AddressWithType, std::unique_ptr<LeAclConnection>) = 0;
  // Invoked when controller sends Connection Complete event with non-Success error code
  virtual void OnLeConnectFail(AddressWithType, ErrorCode reason) = 0;
};

class AclManager : public Module {
 public:
  AclManager();
  // NOTE: It is necessary to forward declare a default destructor that overrides the base class one, because
  // "struct impl" is forwarded declared in .cc and compiler needs a concrete definition of "struct impl" when
  // compiling AclManager's destructor. Hence we need to forward declare the destructor for AclManager to delay
  // compiling AclManager's destructor until it starts linking the .cc file.
  ~AclManager() override;

  // Should register only once when user module starts.
  // Generates OnConnectSuccess when an incoming connection is established.
  virtual void RegisterCallbacks(ConnectionCallbacks* callbacks, os::Handler* handler);

  // Should register only once when user module starts.
  virtual void RegisterLeCallbacks(LeConnectionCallbacks* callbacks, os::Handler* handler);

  // Generates OnConnectSuccess if connected, or OnConnectFail otherwise
  virtual void CreateConnection(Address address);

  // Generates OnLeConnectSuccess if connected, or OnLeConnectFail otherwise
  virtual void CreateLeConnection(AddressWithType address_with_type);

  virtual void SetLeInitiatorAddress(AddressWithType initiator_address);

  // Generates OnConnectFail with error code "terminated by local host 0x16" if cancelled, or OnConnectSuccess if not
  // successfully cancelled and already connected
  virtual void CancelConnect(Address address);

  virtual void MasterLinkKey(KeyFlag key_flag);
  virtual void SwitchRole(Address address, Role role);
  virtual uint16_t ReadDefaultLinkPolicySettings();
  virtual void WriteDefaultLinkPolicySettings(uint16_t default_link_policy_settings);

  // In order to avoid circular dependency use setter rather than module dependency.
  virtual void SetSecurityModule(security::SecurityModule* security_module);

  static const ModuleFactory Factory;

 protected:
  void ListDependencies(ModuleList* list) override;

  void Start() override;

  void Stop() override;

  std::string ToString() const override;

 private:
  friend AclConnection;
  friend ClassicAclConnection;
  friend LeAclConnection;
  struct impl;
  std::unique_ptr<impl> pimpl_;

  struct acl_connection;
  DISALLOW_COPY_AND_ASSIGN(AclManager);
};

}  // namespace hci
}  // namespace bluetooth
