/*
 * Copyright 2015 The Android Open Source Project
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

#include <unistd.h>
#include <cstdint>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include "base/time/time.h"
#include "hci/address.h"
#include "hci/hci_packets.h"
#include "link_layer_controller.h"
#include "model/devices/device.h"
#include "model/setup/async_manager.h"
#include "security_manager.h"

namespace test_vendor_lib {

using ::bluetooth::hci::Address;
using ::bluetooth::packet::PacketView;

// Emulates a dual mode BR/EDR + LE controller by maintaining the link layer
// state machine detailed in the Bluetooth Core Specification Version 4.2,
// Volume 6, Part B, Section 1.1 (page 30). Provides methods corresponding to
// commands sent by the HCI. These methods will be registered as callbacks from
// a controller instance with the HciHandler. To implement a new Bluetooth
// command, simply add the method declaration below, with return type void and a
// single const std::vector<uint8_t>& argument. After implementing the
// method, simply register it with the HciHandler using the SET_HANDLER macro in
// the controller's default constructor. Be sure to name your method after the
// corresponding Bluetooth command in the Core Specification with the prefix
// "Hci" to distinguish it as a controller command.
class DualModeController : public Device {
  // The location of the config file loaded to populate controller attributes.
  static constexpr char kControllerPropertiesFile[] = "/etc/bluetooth/controller_properties.json";
  static constexpr uint16_t kSecurityManagerNumKeys = 15;

 public:
  // Sets all of the methods to be used as callbacks in the HciHandler.
  DualModeController(const std::string& properties_filename = std::string(kControllerPropertiesFile),
                     uint16_t num_keys = kSecurityManagerNumKeys);

  ~DualModeController() = default;

  // Device methods.
  virtual void Initialize(const std::vector<std::string>& args) override;

  virtual std::string GetTypeString() const override;

  virtual void IncomingPacket(
      model::packets::LinkLayerPacketView incoming) override;

  virtual void TimerTick() override;

  // Route commands and data from the stack.
  void HandleAcl(std::shared_ptr<std::vector<uint8_t>> acl_packet);
  void HandleCommand(std::shared_ptr<std::vector<uint8_t>> command_packet);
  void HandleSco(std::shared_ptr<std::vector<uint8_t>> sco_packet);
  void HandleIso(std::shared_ptr<std::vector<uint8_t>> iso_packet);

  // Set the callbacks for scheduling tasks.
  void RegisterTaskScheduler(std::function<AsyncTaskId(std::chrono::milliseconds, const TaskCallback&)> evtScheduler);

  void RegisterPeriodicTaskScheduler(
      std::function<AsyncTaskId(std::chrono::milliseconds, std::chrono::milliseconds, const TaskCallback&)>
          periodicEvtScheduler);

  void RegisterTaskCancel(std::function<void(AsyncTaskId)> cancel);

  // Set the callbacks for sending packets to the HCI.
  void RegisterEventChannel(
      const std::function<void(std::shared_ptr<std::vector<uint8_t>>)>&
          send_event);

  void RegisterAclChannel(const std::function<void(std::shared_ptr<std::vector<uint8_t>>)>& send_acl);

  void RegisterScoChannel(const std::function<void(std::shared_ptr<std::vector<uint8_t>>)>& send_sco);

  void RegisterIsoChannel(
      const std::function<void(std::shared_ptr<std::vector<uint8_t>>)>&
          send_iso);

  // Set the device's address.
  void SetAddress(Address address) override;

  // Controller commands. For error codes, see the Bluetooth Core Specification,
  // Version 4.2, Volume 2, Part D (page 370).

  // Link Control Commands
  // Bluetooth Core Specification Version 4.2 Volume 2 Part E 7.1

  // 7.1.1
  void HciInquiry(PacketView<true> args);

  // 7.1.2
  void HciInquiryCancel(PacketView<true> args);

  // 7.1.5
  void HciCreateConnection(PacketView<true> args);

  // 7.1.6
  void HciDisconnect(PacketView<true> args);

  // 7.1.8
  void HciAcceptConnectionRequest(PacketView<true> args);

  // 7.1.9
  void HciRejectConnectionRequest(PacketView<true> args);

  // 7.1.10
  void HciLinkKeyRequestReply(PacketView<true> args);

  // 7.1.11
  void HciLinkKeyRequestNegativeReply(PacketView<true> args);

  // 7.1.14
  void HciChangeConnectionPacketType(PacketView<true> args);

  // 7.1.15
  void HciAuthenticationRequested(PacketView<true> args);

  // 7.1.16
  void HciSetConnectionEncryption(PacketView<true> args);

  // 7.1.17
  void HciChangeConnectionLinkKey(PacketView<true> args);

  // 7.1.18
  void HciMasterLinkKey(PacketView<true> args);

  // 7.1.19
  void HciRemoteNameRequest(PacketView<true> args);

  // 7.2.8
  void HciSwitchRole(PacketView<true> args);

  // 7.1.21
  void HciReadRemoteSupportedFeatures(PacketView<true> args);

  // 7.1.22
  void HciReadRemoteExtendedFeatures(PacketView<true> args);

  // 7.1.23
  void HciReadRemoteVersionInformation(PacketView<true> args);

  // 7.1.24
  void HciReadClockOffset(PacketView<true> args);

  // 7.1.29
  void HciIoCapabilityRequestReply(PacketView<true> args);

  // 7.1.30
  void HciUserConfirmationRequestReply(PacketView<true> args);

  // 7.1.31
  void HciUserConfirmationRequestNegativeReply(PacketView<true> args);

  // 7.1.32
  void HciUserPasskeyRequestReply(PacketView<true> args);

  // 7.1.33
  void HciUserPasskeyRequestNegativeReply(PacketView<true> args);

  // 7.1.34
  void HciRemoteOobDataRequestReply(PacketView<true> args);

  // 7.1.35
  void HciRemoteOobDataRequestNegativeReply(PacketView<true> args);

  // 7.1.36
  void HciIoCapabilityRequestNegativeReply(PacketView<true> args);

  // Link Policy Commands
  // Bluetooth Core Specification Version 4.2 Volume 2 Part E 7.2

  // 7.2.1
  void HciHoldMode(PacketView<true> args);

  // 7.2.2
  void HciSniffMode(PacketView<true> args);

  // 7.2.3
  void HciExitSniffMode(PacketView<true> args);

  // 7.2.6
  void HciQosSetup(PacketView<true> args);

  // 7.2.10
  void HciWriteLinkPolicySettings(PacketView<true> args);

  // 7.2.12
  void HciWriteDefaultLinkPolicySettings(PacketView<true> args);

  // 7.2.13
  void HciFlowSpecification(PacketView<true> args);

  // 7.2.14
  void HciSniffSubrating(PacketView<true> args);

  // Link Controller Commands
  // Bluetooth Core Specification Version 4.2 Volume 2 Part E 7.3

  // 7.3.1
  void HciSetEventMask(PacketView<true> args);

  // 7.3.2
  void HciReset(PacketView<true> args);

  // 7.3.3
  void HciSetEventFilter(PacketView<true> args);

  // 7.3.10
  void HciDeleteStoredLinkKey(PacketView<true> args);

  // 7.3.11
  void HciWriteLocalName(PacketView<true> args);

  // 7.3.12
  void HciReadLocalName(PacketView<true> args);

  // 7.3.16
  void HciWritePageTimeout(PacketView<true> args);

  // 7.3.18
  void HciWriteScanEnable(PacketView<true> args);

  // 7.3.22
  void HciWriteInquiryScanActivity(PacketView<true> args);

  // 7.3.23
  void HciReadAuthenticationEnable(PacketView<true> args);

  // 7.3.24
  void HciWriteAuthenticationEnable(PacketView<true> args);

  // 7.3.26
  void HciWriteClassOfDevice(PacketView<true> args);

  // 7.3.28
  void HciWriteVoiceSetting(PacketView<true> args);

  // 7.3.39
  void HciHostBufferSize(PacketView<true> args);

  // 7.3.42
  void HciWriteLinkSupervisionTimeout(PacketView<true> args);

  // 7.3.45
  void HciWriteCurrentIacLap(PacketView<true> args);

  // 7.3.48
  void HciWriteInquiryScanType(PacketView<true> args);

  // 7.3.50
  void HciWriteInquiryMode(PacketView<true> args);

  // 7.3.52
  void HciWritePageScanType(PacketView<true> args);

  // 7.3.56
  void HciWriteExtendedInquiryResponse(PacketView<true> args);

  // 7.3.57
  void HciRefreshEncryptionKey(PacketView<true> args);

  // 7.3.59
  void HciWriteSimplePairingMode(PacketView<true> args);

  // 7.3.79
  void HciWriteLeHostSupport(PacketView<true> args);

  // 7.3.92
  void HciWriteSecureConnectionsHostSupport(PacketView<true> args);

  // Informational Parameters Commands
  // Bluetooth Core Specification Version 4.2 Volume 2 Part E 7.4

  // 7.4.5
  void HciReadBufferSize(PacketView<true> args);

  // 7.4.1
  void HciReadLocalVersionInformation(PacketView<true> args);

  // 7.4.6
  void HciReadBdAddr(PacketView<true> args);

  // 7.4.2
  void HciReadLocalSupportedCommands(PacketView<true> args);

  // 7.4.3
  void HciReadLocalSupportedFeatures(PacketView<true> args);

  // 7.4.4
  void HciReadLocalExtendedFeatures(PacketView<true> args);

  // 7.4.8
  void HciReadLocalSupportedCodecs(PacketView<true> args);

  // Status Parameters Commands
  // Bluetooth Core Specification Version 4.2 Volume 2 Part E 7.5

  // 7.5.7
  void HciReadEncryptionKeySize(PacketView<true> args);

  // Test Commands
  // Bluetooth Core Specification Version 4.2 Volume 2 Part E 7.7

  // 7.7.1
  void HciReadLoopbackMode(PacketView<true> args);

  // 7.7.2
  void HciWriteLoopbackMode(PacketView<true> args);

  // LE Controller Commands
  // Bluetooth Core Specification Version 4.2 Volume 2 Part E 7.8

  // 7.8.1
  void HciLeSetEventMask(PacketView<true> args);

  // 7.8.2
  void HciLeReadBufferSize(PacketView<true> args);

  // 7.8.3
  void HciLeReadLocalSupportedFeatures(PacketView<true> args);

  // 7.8.4
  void HciLeSetRandomAddress(PacketView<true> args);

  // 7.8.5
  void HciLeSetAdvertisingParameters(PacketView<true> args);

  // 7.8.7
  void HciLeSetAdvertisingData(PacketView<true> args);

  // 7.8.8
  void HciLeSetScanResponseData(PacketView<true> args);

  // 7.8.9
  void HciLeSetAdvertisingEnable(PacketView<true> args);

  // 7.8.10
  void HciLeSetScanParameters(PacketView<true> args);

  // 7.8.11
  void HciLeSetScanEnable(PacketView<true> args);

  // 7.8.12
  void HciLeCreateConnection(PacketView<true> args);

  // 7.8.18
  void HciLeConnectionUpdate(PacketView<true> args);

  // 7.8.13
  void HciLeConnectionCancel(PacketView<true> args);

  // 7.8.14
  void HciLeReadWhiteListSize(PacketView<true> args);

  // 7.8.15
  void HciLeClearWhiteList(PacketView<true> args);

  // 7.8.16
  void HciLeAddDeviceToWhiteList(PacketView<true> args);

  // 7.8.17
  void HciLeRemoveDeviceFromWhiteList(PacketView<true> args);

  // 7.8.21
  void HciLeReadRemoteFeatures(PacketView<true> args);

  // 7.8.23
  void HciLeRand(PacketView<true> args);

  // 7.8.24
  void HciLeStartEncryption(PacketView<true> args);

  // 7.8.27
  void HciLeReadSupportedStates(PacketView<true> args);

  // 7.8.38
  void HciLeAddDeviceToResolvingList(PacketView<true> args);

  // 7.8.39
  void HciLeRemoveDeviceFromResolvingList(PacketView<true> args);

  // 7.8.40
  void HciLeClearResolvingList(PacketView<true> args);

  // 7.8.77
  void HciLeSetPrivacyMode(PacketView<true> args);

  // Vendor-specific Commands

  void HciLeVendorSleepMode(PacketView<true> args);
  void HciLeVendorCap(PacketView<true> args);
  void HciLeVendorMultiAdv(PacketView<true> args);
  void HciLeVendor155(PacketView<true> args);
  void HciLeVendor157(PacketView<true> args);
  void HciLeEnergyInfo(PacketView<true> args);
  void HciLeAdvertisingFilter(PacketView<true> args);
  void HciLeExtendedScanParams(PacketView<true> args);

  void SetTimerPeriod(std::chrono::milliseconds new_period);
  void StartTimer();
  void StopTimer();

 protected:
  LinkLayerController link_layer_controller_{properties_};

 private:
  // Set a timer for a future action
  void AddControllerEvent(std::chrono::milliseconds, const TaskCallback& callback);

  void AddConnectionAction(const TaskCallback& callback, uint16_t handle);

  void SendCommandCompleteUnknownOpCodeEvent(uint16_t command_opcode) const;

  // Callbacks to send packets back to the HCI.
  std::function<void(std::shared_ptr<bluetooth::hci::AclPacketBuilder>)>
      send_acl_;
  std::function<void(std::shared_ptr<bluetooth::hci::EventPacketBuilder>)>
      send_event_;
  std::function<void(std::shared_ptr<std::vector<uint8_t>>)> send_sco_;
  std::function<void(std::shared_ptr<std::vector<uint8_t>>)> send_iso_;

  // Maintains the commands to be registered and used in the HciHandler object.
  // Keys are command opcodes and values are the callbacks to handle each
  // command.
  std::unordered_map<uint16_t, std::function<void(PacketView<true>)>>
      active_hci_commands_;

  bluetooth::hci::LoopbackMode loopback_mode_;

  SecurityManager security_manager_;

  DualModeController(const DualModeController& cmdPckt) = delete;
  DualModeController& operator=(const DualModeController& cmdPckt) = delete;
};

}  // namespace test_vendor_lib
