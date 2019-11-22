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
  void HciInquiry(bluetooth::packet::PacketView<true> args);

  // 7.1.2
  void HciInquiryCancel(bluetooth::packet::PacketView<true> args);

  // 7.1.5
  void HciCreateConnection(bluetooth::packet::PacketView<true> args);

  // 7.1.6
  void HciDisconnect(bluetooth::packet::PacketView<true> args);

  // 7.1.8
  void HciAcceptConnectionRequest(bluetooth::packet::PacketView<true> args);

  // 7.1.9
  void HciRejectConnectionRequest(bluetooth::packet::PacketView<true> args);

  // 7.1.10
  void HciLinkKeyRequestReply(bluetooth::packet::PacketView<true> args);

  // 7.1.11
  void HciLinkKeyRequestNegativeReply(bluetooth::packet::PacketView<true> args);

  // 7.1.14
  void HciChangeConnectionPacketType(bluetooth::packet::PacketView<true> args);

  // 7.1.15
  void HciAuthenticationRequested(bluetooth::packet::PacketView<true> args);

  // 7.1.16
  void HciSetConnectionEncryption(bluetooth::packet::PacketView<true> args);

  // 7.1.17
  void HciChangeConnectionLinkKey(bluetooth::packet::PacketView<true> args);

  // 7.1.18
  void HciMasterLinkKey(bluetooth::packet::PacketView<true> args);

  // 7.1.19
  void HciRemoteNameRequest(bluetooth::packet::PacketView<true> args);

  // 7.2.8
  void HciSwitchRole(bluetooth::packet::PacketView<true> args);

  // 7.1.21
  void HciReadRemoteSupportedFeatures(bluetooth::packet::PacketView<true> args);

  // 7.1.22
  void HciReadRemoteExtendedFeatures(bluetooth::packet::PacketView<true> args);

  // 7.1.23
  void HciReadRemoteVersionInformation(
      bluetooth::packet::PacketView<true> args);

  // 7.1.24
  void HciReadClockOffset(bluetooth::packet::PacketView<true> args);

  // 7.1.29
  void HciIoCapabilityRequestReply(bluetooth::packet::PacketView<true> args);

  // 7.1.30
  void HciUserConfirmationRequestReply(
      bluetooth::packet::PacketView<true> args);

  // 7.1.31
  void HciUserConfirmationRequestNegativeReply(
      bluetooth::packet::PacketView<true> args);

  // 7.1.32
  void HciUserPasskeyRequestReply(bluetooth::packet::PacketView<true> args);

  // 7.1.33
  void HciUserPasskeyRequestNegativeReply(
      bluetooth::packet::PacketView<true> args);

  // 7.1.34
  void HciRemoteOobDataRequestReply(bluetooth::packet::PacketView<true> args);

  // 7.1.35
  void HciRemoteOobDataRequestNegativeReply(
      bluetooth::packet::PacketView<true> args);

  // 7.1.36
  void HciIoCapabilityRequestNegativeReply(
      bluetooth::packet::PacketView<true> args);

  // Link Policy Commands
  // Bluetooth Core Specification Version 4.2 Volume 2 Part E 7.2

  // 7.2.1
  void HciHoldMode(bluetooth::packet::PacketView<true> args);

  // 7.2.2
  void HciSniffMode(bluetooth::packet::PacketView<true> args);

  // 7.2.3
  void HciExitSniffMode(bluetooth::packet::PacketView<true> args);

  // 7.2.6
  void HciQosSetup(bluetooth::packet::PacketView<true> args);

  // 7.2.10
  void HciWriteLinkPolicySettings(bluetooth::packet::PacketView<true> args);

  // 7.2.12
  void HciWriteDefaultLinkPolicySettings(
      bluetooth::packet::PacketView<true> args);

  // 7.2.13
  void HciFlowSpecification(bluetooth::packet::PacketView<true> args);

  // 7.2.14
  void HciSniffSubrating(bluetooth::packet::PacketView<true> args);

  // Link Controller Commands
  // Bluetooth Core Specification Version 4.2 Volume 2 Part E 7.3

  // 7.3.1
  void HciSetEventMask(bluetooth::packet::PacketView<true> args);

  // 7.3.2
  void HciReset(bluetooth::packet::PacketView<true> args);

  // 7.3.3
  void HciSetEventFilter(bluetooth::packet::PacketView<true> args);

  // 7.3.10
  void HciDeleteStoredLinkKey(bluetooth::packet::PacketView<true> args);

  // 7.3.11
  void HciWriteLocalName(bluetooth::packet::PacketView<true> args);

  // 7.3.12
  void HciReadLocalName(bluetooth::packet::PacketView<true> args);

  // 7.3.16
  void HciWritePageTimeout(bluetooth::packet::PacketView<true> args);

  // 7.3.18
  void HciWriteScanEnable(bluetooth::packet::PacketView<true> args);

  // 7.3.22
  void HciWriteInquiryScanActivity(bluetooth::packet::PacketView<true> args);

  // 7.3.23
  void HciReadAuthenticationEnable(bluetooth::packet::PacketView<true> args);

  // 7.3.24
  void HciWriteAuthenticationEnable(bluetooth::packet::PacketView<true> args);

  // 7.3.26
  void HciWriteClassOfDevice(bluetooth::packet::PacketView<true> args);

  // 7.3.28
  void HciWriteVoiceSetting(bluetooth::packet::PacketView<true> args);

  // 7.3.39
  void HciHostBufferSize(bluetooth::packet::PacketView<true> args);

  // 7.3.42
  void HciWriteLinkSupervisionTimeout(bluetooth::packet::PacketView<true> args);

  // 7.3.45
  void HciWriteCurrentIacLap(bluetooth::packet::PacketView<true> args);

  // 7.3.48
  void HciWriteInquiryScanType(bluetooth::packet::PacketView<true> args);

  // 7.3.50
  void HciWriteInquiryMode(bluetooth::packet::PacketView<true> args);

  // 7.3.52
  void HciWritePageScanType(bluetooth::packet::PacketView<true> args);

  // 7.3.56
  void HciWriteExtendedInquiryResponse(
      bluetooth::packet::PacketView<true> args);

  // 7.3.57
  void HciRefreshEncryptionKey(bluetooth::packet::PacketView<true> args);

  // 7.3.59
  void HciWriteSimplePairingMode(bluetooth::packet::PacketView<true> args);

  // 7.3.79
  void HciWriteLeHostSupport(bluetooth::packet::PacketView<true> args);

  // 7.3.92
  void HciWriteSecureConnectionsHostSupport(
      bluetooth::packet::PacketView<true> args);

  // Informational Parameters Commands
  // Bluetooth Core Specification Version 4.2 Volume 2 Part E 7.4

  // 7.4.5
  void HciReadBufferSize(bluetooth::packet::PacketView<true> args);

  // 7.4.1
  void HciReadLocalVersionInformation(bluetooth::packet::PacketView<true> args);

  // 7.4.6
  void HciReadBdAddr(bluetooth::packet::PacketView<true> args);

  // 7.4.2
  void HciReadLocalSupportedCommands(bluetooth::packet::PacketView<true> args);

  // 7.4.3
  void HciReadLocalSupportedFeatures(bluetooth::packet::PacketView<true> args);

  // 7.4.4
  void HciReadLocalExtendedFeatures(bluetooth::packet::PacketView<true> args);

  // 7.4.8
  void HciReadLocalSupportedCodecs(bluetooth::packet::PacketView<true> args);

  // Status Parameters Commands
  // Bluetooth Core Specification Version 4.2 Volume 2 Part E 7.5

  // 7.5.7
  void HciReadEncryptionKeySize(bluetooth::packet::PacketView<true> args);

  // Test Commands
  // Bluetooth Core Specification Version 4.2 Volume 2 Part E 7.7

  // 7.7.1
  void HciReadLoopbackMode(bluetooth::packet::PacketView<true> args);

  // 7.7.2
  void HciWriteLoopbackMode(bluetooth::packet::PacketView<true> args);

  // LE Controller Commands
  // Bluetooth Core Specification Version 4.2 Volume 2 Part E 7.8

  // 7.8.1
  void HciLeSetEventMask(bluetooth::packet::PacketView<true> args);

  // 7.8.2
  void HciLeReadBufferSize(bluetooth::packet::PacketView<true> args);

  // 7.8.3
  void HciLeReadLocalSupportedFeatures(
      bluetooth::packet::PacketView<true> args);

  // 7.8.4
  void HciLeSetRandomAddress(bluetooth::packet::PacketView<true> args);

  // 7.8.5
  void HciLeSetAdvertisingParameters(bluetooth::packet::PacketView<true> args);

  // 7.8.7
  void HciLeSetAdvertisingData(bluetooth::packet::PacketView<true> args);

  // 7.8.8
  void HciLeSetScanResponseData(bluetooth::packet::PacketView<true> args);

  // 7.8.9
  void HciLeSetAdvertisingEnable(bluetooth::packet::PacketView<true> args);

  // 7.8.10
  void HciLeSetScanParameters(bluetooth::packet::PacketView<true> args);

  // 7.8.11
  void HciLeSetScanEnable(bluetooth::packet::PacketView<true> args);

  // 7.8.12
  void HciLeCreateConnection(bluetooth::packet::PacketView<true> args);

  // 7.8.18
  void HciLeConnectionUpdate(bluetooth::packet::PacketView<true> args);

  // 7.8.13
  void HciLeConnectionCancel(bluetooth::packet::PacketView<true> args);

  // 7.8.14
  void HciLeReadWhiteListSize(bluetooth::packet::PacketView<true> args);

  // 7.8.15
  void HciLeClearWhiteList(bluetooth::packet::PacketView<true> args);

  // 7.8.16
  void HciLeAddDeviceToWhiteList(bluetooth::packet::PacketView<true> args);

  // 7.8.17
  void HciLeRemoveDeviceFromWhiteList(bluetooth::packet::PacketView<true> args);

  // 7.8.21
  void HciLeReadRemoteFeatures(bluetooth::packet::PacketView<true> args);

  // 7.8.23
  void HciLeRand(bluetooth::packet::PacketView<true> args);

  // 7.8.24
  void HciLeStartEncryption(bluetooth::packet::PacketView<true> args);

  // 7.8.27
  void HciLeReadSupportedStates(bluetooth::packet::PacketView<true> args);

  // 7.8.38
  void HciLeAddDeviceToResolvingList(bluetooth::packet::PacketView<true> args);

  // 7.8.39
  void HciLeRemoveDeviceFromResolvingList(
      bluetooth::packet::PacketView<true> args);

  // 7.8.40
  void HciLeClearResolvingList(bluetooth::packet::PacketView<true> args);

  // 7.8.77
  void HciLeSetPrivacyMode(bluetooth::packet::PacketView<true> args);

  // Vendor-specific Commands

  void HciLeVendorSleepMode(bluetooth::packet::PacketView<true> args);
  void HciLeVendorCap(bluetooth::packet::PacketView<true> args);
  void HciLeVendorMultiAdv(bluetooth::packet::PacketView<true> args);
  void HciLeVendor155(bluetooth::packet::PacketView<true> args);
  void HciLeVendor157(bluetooth::packet::PacketView<true> args);
  void HciLeEnergyInfo(bluetooth::packet::PacketView<true> args);
  void HciLeAdvertisingFilter(bluetooth::packet::PacketView<true> args);
  void HciLeExtendedScanParams(bluetooth::packet::PacketView<true> args);

  void SetTimerPeriod(std::chrono::milliseconds new_period);
  void StartTimer();
  void StopTimer();

 protected:
  LinkLayerController link_layer_controller_{properties_};

 private:
  // Set a timer for a future action
  void AddControllerEvent(std::chrono::milliseconds, const TaskCallback& callback);

  void AddConnectionAction(const TaskCallback& callback, uint16_t handle);

  // Creates a command complete event and sends it back to the HCI.
  void SendCommandComplete(hci::OpCode command_opcode, const std::vector<uint8_t>& return_parameters) const;

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
  std::unordered_map<uint16_t,
                     std::function<void(bluetooth::packet::PacketView<true>)>>
      active_hci_commands_;

  hci::LoopbackMode loopback_mode_;

  SecurityManager security_manager_;

  DualModeController(const DualModeController& cmdPckt) = delete;
  DualModeController& operator=(const DualModeController& cmdPckt) = delete;
};

}  // namespace test_vendor_lib
