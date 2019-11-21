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

#include "dual_mode_controller.h"

#include <memory>

#include <base/files/file_util.h>
#include <base/json/json_reader.h>
#include <base/values.h>

#include "os/log.h"
#include "packet/raw_builder.h"

#include "hci.h"
#include "packets/hci/acl_packet_view.h"
#include "packets/hci/command_packet_view.h"
#include "packets/hci/sco_packet_view.h"

using std::vector;
using test_vendor_lib::hci::EventCode;
using test_vendor_lib::hci::OpCode;

namespace {

size_t LastNonZero(test_vendor_lib::packets::PacketView<true> view) {
  for (size_t i = view.size() - 1; i > 0; i--) {
    if (view[i] != 0) {
      return i;
    }
  }
  return 0;
}

}  // namespace

namespace test_vendor_lib {
constexpr char DualModeController::kControllerPropertiesFile[];
constexpr uint16_t DualModeController::kSecurityManagerNumKeys;

// Device methods.
void DualModeController::Initialize(const std::vector<std::string>& args) {
  if (args.size() < 2) return;

  Address addr;
  if (Address::FromString(args[1], addr)) {
    properties_.SetAddress(addr);
  } else {
    LOG_ALWAYS_FATAL("Invalid address: %s", args[1].c_str());
  }
};

std::string DualModeController::GetTypeString() const {
  return "Simulated Bluetooth Controller";
}

void DualModeController::IncomingPacket(
    model::packets::LinkLayerPacketView incoming) {
  link_layer_controller_.IncomingPacket(incoming);
}

void DualModeController::TimerTick() {
  link_layer_controller_.TimerTick();
}

void DualModeController::SendCommandCompleteSuccess(
    bluetooth::hci::OpCode command_opcode) const {
  SendCommandCompleteOnlyStatus(command_opcode,
                                bluetooth::hci::ErrorCode::SUCCESS);
}

void DualModeController::SendCommandCompleteUnknownOpCodeEvent(uint16_t command_opcode) const {
  std::unique_ptr<bluetooth::packet::RawBuilder> raw_builder_ptr =
      std::make_unique<bluetooth::packet::RawBuilder>();
  raw_builder_ptr->AddOctets1(0x01);  // num_responses
  raw_builder_ptr->AddOctets2(command_opcode);
  raw_builder_ptr->AddOctets1(
      static_cast<uint8_t>(bluetooth::hci::ErrorCode::UNKNOWN_HCI_COMMAND));

  auto packet = bluetooth::hci::EventPacketBuilder::Create(
      bluetooth::hci::EventCode::COMMAND_COMPLETE, std::move(raw_builder_ptr));
  send_event_(std::move(packet));
}

void DualModeController::SendCommandCompleteOnlyStatus(
    bluetooth::hci::OpCode command_opcode,
    bluetooth::hci::ErrorCode status) const {
  std::unique_ptr<bluetooth::packet::RawBuilder> raw_builder_ptr =
      std::make_unique<bluetooth::packet::RawBuilder>();
  raw_builder_ptr->AddOctets1(static_cast<uint8_t>(status));
  auto packet = bluetooth::hci::CommandCompleteBuilder::Create(
      0x01, command_opcode, std::move(raw_builder_ptr));
  send_event_(std::move(packet));
}

void DualModeController::SendCommandStatus(
    bluetooth::hci::ErrorCode status,
    bluetooth::hci::OpCode command_opcode) const {
  std::unique_ptr<bluetooth::packet::RawBuilder> raw_builder_ptr =
      std::make_unique<bluetooth::packet::RawBuilder>();
  auto packet = bluetooth::hci::CommandStatusBuilder::Create(
      status, 0x01, command_opcode, std::move(raw_builder_ptr));
  send_event_(std::move(packet));
}

void DualModeController::SendCommandStatusSuccess(
    bluetooth::hci::OpCode command_opcode) const {
  SendCommandStatus(bluetooth::hci::ErrorCode::SUCCESS, command_opcode);
}

DualModeController::DualModeController(const std::string& properties_filename, uint16_t num_keys)
    : Device(properties_filename), security_manager_(num_keys) {
  loopback_mode_ = hci::LoopbackMode::NO;

  Address public_address;
  ASSERT(Address::FromString("3C:5A:B4:04:05:06", public_address));
  properties_.SetAddress(public_address);

  link_layer_controller_.RegisterRemoteChannel(
      [this](std::shared_ptr<model::packets::LinkLayerPacketBuilder> packet,
             Phy::Type phy_type) {
        DualModeController::SendLinkLayerPacket(packet, phy_type);
      });

#define SET_HANDLER(opcode, method) \
  active_hci_commands_[static_cast<uint16_t>(opcode)] = [this](packets::PacketView<true> param) { method(param); };
  SET_HANDLER(OpCode::RESET, HciReset);
  SET_HANDLER(OpCode::READ_BUFFER_SIZE, HciReadBufferSize);
  SET_HANDLER(OpCode::HOST_BUFFER_SIZE, HciHostBufferSize);
  SET_HANDLER(OpCode::SNIFF_SUBRATING, HciSniffSubrating);
  SET_HANDLER(OpCode::READ_ENCRYPTION_KEY_SIZE, HciReadEncryptionKeySize);
  SET_HANDLER(OpCode::READ_LOCAL_VERSION_INFORMATION, HciReadLocalVersionInformation);
  SET_HANDLER(OpCode::READ_BD_ADDR, HciReadBdAddr);
  SET_HANDLER(OpCode::READ_LOCAL_SUPPORTED_COMMANDS, HciReadLocalSupportedCommands);
  SET_HANDLER(OpCode::READ_LOCAL_SUPPORTED_FEATURES, HciReadLocalSupportedFeatures);
  SET_HANDLER(OpCode::READ_LOCAL_SUPPORTED_CODECS, HciReadLocalSupportedCodecs);
  SET_HANDLER(OpCode::READ_LOCAL_EXTENDED_FEATURES, HciReadLocalExtendedFeatures);
  SET_HANDLER(OpCode::READ_REMOTE_EXTENDED_FEATURES, HciReadRemoteExtendedFeatures);
  SET_HANDLER(OpCode::SWITCH_ROLE, HciSwitchRole);
  SET_HANDLER(OpCode::READ_REMOTE_SUPPORTED_FEATURES, HciReadRemoteSupportedFeatures);
  SET_HANDLER(OpCode::READ_CLOCK_OFFSET, HciReadClockOffset);
  SET_HANDLER(OpCode::IO_CAPABILITY_REQUEST_REPLY, HciIoCapabilityRequestReply);
  SET_HANDLER(OpCode::USER_CONFIRMATION_REQUEST_REPLY, HciUserConfirmationRequestReply);
  SET_HANDLER(OpCode::USER_CONFIRMATION_REQUEST_NEGATIVE_REPLY, HciUserConfirmationRequestNegativeReply);
  SET_HANDLER(OpCode::IO_CAPABILITY_REQUEST_NEGATIVE_REPLY, HciIoCapabilityRequestNegativeReply);
  SET_HANDLER(OpCode::WRITE_SIMPLE_PAIRING_MODE, HciWriteSimplePairingMode);
  SET_HANDLER(OpCode::WRITE_LE_HOST_SUPPORT, HciWriteLeHostSupport);
  SET_HANDLER(OpCode::WRITE_SECURE_CONNECTIONS_HOST_SUPPORT,
              HciWriteSecureConnectionHostSupport);
  SET_HANDLER(OpCode::SET_EVENT_MASK, HciSetEventMask);
  SET_HANDLER(OpCode::WRITE_INQUIRY_MODE, HciWriteInquiryMode);
  SET_HANDLER(OpCode::WRITE_PAGE_SCAN_TYPE, HciWritePageScanType);
  SET_HANDLER(OpCode::WRITE_INQUIRY_SCAN_TYPE, HciWriteInquiryScanType);
  SET_HANDLER(OpCode::AUTHENTICATION_REQUESTED, HciAuthenticationRequested);
  SET_HANDLER(OpCode::SET_CONNECTION_ENCRYPTION, HciSetConnectionEncryption);
  SET_HANDLER(OpCode::CHANGE_CONNECTION_LINK_KEY, HciChangeConnectionLinkKey);
  SET_HANDLER(OpCode::MASTER_LINK_KEY, HciMasterLinkKey);
  SET_HANDLER(OpCode::WRITE_AUTHENTICATION_ENABLE, HciWriteAuthenticationEnable);
  SET_HANDLER(OpCode::READ_AUTHENTICATION_ENABLE, HciReadAuthenticationEnable);
  SET_HANDLER(OpCode::WRITE_CLASS_OF_DEVICE, HciWriteClassOfDevice);
  SET_HANDLER(OpCode::WRITE_PAGE_TIMEOUT, HciWritePageTimeout);
  SET_HANDLER(OpCode::WRITE_LINK_SUPERVISION_TIMEOUT, HciWriteLinkSupervisionTimeout);
  SET_HANDLER(OpCode::HOLD_MODE, HciHoldMode);
  SET_HANDLER(OpCode::SNIFF_MODE, HciSniffMode);
  SET_HANDLER(OpCode::EXIT_SNIFF_MODE, HciExitSniffMode);
  SET_HANDLER(OpCode::QOS_SETUP, HciQosSetup);
  SET_HANDLER(OpCode::WRITE_DEFAULT_LINK_POLICY_SETTINGS, HciWriteDefaultLinkPolicySettings);
  SET_HANDLER(OpCode::FLOW_SPECIFICATION, HciFlowSpecification);
  SET_HANDLER(OpCode::WRITE_LINK_POLICY_SETTINGS, HciWriteLinkPolicySettings);
  SET_HANDLER(OpCode::CHANGE_CONNECTION_PACKET_TYPE, HciChangeConnectionPacketType);
  SET_HANDLER(OpCode::WRITE_LOCAL_NAME, HciWriteLocalName);
  SET_HANDLER(OpCode::READ_LOCAL_NAME, HciReadLocalName);
  SET_HANDLER(OpCode::WRITE_EXTENDED_INQUIRY_RESPONSE, HciWriteExtendedInquiryResponse);
  SET_HANDLER(OpCode::REFRESH_ENCRYPTION_KEY, HciRefreshEncryptionKey);
  SET_HANDLER(OpCode::WRITE_VOICE_SETTING, HciWriteVoiceSetting);
  SET_HANDLER(OpCode::WRITE_CURRENT_IAC_LAP, HciWriteCurrentIacLap);
  SET_HANDLER(OpCode::WRITE_INQUIRY_SCAN_ACTIVITY, HciWriteInquiryScanActivity);
  SET_HANDLER(OpCode::WRITE_SCAN_ENABLE, HciWriteScanEnable);
  SET_HANDLER(OpCode::SET_EVENT_FILTER, HciSetEventFilter);
  SET_HANDLER(OpCode::INQUIRY, HciInquiry);
  SET_HANDLER(OpCode::INQUIRY_CANCEL, HciInquiryCancel);
  SET_HANDLER(OpCode::ACCEPT_CONNECTION_REQUEST, HciAcceptConnectionRequest);
  SET_HANDLER(OpCode::REJECT_CONNECTION_REQUEST, HciRejectConnectionRequest);
  SET_HANDLER(OpCode::LINK_KEY_REQUEST_REPLY, HciLinkKeyRequestReply);
  SET_HANDLER(OpCode::LINK_KEY_REQUEST_NEGATIVE_REPLY, HciLinkKeyRequestNegativeReply);
  SET_HANDLER(OpCode::DELETE_STORED_LINK_KEY, HciDeleteStoredLinkKey);
  SET_HANDLER(OpCode::REMOTE_NAME_REQUEST, HciRemoteNameRequest);
  SET_HANDLER(OpCode::LE_SET_EVENT_MASK, HciLeSetEventMask);
  SET_HANDLER(OpCode::LE_READ_BUFFER_SIZE, HciLeReadBufferSize);
  SET_HANDLER(OpCode::LE_READ_LOCAL_SUPPORTED_FEATURES, HciLeReadLocalSupportedFeatures);
  SET_HANDLER(OpCode::LE_SET_RANDOM_ADDRESS, HciLeSetRandomAddress);
  SET_HANDLER(OpCode::LE_SET_ADVERTISING_PARAMETERS, HciLeSetAdvertisingParameters);
  SET_HANDLER(OpCode::LE_SET_ADVERTISING_DATA, HciLeSetAdvertisingData);
  SET_HANDLER(OpCode::LE_SET_SCAN_RESPONSE_DATA, HciLeSetScanResponseData);
  SET_HANDLER(OpCode::LE_SET_ADVERTISING_ENABLE, HciLeSetAdvertisingEnable);
  SET_HANDLER(OpCode::LE_SET_SCAN_PARAMETERS, HciLeSetScanParameters);
  SET_HANDLER(OpCode::LE_SET_SCAN_ENABLE, HciLeSetScanEnable);
  SET_HANDLER(OpCode::LE_CREATE_CONNECTION, HciLeCreateConnection);
  SET_HANDLER(OpCode::CREATE_CONNECTION, HciCreateConnection);
  SET_HANDLER(OpCode::DISCONNECT, HciDisconnect);
  SET_HANDLER(OpCode::LE_CREATE_CONNECTION_CANCEL, HciLeConnectionCancel);
  SET_HANDLER(OpCode::LE_READ_WHITE_LIST_SIZE, HciLeReadWhiteListSize);
  SET_HANDLER(OpCode::LE_CLEAR_WHITE_LIST, HciLeClearWhiteList);
  SET_HANDLER(OpCode::LE_ADD_DEVICE_TO_WHITE_LIST, HciLeAddDeviceToWhiteList);
  SET_HANDLER(OpCode::LE_REMOVE_DEVICE_FROM_WHITE_LIST, HciLeRemoveDeviceFromWhiteList);
  SET_HANDLER(OpCode::LE_RAND, HciLeRand);
  SET_HANDLER(OpCode::LE_READ_SUPPORTED_STATES, HciLeReadSupportedStates);
  SET_HANDLER(OpCode::LE_GET_VENDOR_CAPABILITIES, HciLeVendorCap);
  SET_HANDLER(OpCode::LE_MULTI_ADVT, HciLeVendorMultiAdv);
  SET_HANDLER(OpCode::LE_ADV_FILTER, HciLeAdvertisingFilter);
  SET_HANDLER(OpCode::LE_ENERGY_INFO, HciLeEnergyInfo);
  SET_HANDLER(OpCode::LE_EXTENDED_SCAN_PARAMS, HciLeExtendedScanParams);
  SET_HANDLER(OpCode::LE_READ_REMOTE_FEATURES, HciLeReadRemoteFeatures);
  SET_HANDLER(OpCode::READ_REMOTE_VERSION_INFORMATION, HciReadRemoteVersionInformation);
  SET_HANDLER(OpCode::LE_CONNECTION_UPDATE, HciLeConnectionUpdate);
  SET_HANDLER(OpCode::LE_START_ENCRYPTION, HciLeStartEncryption);
  SET_HANDLER(OpCode::LE_ADD_DEVICE_TO_RESOLVING_LIST,
              HciLeAddDeviceToResolvingList);
  SET_HANDLER(OpCode::LE_REMOVE_DEVICE_FROM_RESOLVING_LIST,
              HciLeRemoveDeviceFromResolvingList);
  SET_HANDLER(OpCode::LE_CLEAR_RESOLVING_LIST, HciLeClearResolvingList);
  SET_HANDLER(OpCode::LE_SET_PRIVACY_MODE, HciLeSetPrivacyMode);
  // Testing Commands
  SET_HANDLER(OpCode::READ_LOOPBACK_MODE, HciReadLoopbackMode);
  SET_HANDLER(OpCode::WRITE_LOOPBACK_MODE, HciWriteLoopbackMode);
#undef SET_HANDLER
}

void DualModeController::HciSniffSubrating(packets::PacketView<true> args) {
  ASSERT_LOG(args.size() == 8, "%s size=%zu", __func__, args.size());

  uint16_t handle = args.begin().extract<uint16_t>();

  auto packet = bluetooth::hci::SniffSubratingCompleteBuilder::Create(
      0x01, bluetooth::hci::ErrorCode::SUCCESS, handle);
  send_event_(std::move(packet));
}

void DualModeController::RegisterTaskScheduler(
    std::function<AsyncTaskId(std::chrono::milliseconds, const TaskCallback&)> oneshot_scheduler) {
  link_layer_controller_.RegisterTaskScheduler(oneshot_scheduler);
}

void DualModeController::RegisterPeriodicTaskScheduler(
    std::function<AsyncTaskId(std::chrono::milliseconds, std::chrono::milliseconds, const TaskCallback&)>
        periodic_scheduler) {
  link_layer_controller_.RegisterPeriodicTaskScheduler(periodic_scheduler);
}

void DualModeController::RegisterTaskCancel(std::function<void(AsyncTaskId)> task_cancel) {
  link_layer_controller_.RegisterTaskCancel(task_cancel);
}

void DualModeController::HandleAcl(std::shared_ptr<std::vector<uint8_t>> packet) {
  auto acl_packet = packets::AclPacketView::Create(packet);
  if (loopback_mode_ == hci::LoopbackMode::LOCAL) {
    uint16_t handle = acl_packet.GetHandle();

    std::unique_ptr<bluetooth::packet::RawBuilder> raw_builder_ptr =
        std::make_unique<bluetooth::packet::RawBuilder>();
    raw_builder_ptr->AddOctets1(0x01);
    raw_builder_ptr->AddOctets2(handle);
    raw_builder_ptr->AddOctets2(0x01);

    auto packet = bluetooth::hci::EventPacketBuilder::Create(
        bluetooth::hci::EventCode::NUMBER_OF_COMPLETED_PACKETS,
        std::move(raw_builder_ptr));
    send_event_(std::move(packet));
    return;
  }

  link_layer_controller_.SendAclToRemote(acl_packet);
}

void DualModeController::HandleSco(std::shared_ptr<std::vector<uint8_t>> packet) {
  auto sco_packet = packets::ScoPacketView::Create(packet);
  if (loopback_mode_ == hci::LoopbackMode::LOCAL) {
    uint16_t handle = sco_packet.GetHandle();
    send_sco_(packet);
    std::unique_ptr<bluetooth::packet::RawBuilder> raw_builder_ptr =
        std::make_unique<bluetooth::packet::RawBuilder>();
    raw_builder_ptr->AddOctets1(0x01);
    raw_builder_ptr->AddOctets2(handle);
    raw_builder_ptr->AddOctets2(0x01);

    auto packet = bluetooth::hci::EventPacketBuilder::Create(
        bluetooth::hci::EventCode::NUMBER_OF_COMPLETED_PACKETS,
        std::move(raw_builder_ptr));
    send_event_(std::move(packet));
    return;
  }
}

void DualModeController::HandleIso(
    std::shared_ptr<std::vector<uint8_t>> /* packet */) {
  // TODO: implement handling similar to HandleSco
}

void DualModeController::HandleCommand(std::shared_ptr<std::vector<uint8_t>> packet) {
  auto command_packet = packets::CommandPacketView::Create(packet);
  uint16_t opcode = command_packet.GetOpcode();
  hci::OpCode op = static_cast<hci::OpCode>(opcode);

  if (loopback_mode_ == hci::LoopbackMode::LOCAL &&
      // Loopback exceptions.
      op != OpCode::RESET && op != OpCode::SET_CONTROLLER_TO_HOST_FLOW_CONTROL && op != OpCode::HOST_BUFFER_SIZE &&
      op != OpCode::HOST_NUM_COMPLETED_PACKETS && op != OpCode::READ_BUFFER_SIZE && op != OpCode::READ_LOOPBACK_MODE &&
      op != OpCode::WRITE_LOOPBACK_MODE) {
    std::unique_ptr<bluetooth::packet::RawBuilder> raw_builder_ptr =
        std::make_unique<bluetooth::packet::RawBuilder>();
    raw_builder_ptr->AddOctets(*packet);
    auto packet = bluetooth::hci::LoopbackCommandBuilder::Create(
        std::move(raw_builder_ptr));
    send_event_(std::move(packet));
  } else if (active_hci_commands_.count(opcode) > 0) {
    active_hci_commands_[opcode](command_packet.GetPayload());
  } else {
    SendCommandCompleteUnknownOpCodeEvent(opcode);
    LOG_INFO("Unknown command, opcode: 0x%04X, OGF: 0x%04X, OCF: 0x%04X",
             opcode, (opcode & 0xFC00) >> 10, opcode & 0x03FF);
  }
}

void DualModeController::RegisterEventChannel(
    const std::function<void(std::shared_ptr<std::vector<uint8_t>>)>& callback) {
  send_event_ =
      [callback](std::shared_ptr<bluetooth::hci::EventPacketBuilder> event) {
        auto bytes = std::make_shared<std::vector<uint8_t>>();
        bluetooth::packet::BitInserter bit_inserter(*bytes);
        bytes->reserve(event->size());
        event->Serialize(bit_inserter);
        callback(std::move(bytes));
      };
  link_layer_controller_.RegisterEventChannel(send_event_);
}

void DualModeController::RegisterAclChannel(
    const std::function<void(std::shared_ptr<std::vector<uint8_t>>)>& callback) {
  link_layer_controller_.RegisterAclChannel(callback);
  send_acl_ = callback;
}

void DualModeController::RegisterScoChannel(
    const std::function<void(std::shared_ptr<std::vector<uint8_t>>)>& callback) {
  link_layer_controller_.RegisterScoChannel(callback);
  send_sco_ = callback;
}

void DualModeController::RegisterIsoChannel(
    const std::function<void(std::shared_ptr<std::vector<uint8_t>>)>&
        callback) {
  link_layer_controller_.RegisterIsoChannel(callback);
  send_iso_ = callback;
}

void DualModeController::HciReset(packets::PacketView<true> args) {
  ASSERT_LOG(args.size() == 0, "%s  size=%zu", __func__, args.size());
  link_layer_controller_.Reset();
  if (loopback_mode_ == hci::LoopbackMode::LOCAL) {
    loopback_mode_ = hci::LoopbackMode::NO;
  }

  SendCommandCompleteSuccess(bluetooth::hci::OpCode::RESET);
}

void DualModeController::HciReadBufferSize(packets::PacketView<true> args) {
  ASSERT_LOG(args.size() == 0, "%s  size=%zu", __func__, args.size());

  auto packet = bluetooth::hci::ReadBufferSizeCompleteBuilder::Create(
      0x01, bluetooth::hci::ErrorCode::SUCCESS,
      properties_.GetAclDataPacketSize(),
      properties_.GetSynchronousDataPacketSize(),
      properties_.GetTotalNumAclDataPackets(),
      properties_.GetTotalNumSynchronousDataPackets());
  send_event_(std::move(packet));
}

void DualModeController::HciReadEncryptionKeySize(
    packets::PacketView<true> args) {
  ASSERT_LOG(args.size() == 2, "%s  size=%zu", __func__, args.size());

  uint16_t handle = args.begin().extract<uint16_t>();

  auto packet = bluetooth::hci::ReadEncryptionKeySizeCompleteBuilder::Create(
      0x01, bluetooth::hci::ErrorCode::SUCCESS, handle,
      properties_.GetEncryptionKeySize());
  send_event_(std::move(packet));
}

void DualModeController::HciHostBufferSize(packets::PacketView<true> args) {
  ASSERT_LOG(args.size() == 7, "%s  size=%zu", __func__, args.size());
  SendCommandCompleteSuccess(bluetooth::hci::OpCode::HOST_BUFFER_SIZE);
}

void DualModeController::HciReadLocalVersionInformation(packets::PacketView<true> args) {
  ASSERT_LOG(args.size() == 0, "%s  size=%zu", __func__, args.size());

  std::unique_ptr<bluetooth::packet::RawBuilder> raw_builder_ptr =
      std::make_unique<bluetooth::packet::RawBuilder>();
  raw_builder_ptr->AddOctets1(
      static_cast<uint8_t>(bluetooth::hci::ErrorCode::SUCCESS));
  raw_builder_ptr->AddOctets1(properties_.GetVersion());
  raw_builder_ptr->AddOctets2(properties_.GetRevision());
  raw_builder_ptr->AddOctets1(properties_.GetLmpPalVersion());
  raw_builder_ptr->AddOctets2(properties_.GetManufacturerName());
  raw_builder_ptr->AddOctets2(properties_.GetLmpPalSubversion());

  auto packet = bluetooth::hci::CommandCompleteBuilder::Create(
      0x01, bluetooth::hci::OpCode::READ_LOCAL_VERSION_INFORMATION,
      std::move(raw_builder_ptr));
  send_event_(std::move(packet));
}

void DualModeController::HciReadRemoteVersionInformation(packets::PacketView<true> args) {
  ASSERT_LOG(args.size() == 2, "%s  size=%zu", __func__, args.size());

  uint16_t handle = args.begin().extract<uint16_t>();

  auto status = link_layer_controller_.SendCommandToRemoteByHandle(
      bluetooth::hci::OpCode::READ_REMOTE_VERSION_INFORMATION, args, handle);

  SendCommandStatus(status,
                    bluetooth::hci::OpCode::READ_REMOTE_VERSION_INFORMATION);
}

void DualModeController::HciReadBdAddr(packets::PacketView<true> args) {
  ASSERT_LOG(args.size() == 0, "%s  size=%zu", __func__, args.size());
  auto packet = bluetooth::hci::ReadBdAddrCompleteBuilder::Create(
      0x01, bluetooth::hci::ErrorCode::SUCCESS, properties_.GetAddress());
  send_event_(std::move(packet));
}

void DualModeController::HciReadLocalSupportedCommands(packets::PacketView<true> args) {
  ASSERT_LOG(args.size() == 0, "%s  size=%zu", __func__, args.size());

  std::array<uint8_t, 64> supported_commands;
  supported_commands.fill(0x00);
  size_t len = properties_.GetSupportedCommands().size();
  if (len > 64) {
    len = 64;
  }
  std::copy_n(properties_.GetSupportedCommands().begin(), len,
              supported_commands.begin());

  auto packet =
      bluetooth::hci::ReadLocalSupportedCommandsCompleteBuilder::Create(
          0x01, bluetooth::hci::ErrorCode::SUCCESS, supported_commands);
  send_event_(std::move(packet));
}

void DualModeController::HciReadLocalSupportedFeatures(packets::PacketView<true> args) {
  ASSERT_LOG(args.size() == 0, "%s  size=%zu", __func__, args.size());
  auto packet =
      bluetooth::hci::ReadLocalSupportedFeaturesCompleteBuilder::Create(
          0x01, bluetooth::hci::ErrorCode::SUCCESS,
          properties_.GetSupportedFeatures());
  send_event_(std::move(packet));
}

void DualModeController::HciReadLocalSupportedCodecs(packets::PacketView<true> args) {
  ASSERT_LOG(args.size() == 0, "%s  size=%zu", __func__, args.size());
  auto packet = bluetooth::hci::ReadLocalSupportedCodecsCompleteBuilder::Create(
      0x01, bluetooth::hci::ErrorCode::SUCCESS,
      properties_.GetSupportedCodecs(), properties_.GetVendorSpecificCodecs());
  send_event_(std::move(packet));
}

void DualModeController::HciReadLocalExtendedFeatures(packets::PacketView<true> args) {
  ASSERT_LOG(args.size() == 1, "%s  size=%zu", __func__, args.size());
  uint8_t page_number = args.begin().extract<uint8_t>();

  auto pakcet =
      bluetooth::hci::ReadLocalExtendedFeaturesCompleteBuilder::Create(
          0x01, bluetooth::hci::ErrorCode::SUCCESS, page_number,
          properties_.GetExtendedFeaturesMaximumPageNumber(),
          properties_.GetExtendedFeatures(page_number));
  send_event_(std::move(pakcet));
}

void DualModeController::HciReadRemoteExtendedFeatures(packets::PacketView<true> args) {
  ASSERT_LOG(args.size() == 3, "%s  size=%zu", __func__, args.size());

  uint16_t handle = args.begin().extract<uint16_t>();

  auto status = link_layer_controller_.SendCommandToRemoteByHandle(
      bluetooth::hci::OpCode::READ_REMOTE_EXTENDED_FEATURES, args, handle);

  SendCommandStatus(status,
                    bluetooth::hci::OpCode::READ_REMOTE_EXTENDED_FEATURES);
}

void DualModeController::HciSwitchRole(packets::PacketView<true> args) {
  ASSERT_LOG(args.size() == 7, "%s  size=%zu", __func__, args.size());

  Address address = args.begin().extract<Address>();
  uint8_t role = args.begin().extract<uint8_t>();

  auto status = link_layer_controller_.SwitchRole(address, role);

  SendCommandStatus(status, bluetooth::hci::OpCode::SWITCH_ROLE);
}

void DualModeController::HciReadRemoteSupportedFeatures(packets::PacketView<true> args) {
  ASSERT_LOG(args.size() == 2, "%s  size=%zu", __func__, args.size());

  uint16_t handle = args.begin().extract<uint16_t>();

  auto status = link_layer_controller_.SendCommandToRemoteByHandle(
      bluetooth::hci::OpCode::READ_REMOTE_SUPPORTED_FEATURES, args, handle);

  SendCommandStatus(status,
                    bluetooth::hci::OpCode::READ_REMOTE_SUPPORTED_FEATURES);
}

void DualModeController::HciReadClockOffset(packets::PacketView<true> args) {
  ASSERT_LOG(args.size() == 2, "%s  size=%zu", __func__, args.size());

  uint16_t handle = args.begin().extract<uint16_t>();

  auto status = link_layer_controller_.SendCommandToRemoteByHandle(
      bluetooth::hci::OpCode::READ_CLOCK_OFFSET, args, handle);

  SendCommandStatus(status, bluetooth::hci::OpCode::READ_CLOCK_OFFSET);
}

void DualModeController::HciIoCapabilityRequestReply(packets::PacketView<true> args) {
  ASSERT_LOG(args.size() == 9, "%s  size=%zu", __func__, args.size());

  auto args_itr = args.begin();
  Address peer = args_itr.extract<Address>();
  uint8_t io_capability = args_itr.extract<uint8_t>();
  uint8_t oob_data_present_flag = args_itr.extract<uint8_t>();
  uint8_t authentication_requirements = args_itr.extract<uint8_t>();

  auto status = link_layer_controller_.IoCapabilityRequestReply(
      peer, io_capability, oob_data_present_flag, authentication_requirements);
  auto packet = bluetooth::hci::IoCapabilityRequestReplyCompleteBuilder::Create(
      0x01, status, peer);

  send_event_(std::move(packet));
}

void DualModeController::HciUserConfirmationRequestReply(packets::PacketView<true> args) {
  ASSERT_LOG(args.size() == 6, "%s  size=%zu", __func__, args.size());

  Address peer = args.begin().extract<Address>();

  auto status = link_layer_controller_.UserConfirmationRequestReply(peer);
  auto packet =
      bluetooth::hci::UserConfirmationRequestReplyCompleteBuilder::Create(
          0x01, status, peer);

  send_event_(std::move(packet));
}

void DualModeController::HciUserConfirmationRequestNegativeReply(packets::PacketView<true> args) {
  ASSERT_LOG(args.size() == 6, "%s  size=%zu", __func__, args.size());

  Address peer = args.begin().extract<Address>();

  auto status =
      link_layer_controller_.UserConfirmationRequestNegativeReply(peer);
  auto packet =
      bluetooth::hci::UserConfirmationRequestNegativeReplyCompleteBuilder::
          Create(0x01, status, peer);

  send_event_(std::move(packet));
}

void DualModeController::HciUserPasskeyRequestReply(packets::PacketView<true> args) {
  ASSERT_LOG(args.size() == 10, "%s  size=%zu", __func__, args.size());

  auto args_itr = args.begin();
  Address peer = args_itr.extract<Address>();
  uint32_t numeric_value = args_itr.extract<uint32_t>();

  auto status =
      link_layer_controller_.UserPasskeyRequestReply(peer, numeric_value);
  auto packet = bluetooth::hci::UserPasskeyRequestReplyCompleteBuilder::Create(
      0x01, status, peer);

  send_event_(std::move(packet));
}

void DualModeController::HciUserPasskeyRequestNegativeReply(packets::PacketView<true> args) {
  ASSERT_LOG(args.size() == 6, "%s  size=%zu", __func__, args.size());

  Address peer = args.begin().extract<Address>();

  auto status = link_layer_controller_.UserPasskeyRequestNegativeReply(peer);
  auto packet =
      bluetooth::hci::UserPasskeyRequestNegativeReplyCompleteBuilder::Create(
          0x01, status, peer);

  send_event_(std::move(packet));
}

void DualModeController::HciRemoteOobDataRequestReply(packets::PacketView<true> args) {
  ASSERT_LOG(args.size() == 38, "%s  size=%zu", __func__, args.size());

  auto args_itr = args.begin();
  Address peer = args_itr.extract<Address>();
  std::vector<uint8_t> c;
  std::vector<uint8_t> r;
  for (size_t i = 0; i < 16; i++) {
    c.push_back(args_itr.extract<uint8_t>());
  }
  for (size_t i = 0; i < 16; i++) {
    r.push_back(args_itr.extract<uint8_t>());
  }
  auto status = link_layer_controller_.RemoteOobDataRequestReply(peer, c, r);
  auto packet =
      bluetooth::hci::RemoteOobDataRequestReplyCompleteBuilder::Create(
          0x01, status, peer);

  send_event_(std::move(packet));
}

void DualModeController::HciRemoteOobDataRequestNegativeReply(packets::PacketView<true> args) {
  ASSERT_LOG(args.size() == 6, "%s  size=%zu", __func__, args.size());

  Address peer = args.begin().extract<Address>();

  auto status = link_layer_controller_.RemoteOobDataRequestNegativeReply(peer);
  auto packet =
      bluetooth::hci::RemoteOobDataRequestNegativeReplyCompleteBuilder::Create(
          0x01, status, peer);

  send_event_(std::move(packet));
}

void DualModeController::HciIoCapabilityRequestNegativeReply(packets::PacketView<true> args) {
  ASSERT_LOG(args.size() == 7, "%s  size=%zu", __func__, args.size());

  auto args_itr = args.begin();
  Address peer = args_itr.extract<Address>();
  hci::Status reason = args_itr.extract<hci::Status>();

  auto status =
      link_layer_controller_.IoCapabilityRequestNegativeReply(peer, reason);
  auto packet =
      bluetooth::hci::IoCapabilityRequestNegativeReplyCompleteBuilder::Create(
          0x01, status, peer);

  send_event_(std::move(packet));
}

void DualModeController::HciWriteSimplePairingMode(packets::PacketView<true> args) {
  ASSERT_LOG(args.size() == 1, "%s  size=%zu", __func__, args.size());
  ASSERT(args[0] == 1 || args[0] == 0);
  link_layer_controller_.WriteSimplePairingMode(args[0] == 1);
  SendCommandCompleteSuccess(bluetooth::hci::OpCode::WRITE_SIMPLE_PAIRING_MODE);
}

void DualModeController::HciChangeConnectionPacketType(packets::PacketView<true> args) {
  ASSERT_LOG(args.size() == 4, "%s  size=%zu", __func__, args.size());
  auto args_itr = args.begin();
  uint16_t handle = args_itr.extract<uint16_t>();
  uint16_t packet_type = args_itr.extract<uint16_t>();

  auto status =
      link_layer_controller_.ChangeConnectionPacketType(handle, packet_type);

  SendCommandStatus(status,
                    bluetooth::hci::OpCode::CHANGE_CONNECTION_PACKET_TYPE);
}

void DualModeController::HciWriteLeHostSupport(packets::PacketView<true> args) {
  ASSERT_LOG(args.size() == 2, "%s  size=%zu", __func__, args.size());
  SendCommandCompleteSuccess(bluetooth::hci::OpCode::WRITE_LE_HOST_SUPPORT);
}

void DualModeController::HciWriteSecureConnectionHostSupport(
    packets::PacketView<true> args) {
  ASSERT_LOG(args.size() == 1, "%s  size=%zu", __func__, args.size());
  properties_.SetExtendedFeatures(properties_.GetExtendedFeatures(1) | 0x8, 1);
  SendCommandCompleteSuccess(
      bluetooth::hci::OpCode::WRITE_SECURE_CONNECTIONS_HOST_SUPPORT);
}

void DualModeController::HciSetEventMask(packets::PacketView<true> args) {
  ASSERT_LOG(args.size() == 8, "%s  size=%zu", __func__, args.size());
  SendCommandCompleteSuccess(bluetooth::hci::OpCode::SET_EVENT_MASK);
}

void DualModeController::HciWriteInquiryMode(packets::PacketView<true> args) {
  ASSERT_LOG(args.size() == 1, "%s  size=%zu", __func__, args.size());
  link_layer_controller_.SetInquiryMode(args[0]);
  SendCommandCompleteSuccess(bluetooth::hci::OpCode::WRITE_INQUIRY_MODE);
}

void DualModeController::HciWritePageScanType(packets::PacketView<true> args) {
  ASSERT_LOG(args.size() == 1, "%s  size=%zu", __func__, args.size());
  SendCommandCompleteSuccess(bluetooth::hci::OpCode::WRITE_PAGE_SCAN_TYPE);
}

void DualModeController::HciWriteInquiryScanType(packets::PacketView<true> args) {
  ASSERT_LOG(args.size() == 1, "%s  size=%zu", __func__, args.size());
  SendCommandCompleteSuccess(bluetooth::hci::OpCode::WRITE_INQUIRY_SCAN_TYPE);
}

void DualModeController::HciAuthenticationRequested(packets::PacketView<true> args) {
  ASSERT_LOG(args.size() == 2, "%s  size=%zu", __func__, args.size());
  uint16_t handle = args.begin().extract<uint16_t>();
  auto status = link_layer_controller_.AuthenticationRequested(handle);

  SendCommandStatus(status, bluetooth::hci::OpCode::AUTHENTICATION_REQUESTED);
}

void DualModeController::HciSetConnectionEncryption(packets::PacketView<true> args) {
  ASSERT_LOG(args.size() == 3, "%s  size=%zu", __func__, args.size());
  auto args_itr = args.begin();
  uint16_t handle = args_itr.extract<uint16_t>();
  uint8_t encryption_enable = args_itr.extract<uint8_t>();
  auto status =
      link_layer_controller_.SetConnectionEncryption(handle, encryption_enable);

  SendCommandStatus(status, bluetooth::hci::OpCode::SET_CONNECTION_ENCRYPTION);
}

void DualModeController::HciChangeConnectionLinkKey(packets::PacketView<true> args) {
  ASSERT_LOG(args.size() == 2, "%s  size=%zu", __func__, args.size());
  auto args_itr = args.begin();
  uint16_t handle = args_itr.extract<uint16_t>();

  auto status = link_layer_controller_.ChangeConnectionLinkKey(handle);

  SendCommandStatus(status, bluetooth::hci::OpCode::CHANGE_CONNECTION_LINK_KEY);
}

void DualModeController::HciMasterLinkKey(packets::PacketView<true> args) {
  ASSERT_LOG(args.size() == 1, "%s  size=%zu", __func__, args.size());
  auto args_itr = args.begin();
  uint8_t key_flag = args_itr.extract<uint8_t>();

  auto status = link_layer_controller_.MasterLinkKey(key_flag);

  SendCommandStatus(status, bluetooth::hci::OpCode::MASTER_LINK_KEY);
}

void DualModeController::HciWriteAuthenticationEnable(packets::PacketView<true> args) {
  ASSERT_LOG(args.size() == 1, "%s  size=%zu", __func__, args.size());
  properties_.SetAuthenticationEnable(args[0]);
  SendCommandCompleteSuccess(
      bluetooth::hci::OpCode::WRITE_AUTHENTICATION_ENABLE);
}

void DualModeController::HciReadAuthenticationEnable(packets::PacketView<true> args) {
  ASSERT_LOG(args.size() == 0, "%s  size=%zu", __func__, args.size());
  auto packet = bluetooth::hci::ReadAuthenticationEnableCompleteBuilder::Create(
      0x01, bluetooth::hci::ErrorCode::SUCCESS,
      static_cast<bluetooth::hci::AuthenticationEnable>(
          properties_.GetAuthenticationEnable()));
  send_event_(std::move(packet));
}

void DualModeController::HciWriteClassOfDevice(packets::PacketView<true> args) {
  ASSERT_LOG(args.size() == 3, "%s  size=%zu", __func__, args.size());
  properties_.SetClassOfDevice(args[0], args[1], args[2]);
  SendCommandCompleteSuccess(bluetooth::hci::OpCode::WRITE_CLASS_OF_DEVICE);
}

void DualModeController::HciWritePageTimeout(packets::PacketView<true> args) {
  ASSERT_LOG(args.size() == 2, "%s  size=%zu", __func__, args.size());
  SendCommandCompleteSuccess(bluetooth::hci::OpCode::WRITE_PAGE_TIMEOUT);
}

void DualModeController::HciHoldMode(packets::PacketView<true> args) {
  ASSERT_LOG(args.size() == 6, "%s  size=%zu", __func__, args.size());
  auto args_itr = args.begin();
  uint16_t handle = args_itr.extract<uint16_t>();
  uint16_t hold_mode_max_interval = args_itr.extract<uint16_t>();
  uint16_t hold_mode_min_interval = args_itr.extract<uint16_t>();

  auto status = link_layer_controller_.HoldMode(handle, hold_mode_max_interval,
                                                hold_mode_min_interval);

  SendCommandStatus(status, bluetooth::hci::OpCode::HOLD_MODE);
}

void DualModeController::HciSniffMode(packets::PacketView<true> args) {
  ASSERT_LOG(args.size() == 10, "%s  size=%zu", __func__, args.size());
  auto args_itr = args.begin();
  uint16_t handle = args_itr.extract<uint16_t>();
  uint16_t sniff_max_interval = args_itr.extract<uint16_t>();
  uint16_t sniff_min_interval = args_itr.extract<uint16_t>();
  uint16_t sniff_attempt = args_itr.extract<uint16_t>();
  uint16_t sniff_timeout = args_itr.extract<uint16_t>();

  auto status = link_layer_controller_.SniffMode(handle, sniff_max_interval,
                                                 sniff_min_interval,
                                                 sniff_attempt, sniff_timeout);

  SendCommandStatus(status, bluetooth::hci::OpCode::SNIFF_MODE);
}

void DualModeController::HciExitSniffMode(packets::PacketView<true> args) {
  ASSERT_LOG(args.size() == 2, "%s  size=%zu", __func__, args.size());
  auto args_itr = args.begin();
  uint16_t handle = args_itr.extract<uint16_t>();

  auto status = link_layer_controller_.ExitSniffMode(handle);

  SendCommandStatus(status, bluetooth::hci::OpCode::EXIT_SNIFF_MODE);
}

void DualModeController::HciQosSetup(packets::PacketView<true> args) {
  ASSERT_LOG(args.size() == 20, "%s  size=%zu", __func__, args.size());
  auto args_itr = args.begin();
  uint16_t handle = args_itr.extract<uint16_t>();
  args_itr.extract<uint8_t>();  // unused
  uint8_t service_type = args_itr.extract<uint8_t>();
  uint32_t token_rate = args_itr.extract<uint32_t>();
  uint32_t peak_bandwidth = args_itr.extract<uint32_t>();
  uint32_t latency = args_itr.extract<uint32_t>();
  uint32_t delay_variation = args_itr.extract<uint32_t>();

  auto status =
      link_layer_controller_.QosSetup(handle, service_type, token_rate,
                                      peak_bandwidth, latency, delay_variation);

  SendCommandStatus(status, bluetooth::hci::OpCode::QOS_SETUP);
}

void DualModeController::HciWriteDefaultLinkPolicySettings(packets::PacketView<true> args) {
  ASSERT_LOG(args.size() == 2, "%s  size=%zu", __func__, args.size());
  SendCommandCompleteSuccess(
      bluetooth::hci::OpCode::WRITE_DEFAULT_LINK_POLICY_SETTINGS);
}

void DualModeController::HciFlowSpecification(packets::PacketView<true> args) {
  ASSERT_LOG(args.size() == 21, "%s  size=%zu", __func__, args.size());
  auto args_itr = args.begin();
  uint16_t handle = args_itr.extract<uint16_t>();
  args_itr.extract<uint8_t>();  // unused
  uint8_t flow_direction = args_itr.extract<uint8_t>();
  uint8_t service_type = args_itr.extract<uint8_t>();
  uint32_t token_rate = args_itr.extract<uint32_t>();
  uint32_t token_bucket_size = args_itr.extract<uint32_t>();
  uint32_t peak_bandwidth = args_itr.extract<uint32_t>();
  uint32_t access_latency = args_itr.extract<uint32_t>();

  auto status = link_layer_controller_.FlowSpecification(
      handle, flow_direction, service_type, token_rate, token_bucket_size,
      peak_bandwidth, access_latency);

  SendCommandStatus(status, bluetooth::hci::OpCode::FLOW_SPECIFICATION);
}

void DualModeController::HciWriteLinkPolicySettings(packets::PacketView<true> args) {
  ASSERT_LOG(args.size() == 4, "%s  size=%zu", __func__, args.size());

  auto args_itr = args.begin();
  uint16_t handle = args_itr.extract<uint16_t>();
  uint16_t settings = args_itr.extract<uint16_t>();

  auto status =
      link_layer_controller_.WriteLinkPolicySettings(handle, settings);

  auto packet = bluetooth::hci::WriteLinkPolicySettingsCompleteBuilder::Create(
      0x01, status, handle);
  send_event_(std::move(packet));
}

void DualModeController::HciWriteLinkSupervisionTimeout(packets::PacketView<true> args) {
  ASSERT_LOG(args.size() == 4, "%s  size=%zu", __func__, args.size());

  auto args_itr = args.begin();
  uint16_t handle = args_itr.extract<uint16_t>();
  uint16_t timeout = args_itr.extract<uint16_t>();

  auto status =
      link_layer_controller_.WriteLinkSupervisionTimeout(handle, timeout);
  auto packet =
      bluetooth::hci::WriteLinkSupervisionTimeoutCompleteBuilder::Create(
          0x01, status, handle);
  send_event_(std::move(packet));
}

void DualModeController::HciReadLocalName(packets::PacketView<true> args) {
  ASSERT_LOG(args.size() == 0, "%s  size=%zu", __func__, args.size());

  std::array<uint8_t, 248> local_name;
  local_name.fill(0x00);
  size_t len = properties_.GetName().size();
  if (len > 247) {
    len = 247;  // one byte for NULL octet (0x00)
  }
  std::copy_n(properties_.GetName().begin(), len, local_name.begin());

  auto packet = bluetooth::hci::ReadLocalNameCompleteBuilder::Create(
      0x01, bluetooth::hci::ErrorCode::SUCCESS, local_name);
  send_event_(std::move(packet));
}

void DualModeController::HciWriteLocalName(packets::PacketView<true> args) {
  ASSERT_LOG(args.size() == 248, "%s  size=%zu", __func__, args.size());
  std::vector<uint8_t> clipped(args.begin(), args.begin() + LastNonZero(args) + 1);
  properties_.SetName(clipped);
  SendCommandCompleteSuccess(bluetooth::hci::OpCode::WRITE_LOCAL_NAME);
}

void DualModeController::HciWriteExtendedInquiryResponse(packets::PacketView<true> args) {
  ASSERT_LOG(args.size() == 241, "%s  size=%zu", __func__, args.size());
  // Strip FEC byte and trailing zeros
  std::vector<uint8_t> clipped(args.begin() + 1, args.begin() + LastNonZero(args) + 1);
  properties_.SetExtendedInquiryData(clipped);
  LOG_WARN("Write EIR Inquiry - Size = %d (%d)", static_cast<int>(properties_.GetExtendedInquiryData().size()),
           static_cast<int>(clipped.size()));
  SendCommandCompleteSuccess(
      bluetooth::hci::OpCode::WRITE_EXTENDED_INQUIRY_RESPONSE);
}

void DualModeController::HciRefreshEncryptionKey(packets::PacketView<true> args) {
  ASSERT_LOG(args.size() == 2, "%s  size=%zu", __func__, args.size());
  auto args_itr = args.begin();
  uint16_t handle = args_itr.extract<uint16_t>();
  SendCommandStatusSuccess(bluetooth::hci::OpCode::REFRESH_ENCRYPTION_KEY);
  // TODO: Support this in the link layer
  auto packet = bluetooth::hci::EncryptionKeyRefreshCompleteBuilder::Create(
      bluetooth::hci::ErrorCode::SUCCESS, handle);
  send_event_(std::move(packet));
}

void DualModeController::HciWriteVoiceSetting(packets::PacketView<true> args) {
  ASSERT_LOG(args.size() == 2, "%s  size=%zu", __func__, args.size());
  SendCommandCompleteSuccess(bluetooth::hci::OpCode::WRITE_VOICE_SETTING);
}

void DualModeController::HciWriteCurrentIacLap(packets::PacketView<true> args) {
  ASSERT(args.size() > 0);
  ASSERT(args.size() == 1 + (3 * args[0]));  // count + 3-byte IACs

  SendCommandCompleteSuccess(bluetooth::hci::OpCode::WRITE_CURRENT_IAC_LAP);
}

void DualModeController::HciWriteInquiryScanActivity(packets::PacketView<true> args) {
  ASSERT_LOG(args.size() == 4, "%s  size=%zu", __func__, args.size());
  SendCommandCompleteSuccess(
      bluetooth::hci::OpCode::WRITE_INQUIRY_SCAN_ACTIVITY);
}

void DualModeController::HciWriteScanEnable(packets::PacketView<true> args) {
  ASSERT_LOG(args.size() == 1, "%s  size=%zu", __func__, args.size());
  link_layer_controller_.SetInquiryScanEnable(args[0] & 0x1);
  link_layer_controller_.SetPageScanEnable(args[0] & 0x2);
  SendCommandCompleteSuccess(bluetooth::hci::OpCode::WRITE_SCAN_ENABLE);
}

void DualModeController::HciSetEventFilter(packets::PacketView<true> args) {
  ASSERT(args.size() > 0);
  SendCommandCompleteSuccess(bluetooth::hci::OpCode::SET_EVENT_FILTER);
}

void DualModeController::HciInquiry(packets::PacketView<true> args) {
  ASSERT_LOG(args.size() == 5, "%s  size=%zu", __func__, args.size());
  link_layer_controller_.SetInquiryLAP(args[0] | (args[1], 8) | (args[2], 16));
  link_layer_controller_.SetInquiryMaxResponses(args[4]);
  link_layer_controller_.StartInquiry(std::chrono::milliseconds(args[3] * 1280));

  SendCommandStatusSuccess(bluetooth::hci::OpCode::INQUIRY);
}

void DualModeController::HciInquiryCancel(packets::PacketView<true> args) {
  ASSERT_LOG(args.size() == 0, "%s  size=%zu", __func__, args.size());
  link_layer_controller_.InquiryCancel();
  SendCommandCompleteSuccess(bluetooth::hci::OpCode::INQUIRY_CANCEL);
}

void DualModeController::HciAcceptConnectionRequest(packets::PacketView<true> args) {
  ASSERT_LOG(args.size() == 7, "%s  size=%zu", __func__, args.size());
  Address addr = args.begin().extract<Address>();
  bool try_role_switch = args[6] == 0;
  auto status =
      link_layer_controller_.AcceptConnectionRequest(addr, try_role_switch);
  SendCommandStatus(status, bluetooth::hci::OpCode::ACCEPT_CONNECTION_REQUEST);
}

void DualModeController::HciRejectConnectionRequest(packets::PacketView<true> args) {
  ASSERT_LOG(args.size() == 7, "%s  size=%zu", __func__, args.size());
  auto args_itr = args.begin();
  Address addr = args_itr.extract<Address>();
  uint8_t reason = args_itr.extract<uint8_t>();
  auto status = link_layer_controller_.RejectConnectionRequest(addr, reason);
  SendCommandStatus(status, bluetooth::hci::OpCode::REJECT_CONNECTION_REQUEST);
}

void DualModeController::HciLinkKeyRequestReply(packets::PacketView<true> args) {
  ASSERT_LOG(args.size() == 22, "%s  size=%zu", __func__, args.size());
  Address addr = args.begin().extract<Address>();
  packets::PacketView<true> key = args.SubViewLittleEndian(6, 22);
  auto status = link_layer_controller_.LinkKeyRequestReply(addr, key);
  auto packet =
      bluetooth::hci::LinkKeyRequestReplyCompleteBuilder::Create(0x01, status);
  send_event_(std::move(packet));
}

void DualModeController::HciLinkKeyRequestNegativeReply(packets::PacketView<true> args) {
  ASSERT_LOG(args.size() == 6, "%s  size=%zu", __func__, args.size());
  Address addr = args.begin().extract<Address>();
  auto status = link_layer_controller_.LinkKeyRequestNegativeReply(addr);
  auto packet =
      bluetooth::hci::LinkKeyRequestNegativeReplyCompleteBuilder::Create(
          0x01, status, addr);
  send_event_(std::move(packet));
}

void DualModeController::HciDeleteStoredLinkKey(packets::PacketView<true> args) {
  ASSERT_LOG(args.size() == 7, "%s  size=%zu", __func__, args.size());

  uint16_t deleted_keys = 0;

  if (args[6] == 0) {
    Address addr = args.begin().extract<Address>();
    deleted_keys = security_manager_.DeleteKey(addr);
  }

  if (args[6] == 1) {
    security_manager_.DeleteAllKeys();
  }

  auto packet = bluetooth::hci::DeleteStoredLinkKeyCompleteBuilder::Create(
      0x01, bluetooth::hci::ErrorCode::SUCCESS, deleted_keys);

  send_event_(std::move(packet));
}

void DualModeController::HciRemoteNameRequest(packets::PacketView<true> args) {
  ASSERT_LOG(args.size() == 10, "%s  size=%zu", __func__, args.size());

  Address remote_addr = args.begin().extract<Address>();

  auto status = link_layer_controller_.SendCommandToRemoteByAddress(
      bluetooth::hci::OpCode::REMOTE_NAME_REQUEST, args, remote_addr, false);

  SendCommandStatus(status, bluetooth::hci::OpCode::REMOTE_NAME_REQUEST);
}

void DualModeController::HciLeSetEventMask(packets::PacketView<true> args) {
  ASSERT_LOG(args.size() == 8, "%s  size=%zu", __func__, args.size());
  /*
    uint64_t mask = args.begin().extract<uint64_t>();
    link_layer_controller_.SetLeEventMask(mask);
  */
  SendCommandCompleteSuccess(bluetooth::hci::OpCode::LE_SET_EVENT_MASK);
}

void DualModeController::HciLeReadBufferSize(packets::PacketView<true> args) {
  ASSERT_LOG(args.size() == 0, "%s  size=%zu", __func__, args.size());

  std::unique_ptr<bluetooth::packet::RawBuilder> raw_builder_ptr =
      std::make_unique<bluetooth::packet::RawBuilder>();
  raw_builder_ptr->AddOctets1(
      static_cast<uint8_t>(bluetooth::hci::ErrorCode::SUCCESS));
  raw_builder_ptr->AddOctets2(properties_.GetLeDataPacketLength());
  raw_builder_ptr->AddOctets1(properties_.GetTotalNumLeDataPackets());

  auto packet = bluetooth::hci::CommandCompleteBuilder::Create(
      0x01, bluetooth::hci::OpCode::LE_READ_BUFFER_SIZE,
      std::move(raw_builder_ptr));
  send_event_(std::move(packet));
}

void DualModeController::HciLeReadLocalSupportedFeatures(packets::PacketView<true> args) {
  ASSERT_LOG(args.size() == 0, "%s  size=%zu", __func__, args.size());
  auto packet =
      bluetooth::hci::LeReadLocalSupportedFeaturesCompleteBuilder::Create(
          0x01, bluetooth::hci::ErrorCode::SUCCESS,
          properties_.GetLeSupportedFeatures());
  send_event_(std::move(packet));
}

void DualModeController::HciLeSetRandomAddress(packets::PacketView<true> args) {
  ASSERT_LOG(args.size() == 6, "%s  size=%zu", __func__, args.size());
  properties_.SetLeAddress(args.begin().extract<Address>());
  SendCommandCompleteSuccess(bluetooth::hci::OpCode::LE_SET_RANDOM_ADDRESS);
}

void DualModeController::HciLeSetAdvertisingParameters(packets::PacketView<true> args) {
  ASSERT_LOG(args.size() == 15, "%s  size=%zu", __func__, args.size());
  auto args_itr = args.begin();
  properties_.SetLeAdvertisingParameters(
      args_itr.extract<uint16_t>() /* AdverisingIntervalMin */,
      args_itr.extract<uint16_t>() /* AdverisingIntervalMax */, args_itr.extract<uint8_t>() /* AdverisingType */,
      args_itr.extract<uint8_t>() /* OwnAddressType */, args_itr.extract<uint8_t>() /* PeerAddressType */,
      args_itr.extract<Address>() /* PeerAddress */, args_itr.extract<uint8_t>() /* AdvertisingChannelMap */,
      args_itr.extract<uint8_t>() /* AdvertisingFilterPolicy */
  );

  SendCommandCompleteSuccess(
      bluetooth::hci::OpCode::LE_SET_ADVERTISING_PARAMETERS);
}

void DualModeController::HciLeSetAdvertisingData(packets::PacketView<true> args) {
  ASSERT_LOG(args.size() == 32, "%s  size=%zu", __func__, args.size());
  properties_.SetLeAdvertisement(std::vector<uint8_t>(args.begin() + 1, args.end()));
  SendCommandCompleteSuccess(bluetooth::hci::OpCode::LE_SET_ADVERTISING_DATA);
}

void DualModeController::HciLeSetScanResponseData(packets::PacketView<true> args) {
  ASSERT_LOG(args.size() == 32, "%s  size=%zu", __func__, args.size());
  properties_.SetLeScanResponse(std::vector<uint8_t>(args.begin() + 1, args.end()));
  SendCommandCompleteSuccess(bluetooth::hci::OpCode::LE_SET_SCAN_RESPONSE_DATA);
}

void DualModeController::HciLeSetAdvertisingEnable(packets::PacketView<true> args) {
  ASSERT_LOG(args.size() == 1, "%s  size=%zu", __func__, args.size());
  auto status = link_layer_controller_.SetLeAdvertisingEnable(
      args.begin().extract<uint8_t>());
  SendCommandCompleteOnlyStatus(
      bluetooth::hci::OpCode::LE_SET_ADVERTISING_ENABLE, status);
}

void DualModeController::HciLeSetScanParameters(packets::PacketView<true> args) {
  ASSERT_LOG(args.size() == 7, "%s  size=%zu", __func__, args.size());
  link_layer_controller_.SetLeScanType(args[0]);
  link_layer_controller_.SetLeScanInterval(args[1] | (args[2], 8));
  link_layer_controller_.SetLeScanWindow(args[3] | (args[4], 8));
  link_layer_controller_.SetLeAddressType(args[5]);
  link_layer_controller_.SetLeScanFilterPolicy(args[6]);
  SendCommandCompleteSuccess(bluetooth::hci::OpCode::LE_SET_SCAN_PARAMETERS);
}

void DualModeController::HciLeSetScanEnable(packets::PacketView<true> args) {
  ASSERT_LOG(args.size() == 2, "%s  size=%zu", __func__, args.size());
  LOG_INFO("SetScanEnable: %d %d", args[0], args[1]);
  link_layer_controller_.SetLeScanEnable(args[0]);
  link_layer_controller_.SetLeFilterDuplicates(args[1]);
  SendCommandCompleteSuccess(bluetooth::hci::OpCode::LE_SET_SCAN_ENABLE);
}

void DualModeController::HciLeCreateConnection(packets::PacketView<true> args) {
  ASSERT_LOG(args.size() == 25, "%s  size=%zu", __func__, args.size());
  auto args_itr = args.begin();
  link_layer_controller_.SetLeScanInterval(args_itr.extract<uint16_t>());
  link_layer_controller_.SetLeScanWindow(args_itr.extract<uint16_t>());
  uint8_t initiator_filter_policy = args_itr.extract<uint8_t>();
  link_layer_controller_.SetLeInitiatorFilterPolicy(initiator_filter_policy);

  if (initiator_filter_policy == 0) {  // White list not used
    uint8_t peer_address_type = args_itr.extract<uint8_t>();
    Address peer_address = args_itr.extract<Address>();
    link_layer_controller_.SetLePeerAddressType(peer_address_type);
    link_layer_controller_.SetLePeerAddress(peer_address);
  }
  link_layer_controller_.SetLeAddressType(args_itr.extract<uint8_t>());
  link_layer_controller_.SetLeConnectionIntervalMin(args_itr.extract<uint16_t>());
  link_layer_controller_.SetLeConnectionIntervalMax(args_itr.extract<uint16_t>());
  link_layer_controller_.SetLeConnectionLatency(args_itr.extract<uint16_t>());
  link_layer_controller_.SetLeSupervisionTimeout(args_itr.extract<uint16_t>());
  link_layer_controller_.SetLeMinimumCeLength(args_itr.extract<uint16_t>());
  link_layer_controller_.SetLeMaximumCeLength(args_itr.extract<uint16_t>());

  auto status = link_layer_controller_.SetLeConnect(true);

  SendCommandStatus(status, bluetooth::hci::OpCode::LE_CREATE_CONNECTION);
}

void DualModeController::HciLeConnectionUpdate(packets::PacketView<true> args) {
  ASSERT_LOG(args.size() == 14, "%s  size=%zu", __func__, args.size());

  SendCommandStatus(
      bluetooth::hci::ErrorCode::CONNECTION_REJECTED_UNACCEPTABLE_BD_ADDR,
      bluetooth::hci::OpCode::LE_CONNECTION_UPDATE);

  auto packet = bluetooth::hci::LeConnectionUpdateCompleteBuilder::Create(
      bluetooth::hci::ErrorCode::SUCCESS, 0x0002, 0x0006, 0x0000, 0x01f4);
}

void DualModeController::HciCreateConnection(packets::PacketView<true> args) {
  ASSERT_LOG(args.size() == 13, "%s  size=%zu", __func__, args.size());

  auto args_itr = args.begin();
  Address address = args_itr.extract<Address>();
  uint16_t packet_type = args_itr.extract<uint16_t>();
  uint8_t page_scan_mode = args_itr.extract<uint8_t>();
  uint16_t clock_offset = args_itr.extract<uint16_t>();
  uint8_t allow_role_switch = args_itr.extract<uint8_t>();

  auto status = link_layer_controller_.CreateConnection(
      address, packet_type, page_scan_mode, clock_offset, allow_role_switch);

  SendCommandStatus(status, bluetooth::hci::OpCode::CREATE_CONNECTION);
}

void DualModeController::HciDisconnect(packets::PacketView<true> args) {
  ASSERT_LOG(args.size() == 3, "%s  size=%zu", __func__, args.size());

  auto args_itr = args.begin();
  uint16_t handle = args_itr.extract<uint16_t>();
  uint8_t reason = args_itr.extract<uint8_t>();

  auto status = link_layer_controller_.Disconnect(handle, reason);

  SendCommandStatus(status, bluetooth::hci::OpCode::DISCONNECT);
}

void DualModeController::HciLeConnectionCancel(packets::PacketView<true> args) {
  ASSERT_LOG(args.size() == 0, "%s  size=%zu", __func__, args.size());
  link_layer_controller_.SetLeConnect(false);
  SendCommandStatusSuccess(bluetooth::hci::OpCode::LE_CREATE_CONNECTION_CANCEL);
  /* For testing Jakub's patch:  Figure out a neat way to call this without
     recompiling.  I'm thinking about a bad device. */
  /*
  SendCommandCompleteOnlyStatus(OpCode::LE_CREATE_CONNECTION_CANCEL,
                                bluetooth::hci::ErrorCode::COMMAND_DISALLOWED);
  */
}

void DualModeController::HciLeReadWhiteListSize(packets::PacketView<true> args) {
  ASSERT_LOG(args.size() == 0, "%s  size=%zu", __func__, args.size());
  auto packet = bluetooth::hci::LeReadWhiteListSizeCompleteBuilder::Create(
      0x01, bluetooth::hci::ErrorCode::SUCCESS,
      properties_.GetLeWhiteListSize());
  send_event_(std::move(packet));
}

void DualModeController::HciLeClearWhiteList(packets::PacketView<true> args) {
  ASSERT_LOG(args.size() == 0, "%s  size=%zu", __func__, args.size());
  link_layer_controller_.LeWhiteListClear();
  SendCommandCompleteSuccess(bluetooth::hci::OpCode::LE_CLEAR_WHITE_LIST);
}

void DualModeController::HciLeAddDeviceToWhiteList(packets::PacketView<true> args) {
  ASSERT_LOG(args.size() == 7, "%s  size=%zu", __func__, args.size());

  if (link_layer_controller_.LeWhiteListFull()) {
    SendCommandCompleteOnlyStatus(
        bluetooth::hci::OpCode::LE_ADD_DEVICE_TO_WHITE_LIST,
        bluetooth::hci::ErrorCode::MEMORY_CAPACITY_EXCEEDED);
    return;
  }
  auto args_itr = args.begin();
  uint8_t addr_type = args_itr.extract<uint8_t>();
  Address address = args_itr.extract<Address>();
  link_layer_controller_.LeWhiteListAddDevice(address, addr_type);
  SendCommandCompleteSuccess(
      bluetooth::hci::OpCode::LE_ADD_DEVICE_TO_WHITE_LIST);
}

void DualModeController::HciLeRemoveDeviceFromWhiteList(packets::PacketView<true> args) {
  ASSERT_LOG(args.size() == 7, "%s  size=%zu", __func__, args.size());

  auto args_itr = args.begin();
  uint8_t addr_type = args_itr.extract<uint8_t>();
  Address address = args_itr.extract<Address>();
  link_layer_controller_.LeWhiteListRemoveDevice(address, addr_type);
  SendCommandCompleteSuccess(
      bluetooth::hci::OpCode::LE_REMOVE_DEVICE_FROM_WHITE_LIST);
}

void DualModeController::HciLeClearResolvingList(
    packets::PacketView<true> args) {
  ASSERT_LOG(args.size() == 0, "%s  size=%zu", __func__, args.size());
  link_layer_controller_.LeResolvingListClear();
  SendCommandCompleteSuccess(bluetooth::hci::OpCode::LE_CLEAR_RESOLVING_LIST);
}

void DualModeController::HciLeAddDeviceToResolvingList(
    packets::PacketView<true> args) {
  ASSERT_LOG(args.size() == 39, "%s  size=%zu", __func__, args.size());

  if (link_layer_controller_.LeResolvingListFull()) {
    SendCommandCompleteOnlyStatus(
        bluetooth::hci::OpCode::LE_ADD_DEVICE_TO_RESOLVING_LIST,
        bluetooth::hci::ErrorCode::MEMORY_CAPACITY_EXCEEDED);
    return;
  }
  auto args_itr = args.begin();
  uint8_t addr_type = args_itr.extract<uint8_t>();
  Address address = args_itr.extract<Address>();
  std::array<uint8_t, LinkLayerController::kIrk_size> peerIrk;
  std::array<uint8_t, LinkLayerController::kIrk_size> localIrk;
  for (size_t irk_ind = 0; irk_ind < LinkLayerController::kIrk_size;
       irk_ind++) {
    peerIrk[irk_ind] = args_itr.extract<uint8_t>();
  }

  for (size_t irk_ind = 0; irk_ind < LinkLayerController::kIrk_size;
       irk_ind++) {
    localIrk[irk_ind] = args_itr.extract<uint8_t>();
  }

  link_layer_controller_.LeResolvingListAddDevice(address, addr_type, peerIrk,
                                                  localIrk);
  SendCommandCompleteSuccess(
      bluetooth::hci::OpCode::LE_ADD_DEVICE_TO_RESOLVING_LIST);
}

void DualModeController::HciLeRemoveDeviceFromResolvingList(
    packets::PacketView<true> args) {
  ASSERT_LOG(args.size() == 7, "%s  size=%zu", __func__, args.size());

  auto args_itr = args.begin();
  uint8_t addr_type = args_itr.extract<uint8_t>();
  Address address = args_itr.extract<Address>();
  link_layer_controller_.LeResolvingListRemoveDevice(address, addr_type);
  SendCommandCompleteSuccess(
      bluetooth::hci::OpCode::LE_REMOVE_DEVICE_FROM_RESOLVING_LIST);
}

void DualModeController::HciLeSetPrivacyMode(packets::PacketView<true> args) {
  ASSERT_LOG(args.size() == 8, "%s  size=%zu", __func__, args.size());

  auto args_itr = args.begin();
  uint8_t peer_identity_address_type = args_itr.extract<uint8_t>();
  Address peer_identity_address = args_itr.extract<Address>();
  uint8_t privacy_mode = args_itr.extract<uint8_t>();

  if (link_layer_controller_.LeResolvingListContainsDevice(
          peer_identity_address, peer_identity_address_type)) {
    link_layer_controller_.LeSetPrivacyMode(
        peer_identity_address_type, peer_identity_address, privacy_mode);
  }

  SendCommandCompleteSuccess(bluetooth::hci::OpCode::LE_SET_PRIVACY_MODE);
}

void DualModeController::HciLeReadRemoteFeatures(packets::PacketView<true> args) {
  ASSERT_LOG(args.size() == 2, "%s  size=%zu", __func__, args.size());

  uint16_t handle = args.begin().extract<uint16_t>();

  auto status = link_layer_controller_.SendCommandToRemoteByHandle(
      bluetooth::hci::OpCode::LE_READ_REMOTE_FEATURES, args, handle);

  SendCommandStatus(status, bluetooth::hci::OpCode::LE_READ_REMOTE_FEATURES);
}

void DualModeController::HciLeRand(packets::PacketView<true> args) {
  ASSERT_LOG(args.size() == 0, "%s  size=%zu", __func__, args.size());
  uint64_t random_val = 0;
  for (size_t rand_bytes = 0; rand_bytes < sizeof(uint64_t); rand_bytes += sizeof(RAND_MAX)) {
    random_val = (random_val << (8 * sizeof(RAND_MAX))) | random();
  }

  auto packet = bluetooth::hci::LeRandCompleteBuilder::Create(
      0x01, bluetooth::hci::ErrorCode::SUCCESS, random_val);
  send_event_(std::move(packet));
}

void DualModeController::HciLeReadSupportedStates(packets::PacketView<true> args) {
  ASSERT_LOG(args.size() == 0, "%s  size=%zu", __func__, args.size());
  auto packet = bluetooth::hci::LeReadSupportedStatesCompleteBuilder::Create(
      0x01, bluetooth::hci::ErrorCode::SUCCESS,
      properties_.GetLeSupportedStates());
  send_event_(std::move(packet));
}

void DualModeController::HciLeVendorCap(packets::PacketView<true> args) {
  ASSERT_LOG(args.size() == 0, "%s  size=%zu", __func__, args.size());
  vector<uint8_t> caps = properties_.GetLeVendorCap();
  if (caps.size() == 0) {
    SendCommandCompleteOnlyStatus(
        bluetooth::hci::OpCode::LE_GET_VENDOR_CAPABILITIES,
        bluetooth::hci::ErrorCode::UNKNOWN_HCI_COMMAND);
    return;
  }

  std::unique_ptr<bluetooth::packet::RawBuilder> raw_builder_ptr =
      std::make_unique<bluetooth::packet::RawBuilder>();
  raw_builder_ptr->AddOctets1(
      static_cast<uint8_t>(bluetooth::hci::ErrorCode::SUCCESS));
  raw_builder_ptr->AddOctets(properties_.GetLeVendorCap());

  auto packet = bluetooth::hci::CommandCompleteBuilder::Create(
      0x01, bluetooth::hci::OpCode::LE_GET_VENDOR_CAPABILITIES,
      std::move(raw_builder_ptr));
  send_event_(std::move(packet));
}

void DualModeController::HciLeVendorMultiAdv(packets::PacketView<true> args) {
  ASSERT(args.size() > 0);
  SendCommandCompleteOnlyStatus(bluetooth::hci::OpCode::LE_MULTI_ADVT,
                                bluetooth::hci::ErrorCode::UNKNOWN_HCI_COMMAND);
}

void DualModeController::HciLeAdvertisingFilter(packets::PacketView<true> args) {
  ASSERT(args.size() > 0);
  SendCommandCompleteOnlyStatus(bluetooth::hci::OpCode::LE_ADV_FILTER,
                                bluetooth::hci::ErrorCode::UNKNOWN_HCI_COMMAND);
}

void DualModeController::HciLeEnergyInfo(packets::PacketView<true> args) {
  ASSERT(args.size() > 0);
  SendCommandCompleteOnlyStatus(bluetooth::hci::OpCode::LE_ENERGY_INFO,
                                bluetooth::hci::ErrorCode::UNKNOWN_HCI_COMMAND);
}

void DualModeController::HciLeExtendedScanParams(packets::PacketView<true> args) {
  ASSERT(args.size() > 0);
  SendCommandCompleteOnlyStatus(bluetooth::hci::OpCode::LE_EXTENDED_SCAN_PARAMS,
                                bluetooth::hci::ErrorCode::UNKNOWN_HCI_COMMAND);
}

void DualModeController::HciLeStartEncryption(packets::PacketView<true> args) {
  ASSERT_LOG(args.size() == 28, "%s  size=%zu", __func__, args.size());

  auto args_itr = args.begin();
  uint16_t handle = args_itr.extract<uint16_t>();
  // uint64_t random_number = args_itr.extract<uint64_t>();
  // uint16_t encrypted_diversifier = args_itr.extract<uint16_t>();
  // std::vector<uint8_t> long_term_key;
  // for (size_t i = 0; i < 16; i++) {
  //   long_term_key.push_back(args_itr.extract<uint18_t>();
  // }
  SendCommandStatus(bluetooth::hci::ErrorCode::SUCCESS,
                    bluetooth::hci::OpCode::LE_START_ENCRYPTION);

  auto packet = bluetooth::hci::EncryptionChangeBuilder::Create(
      bluetooth::hci::ErrorCode::SUCCESS, handle,
      bluetooth::hci::EncryptionEnabled::OFF);
  send_event_(std::move(packet));
#if 0

  std::shared_ptr<packets::AclPacketBuilder> encryption_information =
      std::make_shared<packets::AclPacketBuilder>(
          0x0002, Acl::FIRST_AUTOMATICALLY_FLUSHABLE, Acl::POINT_TO_POINT,
          std::vector<uint8_t>({}));

  encryption_information->AddPayloadOctets2(0x0011);
  encryption_information->AddPayloadOctets2(0x0006);
  encryption_information->AddPayloadOctets1(0x06);
  encryption_information->AddPayloadOctets8(0x0706050403020100);
  encryption_information->AddPayloadOctets8(0x0F0E0D0C0B0A0908);

  send_acl_(encryption_information);

  encryption_information = std::make_shared<packets::AclPacketBuilder>(
      0x0002, Acl::FIRST_AUTOMATICALLY_FLUSHABLE, Acl::POINT_TO_POINT,
      std::vector<uint8_t>({}));

  encryption_information->AddPayloadOctets2(0x000B);
  encryption_information->AddPayloadOctets2(0x0006);
  encryption_information->AddPayloadOctets1(0x07);
  encryption_information->AddPayloadOctets2(0xBEEF);
  encryption_information->AddPayloadOctets8(0x0706050403020100);

  send_acl_(encryption_information);

  encryption_information = std::make_shared<packets::AclPacketBuilder>(
      0x0002, Acl::FIRST_AUTOMATICALLY_FLUSHABLE, Acl::POINT_TO_POINT,
      std::vector<uint8_t>({}));

  encryption_information->AddPayloadOctets2(0x0011);
  encryption_information->AddPayloadOctets2(0x0006);
  encryption_information->AddPayloadOctets1(0x08);
  encryption_information->AddPayloadOctets8(0x0F0E0D0C0B0A0908);
  encryption_information->AddPayloadOctets8(0x0706050403020100);

  send_acl_(encryption_information);

  encryption_information = std::make_shared<packets::AclPacketBuilder>(
      0x0002, Acl::FIRST_AUTOMATICALLY_FLUSHABLE, Acl::POINT_TO_POINT,
      std::vector<uint8_t>({}));

  encryption_information->AddPayloadOctets2(0x0008);
  encryption_information->AddPayloadOctets2(0x0006);
  encryption_information->AddPayloadOctets1(0x09);
  encryption_information->AddPayloadOctets1(0x01);
  encryption_information->AddPayloadOctets6(0xDEADBEEFF00D);
  send_acl_(encryption_information);
  // send_event_(packets::EventPacketBuilder::CreateLeStartEncryption()->ToVector());

#endif
}

void DualModeController::HciReadLoopbackMode(packets::PacketView<true> args) {
  ASSERT_LOG(args.size() == 0, "%s size=%zu", __func__, args.size());
  auto packet = bluetooth::hci::ReadLoopbackModeCompleteBuilder::Create(
      0x01, bluetooth::hci::ErrorCode::SUCCESS,
      static_cast<bluetooth::hci::LoopbackMode>(loopback_mode_));
  send_event_(std::move(packet));
}

void DualModeController::HciWriteLoopbackMode(packets::PacketView<true> args) {
  ASSERT_LOG(args.size() == 1, "%s size=%zu", __func__, args.size());
  loopback_mode_ = static_cast<hci::LoopbackMode>(args[0]);
  // ACL channel
  uint16_t acl_handle = 0x123;
  auto packet_acl = bluetooth::hci::ConnectionCompleteBuilder::Create(
      bluetooth::hci::ErrorCode::SUCCESS, acl_handle, properties_.GetAddress(),
      bluetooth::hci::LinkType::ACL, bluetooth::hci::Enable::DISABLED);
  send_event_(std::move(packet_acl));
  // SCO channel
  uint16_t sco_handle = 0x345;
  auto packet_sco = bluetooth::hci::ConnectionCompleteBuilder::Create(
      bluetooth::hci::ErrorCode::SUCCESS, sco_handle, properties_.GetAddress(),
      bluetooth::hci::LinkType::SCO, bluetooth::hci::Enable::DISABLED);
  send_event_(std::move(packet_sco));
  SendCommandCompleteSuccess(bluetooth::hci::OpCode::WRITE_LOOPBACK_MODE);
}

void DualModeController::SetAddress(Address address) {
  properties_.SetAddress(address);
}

}  // namespace test_vendor_lib
