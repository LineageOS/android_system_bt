/*
 * Copyright 2017 The Android Open Source Project
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

#include "link_layer_controller.h"
#include <hci/hci_packets.h>

#include "include/le_advertisement.h"
#include "os/log.h"
#include "packet/raw_builder.h"

using std::vector;
using namespace std::chrono;
using bluetooth::hci::Address;
using bluetooth::hci::AddressType;
using bluetooth::hci::AddressWithType;

using namespace model::packets;
using model::packets::PacketType;

namespace test_vendor_lib {

constexpr uint16_t kNumCommandPackets = 0x01;

// TODO: Model Rssi?
static uint8_t GetRssi() {
  static uint8_t rssi = 0;
  rssi += 5;
  if (rssi > 128) {
    rssi = rssi % 7;
  }
  return -(rssi);
}

void LinkLayerController::SendLeLinkLayerPacket(
    std::unique_ptr<model::packets::LinkLayerPacketBuilder> packet) {
  std::shared_ptr<model::packets::LinkLayerPacketBuilder> shared_packet =
      std::move(packet);
  ScheduleTask(milliseconds(50), [this, shared_packet]() {
    send_to_remote_(shared_packet, Phy::Type::LOW_ENERGY);
  });
}

void LinkLayerController::SendLinkLayerPacket(
    std::unique_ptr<model::packets::LinkLayerPacketBuilder> packet) {
  std::shared_ptr<model::packets::LinkLayerPacketBuilder> shared_packet =
      std::move(packet);
  ScheduleTask(milliseconds(50), [this, shared_packet]() {
    send_to_remote_(shared_packet, Phy::Type::BR_EDR);
  });
}

ErrorCode LinkLayerController::SendCommandToRemoteByAddress(
    OpCode opcode, bluetooth::packet::PacketView<true> args,
    const Address& remote) {
  Address local_address = properties_.GetAddress();

  switch (opcode) {
    case (OpCode::REMOTE_NAME_REQUEST):
      // LMP features get requested with remote name requests.
      SendLinkLayerPacket(model::packets::ReadRemoteLmpFeaturesBuilder::Create(
          local_address, remote));
      SendLinkLayerPacket(model::packets::RemoteNameRequestBuilder::Create(
          local_address, remote));
      break;
    case (OpCode::READ_REMOTE_SUPPORTED_FEATURES):
      SendLinkLayerPacket(
          model::packets::ReadRemoteSupportedFeaturesBuilder::Create(
              local_address, remote));
      break;
    case (OpCode::READ_REMOTE_EXTENDED_FEATURES): {
      uint8_t page_number =
          (args.begin() + 2).extract<uint8_t>();  // skip the handle
      SendLinkLayerPacket(
          model::packets::ReadRemoteExtendedFeaturesBuilder::Create(
              local_address, remote, page_number));
    } break;
    case (OpCode::READ_REMOTE_VERSION_INFORMATION):
      SendLinkLayerPacket(
          model::packets::ReadRemoteVersionInformationBuilder::Create(
              local_address, remote));
      break;
    case (OpCode::READ_CLOCK_OFFSET):
      SendLinkLayerPacket(model::packets::ReadClockOffsetBuilder::Create(
          local_address, remote));
      break;
    default:
      LOG_INFO("Dropping unhandled command 0x%04x",
               static_cast<uint16_t>(opcode));
      return ErrorCode::UNKNOWN_HCI_COMMAND;
  }

  return ErrorCode::SUCCESS;
}

ErrorCode LinkLayerController::SendCommandToRemoteByHandle(
    OpCode opcode, bluetooth::packet::PacketView<true> args, uint16_t handle) {
  // TODO: Handle LE connections
  if (!connections_.HasHandle(handle)) {
    return ErrorCode::UNKNOWN_CONNECTION;
  }
  return SendCommandToRemoteByAddress(
      opcode, args, connections_.GetAddress(handle).GetAddress());
}

ErrorCode LinkLayerController::SendAclToRemote(
    bluetooth::hci::AclView acl_packet) {
  uint16_t handle = acl_packet.GetHandle();
  if (!connections_.HasHandle(handle)) {
    return ErrorCode::UNKNOWN_CONNECTION;
  }

  AddressWithType my_address = connections_.GetOwnAddress(handle);
  AddressWithType destination = connections_.GetAddress(handle);
  Phy::Type phy = connections_.GetPhyType(handle);

  ScheduleTask(milliseconds(1), [this, handle]() {
    std::vector<bluetooth::hci::CompletedPackets> completed_packets;
    bluetooth::hci::CompletedPackets cp;
    cp.connection_handle_ = handle;
    cp.host_num_of_completed_packets_ = kNumCommandPackets;
    completed_packets.push_back(cp);
    auto packet = bluetooth::hci::NumberOfCompletedPacketsBuilder::Create(
        completed_packets);
    send_event_(std::move(packet));
  });

  auto acl_payload = acl_packet.GetPayload();

  std::unique_ptr<bluetooth::packet::RawBuilder> raw_builder_ptr =
      std::make_unique<bluetooth::packet::RawBuilder>();
  std::vector<uint8_t> payload_bytes(acl_payload.begin(), acl_payload.end());

  uint16_t first_two_bytes =
      static_cast<uint16_t>(acl_packet.GetHandle()) +
      (static_cast<uint16_t>(acl_packet.GetPacketBoundaryFlag()) << 12) +
      (static_cast<uint16_t>(acl_packet.GetBroadcastFlag()) << 14);
  raw_builder_ptr->AddOctets2(first_two_bytes);
  raw_builder_ptr->AddOctets2(static_cast<uint16_t>(payload_bytes.size()));
  raw_builder_ptr->AddOctets(payload_bytes);

  auto acl = model::packets::AclBuilder::Create(my_address.GetAddress(),
                                                destination.GetAddress(),
                                                std::move(raw_builder_ptr));

  switch (phy) {
    case Phy::Type::BR_EDR:
      SendLinkLayerPacket(std::move(acl));
      break;
    case Phy::Type::LOW_ENERGY:
      SendLeLinkLayerPacket(std::move(acl));
      break;
  }
  return ErrorCode::SUCCESS;
}

void LinkLayerController::IncomingPacket(
    model::packets::LinkLayerPacketView incoming) {
  ASSERT(incoming.IsValid());
  auto destination_address = incoming.GetDestinationAddress();

  // Match broadcasts
  bool address_matches = (destination_address == Address::kEmpty);

  // Match addresses from device properties
  if (destination_address == properties_.GetAddress() ||
      destination_address == properties_.GetLeAddress()) {
    address_matches = true;
  }

  // Check advertising addresses
  for (const auto& advertiser : advertisers_) {
    if (advertiser.IsEnabled() &&
        advertiser.GetAddress().GetAddress() == destination_address) {
      address_matches = true;
    }
  }

  // Check connection addresses
  if (connections_.GetHandleOnlyAddress(destination_address) !=
      kReservedHandle) {
    address_matches = true;
  }

  // Drop packets not addressed to me
  if (!address_matches) {
    return;
  }

  switch (incoming.GetType()) {
    case model::packets::PacketType::ACL:
      IncomingAclPacket(incoming);
      break;
    case model::packets::PacketType::DISCONNECT:
      IncomingDisconnectPacket(incoming);
      break;
    case model::packets::PacketType::ENCRYPT_CONNECTION:
      IncomingEncryptConnection(incoming);
      break;
    case model::packets::PacketType::ENCRYPT_CONNECTION_RESPONSE:
      IncomingEncryptConnectionResponse(incoming);
      break;
    case model::packets::PacketType::INQUIRY:
      if (inquiry_scans_enabled_) {
        IncomingInquiryPacket(incoming);
      }
      break;
    case model::packets::PacketType::INQUIRY_RESPONSE:
      IncomingInquiryResponsePacket(incoming);
      break;
    case model::packets::PacketType::IO_CAPABILITY_REQUEST:
      IncomingIoCapabilityRequestPacket(incoming);
      break;
    case model::packets::PacketType::IO_CAPABILITY_RESPONSE:
      IncomingIoCapabilityResponsePacket(incoming);
      break;
    case model::packets::PacketType::IO_CAPABILITY_NEGATIVE_RESPONSE:
      IncomingIoCapabilityNegativeResponsePacket(incoming);
      break;
    case PacketType::ISO:
      IncomingIsoPacket(incoming);
      break;
    case PacketType::ISO_CONNECTION_REQUEST:
      IncomingIsoConnectionRequestPacket(incoming);
      break;
    case PacketType::ISO_CONNECTION_RESPONSE:
      IncomingIsoConnectionResponsePacket(incoming);
      break;
    case PacketType::KEYPRESS_NOTIFICATION:
      IncomingKeypressNotificationPacket(incoming);
      break;
    case model::packets::PacketType::LE_ADVERTISEMENT:
      if (le_scan_enable_ != bluetooth::hci::OpCode::NONE || le_connect_) {
        IncomingLeAdvertisementPacket(incoming);
      }
      break;
    case model::packets::PacketType::LE_CONNECT:
      IncomingLeConnectPacket(incoming);
      break;
    case model::packets::PacketType::LE_CONNECT_COMPLETE:
      IncomingLeConnectCompletePacket(incoming);
      break;
    case model::packets::PacketType::LE_ENCRYPT_CONNECTION:
      IncomingLeEncryptConnection(incoming);
      break;
    case model::packets::PacketType::LE_ENCRYPT_CONNECTION_RESPONSE:
      IncomingLeEncryptConnectionResponse(incoming);
      break;
    case model::packets::PacketType::LE_SCAN:
      // TODO: Check Advertising flags and see if we are scannable.
      IncomingLeScanPacket(incoming);
      break;
    case model::packets::PacketType::LE_SCAN_RESPONSE:
      if (le_scan_enable_ != bluetooth::hci::OpCode::NONE &&
          le_scan_type_ == 1) {
        IncomingLeScanResponsePacket(incoming);
      }
      break;
    case model::packets::PacketType::PAGE:
      if (page_scans_enabled_) {
        IncomingPagePacket(incoming);
      }
      break;
    case model::packets::PacketType::PAGE_RESPONSE:
      IncomingPageResponsePacket(incoming);
      break;
    case model::packets::PacketType::PAGE_REJECT:
      IncomingPageRejectPacket(incoming);
      break;
    case (model::packets::PacketType::PASSKEY):
      IncomingPasskeyPacket(incoming);
      break;
    case (model::packets::PacketType::PASSKEY_FAILED):
      IncomingPasskeyFailedPacket(incoming);
      break;
    case (model::packets::PacketType::PIN_REQUEST):
      IncomingPinRequestPacket(incoming);
      break;
    case (model::packets::PacketType::PIN_RESPONSE):
      IncomingPinResponsePacket(incoming);
      break;
    case (model::packets::PacketType::REMOTE_NAME_REQUEST):
      IncomingRemoteNameRequest(incoming);
      break;
    case (model::packets::PacketType::REMOTE_NAME_REQUEST_RESPONSE):
      IncomingRemoteNameRequestResponse(incoming);
      break;
    case (model::packets::PacketType::READ_REMOTE_SUPPORTED_FEATURES):
      IncomingReadRemoteSupportedFeatures(incoming);
      break;
    case (model::packets::PacketType::READ_REMOTE_SUPPORTED_FEATURES_RESPONSE):
      IncomingReadRemoteSupportedFeaturesResponse(incoming);
      break;
    case (model::packets::PacketType::READ_REMOTE_LMP_FEATURES):
      IncomingReadRemoteLmpFeatures(incoming);
      break;
    case (model::packets::PacketType::READ_REMOTE_LMP_FEATURES_RESPONSE):
      IncomingReadRemoteLmpFeaturesResponse(incoming);
      break;
    case (model::packets::PacketType::READ_REMOTE_EXTENDED_FEATURES):
      IncomingReadRemoteExtendedFeatures(incoming);
      break;
    case (model::packets::PacketType::READ_REMOTE_EXTENDED_FEATURES_RESPONSE):
      IncomingReadRemoteExtendedFeaturesResponse(incoming);
      break;
    case (model::packets::PacketType::READ_REMOTE_VERSION_INFORMATION):
      IncomingReadRemoteVersion(incoming);
      break;
    case (model::packets::PacketType::READ_REMOTE_VERSION_INFORMATION_RESPONSE):
      IncomingReadRemoteVersionResponse(incoming);
      break;
    case (model::packets::PacketType::READ_CLOCK_OFFSET):
      IncomingReadClockOffset(incoming);
      break;
    case (model::packets::PacketType::READ_CLOCK_OFFSET_RESPONSE):
      IncomingReadClockOffsetResponse(incoming);
      break;
    default:
      LOG_WARN("Dropping unhandled packet of type %s",
               model::packets::PacketTypeText(incoming.GetType()).c_str());
  }
}

void LinkLayerController::IncomingAclPacket(
    model::packets::LinkLayerPacketView incoming) {
  LOG_INFO("Acl Packet %s -> %s",
           incoming.GetSourceAddress().ToString().c_str(),
           incoming.GetDestinationAddress().ToString().c_str());

  auto acl = model::packets::AclView::Create(incoming);
  ASSERT(acl.IsValid());
  auto payload = acl.GetPayload();
  std::shared_ptr<std::vector<uint8_t>> payload_bytes =
      std::make_shared<std::vector<uint8_t>>(payload.begin(), payload.end());

  bluetooth::hci::PacketView<bluetooth::hci::kLittleEndian> raw_packet(
      payload_bytes);
  auto acl_view = bluetooth::hci::AclView::Create(raw_packet);
  ASSERT(acl_view.IsValid());

  LOG_INFO("Remote handle 0x%x size %d", acl_view.GetHandle(),
           static_cast<int>(acl_view.size()));
  uint16_t local_handle =
      connections_.GetHandleOnlyAddress(incoming.GetSourceAddress());
  LOG_INFO("Local handle 0x%x", local_handle);

  std::vector<uint8_t> payload_data(acl_view.GetPayload().begin(),
                                    acl_view.GetPayload().end());
  uint16_t acl_buffer_size = properties_.GetAclDataPacketSize();
  int num_packets =
      (payload_data.size() + acl_buffer_size - 1) / acl_buffer_size;

  auto pb_flag_controller_to_host = acl_view.GetPacketBoundaryFlag();
  if (pb_flag_controller_to_host ==
      bluetooth::hci::PacketBoundaryFlag::FIRST_NON_AUTOMATICALLY_FLUSHABLE) {
    pb_flag_controller_to_host =
        bluetooth::hci::PacketBoundaryFlag::FIRST_AUTOMATICALLY_FLUSHABLE;
  }
  for (int i = 0; i < num_packets; i++) {
    size_t start_index = acl_buffer_size * i;
    size_t end_index =
        std::min(start_index + acl_buffer_size, payload_data.size());
    std::vector<uint8_t> fragment(&payload_data[start_index],
                                  &payload_data[end_index]);
    std::unique_ptr<bluetooth::packet::RawBuilder> raw_builder_ptr =
        std::make_unique<bluetooth::packet::RawBuilder>(fragment);
    auto acl_packet = bluetooth::hci::AclBuilder::Create(
        local_handle, pb_flag_controller_to_host, acl_view.GetBroadcastFlag(),
        std::move(raw_builder_ptr));
    pb_flag_controller_to_host =
        bluetooth::hci::PacketBoundaryFlag::CONTINUING_FRAGMENT;

    send_acl_(std::move(acl_packet));
  }
}

void LinkLayerController::IncomingRemoteNameRequest(
    model::packets::LinkLayerPacketView packet) {
  auto view = model::packets::RemoteNameRequestView::Create(packet);
  ASSERT(view.IsValid());

  SendLinkLayerPacket(model::packets::RemoteNameRequestResponseBuilder::Create(
      packet.GetDestinationAddress(), packet.GetSourceAddress(),
      properties_.GetName()));
}

void LinkLayerController::IncomingRemoteNameRequestResponse(
    model::packets::LinkLayerPacketView packet) {
  auto view = model::packets::RemoteNameRequestResponseView::Create(packet);
  ASSERT(view.IsValid());

  send_event_(bluetooth::hci::RemoteNameRequestCompleteBuilder::Create(
      ErrorCode::SUCCESS, packet.GetSourceAddress(), view.GetName()));
}

void LinkLayerController::IncomingReadRemoteLmpFeatures(
    model::packets::LinkLayerPacketView packet) {
  SendLinkLayerPacket(
      model::packets::ReadRemoteLmpFeaturesResponseBuilder::Create(
          packet.GetDestinationAddress(), packet.GetSourceAddress(),
          properties_.GetExtendedFeatures(1)));
}

void LinkLayerController::IncomingReadRemoteLmpFeaturesResponse(
    model::packets::LinkLayerPacketView packet) {
  auto view = model::packets::ReadRemoteLmpFeaturesResponseView::Create(packet);
  ASSERT(view.IsValid());
  send_event_(
      bluetooth::hci::RemoteHostSupportedFeaturesNotificationBuilder::Create(
          packet.GetSourceAddress(), view.GetFeatures()));
}

void LinkLayerController::IncomingReadRemoteSupportedFeatures(
    model::packets::LinkLayerPacketView packet) {
  SendLinkLayerPacket(
      model::packets::ReadRemoteSupportedFeaturesResponseBuilder::Create(
          packet.GetDestinationAddress(), packet.GetSourceAddress(),
          properties_.GetSupportedFeatures()));
}

void LinkLayerController::IncomingReadRemoteSupportedFeaturesResponse(
    model::packets::LinkLayerPacketView packet) {
  auto view =
      model::packets::ReadRemoteSupportedFeaturesResponseView::Create(packet);
  ASSERT(view.IsValid());
  Address source = packet.GetSourceAddress();
  uint16_t handle = connections_.GetHandleOnlyAddress(source);
  if (handle == kReservedHandle) {
    LOG_INFO("Discarding response from a disconnected device %s",
             source.ToString().c_str());
    return;
  }
  send_event_(
      bluetooth::hci::ReadRemoteSupportedFeaturesCompleteBuilder::Create(
          ErrorCode::SUCCESS, handle, view.GetFeatures()));
}

void LinkLayerController::IncomingReadRemoteExtendedFeatures(
    model::packets::LinkLayerPacketView packet) {
  auto view = model::packets::ReadRemoteExtendedFeaturesView::Create(packet);
  ASSERT(view.IsValid());
  uint8_t page_number = view.GetPageNumber();
  uint8_t error_code = static_cast<uint8_t>(ErrorCode::SUCCESS);
  if (page_number > properties_.GetExtendedFeaturesMaximumPageNumber()) {
    error_code = static_cast<uint8_t>(ErrorCode::INVALID_LMP_OR_LL_PARAMETERS);
  }
  SendLinkLayerPacket(
      model::packets::ReadRemoteExtendedFeaturesResponseBuilder::Create(
          packet.GetDestinationAddress(), packet.GetSourceAddress(), error_code,
          page_number, properties_.GetExtendedFeaturesMaximumPageNumber(),
          properties_.GetExtendedFeatures(view.GetPageNumber())));
}

void LinkLayerController::IncomingReadRemoteExtendedFeaturesResponse(
    model::packets::LinkLayerPacketView packet) {
  auto view =
      model::packets::ReadRemoteExtendedFeaturesResponseView::Create(packet);
  ASSERT(view.IsValid());
  Address source = packet.GetSourceAddress();
  uint16_t handle = connections_.GetHandleOnlyAddress(source);
  if (handle == kReservedHandle) {
    LOG_INFO("Discarding response from a disconnected device %s",
             source.ToString().c_str());
    return;
  }
  send_event_(bluetooth::hci::ReadRemoteExtendedFeaturesCompleteBuilder::Create(
      static_cast<ErrorCode>(view.GetStatus()), handle, view.GetPageNumber(),
      view.GetMaxPageNumber(), view.GetFeatures()));
}

void LinkLayerController::IncomingReadRemoteVersion(
    model::packets::LinkLayerPacketView packet) {
  SendLinkLayerPacket(
      model::packets::ReadRemoteVersionInformationResponseBuilder::Create(
          packet.GetDestinationAddress(), packet.GetSourceAddress(),
          properties_.GetLmpPalVersion(), properties_.GetLmpPalSubversion(),
          properties_.GetManufacturerName()));
}

void LinkLayerController::IncomingReadRemoteVersionResponse(
    model::packets::LinkLayerPacketView packet) {
  auto view =
      model::packets::ReadRemoteVersionInformationResponseView::Create(packet);
  ASSERT(view.IsValid());
  Address source = packet.GetSourceAddress();
  uint16_t handle = connections_.GetHandleOnlyAddress(source);
  if (handle == kReservedHandle) {
    LOG_INFO("Discarding response from a disconnected device %s",
             source.ToString().c_str());
    return;
  }
  send_event_(
      bluetooth::hci::ReadRemoteVersionInformationCompleteBuilder::Create(
          ErrorCode::SUCCESS, handle, view.GetLmpVersion(),
          view.GetManufacturerName(), view.GetLmpSubversion()));
}

void LinkLayerController::IncomingReadClockOffset(
    model::packets::LinkLayerPacketView packet) {
  SendLinkLayerPacket(model::packets::ReadClockOffsetResponseBuilder::Create(
      packet.GetDestinationAddress(), packet.GetSourceAddress(),
      properties_.GetClockOffset()));
}

void LinkLayerController::IncomingReadClockOffsetResponse(
    model::packets::LinkLayerPacketView packet) {
  auto view = model::packets::ReadClockOffsetResponseView::Create(packet);
  ASSERT(view.IsValid());
  Address source = packet.GetSourceAddress();
  uint16_t handle = connections_.GetHandleOnlyAddress(source);
  if (handle == kReservedHandle) {
    LOG_INFO("Discarding response from a disconnected device %s",
             source.ToString().c_str());
    return;
  }
  send_event_(bluetooth::hci::ReadClockOffsetCompleteBuilder::Create(
      ErrorCode::SUCCESS, handle, view.GetOffset()));
}

void LinkLayerController::IncomingDisconnectPacket(
    model::packets::LinkLayerPacketView incoming) {
  LOG_INFO("Disconnect Packet");
  auto disconnect = model::packets::DisconnectView::Create(incoming);
  ASSERT(disconnect.IsValid());

  Address peer = incoming.GetSourceAddress();
  uint16_t handle = connections_.GetHandleOnlyAddress(peer);
  if (handle == kReservedHandle) {
    LOG_INFO("Discarding disconnect from a disconnected device %s",
             peer.ToString().c_str());
    return;
  }
  ASSERT_LOG(connections_.Disconnect(handle),
             "GetHandle() returned invalid handle %hx", handle);

  uint8_t reason = disconnect.GetReason();
  ScheduleTask(milliseconds(20),
               [this, handle, reason]() { DisconnectCleanup(handle, reason); });
}

void LinkLayerController::IncomingEncryptConnection(
    model::packets::LinkLayerPacketView incoming) {
  LOG_INFO();

  // TODO: Check keys
  Address peer = incoming.GetSourceAddress();
  uint16_t handle = connections_.GetHandleOnlyAddress(peer);
  if (handle == kReservedHandle) {
    LOG_INFO("Unknown connection @%s", peer.ToString().c_str());
    return;
  }
  send_event_(bluetooth::hci::EncryptionChangeBuilder::Create(
      ErrorCode::SUCCESS, handle, bluetooth::hci::EncryptionEnabled::ON));

  uint16_t count = security_manager_.ReadKey(peer);
  if (count == 0) {
    LOG_ERROR("NO KEY HERE for %s", peer.ToString().c_str());
    return;
  }
  auto array = security_manager_.GetKey(peer);
  std::vector<uint8_t> key_vec{array.begin(), array.end()};
  auto response = model::packets::EncryptConnectionResponseBuilder::Create(
      properties_.GetAddress(), peer, key_vec);
  SendLinkLayerPacket(std::move(response));
}

void LinkLayerController::IncomingEncryptConnectionResponse(
    model::packets::LinkLayerPacketView incoming) {
  LOG_INFO();
  // TODO: Check keys
  uint16_t handle =
      connections_.GetHandleOnlyAddress(incoming.GetSourceAddress());
  if (handle == kReservedHandle) {
    LOG_INFO("Unknown connection @%s",
             incoming.GetSourceAddress().ToString().c_str());
    return;
  }
  auto packet = bluetooth::hci::EncryptionChangeBuilder::Create(
      ErrorCode::SUCCESS, handle, bluetooth::hci::EncryptionEnabled::ON);
  send_event_(std::move(packet));
}

void LinkLayerController::IncomingInquiryPacket(
    model::packets::LinkLayerPacketView incoming) {
  auto inquiry = model::packets::InquiryView::Create(incoming);
  ASSERT(inquiry.IsValid());

  Address peer = incoming.GetSourceAddress();

  switch (inquiry.GetInquiryType()) {
    case (model::packets::InquiryType::STANDARD): {
      auto inquiry_response = model::packets::InquiryResponseBuilder::Create(
          properties_.GetAddress(), peer,
          properties_.GetPageScanRepetitionMode(),
          properties_.GetClassOfDevice(), properties_.GetClockOffset());
      SendLinkLayerPacket(std::move(inquiry_response));
    } break;
    case (model::packets::InquiryType::RSSI): {
      auto inquiry_response =
          model::packets::InquiryResponseWithRssiBuilder::Create(
              properties_.GetAddress(), peer,
              properties_.GetPageScanRepetitionMode(),
              properties_.GetClassOfDevice(), properties_.GetClockOffset(),
              GetRssi());
      SendLinkLayerPacket(std::move(inquiry_response));
    } break;
    case (model::packets::InquiryType::EXTENDED): {
      auto inquiry_response =
          model::packets::ExtendedInquiryResponseBuilder::Create(
              properties_.GetAddress(), peer,
              properties_.GetPageScanRepetitionMode(),
              properties_.GetClassOfDevice(), properties_.GetClockOffset(),
              GetRssi(), properties_.GetExtendedInquiryData());
      SendLinkLayerPacket(std::move(inquiry_response));

    } break;
    default:
      LOG_WARN("Unhandled Incoming Inquiry of type %d",
               static_cast<int>(inquiry.GetType()));
      return;
  }
  // TODO: Send an Inquiry Response Notification Event 7.7.74
}

void LinkLayerController::IncomingInquiryResponsePacket(
    model::packets::LinkLayerPacketView incoming) {
  auto basic_inquiry_response =
      model::packets::BasicInquiryResponseView::Create(incoming);
  ASSERT(basic_inquiry_response.IsValid());
  std::vector<uint8_t> eir;

  switch (basic_inquiry_response.GetInquiryType()) {
    case (model::packets::InquiryType::STANDARD): {
      // TODO: Support multiple inquiries in the same packet.
      auto inquiry_response =
          model::packets::InquiryResponseView::Create(basic_inquiry_response);
      ASSERT(inquiry_response.IsValid());

      auto page_scan_repetition_mode =
          (bluetooth::hci::PageScanRepetitionMode)
              inquiry_response.GetPageScanRepetitionMode();

      std::vector<bluetooth::hci::InquiryResult> responses;
      responses.emplace_back();
      responses.back().bd_addr_ = inquiry_response.GetSourceAddress();
      responses.back().page_scan_repetition_mode_ = page_scan_repetition_mode;
      responses.back().class_of_device_ = inquiry_response.GetClassOfDevice();
      responses.back().clock_offset_ = inquiry_response.GetClockOffset();
      auto packet = bluetooth::hci::InquiryResultBuilder::Create(responses);
      send_event_(std::move(packet));
    } break;

    case (model::packets::InquiryType::RSSI): {
      auto inquiry_response =
          model::packets::InquiryResponseWithRssiView::Create(
              basic_inquiry_response);
      ASSERT(inquiry_response.IsValid());

      auto page_scan_repetition_mode =
          (bluetooth::hci::PageScanRepetitionMode)
              inquiry_response.GetPageScanRepetitionMode();

      std::vector<bluetooth::hci::InquiryResultWithRssi> responses;
      responses.emplace_back();
      responses.back().address_ = inquiry_response.GetSourceAddress();
      responses.back().page_scan_repetition_mode_ = page_scan_repetition_mode;
      responses.back().class_of_device_ = inquiry_response.GetClassOfDevice();
      responses.back().clock_offset_ = inquiry_response.GetClockOffset();
      responses.back().rssi_ = inquiry_response.GetRssi();
      auto packet =
          bluetooth::hci::InquiryResultWithRssiBuilder::Create(responses);
      send_event_(std::move(packet));
    } break;

    case (model::packets::InquiryType::EXTENDED): {
      auto inquiry_response =
          model::packets::ExtendedInquiryResponseView::Create(
              basic_inquiry_response);
      ASSERT(inquiry_response.IsValid());

      std::unique_ptr<bluetooth::packet::RawBuilder> raw_builder_ptr =
          std::make_unique<bluetooth::packet::RawBuilder>();
      raw_builder_ptr->AddOctets1(kNumCommandPackets);
      raw_builder_ptr->AddAddress(inquiry_response.GetSourceAddress());
      raw_builder_ptr->AddOctets1(inquiry_response.GetPageScanRepetitionMode());
      raw_builder_ptr->AddOctets1(0x00);  // _reserved_
      auto class_of_device = inquiry_response.GetClassOfDevice();
      for (unsigned int i = 0; i < class_of_device.kLength; i++) {
        raw_builder_ptr->AddOctets1(class_of_device.cod[i]);
      }
      raw_builder_ptr->AddOctets2(inquiry_response.GetClockOffset());
      raw_builder_ptr->AddOctets1(inquiry_response.GetRssi());
      raw_builder_ptr->AddOctets(inquiry_response.GetExtendedData());

      auto packet = bluetooth::hci::EventBuilder::Create(
          bluetooth::hci::EventCode::EXTENDED_INQUIRY_RESULT,
          std::move(raw_builder_ptr));
      send_event_(std::move(packet));
    } break;
    default:
      LOG_WARN("Unhandled Incoming Inquiry Response of type %d",
               static_cast<int>(basic_inquiry_response.GetInquiryType()));
  }
}

void LinkLayerController::IncomingIoCapabilityRequestPacket(
    model::packets::LinkLayerPacketView incoming) {
  Address peer = incoming.GetSourceAddress();
  uint16_t handle = connections_.GetHandle(AddressWithType(
      peer, bluetooth::hci::AddressType::PUBLIC_DEVICE_ADDRESS));
  if (handle == kReservedHandle) {
    LOG_INFO("Device not connected %s", peer.ToString().c_str());
    return;
  }

  if (!properties_.GetSecureSimplePairingSupported()) {
    LOG_WARN("Trying PIN pairing for %s",
             incoming.GetDestinationAddress().ToString().c_str());
    SendLinkLayerPacket(
        model::packets::IoCapabilityNegativeResponseBuilder::Create(
            incoming.GetDestinationAddress(), incoming.GetSourceAddress(),
            static_cast<uint8_t>(
                ErrorCode::UNSUPPORTED_REMOTE_OR_LMP_FEATURE)));
    security_manager_.AuthenticationRequest(incoming.GetSourceAddress(),
                                            handle);
    security_manager_.SetPinRequested(peer);
    send_event_(bluetooth::hci::PinCodeRequestBuilder::Create(
        incoming.GetSourceAddress()));
    return;
  }

  auto request = model::packets::IoCapabilityRequestView::Create(incoming);
  ASSERT(request.IsValid());

  uint8_t io_capability = request.GetIoCapability();
  uint8_t oob_data_present = request.GetOobDataPresent();
  uint8_t authentication_requirements = request.GetAuthenticationRequirements();

  auto packet = bluetooth::hci::IoCapabilityResponseBuilder::Create(
      peer, static_cast<bluetooth::hci::IoCapability>(io_capability),
      static_cast<bluetooth::hci::OobDataPresent>(oob_data_present),
      static_cast<bluetooth::hci::AuthenticationRequirements>(
          authentication_requirements));
  send_event_(std::move(packet));

  bool pairing_started = security_manager_.AuthenticationInProgress();
  if (!pairing_started) {
    security_manager_.AuthenticationRequest(peer, handle);
    StartSimplePairing(peer);
  }

  security_manager_.SetPeerIoCapability(peer, io_capability, oob_data_present,
                                        authentication_requirements);
  if (pairing_started) {
    PairingType pairing_type = security_manager_.GetSimplePairingType();
    if (pairing_type != PairingType::INVALID) {
      ScheduleTask(milliseconds(5), [this, peer, pairing_type]() {
        AuthenticateRemoteStage1(peer, pairing_type);
      });
    } else {
      LOG_INFO("Security Manager returned INVALID");
    }
  }
}

void LinkLayerController::IncomingIoCapabilityResponsePacket(
    model::packets::LinkLayerPacketView incoming) {
  auto response = model::packets::IoCapabilityResponseView::Create(incoming);
  ASSERT(response.IsValid());
  if (!properties_.GetSecureSimplePairingSupported()) {
    LOG_WARN("Only simple pairing mode is implemented");
    SendLinkLayerPacket(
        model::packets::IoCapabilityNegativeResponseBuilder::Create(
            incoming.GetDestinationAddress(), incoming.GetSourceAddress(),
            static_cast<uint8_t>(
                ErrorCode::UNSUPPORTED_REMOTE_OR_LMP_FEATURE)));
    return;
  }

  Address peer = incoming.GetSourceAddress();
  uint8_t io_capability = response.GetIoCapability();
  uint8_t oob_data_present = response.GetOobDataPresent();
  uint8_t authentication_requirements =
      response.GetAuthenticationRequirements();

  security_manager_.SetPeerIoCapability(peer, io_capability, oob_data_present,
                                        authentication_requirements);

  auto packet = bluetooth::hci::IoCapabilityResponseBuilder::Create(
      peer, static_cast<bluetooth::hci::IoCapability>(io_capability),
      static_cast<bluetooth::hci::OobDataPresent>(oob_data_present),
      static_cast<bluetooth::hci::AuthenticationRequirements>(
          authentication_requirements));
  send_event_(std::move(packet));

  PairingType pairing_type = security_manager_.GetSimplePairingType();
  if (pairing_type != PairingType::INVALID) {
    ScheduleTask(milliseconds(5), [this, peer, pairing_type]() {
      AuthenticateRemoteStage1(peer, pairing_type);
    });
  } else {
    LOG_INFO("Security Manager returned INVALID");
  }
}

void LinkLayerController::IncomingIoCapabilityNegativeResponsePacket(
    model::packets::LinkLayerPacketView incoming) {
  Address peer = incoming.GetSourceAddress();

  ASSERT(security_manager_.GetAuthenticationAddress() == peer);

  security_manager_.InvalidateIoCapabilities();
  LOG_INFO("%s doesn't support SSP, try PIN",
           incoming.GetSourceAddress().ToString().c_str());
  security_manager_.SetPinRequested(peer);
  send_event_(bluetooth::hci::PinCodeRequestBuilder::Create(
      incoming.GetSourceAddress()));
}

void LinkLayerController::IncomingIsoPacket(LinkLayerPacketView incoming) {
  auto iso = IsoDataPacketView::Create(incoming);
  ASSERT(iso.IsValid());

  uint16_t cis_handle = iso.GetHandle();
  if (!connections_.HasCisHandle(cis_handle)) {
    LOG_INFO("Dropping ISO packet to unknown handle 0x%hx", cis_handle);
    return;
  }
  if (!connections_.HasConnectedCis(cis_handle)) {
    LOG_INFO("Dropping ISO packet to a disconnected handle 0x%hx", cis_handle);
    return;
  }
  LOG_INFO("ISO packet scheduling is not implemented");
  // send_iso_(bluetooth::hci::IsoWithTimestampBuilder::Create())
}

void LinkLayerController::HandleIso(bluetooth::hci::IsoView iso) {
  auto cis_handle = iso.GetConnectionHandle();
  if (!connections_.HasCisHandle(cis_handle)) {
    LOG_INFO("Dropping ISO packet to unknown handle 0x%hx", cis_handle);
    return;
  }
  if (!connections_.HasConnectedCis(cis_handle)) {
    LOG_INFO("Dropping ISO packet to disconnected handle 0x%hx", cis_handle);
    return;
  }

  auto stream_parameters = connections_.GetStreamParameters(cis_handle);
  auto acl_handle = stream_parameters.handle;
  uint16_t remote_handle = kReservedHandle;  // TODO: Decide how to handle this
  model::packets::StartContinuation start_flag =
      model::packets::StartContinuation::START;
  model::packets::Complete complete_flag = model::packets::Complete::COMPLETE;
  switch (iso.GetPbFlag()) {
    case bluetooth::hci::IsoPacketBoundaryFlag::COMPLETE_SDU:
      start_flag = model::packets::StartContinuation::START;
      complete_flag = model::packets::Complete::COMPLETE;
      break;
    case bluetooth::hci::IsoPacketBoundaryFlag::CONTINUATION_FRAGMENT:
      start_flag = model::packets::StartContinuation::CONTINUATION;
      complete_flag = model::packets::Complete::INCOMPLETE;
      break;
    case bluetooth::hci::IsoPacketBoundaryFlag::FIRST_FRAGMENT:
      start_flag = model::packets::StartContinuation::START;
      complete_flag = model::packets::Complete::INCOMPLETE;
      break;
    case bluetooth::hci::IsoPacketBoundaryFlag::LAST_FRAGMENT:
      start_flag = model::packets::StartContinuation::CONTINUATION;
      complete_flag = model::packets::Complete::INCOMPLETE;
      break;
  }
  std::unique_ptr<bluetooth::packet::RawBuilder> payload =
      std::make_unique<bluetooth::packet::RawBuilder>();
  for (const auto& it : iso.GetPayload()) {
    payload->AddOctets1(it);
  }
  if (start_flag == model::packets::StartContinuation::START) {
    auto timestamped = bluetooth::hci::IsoWithTimestampView::Create(iso);
    ASSERT(timestamped.IsValid());
    uint32_t timestamp = timestamped.GetTimeStamp();
    SendLeLinkLayerPacket(model::packets::IsoStartBuilder::Create(
        connections_.GetOwnAddress(acl_handle).GetAddress(),
        connections_.GetAddress(acl_handle).GetAddress(), acl_handle,
        remote_handle, complete_flag, timestamp, std::move(payload)));

  } else {
    SendLeLinkLayerPacket(model::packets::IsoContinuationBuilder::Create(
        connections_.GetOwnAddress(acl_handle).GetAddress(),
        connections_.GetAddress(acl_handle).GetAddress(), acl_handle,
        remote_handle, complete_flag, std::move(payload)));
  }
}

void LinkLayerController::IncomingIsoConnectionRequestPacket(
    LinkLayerPacketView incoming) {
  auto req = IsoConnectionRequestView::Create(incoming);
  ASSERT(req.IsValid());
  std::vector<bluetooth::hci::CisParametersConfig> stream_configs;
  bluetooth::hci::CisParametersConfig stream_config;

  stream_config.max_sdu_m_to_s_ = req.GetMaxSduMToS();
  stream_config.max_sdu_s_to_m_ = req.GetMaxSduSToM();

  stream_configs.push_back(stream_config);

  uint8_t group_id = req.GetCigId();

  /* CIG should be created by the local host before use */
  bluetooth::hci::CreateCisConfig config;
  config.cis_connection_handle_ = req.GetRequesterCisHandle();
  if (!connections_.HasCisHandle(config.cis_connection_handle_)) {
    LOG_INFO("Rejecting connection request to unknown CIS handle 0x%0hx",
             config.cis_connection_handle_);
    SendLeLinkLayerPacket(model::packets::IsoConnectionResponseBuilder::Create(
        incoming.GetDestinationAddress(), incoming.GetSourceAddress(),
        static_cast<uint8_t>(ErrorCode::INVALID_LMP_OR_LL_PARAMETERS),
        config.acl_connection_handle_, config.cis_connection_handle_));
    return;
  }
  config.acl_connection_handle_ =
      connections_.GetHandleOnlyAddress(incoming.GetSourceAddress());
  connections_.CreatePendingCis(config);
  send_event_(bluetooth::hci::LeCisRequestBuilder::Create(
      config.acl_connection_handle_, config.cis_connection_handle_, group_id,
      req.GetId()));
}

void LinkLayerController::IncomingIsoConnectionResponsePacket(
    LinkLayerPacketView incoming) {
  auto response = IsoConnectionResponseView::Create(incoming);
  ASSERT(response.IsValid());

  bluetooth::hci::CreateCisConfig config;
  config.acl_connection_handle_ = response.GetRequesterAclHandle();
  config.cis_connection_handle_ = response.GetRequesterCisHandle();
  if (!connections_.HasPendingCisConnection(config.cis_connection_handle_)) {
    LOG_INFO("Ignoring connection response with unknown CIS handle 0x%04hx",
             config.cis_connection_handle_);
    return;
  }
  ErrorCode status = static_cast<ErrorCode>(response.GetStatus());
  if (status != ErrorCode::SUCCESS) {
    send_event_(bluetooth::hci::LeCisEstablishedBuilder::Create(
        status, config.cis_connection_handle_, 0, 0, 0, 0,
        bluetooth::hci::SecondaryPhyType::NO_PACKETS,
        bluetooth::hci::SecondaryPhyType::NO_PACKETS, 0, 0, 0, 0, 0, 0, 0, 0));
    return;
  }
  connections_.ConnectCis(config.cis_connection_handle_);
  auto stream_parameters =
      connections_.GetStreamParameters(config.cis_connection_handle_);
  auto group_parameters =
      connections_.GetGroupParameters(stream_parameters.group_id);
  // TODO: Which of these are important enough to fake?
  uint32_t cig_sync_delay = 0x100;
  uint32_t cis_sync_delay = 0x200;
  uint32_t latency_m_to_s = group_parameters.max_transport_latency_m_to_s;
  uint32_t latency_s_to_m = group_parameters.max_transport_latency_s_to_m;
  uint8_t nse = 1;
  uint8_t bn_m_to_s = 0;
  uint8_t bn_s_to_m = 0;
  uint8_t ft_m_to_s = 0;
  uint8_t ft_s_to_m = 0;
  uint8_t max_pdu_m_to_s = 0x40;
  uint8_t max_pdu_s_to_m = 0x40;
  uint16_t iso_interval = 0x100;
  send_event_(bluetooth::hci::LeCisEstablishedBuilder::Create(
      status, config.cis_connection_handle_, cig_sync_delay, cis_sync_delay,
      latency_m_to_s, latency_s_to_m,
      bluetooth::hci::SecondaryPhyType::NO_PACKETS,
      bluetooth::hci::SecondaryPhyType::NO_PACKETS, nse, bn_m_to_s, bn_s_to_m,
      ft_m_to_s, ft_s_to_m, max_pdu_m_to_s, max_pdu_s_to_m, iso_interval));
}

void LinkLayerController::IncomingKeypressNotificationPacket(
    model::packets::LinkLayerPacketView incoming) {
  auto keypress = model::packets::KeypressNotificationView::Create(incoming);
  ASSERT(keypress.IsValid());
  auto notification_type = keypress.GetNotificationType();
  if (notification_type >
      model::packets::PasskeyNotificationType::ENTRY_COMPLETED) {
    LOG_WARN("Dropping unknown notification type %d",
             static_cast<int>(notification_type));
    return;
  }
  send_event_(bluetooth::hci::KeypressNotificationBuilder::Create(
      incoming.GetSourceAddress(),
      static_cast<bluetooth::hci::KeypressNotificationType>(
          notification_type)));
}

void LinkLayerController::IncomingLeAdvertisementPacket(
    model::packets::LinkLayerPacketView incoming) {
  // TODO: Handle multiple advertisements per packet.

  Address address = incoming.GetSourceAddress();
  auto advertisement = model::packets::LeAdvertisementView::Create(incoming);
  ASSERT(advertisement.IsValid());
  auto address_type = advertisement.GetAddressType();
  auto adv_type = advertisement.GetAdvertisementType();

  if (le_scan_enable_ == bluetooth::hci::OpCode::LE_SET_SCAN_ENABLE) {
    vector<uint8_t> ad = advertisement.GetData();

    std::unique_ptr<bluetooth::packet::RawBuilder> raw_builder_ptr =
        std::make_unique<bluetooth::packet::RawBuilder>();
    raw_builder_ptr->AddOctets1(
        static_cast<uint8_t>(bluetooth::hci::SubeventCode::ADVERTISING_REPORT));
    raw_builder_ptr->AddOctets1(0x01);  // num reports
    raw_builder_ptr->AddOctets1(static_cast<uint8_t>(adv_type));
    raw_builder_ptr->AddOctets1(static_cast<uint8_t>(address_type));
    raw_builder_ptr->AddAddress(address);
    raw_builder_ptr->AddOctets1(ad.size());
    raw_builder_ptr->AddOctets(ad);
    raw_builder_ptr->AddOctets1(GetRssi());
    auto packet = bluetooth::hci::EventBuilder::Create(
        bluetooth::hci::EventCode::LE_META_EVENT, std::move(raw_builder_ptr));
    send_event_(std::move(packet));
  }

  if (le_scan_enable_ == bluetooth::hci::OpCode::LE_SET_EXTENDED_SCAN_ENABLE) {
    vector<uint8_t> ad = advertisement.GetData();

    std::unique_ptr<bluetooth::packet::RawBuilder> raw_builder_ptr =
        std::make_unique<bluetooth::packet::RawBuilder>();
    raw_builder_ptr->AddOctets1(static_cast<uint8_t>(
        bluetooth::hci::SubeventCode::EXTENDED_ADVERTISING_REPORT));
    raw_builder_ptr->AddOctets1(0x01);  // num reports
    switch (adv_type) {
      case model::packets::AdvertisementType::ADV_IND:
        raw_builder_ptr->AddOctets1(0x13);
        break;
      case model::packets::AdvertisementType::ADV_DIRECT_IND:
        raw_builder_ptr->AddOctets1(0x15);
        break;
      case model::packets::AdvertisementType::ADV_SCAN_IND:
        raw_builder_ptr->AddOctets1(0x12);
        break;
      case model::packets::AdvertisementType::ADV_NONCONN_IND:
        raw_builder_ptr->AddOctets1(0x10);
        break;
      case model::packets::AdvertisementType::SCAN_RESPONSE:
        raw_builder_ptr->AddOctets1(0x1b);  // 0x1a for ADV_SCAN_IND scan
        return;
    }
    raw_builder_ptr->AddOctets1(0x00);  // Reserved
    raw_builder_ptr->AddOctets1(static_cast<uint8_t>(address_type));
    raw_builder_ptr->AddAddress(address);
    raw_builder_ptr->AddOctets1(1);     // Primary_PHY
    raw_builder_ptr->AddOctets1(0);     // Secondary_PHY
    raw_builder_ptr->AddOctets1(0xFF);  // Advertising_SID - not provided
    raw_builder_ptr->AddOctets1(0x7F);  // Tx_Power - Not available
    raw_builder_ptr->AddOctets1(GetRssi());
    raw_builder_ptr->AddOctets2(0);  // Periodic_Advertising_Interval - None
    raw_builder_ptr->AddOctets1(0);  // Direct_Address_Type - PUBLIC
    raw_builder_ptr->AddAddress(Address::kEmpty);  // Direct_Address
    raw_builder_ptr->AddOctets1(ad.size());
    raw_builder_ptr->AddOctets(ad);
    send_event_(bluetooth::hci::EventBuilder::Create(
        bluetooth::hci::EventCode::LE_META_EVENT, std::move(raw_builder_ptr)));
  }

  // Active scanning
  if (le_scan_enable_ != bluetooth::hci::OpCode::NONE && le_scan_type_ == 1) {
    auto to_send = model::packets::LeScanBuilder::Create(
        properties_.GetLeAddress(), address);
    SendLeLinkLayerPacket(std::move(to_send));
  }

  // Connect
  if ((le_connect_ && le_peer_address_ == address &&
       le_peer_address_type_ == static_cast<uint8_t>(address_type) &&
       (adv_type == model::packets::AdvertisementType::ADV_IND ||
        adv_type == model::packets::AdvertisementType::ADV_DIRECT_IND)) ||
      (LeConnectListContainsDevice(address,
                                   static_cast<uint8_t>(address_type)))) {
    if (!connections_.CreatePendingLeConnection(AddressWithType(
            address, static_cast<bluetooth::hci::AddressType>(address_type)))) {
      LOG_WARN(
          "CreatePendingLeConnection failed for connection to %s (type %hhx)",
          incoming.GetSourceAddress().ToString().c_str(), address_type);
    }
    Address own_address;
    auto own_address_type =
        static_cast<bluetooth::hci::OwnAddressType>(le_address_type_);
    switch (own_address_type) {
      case bluetooth::hci::OwnAddressType::PUBLIC_DEVICE_ADDRESS:
        own_address = properties_.GetAddress();
        break;
      case bluetooth::hci::OwnAddressType::RANDOM_DEVICE_ADDRESS:
        own_address = properties_.GetLeAddress();
        break;
      default:
        LOG_ALWAYS_FATAL(
            "Unhandled connection address type %s",
            bluetooth::hci::OwnAddressTypeText(own_address_type).c_str());
    }
    LOG_INFO("Connecting to %s (type %hhx) own_address %s (type %hhx)",
             incoming.GetSourceAddress().ToString().c_str(), address_type,
             own_address.ToString().c_str(), le_address_type_);
    le_connect_ = false;
    le_scan_enable_ = bluetooth::hci::OpCode::NONE;

    auto to_send = model::packets::LeConnectBuilder::Create(
        own_address, incoming.GetSourceAddress(), le_connection_interval_min_,
        le_connection_interval_max_, le_connection_latency_,
        le_connection_supervision_timeout_,
        static_cast<uint8_t>(le_address_type_));

    SendLeLinkLayerPacket(std::move(to_send));
  }
}

void LinkLayerController::HandleLeConnection(AddressWithType address,
                                             AddressWithType own_address,
                                             uint8_t role,
                                             uint16_t connection_interval,
                                             uint16_t connection_latency,
                                             uint16_t supervision_timeout) {
  // TODO: Choose between LeConnectionComplete and LeEnhancedConnectionComplete
  uint16_t handle = connections_.CreateLeConnection(address, own_address);
  if (handle == kReservedHandle) {
    LOG_WARN("No pending connection for connection from %s",
             address.ToString().c_str());
    return;
  }
  auto packet = bluetooth::hci::LeConnectionCompleteBuilder::Create(
      ErrorCode::SUCCESS, handle, static_cast<bluetooth::hci::Role>(role),
      address.GetAddressType(), address.GetAddress(), connection_interval,
      connection_latency, supervision_timeout,
      static_cast<bluetooth::hci::ClockAccuracy>(0x00));
  send_event_(std::move(packet));
}

void LinkLayerController::IncomingLeConnectPacket(
    model::packets::LinkLayerPacketView incoming) {
  auto connect = model::packets::LeConnectView::Create(incoming);
  ASSERT(connect.IsValid());
  uint16_t connection_interval = (connect.GetLeConnectionIntervalMax() +
                                  connect.GetLeConnectionIntervalMin()) /
                                 2;
  if (!connections_.CreatePendingLeConnection(AddressWithType(
          incoming.GetSourceAddress(), static_cast<bluetooth::hci::AddressType>(
                                           connect.GetAddressType())))) {
    LOG_WARN(
        "CreatePendingLeConnection failed for connection from %s (type "
        "%hhx)",
        incoming.GetSourceAddress().ToString().c_str(),
        connect.GetAddressType());
    return;
  }
  bluetooth::hci::AddressWithType my_address{};
  bool matched_advertiser = false;
  for (auto advertiser : advertisers_) {
    AddressWithType advertiser_address = advertiser.GetAddress();
    if (incoming.GetDestinationAddress() == advertiser_address.GetAddress()) {
      my_address = advertiser_address;
      matched_advertiser = true;
    }
  }

  if (!matched_advertiser) {
    LOG_INFO("Dropping unmatched connection request to %s",
             incoming.GetSourceAddress().ToString().c_str());
    return;
  }

  HandleLeConnection(
      AddressWithType(
          incoming.GetSourceAddress(),
          static_cast<bluetooth::hci::AddressType>(connect.GetAddressType())),
      my_address, static_cast<uint8_t>(bluetooth::hci::Role::PERIPHERAL),
      connection_interval, connect.GetLeConnectionLatency(),
      connect.GetLeConnectionSupervisionTimeout());

  auto to_send = model::packets::LeConnectCompleteBuilder::Create(
      incoming.GetDestinationAddress(), incoming.GetSourceAddress(),
      connection_interval, connect.GetLeConnectionLatency(),
      connect.GetLeConnectionSupervisionTimeout(),
      static_cast<uint8_t>(my_address.GetAddressType()));
  SendLeLinkLayerPacket(std::move(to_send));
}

void LinkLayerController::IncomingLeConnectCompletePacket(
    model::packets::LinkLayerPacketView incoming) {
  auto complete = model::packets::LeConnectCompleteView::Create(incoming);
  ASSERT(complete.IsValid());
  HandleLeConnection(
      AddressWithType(
          incoming.GetSourceAddress(),
          static_cast<bluetooth::hci::AddressType>(complete.GetAddressType())),
      AddressWithType(
          incoming.GetDestinationAddress(),
          static_cast<bluetooth::hci::AddressType>(le_address_type_)),
      static_cast<uint8_t>(bluetooth::hci::Role::CENTRAL),
      complete.GetLeConnectionInterval(), complete.GetLeConnectionLatency(),
      complete.GetLeConnectionSupervisionTimeout());
}

void LinkLayerController::IncomingLeEncryptConnection(
    model::packets::LinkLayerPacketView incoming) {
  LOG_INFO();

  Address peer = incoming.GetSourceAddress();
  uint16_t handle = connections_.GetHandleOnlyAddress(peer);
  if (handle == kReservedHandle) {
    LOG_INFO("@%s: Unknown connection @%s",
             incoming.GetDestinationAddress().ToString().c_str(),
             peer.ToString().c_str());
    return;
  }
  auto le_encrypt = model::packets::LeEncryptConnectionView::Create(incoming);
  ASSERT(le_encrypt.IsValid());

  // TODO: Save keys to check

  send_event_(bluetooth::hci::LeLongTermKeyRequestBuilder::Create(
      handle, le_encrypt.GetRand(), le_encrypt.GetEdiv()));
}

void LinkLayerController::IncomingLeEncryptConnectionResponse(
    model::packets::LinkLayerPacketView incoming) {
  LOG_INFO();
  // TODO: Check keys
  uint16_t handle =
      connections_.GetHandleOnlyAddress(incoming.GetSourceAddress());
  if (handle == kReservedHandle) {
    LOG_INFO("@%s: Unknown connection @%s",
             incoming.GetDestinationAddress().ToString().c_str(),
             incoming.GetSourceAddress().ToString().c_str());
    return;
  }
  ErrorCode status = ErrorCode::SUCCESS;
  auto response =
      model::packets::LeEncryptConnectionResponseView::Create(incoming);
  ASSERT(response.IsValid());

  // Zero LTK is a rejection
  if (response.GetLtk() == std::array<uint8_t, 16>()) {
    status = ErrorCode::AUTHENTICATION_FAILURE;
  }

  if (connections_.IsEncrypted(handle)) {
    send_event_(bluetooth::hci::EncryptionKeyRefreshCompleteBuilder::Create(
        status, handle));
  } else {
    connections_.Encrypt(handle);
    send_event_(bluetooth::hci::EncryptionChangeBuilder::Create(
        status, handle, bluetooth::hci::EncryptionEnabled::ON));
  }
}

void LinkLayerController::IncomingLeScanPacket(
    model::packets::LinkLayerPacketView incoming) {
  for (auto& advertiser : advertisers_) {
    auto to_send = advertiser.GetScanResponse(incoming.GetDestinationAddress(),
                                              incoming.GetSourceAddress());
    if (to_send != nullptr) {
      SendLeLinkLayerPacket(std::move(to_send));
    }
  }
}

void LinkLayerController::IncomingLeScanResponsePacket(
    model::packets::LinkLayerPacketView incoming) {
  auto scan_response = model::packets::LeScanResponseView::Create(incoming);
  ASSERT(scan_response.IsValid());
  vector<uint8_t> ad = scan_response.GetData();
  auto adv_type = scan_response.GetAdvertisementType();
  auto address_type =
      static_cast<LeAdvertisement::AddressType>(scan_response.GetAddressType());
  if (le_scan_enable_ == bluetooth::hci::OpCode::LE_SET_SCAN_ENABLE) {
    if (adv_type != model::packets::AdvertisementType::SCAN_RESPONSE) {
      return;
    }
    std::unique_ptr<bluetooth::packet::RawBuilder> raw_builder_ptr =
        std::make_unique<bluetooth::packet::RawBuilder>();
    raw_builder_ptr->AddOctets1(
        static_cast<uint8_t>(bluetooth::hci::SubeventCode::ADVERTISING_REPORT));
    raw_builder_ptr->AddOctets1(0x01);  // num reports
    raw_builder_ptr->AddOctets1(static_cast<uint8_t>(
        bluetooth::hci::AdvertisingEventType::SCAN_RESPONSE));
    raw_builder_ptr->AddOctets1(static_cast<uint8_t>(address_type));
    raw_builder_ptr->AddAddress(incoming.GetSourceAddress());
    raw_builder_ptr->AddOctets1(ad.size());
    raw_builder_ptr->AddOctets(ad);
    raw_builder_ptr->AddOctets1(GetRssi());
    auto packet = bluetooth::hci::EventBuilder::Create(
        bluetooth::hci::EventCode::LE_META_EVENT, std::move(raw_builder_ptr));
    send_event_(std::move(packet));
  }

  if (le_scan_enable_ == bluetooth::hci::OpCode::LE_SET_EXTENDED_SCAN_ENABLE) {
    std::unique_ptr<bluetooth::packet::RawBuilder> raw_builder_ptr =
        std::make_unique<bluetooth::packet::RawBuilder>();
    raw_builder_ptr->AddOctets1(static_cast<uint8_t>(
        bluetooth::hci::SubeventCode::EXTENDED_ADVERTISING_REPORT));
    raw_builder_ptr->AddOctets1(0x01);  // num reports
    raw_builder_ptr->AddOctets1(0x1a);  // TODO: 0x1b for ADV_SCAN_IND
    raw_builder_ptr->AddOctets1(static_cast<uint8_t>(address_type));
    raw_builder_ptr->AddAddress(incoming.GetSourceAddress());
    raw_builder_ptr->AddOctets1(1);     // Primary_PHY
    raw_builder_ptr->AddOctets1(0);     // Secondary_PHY
    raw_builder_ptr->AddOctets1(0xFF);  // Advertising_SID - not provided
    raw_builder_ptr->AddOctets1(0x7F);  // Tx_Power - Not available
    raw_builder_ptr->AddOctets1(GetRssi());
    raw_builder_ptr->AddOctets1(0);  // Periodic_Advertising_Interval - None
    raw_builder_ptr->AddOctets1(0);  // Direct_Address_Type - PUBLIC
    raw_builder_ptr->AddAddress(Address::kEmpty);  // Direct_Address
    raw_builder_ptr->AddOctets1(ad.size());
    raw_builder_ptr->AddOctets(ad);
    auto packet = bluetooth::hci::EventBuilder::Create(
        bluetooth::hci::EventCode::LE_META_EVENT, std::move(raw_builder_ptr));
    send_event_(std::move(packet));
  }
}

void LinkLayerController::IncomingPasskeyPacket(
    model::packets::LinkLayerPacketView incoming) {
  auto passkey = model::packets::PasskeyView::Create(incoming);
  ASSERT(passkey.IsValid());
  SaveKeyAndAuthenticate('P', incoming.GetSourceAddress());
}

void LinkLayerController::IncomingPasskeyFailedPacket(
    model::packets::LinkLayerPacketView incoming) {
  auto failed = model::packets::PasskeyFailedView::Create(incoming);
  ASSERT(failed.IsValid());
  auto current_peer = incoming.GetSourceAddress();
  security_manager_.AuthenticationRequestFinished();
  ScheduleTask(milliseconds(5), [this, current_peer]() {
    send_event_(bluetooth::hci::SimplePairingCompleteBuilder::Create(
        ErrorCode::AUTHENTICATION_FAILURE, current_peer));
  });
}

void LinkLayerController::IncomingPinRequestPacket(
    model::packets::LinkLayerPacketView incoming) {
  auto request = model::packets::PinRequestView::Create(incoming);
  ASSERT(request.IsValid());
  auto peer = incoming.GetSourceAddress();
  auto handle = connections_.GetHandle(AddressWithType(
      peer, bluetooth::hci::AddressType::PUBLIC_DEVICE_ADDRESS));
  if (handle == kReservedHandle) {
    LOG_INFO("Dropping %s request (no connection)", peer.ToString().c_str());
    auto wrong_pin = request.GetPinCode();
    wrong_pin[0] = wrong_pin[0]++;
    SendLinkLayerPacket(model::packets::PinResponseBuilder::Create(
        properties_.GetAddress(), peer, wrong_pin));
    return;
  }
  if (security_manager_.AuthenticationInProgress()) {
    auto current_peer = security_manager_.GetAuthenticationAddress();
    if (current_peer != peer) {
      LOG_INFO("Dropping %s request (%s in progress)", peer.ToString().c_str(),
               current_peer.ToString().c_str());
      auto wrong_pin = request.GetPinCode();
      wrong_pin[0] = wrong_pin[0]++;
      SendLinkLayerPacket(model::packets::PinResponseBuilder::Create(
          properties_.GetAddress(), peer, wrong_pin));
      return;
    }
  } else {
    LOG_INFO("Incoming authentication request %s", peer.ToString().c_str());
    security_manager_.AuthenticationRequest(peer, handle);
  }
  auto current_peer = security_manager_.GetAuthenticationAddress();
  security_manager_.SetRemotePin(peer, request.GetPinCode());
  if (security_manager_.GetPinRequested(peer)) {
    if (security_manager_.GetLocalPinResponseReceived(peer)) {
      SendLinkLayerPacket(model::packets::PinResponseBuilder::Create(
          properties_.GetAddress(), peer, request.GetPinCode()));
      if (security_manager_.PinCompare()) {
        LOG_INFO("Authenticating %s", peer.ToString().c_str());
        SaveKeyAndAuthenticate('L', peer);  // Legacy
      } else {
        security_manager_.AuthenticationRequestFinished();
        ScheduleTask(milliseconds(5), [this, peer]() {
          send_event_(bluetooth::hci::SimplePairingCompleteBuilder::Create(
              ErrorCode::AUTHENTICATION_FAILURE, peer));
        });
      }
    }
  } else {
    LOG_INFO("PIN pairing %s", properties_.GetAddress().ToString().c_str());
    ScheduleTask(milliseconds(5), [this, peer]() {
      security_manager_.SetPinRequested(peer);
      send_event_(bluetooth::hci::PinCodeRequestBuilder::Create(peer));
    });
  }
}

void LinkLayerController::IncomingPinResponsePacket(
    model::packets::LinkLayerPacketView incoming) {
  auto request = model::packets::PinResponseView::Create(incoming);
  ASSERT(request.IsValid());
  auto peer = incoming.GetSourceAddress();
  auto handle = connections_.GetHandle(AddressWithType(
      peer, bluetooth::hci::AddressType::PUBLIC_DEVICE_ADDRESS));
  if (handle == kReservedHandle) {
    LOG_INFO("Dropping %s request (no connection)", peer.ToString().c_str());
    return;
  }
  if (security_manager_.AuthenticationInProgress()) {
    auto current_peer = security_manager_.GetAuthenticationAddress();
    if (current_peer != peer) {
      LOG_INFO("Dropping %s request (%s in progress)", peer.ToString().c_str(),
               current_peer.ToString().c_str());
      return;
    }
  } else {
    LOG_INFO("Dropping response without authentication request %s",
             peer.ToString().c_str());
    return;
  }
  auto current_peer = security_manager_.GetAuthenticationAddress();
  security_manager_.SetRemotePin(peer, request.GetPinCode());
  if (security_manager_.GetPinRequested(peer)) {
    if (security_manager_.GetLocalPinResponseReceived(peer)) {
      SendLinkLayerPacket(model::packets::PinResponseBuilder::Create(
          properties_.GetAddress(), peer, request.GetPinCode()));
      if (security_manager_.PinCompare()) {
        LOG_INFO("Authenticating %s", peer.ToString().c_str());
        SaveKeyAndAuthenticate('L', peer);  // Legacy
      } else {
        security_manager_.AuthenticationRequestFinished();
        ScheduleTask(milliseconds(5), [this, peer]() {
          send_event_(bluetooth::hci::SimplePairingCompleteBuilder::Create(
              ErrorCode::AUTHENTICATION_FAILURE, peer));
        });
      }
    }
  } else {
    LOG_INFO("PIN pairing %s", properties_.GetAddress().ToString().c_str());
    ScheduleTask(milliseconds(5), [this, peer]() {
      security_manager_.SetPinRequested(peer);
      send_event_(bluetooth::hci::PinCodeRequestBuilder::Create(peer));
    });
  }
}

void LinkLayerController::IncomingPagePacket(
    model::packets::LinkLayerPacketView incoming) {
  auto page = model::packets::PageView::Create(incoming);
  ASSERT(page.IsValid());
  LOG_INFO("from %s", incoming.GetSourceAddress().ToString().c_str());

  if (!connections_.CreatePendingConnection(
          incoming.GetSourceAddress(), properties_.GetAuthenticationEnable())) {
    // Send a response to indicate that we're busy, or drop the packet?
    LOG_WARN("Failed to create a pending connection for %s",
             incoming.GetSourceAddress().ToString().c_str());
  }

  bluetooth::hci::Address source_address{};
  bluetooth::hci::Address::FromString(page.GetSourceAddress().ToString(),
                                      source_address);

  auto packet = bluetooth::hci::ConnectionRequestBuilder::Create(
      source_address, page.GetClassOfDevice(),
      bluetooth::hci::ConnectionRequestLinkType::ACL);

  send_event_(std::move(packet));
}

void LinkLayerController::IncomingPageRejectPacket(
    model::packets::LinkLayerPacketView incoming) {
  LOG_INFO("%s", incoming.GetSourceAddress().ToString().c_str());
  auto reject = model::packets::PageRejectView::Create(incoming);
  ASSERT(reject.IsValid());
  LOG_INFO("Sending CreateConnectionComplete");
  auto packet = bluetooth::hci::ConnectionCompleteBuilder::Create(
      static_cast<ErrorCode>(reject.GetReason()), 0x0eff,
      incoming.GetSourceAddress(), bluetooth::hci::LinkType::ACL,
      bluetooth::hci::Enable::DISABLED);
  send_event_(std::move(packet));
}

void LinkLayerController::IncomingPageResponsePacket(
    model::packets::LinkLayerPacketView incoming) {
  Address peer = incoming.GetSourceAddress();
  LOG_INFO("%s", peer.ToString().c_str());
  bool awaiting_authentication = connections_.AuthenticatePendingConnection();
  uint16_t handle =
      connections_.CreateConnection(peer, incoming.GetDestinationAddress());
  if (handle == kReservedHandle) {
    LOG_WARN("No free handles");
    return;
  }
  auto packet = bluetooth::hci::ConnectionCompleteBuilder::Create(
      ErrorCode::SUCCESS, handle, incoming.GetSourceAddress(),
      bluetooth::hci::LinkType::ACL, bluetooth::hci::Enable::DISABLED);
  send_event_(std::move(packet));

  if (awaiting_authentication) {
    ScheduleTask(milliseconds(5), [this, peer, handle]() {
      HandleAuthenticationRequest(peer, handle);
    });
  }
}

void LinkLayerController::TimerTick() {
  if (inquiry_timer_task_id_ != kInvalidTaskId) Inquiry();
  LeAdvertising();
}

void LinkLayerController::LeAdvertising() {
  steady_clock::time_point now = steady_clock::now();
  for (auto& advertiser : advertisers_) {
    auto ad = advertiser.GetAdvertisement(now);
    if (ad == nullptr) {
      continue;
    }
    SendLeLinkLayerPacket(std::move(ad));
  }
}

void LinkLayerController::RegisterEventChannel(
    const std::function<void(std::shared_ptr<bluetooth::hci::EventBuilder>)>&
        callback) {
  send_event_ = callback;
}

void LinkLayerController::RegisterAclChannel(
    const std::function<void(std::shared_ptr<bluetooth::hci::AclBuilder>)>&
        callback) {
  send_acl_ = callback;
}

void LinkLayerController::RegisterScoChannel(
    const std::function<void(std::shared_ptr<std::vector<uint8_t>>)>&
        callback) {
  send_sco_ = callback;
}

void LinkLayerController::RegisterIsoChannel(
    const std::function<void(std::shared_ptr<std::vector<uint8_t>>)>&
        callback) {
  send_iso_ = callback;
}

void LinkLayerController::RegisterRemoteChannel(
    const std::function<void(
        std::shared_ptr<model::packets::LinkLayerPacketBuilder>, Phy::Type)>&
        callback) {
  send_to_remote_ = callback;
}

void LinkLayerController::RegisterTaskScheduler(
    std::function<AsyncTaskId(milliseconds, const TaskCallback&)>
        event_scheduler) {
  schedule_task_ = event_scheduler;
}

AsyncTaskId LinkLayerController::ScheduleTask(milliseconds delay_ms,
                                              const TaskCallback& callback) {
  if (schedule_task_) {
    return schedule_task_(delay_ms, callback);
  } else {
    callback();
    return 0;
  }
}

void LinkLayerController::RegisterPeriodicTaskScheduler(
    std::function<AsyncTaskId(milliseconds, milliseconds, const TaskCallback&)>
        periodic_event_scheduler) {
  schedule_periodic_task_ = periodic_event_scheduler;
}

void LinkLayerController::CancelScheduledTask(AsyncTaskId task_id) {
  if (schedule_task_ && cancel_task_) {
    cancel_task_(task_id);
  }
}

void LinkLayerController::RegisterTaskCancel(
    std::function<void(AsyncTaskId)> task_cancel) {
  cancel_task_ = task_cancel;
}

void LinkLayerController::StartSimplePairing(const Address& address) {
  // IO Capability Exchange (See the Diagram in the Spec)
  auto packet = bluetooth::hci::IoCapabilityRequestBuilder::Create(address);
  send_event_(std::move(packet));

  // Get a Key, then authenticate
  // PublicKeyExchange(address);
  // AuthenticateRemoteStage1(address);
  // AuthenticateRemoteStage2(address);
}

void LinkLayerController::AuthenticateRemoteStage1(const Address& peer,
                                                   PairingType pairing_type) {
  ASSERT(security_manager_.GetAuthenticationAddress() == peer);
  // TODO: Public key exchange first?
  switch (pairing_type) {
    case PairingType::AUTO_CONFIRMATION:
      send_event_(
          bluetooth::hci::UserConfirmationRequestBuilder::Create(peer, 123456));
      break;
    case PairingType::CONFIRM_Y_N:
      send_event_(
          bluetooth::hci::UserConfirmationRequestBuilder::Create(peer, 123456));
      break;
    case PairingType::DISPLAY_PIN:
      send_event_(
          bluetooth::hci::UserPasskeyNotificationBuilder::Create(peer, 123456));
      break;
    case PairingType::DISPLAY_AND_CONFIRM:
      send_event_(
          bluetooth::hci::UserConfirmationRequestBuilder::Create(peer, 123456));
      break;
    case PairingType::INPUT_PIN:
      send_event_(bluetooth::hci::UserPasskeyRequestBuilder::Create(peer));
      break;
    case PairingType::OUT_OF_BAND:
      LOG_INFO("Oob data request for %s", peer.ToString().c_str());
      send_event_(bluetooth::hci::RemoteOobDataRequestBuilder::Create(peer));
      break;
    case PairingType::PEER_HAS_OUT_OF_BAND:
      LOG_INFO("Trusting that %s has OOB data", peer.ToString().c_str());
      SaveKeyAndAuthenticate('P', peer);
      break;
    default:
      LOG_ALWAYS_FATAL("Invalid PairingType %d",
                       static_cast<int>(pairing_type));
  }
}

void LinkLayerController::AuthenticateRemoteStage2(const Address& peer) {
  uint16_t handle = security_manager_.GetAuthenticationHandle();
  ASSERT(security_manager_.GetAuthenticationAddress() == peer);
  // Check key in security_manager_ ?
  auto packet = bluetooth::hci::AuthenticationCompleteBuilder::Create(
      ErrorCode::SUCCESS, handle);
  send_event_(std::move(packet));
}

ErrorCode LinkLayerController::LinkKeyRequestReply(
    const Address& peer, const std::array<uint8_t, 16>& key) {
  security_manager_.WriteKey(peer, key);
  security_manager_.AuthenticationRequestFinished();

  ScheduleTask(milliseconds(5),
               [this, peer]() { AuthenticateRemoteStage2(peer); });

  return ErrorCode::SUCCESS;
}

ErrorCode LinkLayerController::LinkKeyRequestNegativeReply(
    const Address& address) {
  security_manager_.DeleteKey(address);
  // Simple pairing to get a key
  uint16_t handle = connections_.GetHandleOnlyAddress(address);
  if (handle == kReservedHandle) {
    LOG_INFO("Device not connected %s", address.ToString().c_str());
    return ErrorCode::UNKNOWN_CONNECTION;
  }

  if (properties_.GetSecureSimplePairingSupported()) {
    security_manager_.AuthenticationRequest(address, handle);

    ScheduleTask(milliseconds(5),
                 [this, address]() { StartSimplePairing(address); });
  } else {
    LOG_INFO("PIN pairing %s", properties_.GetAddress().ToString().c_str());
    ScheduleTask(milliseconds(5), [this, address]() {
      security_manager_.SetPinRequested(address);
      send_event_(bluetooth::hci::PinCodeRequestBuilder::Create(address));
    });
  }
  return ErrorCode::SUCCESS;
}

ErrorCode LinkLayerController::IoCapabilityRequestReply(
    const Address& peer, uint8_t io_capability, uint8_t oob_data_present_flag,
    uint8_t authentication_requirements) {
  security_manager_.SetLocalIoCapability(
      peer, io_capability, oob_data_present_flag, authentication_requirements);

  PairingType pairing_type = security_manager_.GetSimplePairingType();

  if (pairing_type != PairingType::INVALID) {
    ScheduleTask(milliseconds(5), [this, peer, pairing_type]() {
      AuthenticateRemoteStage1(peer, pairing_type);
    });
    SendLinkLayerPacket(model::packets::IoCapabilityResponseBuilder::Create(
        properties_.GetAddress(), peer, io_capability, oob_data_present_flag,
        authentication_requirements));
  } else {
    LOG_INFO("Requesting remote capability");

    SendLinkLayerPacket(model::packets::IoCapabilityRequestBuilder::Create(
        properties_.GetAddress(), peer, io_capability, oob_data_present_flag,
        authentication_requirements));
  }

  return ErrorCode::SUCCESS;
}

ErrorCode LinkLayerController::IoCapabilityRequestNegativeReply(
    const Address& peer, ErrorCode reason) {
  if (security_manager_.GetAuthenticationAddress() != peer) {
    return ErrorCode::AUTHENTICATION_FAILURE;
  }

  security_manager_.InvalidateIoCapabilities();

  auto packet = model::packets::IoCapabilityNegativeResponseBuilder::Create(
      properties_.GetAddress(), peer, static_cast<uint8_t>(reason));
  SendLinkLayerPacket(std::move(packet));

  return ErrorCode::SUCCESS;
}

void LinkLayerController::SaveKeyAndAuthenticate(uint8_t key_type,
                                                 const Address& peer) {
  std::array<uint8_t, 16> key_vec{'k',
                                  'e',
                                  'y',
                                  ' ',
                                  key_type,
                                  5,
                                  6,
                                  7,
                                  8,
                                  9,
                                  10,
                                  11,
                                  12,
                                  13,
                                  static_cast<uint8_t>(key_id_ >> 8u),
                                  static_cast<uint8_t>(key_id_)};
  key_id_ += 1;
  security_manager_.WriteKey(peer, key_vec);

  security_manager_.AuthenticationRequestFinished();

  if (key_type == 'L') {
    // Legacy
    ScheduleTask(milliseconds(5), [this, peer, key_vec]() {
      send_event_(bluetooth::hci::LinkKeyNotificationBuilder::Create(
          peer, key_vec, bluetooth::hci::KeyType::AUTHENTICATED_P192));
    });
  } else {
    ScheduleTask(milliseconds(5), [this, peer]() {
      send_event_(bluetooth::hci::SimplePairingCompleteBuilder::Create(
          ErrorCode::SUCCESS, peer));
    });

    ScheduleTask(milliseconds(5), [this, peer, key_vec]() {
      send_event_(bluetooth::hci::LinkKeyNotificationBuilder::Create(
          peer, key_vec, bluetooth::hci::KeyType::AUTHENTICATED_P256));
    });
  }

  ScheduleTask(milliseconds(15),
               [this, peer]() { AuthenticateRemoteStage2(peer); });
}

ErrorCode LinkLayerController::PinCodeRequestReply(const Address& peer,
                                                   std::vector<uint8_t> pin) {
  LOG_INFO("%s", properties_.GetAddress().ToString().c_str());
  auto current_peer = security_manager_.GetAuthenticationAddress();
  if (peer != current_peer) {
    LOG_INFO("%s: %s != %s", properties_.GetAddress().ToString().c_str(),
             peer.ToString().c_str(), current_peer.ToString().c_str());
    security_manager_.AuthenticationRequestFinished();
    ScheduleTask(milliseconds(5), [this, current_peer]() {
      send_event_(bluetooth::hci::SimplePairingCompleteBuilder::Create(
          ErrorCode::AUTHENTICATION_FAILURE, current_peer));
    });
    return ErrorCode::UNKNOWN_CONNECTION;
  }
  if (!security_manager_.GetPinRequested(peer)) {
    LOG_INFO("No Pin Requested for %s", peer.ToString().c_str());
    return ErrorCode::COMMAND_DISALLOWED;
  }
  security_manager_.SetLocalPin(peer, pin);
  if (security_manager_.GetRemotePinResponseReceived(peer)) {
    if (security_manager_.PinCompare()) {
      LOG_INFO("Authenticating %s", peer.ToString().c_str());
      SaveKeyAndAuthenticate('L', peer);  // Legacy
    } else {
      security_manager_.AuthenticationRequestFinished();
      ScheduleTask(milliseconds(5), [this, peer]() {
        send_event_(bluetooth::hci::SimplePairingCompleteBuilder::Create(
            ErrorCode::AUTHENTICATION_FAILURE, peer));
      });
    }
  } else {
    SendLinkLayerPacket(model::packets::PinRequestBuilder::Create(
        properties_.GetAddress(), peer, pin));
  }
  return ErrorCode::SUCCESS;
}

ErrorCode LinkLayerController::PinCodeRequestNegativeReply(
    const Address& peer) {
  auto current_peer = security_manager_.GetAuthenticationAddress();
  security_manager_.AuthenticationRequestFinished();
  ScheduleTask(milliseconds(5), [this, current_peer]() {
    send_event_(bluetooth::hci::SimplePairingCompleteBuilder::Create(
        ErrorCode::AUTHENTICATION_FAILURE, current_peer));
  });
  if (peer != current_peer) {
    return ErrorCode::UNKNOWN_CONNECTION;
  }
  if (!security_manager_.GetPinRequested(peer)) {
    LOG_INFO("No Pin Requested for %s", peer.ToString().c_str());
    return ErrorCode::COMMAND_DISALLOWED;
  }
  return ErrorCode::SUCCESS;
}

ErrorCode LinkLayerController::UserConfirmationRequestReply(
    const Address& peer) {
  if (security_manager_.GetAuthenticationAddress() != peer) {
    return ErrorCode::AUTHENTICATION_FAILURE;
  }
  SaveKeyAndAuthenticate('U', peer);
  return ErrorCode::SUCCESS;
}

ErrorCode LinkLayerController::UserConfirmationRequestNegativeReply(
    const Address& peer) {
  auto current_peer = security_manager_.GetAuthenticationAddress();
  security_manager_.AuthenticationRequestFinished();
  ScheduleTask(milliseconds(5), [this, current_peer]() {
    send_event_(bluetooth::hci::SimplePairingCompleteBuilder::Create(
        ErrorCode::AUTHENTICATION_FAILURE, current_peer));
  });
  if (peer != current_peer) {
    return ErrorCode::UNKNOWN_CONNECTION;
  }
  return ErrorCode::SUCCESS;
}

ErrorCode LinkLayerController::UserPasskeyRequestReply(const Address& peer,
                                                       uint32_t numeric_value) {
  if (security_manager_.GetAuthenticationAddress() != peer) {
    return ErrorCode::AUTHENTICATION_FAILURE;
  }
  SendLinkLayerPacket(model::packets::PasskeyBuilder::Create(
      properties_.GetAddress(), peer, numeric_value));
  SaveKeyAndAuthenticate('P', peer);

  return ErrorCode::SUCCESS;
}

ErrorCode LinkLayerController::UserPasskeyRequestNegativeReply(
    const Address& peer) {
  auto current_peer = security_manager_.GetAuthenticationAddress();
  security_manager_.AuthenticationRequestFinished();
  ScheduleTask(milliseconds(5), [this, current_peer]() {
    send_event_(bluetooth::hci::SimplePairingCompleteBuilder::Create(
        ErrorCode::AUTHENTICATION_FAILURE, current_peer));
  });
  if (peer != current_peer) {
    return ErrorCode::UNKNOWN_CONNECTION;
  }
  return ErrorCode::SUCCESS;
}

ErrorCode LinkLayerController::RemoteOobDataRequestReply(
    const Address& peer, const std::array<uint8_t, 16>& c,
    const std::array<uint8_t, 16>& r) {
  if (security_manager_.GetAuthenticationAddress() != peer) {
    return ErrorCode::AUTHENTICATION_FAILURE;
  }
  LOG_INFO("TODO:Do something with the OOB data c=%d r=%d", c[0], r[0]);
  SaveKeyAndAuthenticate('o', peer);

  return ErrorCode::SUCCESS;
}

ErrorCode LinkLayerController::RemoteOobDataRequestNegativeReply(
    const Address& peer) {
  auto current_peer = security_manager_.GetAuthenticationAddress();
  security_manager_.AuthenticationRequestFinished();
  ScheduleTask(milliseconds(5), [this, current_peer]() {
    send_event_(bluetooth::hci::SimplePairingCompleteBuilder::Create(
        ErrorCode::AUTHENTICATION_FAILURE, current_peer));
  });
  if (peer != current_peer) {
    return ErrorCode::UNKNOWN_CONNECTION;
  }
  return ErrorCode::SUCCESS;
}

ErrorCode LinkLayerController::RemoteOobExtendedDataRequestReply(
    const Address& peer, const std::array<uint8_t, 16>& c192,
    const std::array<uint8_t, 16>& r192, const std::array<uint8_t, 16>& c256,
    const std::array<uint8_t, 16>& r256) {
  if (security_manager_.GetAuthenticationAddress() != peer) {
    return ErrorCode::AUTHENTICATION_FAILURE;
  }
  LOG_INFO(
      "TODO:Do something with the OOB data c192=%d r192=%d c256=%d r256=%d",
      c192[0], r192[0], c256[0], r256[0]);
  SaveKeyAndAuthenticate('O', peer);

  return ErrorCode::SUCCESS;
}

ErrorCode LinkLayerController::SendKeypressNotification(
    const Address& peer,
    bluetooth::hci::KeypressNotificationType notification_type) {
  if (notification_type >
      bluetooth::hci::KeypressNotificationType::ENTRY_COMPLETED) {
    return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
  }

  SendLinkLayerPacket(model::packets::KeypressNotificationBuilder::Create(
      properties_.GetAddress(), peer,
      static_cast<model::packets::PasskeyNotificationType>(notification_type)));
  return ErrorCode::SUCCESS;
}

void LinkLayerController::HandleAuthenticationRequest(const Address& address,
                                                      uint16_t handle) {
    security_manager_.AuthenticationRequest(address, handle);
    auto packet = bluetooth::hci::LinkKeyRequestBuilder::Create(address);
    send_event_(std::move(packet));
}

ErrorCode LinkLayerController::AuthenticationRequested(uint16_t handle) {
  if (!connections_.HasHandle(handle)) {
    LOG_INFO("Authentication Requested for unknown handle %04x", handle);
    return ErrorCode::UNKNOWN_CONNECTION;
  }

  AddressWithType remote = connections_.GetAddress(handle);

  ScheduleTask(milliseconds(5), [this, remote, handle]() {
    HandleAuthenticationRequest(remote.GetAddress(), handle);
  });

  return ErrorCode::SUCCESS;
}

void LinkLayerController::HandleSetConnectionEncryption(
    const Address& peer, uint16_t handle, uint8_t encryption_enable) {
  // TODO: Block ACL traffic or at least guard against it

  if (connections_.IsEncrypted(handle) && encryption_enable) {
    auto packet = bluetooth::hci::EncryptionChangeBuilder::Create(
        ErrorCode::SUCCESS, handle,
        static_cast<bluetooth::hci::EncryptionEnabled>(encryption_enable));
    send_event_(std::move(packet));
    return;
  }

  uint16_t count = security_manager_.ReadKey(peer);
  if (count == 0) {
    LOG_ERROR("NO KEY HERE for %s", peer.ToString().c_str());
    return;
  }
  auto array = security_manager_.GetKey(peer);
  std::vector<uint8_t> key_vec{array.begin(), array.end()};
  auto packet = model::packets::EncryptConnectionBuilder::Create(
      properties_.GetAddress(), peer, key_vec);
  SendLinkLayerPacket(std::move(packet));
}

ErrorCode LinkLayerController::SetConnectionEncryption(
    uint16_t handle, uint8_t encryption_enable) {
  if (!connections_.HasHandle(handle)) {
    LOG_INFO("Set Connection Encryption for unknown handle %04x", handle);
    return ErrorCode::UNKNOWN_CONNECTION;
  }

  if (connections_.IsEncrypted(handle) && !encryption_enable) {
    return ErrorCode::ENCRYPTION_MODE_NOT_ACCEPTABLE;
  }
  AddressWithType remote = connections_.GetAddress(handle);

  if (security_manager_.ReadKey(remote.GetAddress()) == 0) {
    return ErrorCode::PIN_OR_KEY_MISSING;
  }

  ScheduleTask(milliseconds(5), [this, remote, handle, encryption_enable]() {
    HandleSetConnectionEncryption(remote.GetAddress(), handle,
                                  encryption_enable);
  });
  return ErrorCode::SUCCESS;
}

ErrorCode LinkLayerController::AcceptConnectionRequest(const Address& addr,
                                                       bool try_role_switch) {
  if (!connections_.HasPendingConnection(addr)) {
    LOG_INFO("No pending connection for %s", addr.ToString().c_str());
    return ErrorCode::UNKNOWN_CONNECTION;
  }

  LOG_INFO("Accept in 200ms");
  ScheduleTask(milliseconds(200), [this, addr, try_role_switch]() {
    LOG_INFO("Accepted");
    MakePeripheralConnection(addr, try_role_switch);
  });

  return ErrorCode::SUCCESS;
}

void LinkLayerController::MakePeripheralConnection(const Address& addr,
                                                   bool try_role_switch) {
  LOG_INFO("Sending page response to %s", addr.ToString().c_str());
  auto to_send = model::packets::PageResponseBuilder::Create(
      properties_.GetAddress(), addr, try_role_switch);
  SendLinkLayerPacket(std::move(to_send));

  uint16_t handle =
      connections_.CreateConnection(addr, properties_.GetAddress());
  if (handle == kReservedHandle) {
    LOG_INFO("CreateConnection failed");
    return;
  }
  LOG_INFO("CreateConnection returned handle 0x%x", handle);
  auto packet = bluetooth::hci::ConnectionCompleteBuilder::Create(
      ErrorCode::SUCCESS, handle, addr, bluetooth::hci::LinkType::ACL,
      bluetooth::hci::Enable::DISABLED);
  send_event_(std::move(packet));
}

ErrorCode LinkLayerController::RejectConnectionRequest(const Address& addr,
                                                       uint8_t reason) {
  if (!connections_.HasPendingConnection(addr)) {
    LOG_INFO("No pending connection for %s", addr.ToString().c_str());
    return ErrorCode::UNKNOWN_CONNECTION;
  }

  ScheduleTask(milliseconds(200), [this, addr, reason]() {
    RejectPeripheralConnection(addr, reason);
  });

  return ErrorCode::SUCCESS;
}

void LinkLayerController::RejectPeripheralConnection(const Address& addr,
                                                     uint8_t reason) {
  auto to_send = model::packets::PageRejectBuilder::Create(
      properties_.GetAddress(), addr, reason);
  LOG_INFO("Sending page reject to %s (reason 0x%02hhx)",
           addr.ToString().c_str(), reason);
  SendLinkLayerPacket(std::move(to_send));

  auto packet = bluetooth::hci::ConnectionCompleteBuilder::Create(
      static_cast<ErrorCode>(reason), 0xeff, addr,
      bluetooth::hci::LinkType::ACL, bluetooth::hci::Enable::DISABLED);
  send_event_(std::move(packet));
}

ErrorCode LinkLayerController::CreateConnection(const Address& addr, uint16_t,
                                                uint8_t, uint16_t,
                                                uint8_t allow_role_switch) {
  if (!connections_.CreatePendingConnection(
          addr, properties_.GetAuthenticationEnable() == 1)) {
    return ErrorCode::CONTROLLER_BUSY;
  }
  auto page = model::packets::PageBuilder::Create(
      properties_.GetAddress(), addr, properties_.GetClassOfDevice(),
      allow_role_switch);
  SendLinkLayerPacket(std::move(page));

  return ErrorCode::SUCCESS;
}

ErrorCode LinkLayerController::CreateConnectionCancel(const Address& addr) {
  if (!connections_.CancelPendingConnection(addr)) {
    return ErrorCode::UNKNOWN_CONNECTION;
  }
  return ErrorCode::SUCCESS;
}

ErrorCode LinkLayerController::Disconnect(uint16_t handle, uint8_t reason) {
  if (!connections_.HasHandle(handle)) {
    return ErrorCode::UNKNOWN_CONNECTION;
  }

  const AddressWithType remote = connections_.GetAddress(handle);
  auto packet = model::packets::DisconnectBuilder::Create(
      properties_.GetAddress(), remote.GetAddress(), reason);
  SendLinkLayerPacket(std::move(packet));
  ASSERT_LOG(connections_.Disconnect(handle), "Disconnecting %hx", handle);

  ScheduleTask(milliseconds(20), [this, handle]() {
    DisconnectCleanup(
        handle,
        static_cast<uint8_t>(ErrorCode::CONNECTION_TERMINATED_BY_LOCAL_HOST));
  });

  return ErrorCode::SUCCESS;
}

void LinkLayerController::DisconnectCleanup(uint16_t handle, uint8_t reason) {
  // TODO: Clean up other connection state.
  auto packet = bluetooth::hci::DisconnectionCompleteBuilder::Create(
      ErrorCode::SUCCESS, handle, static_cast<ErrorCode>(reason));
  send_event_(std::move(packet));
}

ErrorCode LinkLayerController::ChangeConnectionPacketType(uint16_t handle,
                                                          uint16_t types) {
  if (!connections_.HasHandle(handle)) {
    return ErrorCode::UNKNOWN_CONNECTION;
  }
  auto packet = bluetooth::hci::ConnectionPacketTypeChangedBuilder::Create(
      ErrorCode::SUCCESS, handle, types);
  std::shared_ptr<bluetooth::hci::ConnectionPacketTypeChangedBuilder>
      shared_packet = std::move(packet);
  ScheduleTask(milliseconds(20), [this, shared_packet]() {
    send_event_(std::move(shared_packet));
  });

  return ErrorCode::SUCCESS;
}

ErrorCode LinkLayerController::ChangeConnectionLinkKey(uint16_t handle) {
  if (!connections_.HasHandle(handle)) {
    return ErrorCode::UNKNOWN_CONNECTION;
  }

  // TODO: implement real logic
  return ErrorCode::COMMAND_DISALLOWED;
}

ErrorCode LinkLayerController::CentralLinkKey(uint8_t /* key_flag */) {
  // TODO: implement real logic
  return ErrorCode::COMMAND_DISALLOWED;
}

ErrorCode LinkLayerController::HoldMode(uint16_t handle,
                                        uint16_t hold_mode_max_interval,
                                        uint16_t hold_mode_min_interval) {
  if (!connections_.HasHandle(handle)) {
    return ErrorCode::UNKNOWN_CONNECTION;
  }

  if (hold_mode_max_interval < hold_mode_min_interval) {
    return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
  }

  // TODO: implement real logic
  return ErrorCode::COMMAND_DISALLOWED;
}

ErrorCode LinkLayerController::SniffMode(uint16_t handle,
                                         uint16_t sniff_max_interval,
                                         uint16_t sniff_min_interval,
                                         uint16_t sniff_attempt,
                                         uint16_t sniff_timeout) {
  if (!connections_.HasHandle(handle)) {
    return ErrorCode::UNKNOWN_CONNECTION;
  }

  if (sniff_max_interval < sniff_min_interval || sniff_attempt < 0x0001 ||
      sniff_attempt > 0x7FFF || sniff_timeout > 0x7FFF) {
    return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
  }

  // TODO: implement real logic
  return ErrorCode::COMMAND_DISALLOWED;
}

ErrorCode LinkLayerController::ExitSniffMode(uint16_t handle) {
  if (!connections_.HasHandle(handle)) {
    return ErrorCode::UNKNOWN_CONNECTION;
  }

  // TODO: implement real logic
  return ErrorCode::COMMAND_DISALLOWED;
}

ErrorCode LinkLayerController::QosSetup(uint16_t handle, uint8_t service_type,
                                        uint32_t /* token_rate */,
                                        uint32_t /* peak_bandwidth */,
                                        uint32_t /* latency */,
                                        uint32_t /* delay_variation */) {
  if (!connections_.HasHandle(handle)) {
    return ErrorCode::UNKNOWN_CONNECTION;
  }

  if (service_type > 0x02) {
    return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
  }

  // TODO: implement real logic
  return ErrorCode::COMMAND_DISALLOWED;
}

ErrorCode LinkLayerController::SwitchRole(Address /* bd_addr */,
                                          uint8_t /* role */) {
  // TODO: implement real logic
  return ErrorCode::COMMAND_DISALLOWED;
}

ErrorCode LinkLayerController::WriteLinkPolicySettings(uint16_t handle,
                                                       uint16_t) {
  if (!connections_.HasHandle(handle)) {
    return ErrorCode::UNKNOWN_CONNECTION;
  }
  return ErrorCode::SUCCESS;
}

ErrorCode LinkLayerController::WriteDefaultLinkPolicySettings(
    uint16_t settings) {
  if (settings > 7 /* Sniff + Hold + Role switch */) {
    return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
  }
  default_link_policy_settings_ = settings;
  return ErrorCode::SUCCESS;
}

uint16_t LinkLayerController::ReadDefaultLinkPolicySettings() {
  return default_link_policy_settings_;
}

void LinkLayerController::ReadLocalOobData() {
  std::array<uint8_t, 16> c_array(
      {'c', ' ', 'a', 'r', 'r', 'a', 'y', ' ', '0', '0', '0', '0', '0', '0',
       static_cast<uint8_t>((oob_id_ % 0x10000) >> 8u),
       static_cast<uint8_t>(oob_id_ % 0x100)});

  std::array<uint8_t, 16> r_array(
      {'r', ' ', 'a', 'r', 'r', 'a', 'y', ' ', '0', '0', '0', '0', '0', '0',
       static_cast<uint8_t>((oob_id_ % 0x10000) >> 8u),
       static_cast<uint8_t>(oob_id_ % 0x100)});

  send_event_(bluetooth::hci::ReadLocalOobDataCompleteBuilder::Create(
      1, ErrorCode::SUCCESS, c_array, r_array));
  oob_id_ += 1;
}

void LinkLayerController::ReadLocalOobExtendedData() {
  std::array<uint8_t, 16> c_192_array(
      {'c', ' ', 'a', 'r', 'r', 'a', 'y', ' ', '1', '9', '2', '0', '0', '0',
       static_cast<uint8_t>((oob_id_ % 0x10000) >> 8u),
       static_cast<uint8_t>(oob_id_ % 0x100)});

  std::array<uint8_t, 16> r_192_array(
      {'r', ' ', 'a', 'r', 'r', 'a', 'y', ' ', '1', '9', '2', '0', '0', '0',
       static_cast<uint8_t>((oob_id_ % 0x10000) >> 8u),
       static_cast<uint8_t>(oob_id_ % 0x100)});

  std::array<uint8_t, 16> c_256_array(
      {'c', ' ', 'a', 'r', 'r', 'a', 'y', ' ', '2', '5', '6', '0', '0', '0',
       static_cast<uint8_t>((oob_id_ % 0x10000) >> 8u),
       static_cast<uint8_t>(oob_id_ % 0x100)});

  std::array<uint8_t, 16> r_256_array(
      {'r', ' ', 'a', 'r', 'r', 'a', 'y', ' ', '2', '5', '6', '0', '0', '0',
       static_cast<uint8_t>((oob_id_ % 0x10000) >> 8u),
       static_cast<uint8_t>(oob_id_ % 0x100)});

  send_event_(bluetooth::hci::ReadLocalOobExtendedDataCompleteBuilder::Create(
      1, ErrorCode::SUCCESS, c_192_array, r_192_array, c_256_array,
      r_256_array));
  oob_id_ += 1;
}

ErrorCode LinkLayerController::FlowSpecification(
    uint16_t handle, uint8_t flow_direction, uint8_t service_type,
    uint32_t /* token_rate */, uint32_t /* token_bucket_size */,
    uint32_t /* peak_bandwidth */, uint32_t /* access_latency */) {
  if (!connections_.HasHandle(handle)) {
    return ErrorCode::UNKNOWN_CONNECTION;
  }

  if (flow_direction > 0x01 || service_type > 0x02) {
    return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
  }

  // TODO: implement real logic
  return ErrorCode::COMMAND_DISALLOWED;
}

ErrorCode LinkLayerController::WriteLinkSupervisionTimeout(uint16_t handle,
                                                           uint16_t) {
  if (!connections_.HasHandle(handle)) {
    return ErrorCode::UNKNOWN_CONNECTION;
  }
  return ErrorCode::SUCCESS;
}

ErrorCode LinkLayerController::SetLeExtendedAddress(uint8_t set,
                                                    Address address) {
  advertisers_[set].SetAddress(address);
  return ErrorCode::SUCCESS;
}

ErrorCode LinkLayerController::SetLeExtendedAdvertisingData(
    uint8_t set, const std::vector<uint8_t>& data) {
  advertisers_[set].SetData(data);
  return ErrorCode::SUCCESS;
}

ErrorCode LinkLayerController::SetLeExtendedAdvertisingParameters(
    uint8_t set, uint16_t interval_min, uint16_t interval_max,
    bluetooth::hci::LegacyAdvertisingProperties type,
    bluetooth::hci::OwnAddressType own_address_type,
    bluetooth::hci::PeerAddressType peer_address_type, Address peer,
    bluetooth::hci::AdvertisingFilterPolicy filter_policy) {
  model::packets::AdvertisementType ad_type;
  switch (type) {
    case bluetooth::hci::LegacyAdvertisingProperties::ADV_IND:
      ad_type = model::packets::AdvertisementType::ADV_IND;
      peer = Address::kEmpty;
      break;
    case bluetooth::hci::LegacyAdvertisingProperties::ADV_NONCONN_IND:
      ad_type = model::packets::AdvertisementType::ADV_NONCONN_IND;
      peer = Address::kEmpty;
      break;
    case bluetooth::hci::LegacyAdvertisingProperties::ADV_SCAN_IND:
      ad_type = model::packets::AdvertisementType::ADV_SCAN_IND;
      peer = Address::kEmpty;
      break;
    case bluetooth::hci::LegacyAdvertisingProperties::ADV_DIRECT_IND_HIGH:
    case bluetooth::hci::LegacyAdvertisingProperties::ADV_DIRECT_IND_LOW:
      ad_type = model::packets::AdvertisementType::ADV_DIRECT_IND;
      break;
  }
  auto interval_ms =
      static_cast<int>((interval_max + interval_min) * 0.625 / 2);

  AddressWithType peer_address;
  switch (peer_address_type) {
    case bluetooth::hci::PeerAddressType::PUBLIC_DEVICE_OR_IDENTITY_ADDRESS:
      peer_address = AddressWithType(
          peer, bluetooth::hci::AddressType::PUBLIC_DEVICE_ADDRESS);
      break;
    case bluetooth::hci::PeerAddressType::RANDOM_DEVICE_OR_IDENTITY_ADDRESS:
      peer_address = AddressWithType(
          peer, bluetooth::hci::AddressType::RANDOM_DEVICE_ADDRESS);
      break;
  }

  bluetooth::hci::AddressType own_address_address_type;
  switch (own_address_type) {
    case bluetooth::hci::OwnAddressType::RANDOM_DEVICE_ADDRESS:
      own_address_address_type =
          bluetooth::hci::AddressType::RANDOM_DEVICE_ADDRESS;
      break;
    case bluetooth::hci::OwnAddressType::PUBLIC_DEVICE_ADDRESS:
      own_address_address_type =
          bluetooth::hci::AddressType::PUBLIC_DEVICE_ADDRESS;
      break;
    case bluetooth::hci::OwnAddressType::RESOLVABLE_OR_PUBLIC_ADDRESS:
      own_address_address_type =
          bluetooth::hci::AddressType::PUBLIC_IDENTITY_ADDRESS;
      break;
    case bluetooth::hci::OwnAddressType::RESOLVABLE_OR_RANDOM_ADDRESS:
      own_address_address_type =
          bluetooth::hci::AddressType::RANDOM_IDENTITY_ADDRESS;
      break;
  }

  bluetooth::hci::LeScanningFilterPolicy scanning_filter_policy;
  switch (filter_policy) {
    case bluetooth::hci::AdvertisingFilterPolicy::ALL_DEVICES:
      scanning_filter_policy =
          bluetooth::hci::LeScanningFilterPolicy::ACCEPT_ALL;
      break;
    case bluetooth::hci::AdvertisingFilterPolicy::LISTED_SCAN:
      scanning_filter_policy =
          bluetooth::hci::LeScanningFilterPolicy::CONNECT_LIST_ONLY;
      break;
    case bluetooth::hci::AdvertisingFilterPolicy::LISTED_CONNECT:
      scanning_filter_policy =
          bluetooth::hci::LeScanningFilterPolicy::CHECK_INITIATORS_IDENTITY;
      break;
    case bluetooth::hci::AdvertisingFilterPolicy::LISTED_SCAN_AND_CONNECT:
      scanning_filter_policy = bluetooth::hci::LeScanningFilterPolicy::
          CONNECT_LIST_AND_INITIATORS_IDENTITY;
      break;
  }

  advertisers_[set].InitializeExtended(own_address_address_type, peer_address,
                                       scanning_filter_policy, ad_type,
                                       std::chrono::milliseconds(interval_ms));

  return ErrorCode::SUCCESS;
}

ErrorCode LinkLayerController::LeRemoveAdvertisingSet(uint8_t set) {
  if (set >= advertisers_.size()) {
    return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
  }
  advertisers_[set].Disable();
  return ErrorCode::SUCCESS;
}

ErrorCode LinkLayerController::LeClearAdvertisingSets() {
  for (auto& advertiser : advertisers_) {
    if (advertiser.IsEnabled()) {
      return ErrorCode::COMMAND_DISALLOWED;
    }
  }
  for (auto& advertiser : advertisers_) {
    advertiser.Clear();
  }
  return ErrorCode::SUCCESS;
}

void LinkLayerController::LeConnectionUpdateComplete(
    bluetooth::hci::LeConnectionUpdateView connection_update) {
  uint16_t handle = connection_update.GetConnectionHandle();
  ErrorCode status = ErrorCode::SUCCESS;
  if (!connections_.HasHandle(handle)) {
    status = ErrorCode::UNKNOWN_CONNECTION;
  }
  uint16_t interval_min = connection_update.GetConnIntervalMin();
  uint16_t interval_max = connection_update.GetConnIntervalMax();
  uint16_t latency = connection_update.GetConnLatency();
  uint16_t supervision_timeout = connection_update.GetSupervisionTimeout();

  if (interval_min < 6 || interval_max > 0xC80 || interval_min > interval_max ||
      interval_max < interval_min || latency > 0x1F3 ||
      supervision_timeout < 0xA || supervision_timeout > 0xC80 ||
      // The Supervision_Timeout in milliseconds (*10) shall be larger than (1 +
      // Connection_Latency) * Connection_Interval_Max (* 5/4) * 2
      supervision_timeout <= ((((1 + latency) * interval_max * 10) / 4) / 10)) {
    status = ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
  }
  uint16_t interval = (interval_min + interval_max) / 2;
  send_event_(bluetooth::hci::LeConnectionUpdateCompleteBuilder::Create(
      status, handle, interval, latency, supervision_timeout));
}

ErrorCode LinkLayerController::LeConnectionUpdate(
    bluetooth::hci::LeConnectionUpdateView connection_update) {
  uint16_t handle = connection_update.GetConnectionHandle();
  if (!connections_.HasHandle(handle)) {
    return ErrorCode::UNKNOWN_CONNECTION;
  }

  // This could negotiate with the remote device in the future
  ScheduleTask(milliseconds(25), [this, connection_update]() {
    LeConnectionUpdateComplete(connection_update);
  });

  return ErrorCode::SUCCESS;
}

void LinkLayerController::LeConnectListClear() { le_connect_list_.clear(); }

void LinkLayerController::LeResolvingListClear() { le_resolving_list_.clear(); }

void LinkLayerController::LeConnectListAddDevice(Address addr,
                                                 uint8_t addr_type) {
  std::tuple<Address, uint8_t> new_tuple = std::make_tuple(addr, addr_type);
  for (auto dev : le_connect_list_) {
    if (dev == new_tuple) {
      return;
    }
  }
  le_connect_list_.emplace_back(new_tuple);
}

void LinkLayerController::LeResolvingListAddDevice(
    Address addr, uint8_t addr_type, std::array<uint8_t, kIrk_size> peerIrk,
    std::array<uint8_t, kIrk_size> localIrk) {
  std::tuple<Address, uint8_t, std::array<uint8_t, kIrk_size>,
             std::array<uint8_t, kIrk_size>>
      new_tuple = std::make_tuple(addr, addr_type, peerIrk, localIrk);
  for (size_t i = 0; i < le_connect_list_.size(); i++) {
    auto curr = le_connect_list_[i];
    if (std::get<0>(curr) == addr && std::get<1>(curr) == addr_type) {
      le_resolving_list_[i] = new_tuple;
      return;
    }
  }
  le_resolving_list_.emplace_back(new_tuple);
}

void LinkLayerController::LeSetPrivacyMode(uint8_t address_type, Address addr,
                                           uint8_t mode) {
  // set mode for addr
  LOG_INFO("address type = %d ", address_type);
  LOG_INFO("address = %s ", addr.ToString().c_str());
  LOG_INFO("mode = %d ", mode);
}

void LinkLayerController::LeReadIsoTxSync(uint16_t handle) {}

void LinkLayerController::LeSetCigParameters(
    uint8_t cig_id, uint32_t sdu_interval_m_to_s, uint32_t sdu_interval_s_to_m,
    bluetooth::hci::ClockAccuracy clock_accuracy,
    bluetooth::hci::Packing packing, bluetooth::hci::Enable framing,
    uint16_t max_transport_latency_m_to_s,
    uint16_t max_transport_latency_s_to_m,
    std::vector<bluetooth::hci::CisParametersConfig> cis_config) {
  send_event_(connections_.SetCigParameters(
      cig_id, sdu_interval_m_to_s, sdu_interval_s_to_m, clock_accuracy, packing,
      framing, max_transport_latency_m_to_s, max_transport_latency_s_to_m,
      cis_config));
}

ErrorCode LinkLayerController::LeCreateCis(
    std::vector<bluetooth::hci::CreateCisConfig> cis_config) {
  if (connections_.HasPendingCis()) {
    return ErrorCode::COMMAND_DISALLOWED;
  }
  for (auto& config : cis_config) {
    if (!connections_.HasHandle(config.acl_connection_handle_)) {
      LOG_INFO("Unknown ACL handle %04x", config.acl_connection_handle_);
      return ErrorCode::UNKNOWN_CONNECTION;
    }
    if (!connections_.HasCisHandle(config.cis_connection_handle_)) {
      LOG_INFO("Unknown CIS handle %04x", config.cis_connection_handle_);
      return ErrorCode::UNKNOWN_CONNECTION;
    }
  }
  for (auto& config : cis_config) {
    connections_.CreatePendingCis(config);
    auto own_address =
        connections_.GetOwnAddress(config.acl_connection_handle_);
    auto peer_address = connections_.GetAddress(config.acl_connection_handle_);
    StreamParameters stream_parameters =
        connections_.GetStreamParameters(config.cis_connection_handle_);
    GroupParameters group_parameters =
        connections_.GetGroupParameters(stream_parameters.group_id);

    SendLeLinkLayerPacket(model::packets::IsoConnectionRequestBuilder::Create(
        own_address.GetAddress(), peer_address.GetAddress(),
        stream_parameters.group_id, group_parameters.sdu_interval_m_to_s,
        group_parameters.sdu_interval_s_to_m, group_parameters.interleaved,
        group_parameters.framed, group_parameters.max_transport_latency_m_to_s,
        group_parameters.max_transport_latency_s_to_m,
        stream_parameters.stream_id, stream_parameters.max_sdu_m_to_s,
        stream_parameters.max_sdu_s_to_m, config.cis_connection_handle_,
        config.acl_connection_handle_));
  }
  return ErrorCode::SUCCESS;
}

ErrorCode LinkLayerController::LeRemoveCig(uint8_t cig_id) {
  return connections_.RemoveCig(cig_id);
}

ErrorCode LinkLayerController::LeAcceptCisRequest(uint16_t cis_handle) {
  if (!connections_.HasPendingCisConnection(cis_handle)) {
    return ErrorCode::UNKNOWN_CONNECTION;
  }
  auto acl_handle = connections_.GetPendingAclHandle(cis_handle);

  SendLeLinkLayerPacket(model::packets::IsoConnectionResponseBuilder::Create(
      connections_.GetOwnAddress(acl_handle).GetAddress(),
      connections_.GetAddress(acl_handle).GetAddress(),
      static_cast<uint8_t>(ErrorCode::SUCCESS), cis_handle, acl_handle));

  return ErrorCode::SUCCESS;
}

ErrorCode LinkLayerController::LeRejectCisRequest(uint16_t cis_handle,
                                                  ErrorCode reason) {
  if (!connections_.HasPendingCisConnection(cis_handle)) {
    return ErrorCode::UNKNOWN_CONNECTION;
  }
  auto acl_handle = connections_.GetPendingAclHandle(cis_handle);

  SendLeLinkLayerPacket(model::packets::IsoConnectionResponseBuilder::Create(
      connections_.GetOwnAddress(acl_handle).GetAddress(),
      connections_.GetAddress(acl_handle).GetAddress(),
      static_cast<uint8_t>(reason), acl_handle, cis_handle));
  connections_.RejectCis(cis_handle);
  return ErrorCode::SUCCESS;
}

ErrorCode LinkLayerController::LeCreateBig(
    uint8_t big_handle, uint8_t advertising_handle, uint8_t num_bis,
    uint32_t sdu_interval, uint16_t max_sdu, uint16_t max_transport_latency,
    uint8_t rtn, bluetooth::hci::SecondaryPhyType phy,
    bluetooth::hci::Packing packing, bluetooth::hci::Enable framing,
    bluetooth::hci::Enable encryption, std::vector<uint16_t> broadcast_code) {
  return ErrorCode::SUCCESS;
}

ErrorCode LinkLayerController::LeTerminateBig(uint8_t big_handle,
                                              ErrorCode reason) {
  return ErrorCode::SUCCESS;
}

ErrorCode LinkLayerController::LeBigCreateSync(
    uint8_t big_handle, uint16_t sync_handle, bluetooth::hci::Enable encryption,
    std::vector<uint16_t> broadcast_code, uint8_t mse,
    uint16_t big_sync_timeout, std::vector<uint8_t> bis) {
  return ErrorCode::SUCCESS;
}

void LinkLayerController::LeBigTerminateSync(uint8_t big_handle) {}

ErrorCode LinkLayerController::LeRequestPeerSca(uint16_t request_handle) {
  return ErrorCode::SUCCESS;
}

void LinkLayerController::LeSetupIsoDataPath(
    uint16_t connection_handle,
    bluetooth::hci::DataPathDirection data_path_direction, uint8_t data_path_id,
    uint64_t codec_id, uint32_t controller_Delay,
    std::vector<uint8_t> codec_configuration) {}

void LinkLayerController::LeRemoveIsoDataPath(
    uint16_t connection_handle,
    bluetooth::hci::DataPathDirection data_path_direction) {}

void LinkLayerController::HandleLeEnableEncryption(
    uint16_t handle, std::array<uint8_t, 8> rand, uint16_t ediv,
    std::array<uint8_t, 16> ltk) {
  // TODO: Check keys
  // TODO: Block ACL traffic or at least guard against it
  if (!connections_.HasHandle(handle)) {
    return;
  }
  SendLeLinkLayerPacket(model::packets::LeEncryptConnectionBuilder::Create(
      connections_.GetOwnAddress(handle).GetAddress(),
      connections_.GetAddress(handle).GetAddress(), rand, ediv, ltk));
}

ErrorCode LinkLayerController::LeEnableEncryption(uint16_t handle,
                                                  std::array<uint8_t, 8> rand,
                                                  uint16_t ediv,
                                                  std::array<uint8_t, 16> ltk) {
  if (!connections_.HasHandle(handle)) {
    LOG_INFO("Unknown handle %04x", handle);
    return ErrorCode::UNKNOWN_CONNECTION;
  }

  ScheduleTask(milliseconds(5), [this, handle, rand, ediv, ltk]() {
    HandleLeEnableEncryption(handle, rand, ediv, ltk);
  });
  return ErrorCode::SUCCESS;
}

ErrorCode LinkLayerController::LeLongTermKeyRequestReply(
    uint16_t handle, std::array<uint8_t, 16> ltk) {
  if (!connections_.HasHandle(handle)) {
    LOG_INFO("Unknown handle %04x", handle);
    return ErrorCode::UNKNOWN_CONNECTION;
  }

  // TODO: Check keys
  if (connections_.IsEncrypted(handle)) {
    send_event_(bluetooth::hci::EncryptionKeyRefreshCompleteBuilder::Create(
        ErrorCode::SUCCESS, handle));
  } else {
    connections_.Encrypt(handle);
    send_event_(bluetooth::hci::EncryptionChangeBuilder::Create(
        ErrorCode::SUCCESS, handle, bluetooth::hci::EncryptionEnabled::ON));
  }
  SendLeLinkLayerPacket(
      model::packets::LeEncryptConnectionResponseBuilder::Create(
          connections_.GetOwnAddress(handle).GetAddress(),
          connections_.GetAddress(handle).GetAddress(),
          std::array<uint8_t, 8>(), uint16_t(), ltk));

  return ErrorCode::SUCCESS;
}

ErrorCode LinkLayerController::LeLongTermKeyRequestNegativeReply(
    uint16_t handle) {
  if (!connections_.HasHandle(handle)) {
    LOG_INFO("Unknown handle %04x", handle);
    return ErrorCode::UNKNOWN_CONNECTION;
  }

  SendLeLinkLayerPacket(
      model::packets::LeEncryptConnectionResponseBuilder::Create(
          connections_.GetOwnAddress(handle).GetAddress(),
          connections_.GetAddress(handle).GetAddress(),
          std::array<uint8_t, 8>(), uint16_t(), std::array<uint8_t, 16>()));
  return ErrorCode::SUCCESS;
}

ErrorCode LinkLayerController::SetLeAdvertisingEnable(
    uint8_t le_advertising_enable) {
  if (!le_advertising_enable) {
    advertisers_[0].Disable();
    return ErrorCode::SUCCESS;
  }
  auto interval_ms = (properties_.GetLeAdvertisingIntervalMax() +
                      properties_.GetLeAdvertisingIntervalMin()) *
                     0.625 / 2;

  Address own_address = properties_.GetAddress();
  if (properties_.GetLeAdvertisingOwnAddressType() ==
          static_cast<uint8_t>(
              bluetooth::hci::AddressType::RANDOM_DEVICE_ADDRESS) ||
      properties_.GetLeAdvertisingOwnAddressType() ==
          static_cast<uint8_t>(
              bluetooth::hci::AddressType::RANDOM_IDENTITY_ADDRESS)) {
    if (properties_.GetLeAddress().ToString() == "bb:bb:bb:ba:d0:1e" ||
        properties_.GetLeAddress() == Address::kEmpty) {
      return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
    }
    own_address = properties_.GetLeAddress();
  }
  auto own_address_with_type = AddressWithType(
      own_address, static_cast<bluetooth::hci::AddressType>(
                       properties_.GetLeAdvertisingOwnAddressType()));

  auto interval = std::chrono::milliseconds(static_cast<uint64_t>(interval_ms));
  if (interval < std::chrono::milliseconds(20)) {
    return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
  }
  advertisers_[0].Initialize(
      own_address_with_type,
      bluetooth::hci::AddressWithType(
          properties_.GetLeAdvertisingPeerAddress(),
          static_cast<bluetooth::hci::AddressType>(
              properties_.GetLeAdvertisingPeerAddressType())),
      static_cast<bluetooth::hci::LeScanningFilterPolicy>(
          properties_.GetLeAdvertisingFilterPolicy()),
      static_cast<model::packets::AdvertisementType>(
          properties_.GetLeAdvertisementType()),
      properties_.GetLeAdvertisement(), properties_.GetLeScanResponse(),
      interval);
  advertisers_[0].Enable();
  return ErrorCode::SUCCESS;
}

void LinkLayerController::LeDisableAdvertisingSets() {
  for (auto& advertiser : advertisers_) {
    advertiser.Disable();
  }
}

uint8_t LinkLayerController::LeReadNumberOfSupportedAdvertisingSets() {
  return advertisers_.size();
}

ErrorCode LinkLayerController::SetLeExtendedAdvertisingEnable(
    bluetooth::hci::Enable enable,
    const std::vector<bluetooth::hci::EnabledSet>& enabled_sets) {
  for (const auto& set : enabled_sets) {
    if (set.advertising_handle_ > advertisers_.size()) {
      return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
    }
  }
  for (const auto& set : enabled_sets) {
    auto handle = set.advertising_handle_;
    if (enable == bluetooth::hci::Enable::ENABLED) {
      advertisers_[handle].EnableExtended(
          std::chrono::milliseconds(10 * set.duration_));
    } else {
      advertisers_[handle].Disable();
    }
  }
  return ErrorCode::SUCCESS;
}

void LinkLayerController::LeConnectListRemoveDevice(Address addr,
                                                    uint8_t addr_type) {
  // TODO: Add checks to see if advertising, scanning, or a connection request
  // with the connect list is ongoing.
  std::tuple<Address, uint8_t> erase_tuple = std::make_tuple(addr, addr_type);
  for (size_t i = 0; i < le_connect_list_.size(); i++) {
    if (le_connect_list_[i] == erase_tuple) {
      le_connect_list_.erase(le_connect_list_.begin() + i);
    }
  }
}

void LinkLayerController::LeResolvingListRemoveDevice(Address addr,
                                                      uint8_t addr_type) {
  // TODO: Add checks to see if advertising, scanning, or a connection request
  // with the connect list is ongoing.
  for (size_t i = 0; i < le_connect_list_.size(); i++) {
    auto curr = le_connect_list_[i];
    if (std::get<0>(curr) == addr && std::get<1>(curr) == addr_type) {
      le_resolving_list_.erase(le_resolving_list_.begin() + i);
    }
  }
}

bool LinkLayerController::LeConnectListContainsDevice(Address addr,
                                                      uint8_t addr_type) {
  std::tuple<Address, uint8_t> sought_tuple = std::make_tuple(addr, addr_type);
  for (size_t i = 0; i < le_connect_list_.size(); i++) {
    if (le_connect_list_[i] == sought_tuple) {
      return true;
    }
  }
  return false;
}

bool LinkLayerController::LeResolvingListContainsDevice(Address addr,
                                                        uint8_t addr_type) {
  for (size_t i = 0; i < le_connect_list_.size(); i++) {
    auto curr = le_connect_list_[i];
    if (std::get<0>(curr) == addr && std::get<1>(curr) == addr_type) {
      return true;
    }
  }
  return false;
}

bool LinkLayerController::LeConnectListFull() {
  return le_connect_list_.size() >= properties_.GetLeConnectListSize();
}

bool LinkLayerController::LeResolvingListFull() {
  return le_resolving_list_.size() >= properties_.GetLeResolvingListSize();
}

void LinkLayerController::Reset() {
  if (inquiry_timer_task_id_ != kInvalidTaskId) {
    CancelScheduledTask(inquiry_timer_task_id_);
    inquiry_timer_task_id_ = kInvalidTaskId;
  }
  last_inquiry_ = steady_clock::now();
  le_scan_enable_ = bluetooth::hci::OpCode::NONE;
  LeDisableAdvertisingSets();
  le_connect_ = 0;
}

void LinkLayerController::StartInquiry(milliseconds timeout) {
  inquiry_timer_task_id_ = ScheduleTask(milliseconds(timeout), [this]() {
    LinkLayerController::InquiryTimeout();
  });
}

void LinkLayerController::InquiryCancel() {
  ASSERT(inquiry_timer_task_id_ != kInvalidTaskId);
  CancelScheduledTask(inquiry_timer_task_id_);
  inquiry_timer_task_id_ = kInvalidTaskId;
}

void LinkLayerController::InquiryTimeout() {
  if (inquiry_timer_task_id_ != kInvalidTaskId) {
    inquiry_timer_task_id_ = kInvalidTaskId;
    auto packet =
        bluetooth::hci::InquiryCompleteBuilder::Create(ErrorCode::SUCCESS);
    send_event_(std::move(packet));
  }
}

void LinkLayerController::SetInquiryMode(uint8_t mode) {
  inquiry_mode_ = static_cast<model::packets::InquiryType>(mode);
}

void LinkLayerController::SetInquiryLAP(uint64_t lap) { inquiry_lap_ = lap; }

void LinkLayerController::SetInquiryMaxResponses(uint8_t max) {
  inquiry_max_responses_ = max;
}

void LinkLayerController::Inquiry() {
  steady_clock::time_point now = steady_clock::now();
  if (duration_cast<milliseconds>(now - last_inquiry_) < milliseconds(2000)) {
    return;
  }

  auto packet = model::packets::InquiryBuilder::Create(
      properties_.GetAddress(), Address::kEmpty, inquiry_mode_);
  SendLinkLayerPacket(std::move(packet));
  last_inquiry_ = now;
}

void LinkLayerController::SetInquiryScanEnable(bool enable) {
  inquiry_scans_enabled_ = enable;
}

void LinkLayerController::SetPageScanEnable(bool enable) {
  page_scans_enabled_ = enable;
}

}  // namespace test_vendor_lib
