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

#include "hci.h"
#include "include/le_advertisement.h"
#include "os/log.h"
#include "packets/hci/acl_packet_builder.h"
#include "packets/hci/command_packet_view.h"
#include "packets/hci/sco_packet_builder.h"
#include "packets/raw_builder.h"

#include "packet/raw_builder.h"

using std::vector;
using namespace std::chrono;
using namespace test_vendor_lib::packets;

namespace test_vendor_lib {

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
    send_to_remote_(std::move(shared_packet), Phy::Type::LOW_ENERGY);
  });
}

void LinkLayerController::SendLinkLayerPacket(
    std::unique_ptr<model::packets::LinkLayerPacketBuilder> packet) {
  std::shared_ptr<model::packets::LinkLayerPacketBuilder> shared_packet =
      std::move(packet);
  ScheduleTask(milliseconds(50), [this, shared_packet]() {
    send_to_remote_(std::move(shared_packet), Phy::Type::BR_EDR);
  });
}

bluetooth::hci::ErrorCode LinkLayerController::SendCommandToRemoteByAddress(
    bluetooth::hci::OpCode opcode, PacketView<true> args, const Address& remote,
    bool use_public_address) {
  Address local_address;
  if (use_public_address) {
    local_address = properties_.GetAddress();
  } else {
    local_address = properties_.GetLeAddress();
  }

  std::unique_ptr<bluetooth::packet::RawBuilder> raw_builder_ptr =
      std::make_unique<bluetooth::packet::RawBuilder>();
  std::vector<uint8_t> payload_bytes(args.begin(), args.end());
  raw_builder_ptr->AddOctets2(static_cast<uint16_t>(opcode));
  raw_builder_ptr->AddOctets(payload_bytes);

  auto command = model::packets::CommandBuilder::Create(
      local_address, remote, std::move(raw_builder_ptr));

  SendLinkLayerPacket(std::move(command));
  return bluetooth::hci::ErrorCode::SUCCESS;
}

bluetooth::hci::ErrorCode LinkLayerController::SendCommandToRemoteByHandle(
    bluetooth::hci::OpCode opcode, PacketView<true> args, uint16_t handle) {
  // TODO: Handle LE connections
  bool use_public_address = true;
  if (!connections_.HasHandle(handle)) {
    return bluetooth::hci::ErrorCode::UNKNOWN_CONNECTION;
  }
  return SendCommandToRemoteByAddress(opcode, args, connections_.GetAddress(handle), use_public_address);
}

hci::Status LinkLayerController::SendAclToRemote(AclPacketView acl_packet) {
  uint16_t handle = acl_packet.GetHandle();
  if (!connections_.HasHandle(handle)) {
    return hci::Status::UNKNOWN_CONNECTION;
  }

  Address my_address = properties_.GetAddress();
  Address destination = connections_.GetAddress(handle);
  if (connections_.GetOwnAddressType(handle) != 0) {  // If it's not public, it must be LE
    my_address = properties_.GetLeAddress();
  }

  LOG_INFO("%s(%s): handle 0x%x size %d", __func__, properties_.GetAddress().ToString().c_str(), handle,
           static_cast<int>(acl_packet.size()));

  ScheduleTask(milliseconds(5), [this, handle]() {
    std::unique_ptr<bluetooth::packet::RawBuilder> raw_builder_ptr =
        std::make_unique<bluetooth::packet::RawBuilder>();
    raw_builder_ptr->AddOctets1(0x01);
    raw_builder_ptr->AddOctets2(handle);
    raw_builder_ptr->AddOctets2(0x01);

    auto packet = bluetooth::hci::EventPacketBuilder::Create(
        bluetooth::hci::EventCode::NUMBER_OF_COMPLETED_PACKETS,
        std::move(raw_builder_ptr));
    send_event_(std::move(packet));
  });

  auto acl_payload = acl_packet.GetPayload();

  std::unique_ptr<bluetooth::packet::RawBuilder> raw_builder_ptr =
      std::make_unique<bluetooth::packet::RawBuilder>();
  std::vector<uint8_t> payload_bytes(acl_payload.begin(), acl_payload.end());

  uint16_t first_two_bytes =
      static_cast<uint16_t>(acl_packet.GetHandle()) +
      (static_cast<uint16_t>(acl_packet.GetPacketBoundaryFlags()) << 12) +
      (static_cast<uint16_t>(acl_packet.GetBroadcastFlags()) << 14);
  raw_builder_ptr->AddOctets2(first_two_bytes);
  raw_builder_ptr->AddOctets2(static_cast<uint16_t>(payload_bytes.size()));
  raw_builder_ptr->AddOctets(payload_bytes);

  auto acl = model::packets::AclPacketBuilder::Create(
      my_address, destination, std::move(raw_builder_ptr));

  SendLinkLayerPacket(std::move(acl));
  return hci::Status::SUCCESS;
}

void LinkLayerController::IncomingPacket(
    model::packets::LinkLayerPacketView incoming) {
  ASSERT(incoming.IsValid());

  // TODO: Resolvable private addresses?
  if (incoming.GetDestinationAddress() != properties_.GetAddress() &&
      incoming.GetDestinationAddress() != properties_.GetLeAddress() &&
      incoming.GetDestinationAddress() != Address::kEmpty) {
    // Drop packets not addressed to me
    return;
  }

  switch (incoming.GetType()) {
    case model::packets::PacketType::ACL:
      IncomingAclPacket(incoming);
      break;
    case model::packets::PacketType::COMMAND:
      IncomingCommandPacket(incoming);
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
    case model::packets::PacketType::IO_CAPABILITY_NEGATIVE_RESPONSE:
      IncomingIoCapabilityNegativeResponsePacket(incoming);
      break;
    case model::packets::PacketType::LE_ADVERTISEMENT:
      if (le_scan_enable_ || le_connect_) {
        IncomingLeAdvertisementPacket(incoming);
      }
      break;
    case model::packets::PacketType::LE_CONNECT:
      IncomingLeConnectPacket(incoming);
      break;
    case model::packets::PacketType::LE_CONNECT_COMPLETE:
      IncomingLeConnectCompletePacket(incoming);
      break;
    case model::packets::PacketType::LE_SCAN:
      // TODO: Check Advertising flags and see if we are scannable.
      IncomingLeScanPacket(incoming);
      break;
    case model::packets::PacketType::LE_SCAN_RESPONSE:
      if (le_scan_enable_ && le_scan_type_ == 1) {
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
    case model::packets::PacketType::RESPONSE:
      IncomingResponsePacket(incoming);
      break;
    default:
      LOG_WARN("Dropping unhandled packet of type %d", static_cast<int32_t>(incoming.GetType()));
  }
}

void LinkLayerController::IncomingAclPacket(
    model::packets::LinkLayerPacketView incoming) {
  LOG_INFO("Acl Packet %s -> %s", incoming.GetSourceAddress().ToString().c_str(),
           incoming.GetDestinationAddress().ToString().c_str());

  auto acl = model::packets::AclPacketView::Create(incoming);
  ASSERT(acl.IsValid());
  auto payload = acl.GetPayload();
  std::shared_ptr<std::vector<uint8_t>> payload_bytes =
      std::make_shared<std::vector<uint8_t>>(payload.begin(), payload.end());

  AclPacketView acl_view = AclPacketView::Create(payload_bytes);
  LOG_INFO("%s: remote handle 0x%x size %d", __func__, acl_view.GetHandle(), static_cast<int>(acl_view.size()));
  uint16_t local_handle = connections_.GetHandle(incoming.GetSourceAddress());
  LOG_INFO("%s: local handle 0x%x", __func__, local_handle);

  acl::PacketBoundaryFlagsType boundary_flags = acl_view.GetPacketBoundaryFlags();
  acl::BroadcastFlagsType broadcast_flags = acl_view.GetBroadcastFlags();
  std::unique_ptr<RawBuilder> builder = std::make_unique<RawBuilder>();
  std::vector<uint8_t> raw_data(acl_view.GetPayload().begin(),
                                acl_view.GetPayload().end());
  builder->AddOctets(raw_data);
  send_acl_(AclPacketBuilder::Create(local_handle, boundary_flags, broadcast_flags, std::move(builder))->ToVector());
}

void LinkLayerController::IncomingCommandPacket(
    model::packets::LinkLayerPacketView incoming) {
  // TODO: Check the destination address to see if this packet is for me.
  auto command = model::packets::CommandView::Create(incoming);
  ASSERT(command.IsValid());

  auto args = command.GetPayload().begin();
  std::vector<uint64_t> response_data;
  hci::OpCode opcode = static_cast<hci::OpCode>(args.extract<uint16_t>());
  std::unique_ptr<bluetooth::packet::RawBuilder> raw_builder_ptr =
      std::make_unique<bluetooth::packet::RawBuilder>();

  switch (opcode) {
    case (hci::OpCode::REMOTE_NAME_REQUEST): {
      std::vector<uint8_t> name = properties_.GetName();
      LOG_INFO("Remote Name (Local Name) %d", static_cast<int>(name.size()));
      raw_builder_ptr->AddOctets1(
          static_cast<uint8_t>(bluetooth::hci::ErrorCode::SUCCESS));
      raw_builder_ptr->AddOctets8(name.size());
      raw_builder_ptr->AddOctets(name);
    } break;
    case (hci::OpCode::READ_REMOTE_SUPPORTED_FEATURES):
      LOG_INFO("(%s) Remote Supported Features Requested by: %s %x",
               incoming.GetDestinationAddress().ToString().c_str(), incoming.GetSourceAddress().ToString().c_str(),
               static_cast<int>(properties_.GetSupportedFeatures()));
      raw_builder_ptr->AddOctets1(
          static_cast<uint8_t>(bluetooth::hci::ErrorCode::SUCCESS));
      raw_builder_ptr->AddOctets8(properties_.GetSupportedFeatures());
      break;
    case (hci::OpCode::READ_REMOTE_EXTENDED_FEATURES): {
      uint8_t page_number = (args + 2).extract<uint8_t>();  // skip the handle
      LOG_INFO("(%s) Remote Extended Features %d Requested by: %s", incoming.GetDestinationAddress().ToString().c_str(),
               page_number, incoming.GetSourceAddress().ToString().c_str());
      uint8_t max_page_number = properties_.GetExtendedFeaturesMaximumPageNumber();
      if (page_number > max_page_number) {
        raw_builder_ptr->AddOctets1(static_cast<uint8_t>(
            bluetooth::hci::ErrorCode::INVALID_HCI_COMMAND_PARAMETERS));
        raw_builder_ptr->AddOctets1(page_number);
        raw_builder_ptr->AddOctets1(max_page_number);
        raw_builder_ptr->AddOctets8(0);
      } else {
        raw_builder_ptr->AddOctets1(
            static_cast<uint8_t>(bluetooth::hci::ErrorCode::SUCCESS));
        raw_builder_ptr->AddOctets1(page_number);
        raw_builder_ptr->AddOctets1(max_page_number);
        raw_builder_ptr->AddOctets8(
            properties_.GetExtendedFeatures(page_number));
      }
    } break;
    case (hci::OpCode::READ_REMOTE_VERSION_INFORMATION):
      raw_builder_ptr->AddOctets1(
          static_cast<uint8_t>(bluetooth::hci::ErrorCode::SUCCESS));
      raw_builder_ptr->AddOctets1(properties_.GetLmpPalVersion());
      raw_builder_ptr->AddOctets2(properties_.GetManufacturerName());
      raw_builder_ptr->AddOctets2(properties_.GetLmpPalSubversion());
      break;
    case (hci::OpCode::READ_CLOCK_OFFSET):
      raw_builder_ptr->AddOctets1(
          static_cast<uint8_t>(bluetooth::hci::ErrorCode::SUCCESS));
      raw_builder_ptr->AddOctets2(properties_.GetClockOffset());
      break;
    default:
      LOG_INFO("Dropping unhandled command 0x%04x", static_cast<uint16_t>(opcode));
      return;
  }

  for (uint64_t data : response_data) {
    raw_builder_ptr->AddOctets8(data);
  }

  auto response = model::packets::ResponseBuilder::Create(
      properties_.GetAddress(), incoming.GetSourceAddress(),
      static_cast<uint16_t>(opcode), std::move(raw_builder_ptr));

  SendLinkLayerPacket(std::move(response));
}

void LinkLayerController::IncomingDisconnectPacket(
    model::packets::LinkLayerPacketView incoming) {
  LOG_INFO("Disconnect Packet");
  auto disconnect = model::packets::DisconnectView::Create(incoming);
  ASSERT(disconnect.IsValid());

  Address peer = incoming.GetSourceAddress();
  uint16_t handle = connections_.GetHandle(peer);
  if (handle == acl::kReservedHandle) {
    LOG_INFO("%s: Unknown connection @%s", __func__, peer.ToString().c_str());
    return;
  }
  ASSERT_LOG(connections_.Disconnect(handle), "GetHandle() returned invalid handle %hx", handle);

  uint8_t reason = disconnect.GetReason();
  ScheduleTask(milliseconds(20), [this, handle, reason]() { DisconnectCleanup(handle, reason); });
}

void LinkLayerController::IncomingEncryptConnection(
    model::packets::LinkLayerPacketView incoming) {
  LOG_INFO("%s", __func__);

  // TODO: Check keys
  Address peer = incoming.GetSourceAddress();
  uint16_t handle = connections_.GetHandle(peer);
  if (handle == acl::kReservedHandle) {
    LOG_INFO("%s: Unknown connection @%s", __func__, peer.ToString().c_str());
    return;
  }
  auto packet = bluetooth::hci::EncryptionChangeBuilder::Create(
      bluetooth::hci::ErrorCode::SUCCESS, handle,
      bluetooth::hci::EncryptionEnabled::ON);
  send_event_(std::move(packet));
  auto response = model::packets::EncryptConnectionResponseBuilder::Create(
      properties_.GetAddress(), peer, security_manager_.GetKey(peer));
  SendLinkLayerPacket(std::move(response));
}

void LinkLayerController::IncomingEncryptConnectionResponse(
    model::packets::LinkLayerPacketView incoming) {
  LOG_INFO("%s", __func__);
  // TODO: Check keys
  uint16_t handle = connections_.GetHandle(incoming.GetSourceAddress());
  if (handle == acl::kReservedHandle) {
    LOG_INFO("%s: Unknown connection @%s", __func__, incoming.GetSourceAddress().ToString().c_str());
    return;
  }
  auto packet = bluetooth::hci::EncryptionChangeBuilder::Create(
      bluetooth::hci::ErrorCode::SUCCESS, handle,
      bluetooth::hci::EncryptionEnabled::ON);
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
      LOG_WARN("Unhandled Incoming Inquiry of type %d", static_cast<int>(inquiry.GetType()));
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
      LOG_WARN("Incoming Standard Inquiry Response");
      // TODO: Support multiple inquiries in the same packet.
      auto inquiry_response =
          model::packets::InquiryResponseView::Create(basic_inquiry_response);
      ASSERT(inquiry_response.IsValid());

      auto page_scan_repetition_mode =
          (bluetooth::hci::PageScanRepetitionMode)
              inquiry_response.GetPageScanRepetitionMode();

      auto packet = bluetooth::hci::InquiryResultBuilder::Create(
          0x01, inquiry_response.GetSourceAddress(), page_scan_repetition_mode,
          inquiry_response.GetClassOfDevice(),
          inquiry_response.GetClockOffset());

      send_event_(std::move(packet));
    } break;

    case (model::packets::InquiryType::RSSI): {
      LOG_WARN("Incoming RSSI Inquiry Response");
      auto inquiry_response =
          model::packets::InquiryResponseWithRssiView::Create(
              basic_inquiry_response);
      ASSERT(inquiry_response.IsValid());

      auto page_scan_repetition_mode =
          (bluetooth::hci::PageScanRepetitionMode)
              inquiry_response.GetPageScanRepetitionMode();

      auto packet = bluetooth::hci::InquiryResultWithRssiBuilder::Create(
          0x01, inquiry_response.GetSourceAddress(), page_scan_repetition_mode,
          inquiry_response.GetClassOfDevice(),
          inquiry_response.GetClockOffset(), inquiry_response.GetRssi());
      send_event_(std::move(packet));
    } break;

    case (model::packets::InquiryType::EXTENDED): {
      LOG_WARN("Incoming Extended Inquiry Response");
      auto inquiry_response =
          model::packets::ExtendedInquiryResponseView::Create(
              basic_inquiry_response);
      ASSERT(inquiry_response.IsValid());

      std::unique_ptr<bluetooth::packet::RawBuilder> raw_builder_ptr =
          std::make_unique<bluetooth::packet::RawBuilder>();
      raw_builder_ptr->AddOctets1(0x01);  // num_responses
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

      auto packet = bluetooth::hci::EventPacketBuilder::Create(
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
  LOG_DEBUG("%s", __func__);
  if (!simple_pairing_mode_enabled_) {
    LOG_WARN("%s: Only simple pairing mode is implemented", __func__);
    return;
  }

  auto request = model::packets::IoCapabilityRequestView::Create(incoming);
  ASSERT(request.IsValid());

  Address peer = incoming.GetSourceAddress();
  uint8_t io_capability = request.GetIoCapability();
  uint8_t oob_data_present = request.GetOobDataPresent();
  uint8_t authentication_requirements = request.GetAuthenticationRequirements();

  uint16_t handle = connections_.GetHandle(peer);
  if (handle == acl::kReservedHandle) {
    LOG_INFO("%s: Device not connected %s", __func__, peer.ToString().c_str());
    return;
  }

  security_manager_.AuthenticationRequest(peer, handle);

  security_manager_.SetPeerIoCapability(peer, io_capability, oob_data_present, authentication_requirements);

  auto packet = bluetooth::hci::IoCapabilityResponseBuilder::Create(
      peer, static_cast<bluetooth::hci::IoCapability>(io_capability),
      static_cast<bluetooth::hci::OobDataPresent>(oob_data_present),
      static_cast<bluetooth::hci::AuthenticationRequirements>(
          authentication_requirements));
  send_event_(std::move(packet));

  StartSimplePairing(peer);
}

void LinkLayerController::IncomingIoCapabilityResponsePacket(
    model::packets::LinkLayerPacketView incoming) {
  LOG_DEBUG("%s", __func__);

  auto response = model::packets::IoCapabilityResponseView::Create(incoming);
  ASSERT(response.IsValid());

  Address peer = incoming.GetSourceAddress();
  uint8_t io_capability = response.GetIoCapability();
  uint8_t oob_data_present = response.GetOobDataPresent();
  uint8_t authentication_requirements = response.GetAuthenticationRequirements();

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
    LOG_INFO("%s: Security Manager returned INVALID", __func__);
  }
}

void LinkLayerController::IncomingIoCapabilityNegativeResponsePacket(
    model::packets::LinkLayerPacketView incoming) {
  LOG_DEBUG("%s", __func__);
  Address peer = incoming.GetSourceAddress();

  ASSERT(security_manager_.GetAuthenticationAddress() == peer);

  security_manager_.InvalidateIoCapabilities();
}

void LinkLayerController::IncomingLeAdvertisementPacket(
    model::packets::LinkLayerPacketView incoming) {
  // TODO: Handle multiple advertisements per packet.

  Address address = incoming.GetSourceAddress();
  auto advertisement = model::packets::LeAdvertisementView::Create(incoming);
  ASSERT(advertisement.IsValid());
  auto adv_type = static_cast<LeAdvertisement::AdvertisementType>(
      advertisement.GetAdvertisementType());
  auto address_type =
      static_cast<LeAdvertisement::AddressType>(advertisement.GetAddressType());

  if (le_scan_enable_) {
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
    auto packet = bluetooth::hci::EventPacketBuilder::Create(
        bluetooth::hci::EventCode::LE_META_EVENT, std::move(raw_builder_ptr));
    send_event_(std::move(packet));
  }

  // Active scanning
  if (le_scan_enable_ && le_scan_type_ == 1) {
    auto to_send = model::packets::LeScanBuilder::Create(
        properties_.GetLeAddress(), address);
    SendLeLinkLayerPacket(std::move(to_send));
  }

  // Connect
  if ((le_connect_ && le_peer_address_ == address && le_peer_address_type_ == static_cast<uint8_t>(address_type) &&
       (adv_type == LeAdvertisement::AdvertisementType::ADV_IND ||
        adv_type == LeAdvertisement::AdvertisementType::ADV_DIRECT_IND)) ||
      (LeWhiteListContainsDevice(address, static_cast<uint8_t>(address_type)))) {
    if (!connections_.CreatePendingLeConnection(incoming.GetSourceAddress(), static_cast<uint8_t>(address_type))) {
      LOG_WARN("%s: CreatePendingLeConnection failed for connection to %s (type %hhx)", __func__,
               incoming.GetSourceAddress().ToString().c_str(), address_type);
    }
    LOG_INFO("%s: connecting to %s (type %hhx)", __func__, incoming.GetSourceAddress().ToString().c_str(),
             address_type);
    le_connect_ = false;
    le_scan_enable_ = false;

    auto to_send = model::packets::LeConnectBuilder::Create(
        properties_.GetLeAddress(), incoming.GetSourceAddress(),
        le_connection_interval_min_, le_connection_interval_max_,
        le_connection_latency_, le_connection_supervision_timeout_,
        static_cast<uint8_t>(le_address_type_));

    SendLeLinkLayerPacket(std::move(to_send));
  }
}

void LinkLayerController::HandleLeConnection(Address address, uint8_t address_type, uint8_t own_address_type,
                                             uint8_t role, uint16_t connection_interval, uint16_t connection_latency,
                                             uint16_t supervision_timeout) {
  // TODO: Choose between LeConnectionComplete and LeEnhancedConnectionComplete
  uint16_t handle = connections_.CreateLeConnection(address, address_type, own_address_type);
  if (handle == acl::kReservedHandle) {
    LOG_WARN("%s: No pending connection for connection from %s (type %hhx)", __func__, address.ToString().c_str(),
             address_type);
    return;
  }
  auto packet = bluetooth::hci::LeConnectionCompleteBuilder::Create(
      bluetooth::hci::ErrorCode::SUCCESS, handle,
      static_cast<bluetooth::hci::Role>(role),
      static_cast<bluetooth::hci::AddressType>(address_type), address,
      connection_interval, connection_latency, supervision_timeout,
      static_cast<bluetooth::hci::MasterClockAccuracy>(0x00));
  send_event_(std::move(packet));
}

void LinkLayerController::IncomingLeConnectPacket(
    model::packets::LinkLayerPacketView incoming) {
  auto connect = model::packets::LeConnectView::Create(incoming);
  ASSERT(connect.IsValid());
  uint16_t connection_interval = (connect.GetLeConnectionIntervalMax() + connect.GetLeConnectionIntervalMin()) / 2;
  if (!connections_.CreatePendingLeConnection(incoming.GetSourceAddress(),
                                              static_cast<uint8_t>(connect.GetAddressType()))) {
    LOG_WARN("%s: CreatePendingLeConnection failed for connection from %s (type %hhx)", __func__,
             incoming.GetSourceAddress().ToString().c_str(), connect.GetAddressType());
    return;
  }
  HandleLeConnection(incoming.GetSourceAddress(), static_cast<uint8_t>(connect.GetAddressType()),
                     static_cast<uint8_t>(properties_.GetLeAdvertisingOwnAddressType()),
                     static_cast<uint8_t>(hci::Role::SLAVE), connection_interval, connect.GetLeConnectionLatency(),
                     connect.GetLeConnectionSupervisionTimeout());

  auto to_send = model::packets::LeConnectCompleteBuilder::Create(
      incoming.GetDestinationAddress(), incoming.GetSourceAddress(),
      connection_interval, connect.GetLeConnectionLatency(),
      connect.GetLeConnectionSupervisionTimeout(),
      properties_.GetLeAdvertisingOwnAddressType());
  SendLeLinkLayerPacket(std::move(to_send));
}

void LinkLayerController::IncomingLeConnectCompletePacket(
    model::packets::LinkLayerPacketView incoming) {
  auto complete = model::packets::LeConnectCompleteView::Create(incoming);
  ASSERT(complete.IsValid());
  HandleLeConnection(incoming.GetSourceAddress(), static_cast<uint8_t>(complete.GetAddressType()),
                     static_cast<uint8_t>(le_address_type_), static_cast<uint8_t>(hci::Role::MASTER),
                     complete.GetLeConnectionInterval(), complete.GetLeConnectionLatency(),
                     complete.GetLeConnectionSupervisionTimeout());
}

void LinkLayerController::IncomingLeScanPacket(
    model::packets::LinkLayerPacketView incoming) {
  LOG_INFO("LE Scan Packet");

  auto to_send = model::packets::LeScanResponseBuilder::Create(
      properties_.GetLeAddress(), incoming.GetSourceAddress(),
      static_cast<model::packets::AddressType>(properties_.GetLeAddressType()),
      static_cast<model::packets::AdvertisementType>(
          properties_.GetLeAdvertisementType()),
      properties_.GetLeScanResponse());

  SendLeLinkLayerPacket(std::move(to_send));
}

void LinkLayerController::IncomingLeScanResponsePacket(
    model::packets::LinkLayerPacketView incoming) {
  auto scan_response = model::packets::LeScanResponseView::Create(incoming);
  ASSERT(scan_response.IsValid());
  vector<uint8_t> ad = scan_response.GetData();
  auto adv_type = static_cast<LeAdvertisement::AdvertisementType>(
      scan_response.GetAdvertisementType());
  auto address_type =
      static_cast<LeAdvertisement::AddressType>(scan_response.GetAddressType());

  std::unique_ptr<bluetooth::packet::RawBuilder> raw_builder_ptr =
      std::make_unique<bluetooth::packet::RawBuilder>();
  raw_builder_ptr->AddOctets1(
      static_cast<uint8_t>(bluetooth::hci::SubeventCode::ADVERTISING_REPORT));
  raw_builder_ptr->AddOctets1(0x01);  // num reports
  raw_builder_ptr->AddOctets1(static_cast<uint8_t>(adv_type));
  raw_builder_ptr->AddOctets1(static_cast<uint8_t>(address_type));
  raw_builder_ptr->AddAddress(incoming.GetSourceAddress());
  raw_builder_ptr->AddOctets1(ad.size());
  raw_builder_ptr->AddOctets(ad);
  raw_builder_ptr->AddOctets1(GetRssi());
  auto packet = bluetooth::hci::EventPacketBuilder::Create(
      bluetooth::hci::EventCode::LE_META_EVENT, std::move(raw_builder_ptr));
  send_event_(std::move(packet));
}

void LinkLayerController::IncomingPagePacket(
    model::packets::LinkLayerPacketView incoming) {
  auto page = model::packets::PageView::Create(incoming);
  ASSERT(page.IsValid());
  LOG_INFO("%s from %s", __func__, incoming.GetSourceAddress().ToString().c_str());

  if (!connections_.CreatePendingConnection(incoming.GetSourceAddress())) {
    // Send a response to indicate that we're busy, or drop the packet?
    LOG_WARN("%s: Failed to create a pending connection for %s", __func__,
             incoming.GetSourceAddress().ToString().c_str());
  }

  bluetooth::hci::Address source_address;
  bluetooth::hci::Address::FromString(page.GetSourceAddress().ToString(),
                                      source_address);

  auto packet = bluetooth::hci::ConnectionRequestBuilder::Create(
      source_address, page.GetClassOfDevice(),
      bluetooth::hci::ConnectionRequestLinkType::ACL);

  send_event_(std::move(packet));
}

void LinkLayerController::IncomingPageRejectPacket(
    model::packets::LinkLayerPacketView incoming) {
  LOG_INFO("%s: %s", __func__, incoming.GetSourceAddress().ToString().c_str());
  auto reject = model::packets::PageRejectView::Create(incoming);
  ASSERT(reject.IsValid());
  LOG_INFO("%s: Sending CreateConnectionComplete", __func__);
  auto packet = bluetooth::hci::ConnectionCompleteBuilder::Create(
      static_cast<bluetooth::hci::ErrorCode>(reject.GetReason()), 0x0eff,
      incoming.GetSourceAddress(), bluetooth::hci::LinkType::ACL,
      bluetooth::hci::Enable::DISABLED);
  send_event_(std::move(packet));
}

void LinkLayerController::IncomingPageResponsePacket(
    model::packets::LinkLayerPacketView incoming) {
  LOG_INFO("%s: %s", __func__, incoming.GetSourceAddress().ToString().c_str());
  uint16_t handle = connections_.CreateConnection(incoming.GetSourceAddress());
  if (handle == acl::kReservedHandle) {
    LOG_WARN("%s: No free handles", __func__);
    return;
  }
  auto packet = bluetooth::hci::ConnectionCompleteBuilder::Create(
      bluetooth::hci::ErrorCode::SUCCESS, handle, incoming.GetSourceAddress(),
      bluetooth::hci::LinkType::ACL, bluetooth::hci::Enable::DISABLED);
  send_event_(std::move(packet));
}

void LinkLayerController::IncomingResponsePacket(
    model::packets::LinkLayerPacketView incoming) {
  auto response = model::packets::ResponseView::Create(incoming);
  ASSERT(response.IsValid());

  // TODO: Check to see if I'm expecting this response.

  hci::OpCode opcode = static_cast<hci::OpCode>(response.GetOpcode());
  auto args = response.GetPayload().begin();
  auto status = static_cast<bluetooth::hci::ErrorCode>(args.extract<uint8_t>());

  uint16_t handle = connections_.GetHandle(incoming.GetSourceAddress());

  switch (opcode) {
    case (hci::OpCode::REMOTE_NAME_REQUEST): {
      std::array<uint8_t, 248> remote_name;
      remote_name.fill(0x00);
      uint64_t len = args.extract<uint64_t>();
      if (len > 247) {
        len = 247;  // one byte for NULL octet (0x00)
      }
      for (uint64_t i = 0; i < len; i++) {
        remote_name[i] = args.extract<uint8_t>();
      }
      auto packet = bluetooth::hci::RemoteNameRequestCompleteBuilder::Create(
          status, incoming.GetSourceAddress(), remote_name);
      send_event_(std::move(packet));
    } break;
    case (hci::OpCode::READ_REMOTE_SUPPORTED_FEATURES): {
      auto packet =
          bluetooth::hci::ReadRemoteSupportedFeaturesCompleteBuilder::Create(
              status, handle, args.extract<uint64_t>());
      send_event_(std::move(packet));
    } break;
    case (hci::OpCode::READ_REMOTE_EXTENDED_FEATURES): {
      if (status == bluetooth::hci::ErrorCode::SUCCESS) {
        auto packet =
            bluetooth::hci::ReadRemoteExtendedFeaturesCompleteBuilder::Create(
                status, handle, args.extract<uint8_t>(),
                args.extract<uint8_t>(), args.extract<uint64_t>());
        send_event_(std::move(packet));
      } else {
        auto packet =
            bluetooth::hci::ReadRemoteExtendedFeaturesCompleteBuilder::Create(
                status, handle, 0, 0, 0);
        send_event_(std::move(packet));
      }
    } break;
    case (hci::OpCode::READ_REMOTE_VERSION_INFORMATION): {
      auto packet =
          bluetooth::hci::ReadRemoteVersionInformationCompleteBuilder::Create(
              status, handle, args.extract<uint8_t>(), args.extract<uint16_t>(),
              args.extract<uint16_t>());
      send_event_(std::move(packet));
      LOG_INFO("Read remote version handle 0x%04x", handle);
    } break;
    case (hci::OpCode::READ_CLOCK_OFFSET): {
      auto packet = bluetooth::hci::ReadClockOffsetCompleteBuilder::Create(
          status, handle, args.extract<uint16_t>());
      send_event_(std::move(packet));
    } break;
    default:
      LOG_INFO("Unhandled response to command 0x%04x", static_cast<uint16_t>(opcode));
  }
}

void LinkLayerController::TimerTick() {
  if (inquiry_state_ == Inquiry::InquiryState::INQUIRY) Inquiry();
  if (inquiry_state_ == Inquiry::InquiryState::INQUIRY) PageScan();
  LeAdvertising();
  Connections();
}

void LinkLayerController::LeAdvertising() {
  if (!le_advertising_enable_) {
    return;
  }
  steady_clock::time_point now = steady_clock::now();
  if (duration_cast<milliseconds>(now - last_le_advertisement_) < milliseconds(200)) {
    return;
  }
  last_le_advertisement_ = now;

  auto own_address_type = static_cast<model::packets::AddressType>(
      properties_.GetLeAdvertisingOwnAddressType());
  Address advertising_address = Address::kEmpty;
  if (own_address_type == model::packets::AddressType::PUBLIC) {
    advertising_address = properties_.GetAddress();
  } else if (own_address_type == model::packets::AddressType::RANDOM) {
    advertising_address = properties_.GetLeAddress();
  }
  ASSERT(advertising_address != Address::kEmpty);
  auto to_send = model::packets::LeAdvertisementBuilder::Create(
      advertising_address, Address::kEmpty, own_address_type,
      static_cast<model::packets::AdvertisementType>(own_address_type),
      properties_.GetLeAdvertisement());
  SendLeLinkLayerPacket(std::move(to_send));
}

void LinkLayerController::Connections() {
  // TODO: Keep connections alive?
}

void LinkLayerController::RegisterEventChannel(
    const std::function<
        void(std::shared_ptr<bluetooth::hci::EventPacketBuilder>)>& callback) {
  send_event_ = callback;
}

void LinkLayerController::RegisterAclChannel(
    const std::function<void(std::shared_ptr<std::vector<uint8_t>>)>& callback) {
  send_acl_ = callback;
}

void LinkLayerController::RegisterScoChannel(
    const std::function<void(std::shared_ptr<std::vector<uint8_t>>)>& callback) {
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
    std::function<AsyncTaskId(milliseconds, const TaskCallback&)> event_scheduler) {
  schedule_task_ = event_scheduler;
}

AsyncTaskId LinkLayerController::ScheduleTask(milliseconds delay_ms, const TaskCallback& callback) {
  if (schedule_task_) {
    return schedule_task_(delay_ms, callback);
  } else {
    callback();
    return 0;
  }
}

void LinkLayerController::RegisterPeriodicTaskScheduler(
    std::function<AsyncTaskId(milliseconds, milliseconds, const TaskCallback&)> periodic_event_scheduler) {
  schedule_periodic_task_ = periodic_event_scheduler;
}

void LinkLayerController::CancelScheduledTask(AsyncTaskId task_id) {
  if (schedule_task_ && cancel_task_) {
    cancel_task_(task_id);
  }
}

void LinkLayerController::RegisterTaskCancel(std::function<void(AsyncTaskId)> task_cancel) {
  cancel_task_ = task_cancel;
}

void LinkLayerController::AddControllerEvent(milliseconds delay, const TaskCallback& task) {
  controller_events_.push_back(ScheduleTask(delay, task));
}

void LinkLayerController::WriteSimplePairingMode(bool enabled) {
  ASSERT_LOG(enabled, "The spec says don't disable this!");
  simple_pairing_mode_enabled_ = enabled;
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

void LinkLayerController::AuthenticateRemoteStage1(const Address& peer, PairingType pairing_type) {
  ASSERT(security_manager_.GetAuthenticationAddress() == peer);
  // TODO: Public key exchange first?
  switch (pairing_type) {
    case PairingType::AUTO_CONFIRMATION: {
      auto packet =
          bluetooth::hci::UserConfirmationRequestBuilder::Create(peer, 123456);
      send_event_(std::move(packet));
    } break;
    case PairingType::CONFIRM_Y_N:
      LOG_ALWAYS_FATAL("Unimplemented PairingType %d", static_cast<int>(pairing_type));
      break;
    case PairingType::DISPLAY_PIN:
      LOG_ALWAYS_FATAL("Unimplemented PairingType %d", static_cast<int>(pairing_type));
      break;
    case PairingType::DISPLAY_AND_CONFIRM:
      LOG_ALWAYS_FATAL("Unimplemented PairingType %d", static_cast<int>(pairing_type));
      break;
    case PairingType::INPUT_PIN:
      LOG_ALWAYS_FATAL("Unimplemented PairingType %d", static_cast<int>(pairing_type));
      break;
    case PairingType::INVALID:
      LOG_ALWAYS_FATAL("Unimplemented PairingType %d", static_cast<int>(pairing_type));
      break;
    default:
      LOG_ALWAYS_FATAL("Invalid PairingType %d", static_cast<int>(pairing_type));
  }
}

void LinkLayerController::AuthenticateRemoteStage2(const Address& peer) {
  uint16_t handle = security_manager_.GetAuthenticationHandle();
  ASSERT(security_manager_.GetAuthenticationAddress() == peer);
  // Check key in security_manager_ ?
  auto packet = bluetooth::hci::AuthenticationCompleteBuilder::Create(
      bluetooth::hci::ErrorCode::SUCCESS, handle);
  send_event_(std::move(packet));
}

bluetooth::hci::ErrorCode LinkLayerController::LinkKeyRequestReply(
    const Address& peer, PacketView<true> key) {
  std::vector<uint8_t> key_vec(key.begin(), key.end());
  security_manager_.WriteKey(peer, key_vec);
  security_manager_.AuthenticationRequestFinished();

  ScheduleTask(milliseconds(5), [this, peer]() { AuthenticateRemoteStage2(peer); });

  return bluetooth::hci::ErrorCode::SUCCESS;
}

bluetooth::hci::ErrorCode LinkLayerController::LinkKeyRequestNegativeReply(
    const Address& address) {
  security_manager_.DeleteKey(address);
  // Simple pairing to get a key
  uint16_t handle = connections_.GetHandle(address);
  if (handle == acl::kReservedHandle) {
    LOG_INFO("%s: Device not connected %s", __func__, address.ToString().c_str());
    return bluetooth::hci::ErrorCode::UNKNOWN_CONNECTION;
  }

  security_manager_.AuthenticationRequest(address, handle);

  ScheduleTask(milliseconds(5), [this, address]() { StartSimplePairing(address); });
  return bluetooth::hci::ErrorCode::SUCCESS;
}

bluetooth::hci::ErrorCode LinkLayerController::IoCapabilityRequestReply(
    const Address& peer, uint8_t io_capability, uint8_t oob_data_present_flag,
    uint8_t authentication_requirements) {
  security_manager_.SetLocalIoCapability(peer, io_capability, oob_data_present_flag, authentication_requirements);

  PairingType pairing_type = security_manager_.GetSimplePairingType();

  if (pairing_type != PairingType::INVALID) {
    ScheduleTask(milliseconds(5), [this, peer, pairing_type]() { AuthenticateRemoteStage1(peer, pairing_type); });
    auto packet = model::packets::IoCapabilityResponseBuilder::Create(
        properties_.GetAddress(), peer, io_capability, oob_data_present_flag,
        authentication_requirements);
    SendLinkLayerPacket(std::move(packet));

  } else {
    LOG_INFO("%s: Requesting remote capability", __func__);

    auto packet = model::packets::IoCapabilityRequestBuilder::Create(
        properties_.GetAddress(), peer, io_capability, oob_data_present_flag,
        authentication_requirements);
    SendLinkLayerPacket(std::move(packet));
  }

  return bluetooth::hci::ErrorCode::SUCCESS;
}

bluetooth::hci::ErrorCode LinkLayerController::IoCapabilityRequestNegativeReply(
    const Address& peer, hci::Status reason) {
  if (security_manager_.GetAuthenticationAddress() != peer) {
    return bluetooth::hci::ErrorCode::AUTHENTICATION_FAILURE;
  }

  security_manager_.InvalidateIoCapabilities();

  auto packet = model::packets::IoCapabilityNegativeResponseBuilder::Create(
      properties_.GetAddress(), peer, static_cast<uint8_t>(reason));
  SendLinkLayerPacket(std::move(packet));

  return bluetooth::hci::ErrorCode::SUCCESS;
}

bluetooth::hci::ErrorCode LinkLayerController::UserConfirmationRequestReply(
    const Address& peer) {
  if (security_manager_.GetAuthenticationAddress() != peer) {
    return bluetooth::hci::ErrorCode::AUTHENTICATION_FAILURE;
  }
  // TODO: Key could be calculated here.
  std::vector<uint8_t> key_vec{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
  security_manager_.WriteKey(peer, key_vec);

  security_manager_.AuthenticationRequestFinished();

  ScheduleTask(milliseconds(5), [this, peer]() { AuthenticateRemoteStage2(peer); });
  return bluetooth::hci::ErrorCode::SUCCESS;
}

bluetooth::hci::ErrorCode
LinkLayerController::UserConfirmationRequestNegativeReply(const Address& peer) {
  if (security_manager_.GetAuthenticationAddress() != peer) {
    return bluetooth::hci::ErrorCode::AUTHENTICATION_FAILURE;
  }
  return bluetooth::hci::ErrorCode::SUCCESS;
}

bluetooth::hci::ErrorCode LinkLayerController::UserPasskeyRequestReply(
    const Address& peer, uint32_t numeric_value) {
  if (security_manager_.GetAuthenticationAddress() != peer) {
    return bluetooth::hci::ErrorCode::AUTHENTICATION_FAILURE;
  }
  LOG_INFO("TODO:Do something with the passkey %06d", numeric_value);
  return bluetooth::hci::ErrorCode::SUCCESS;
}

bluetooth::hci::ErrorCode LinkLayerController::UserPasskeyRequestNegativeReply(
    const Address& peer) {
  if (security_manager_.GetAuthenticationAddress() != peer) {
    return bluetooth::hci::ErrorCode::AUTHENTICATION_FAILURE;
  }
  return bluetooth::hci::ErrorCode::SUCCESS;
}

bluetooth::hci::ErrorCode LinkLayerController::RemoteOobDataRequestReply(
    const Address& peer, const std::vector<uint8_t>& c,
    const std::vector<uint8_t>& r) {
  if (security_manager_.GetAuthenticationAddress() != peer) {
    return bluetooth::hci::ErrorCode::AUTHENTICATION_FAILURE;
  }
  LOG_INFO("TODO:Do something with the OOB data c=%d r=%d", c[0], r[0]);
  return bluetooth::hci::ErrorCode::SUCCESS;
}

bluetooth::hci::ErrorCode
LinkLayerController::RemoteOobDataRequestNegativeReply(const Address& peer) {
  if (security_manager_.GetAuthenticationAddress() != peer) {
    return bluetooth::hci::ErrorCode::AUTHENTICATION_FAILURE;
  }
  return bluetooth::hci::ErrorCode::SUCCESS;
}

void LinkLayerController::HandleAuthenticationRequest(const Address& address, uint16_t handle) {
  if (simple_pairing_mode_enabled_ == true) {
    security_manager_.AuthenticationRequest(address, handle);
    auto packet = bluetooth::hci::LinkKeyRequestBuilder::Create(address);
    send_event_(std::move(packet));
  } else {  // Should never happen for our phones
    // Check for a key, try to authenticate, ask for a PIN.
    auto packet = bluetooth::hci::AuthenticationCompleteBuilder::Create(
        bluetooth::hci::ErrorCode::AUTHENTICATION_FAILURE, handle);
    send_event_(std::move(packet));
  }
}

bluetooth::hci::ErrorCode LinkLayerController::AuthenticationRequested(
    uint16_t handle) {
  if (!connections_.HasHandle(handle)) {
    LOG_INFO("Authentication Requested for unknown handle %04x", handle);
    return bluetooth::hci::ErrorCode::UNKNOWN_CONNECTION;
  }

  Address remote = connections_.GetAddress(handle);

  ScheduleTask(milliseconds(5), [this, remote, handle]() { HandleAuthenticationRequest(remote, handle); });

  return bluetooth::hci::ErrorCode::SUCCESS;
}

void LinkLayerController::HandleSetConnectionEncryption(const Address& peer, uint16_t handle,
                                                        uint8_t encryption_enable) {
  // TODO: Block ACL traffic or at least guard against it

  if (connections_.IsEncrypted(handle) && encryption_enable) {
    auto packet = bluetooth::hci::EncryptionChangeBuilder::Create(
        bluetooth::hci::ErrorCode::SUCCESS, handle,
        static_cast<bluetooth::hci::EncryptionEnabled>(encryption_enable));
    send_event_(std::move(packet));
    return;
  }

  auto packet = model::packets::EncryptConnectionBuilder::Create(
      properties_.GetAddress(), peer, security_manager_.GetKey(peer));
  SendLinkLayerPacket(std::move(packet));
}

bluetooth::hci::ErrorCode LinkLayerController::SetConnectionEncryption(
    uint16_t handle, uint8_t encryption_enable) {
  if (!connections_.HasHandle(handle)) {
    LOG_INFO("Set Connection Encryption for unknown handle %04x", handle);
    return bluetooth::hci::ErrorCode::UNKNOWN_CONNECTION;
  }

  if (connections_.IsEncrypted(handle) && !encryption_enable) {
    return bluetooth::hci::ErrorCode::ENCRYPTION_MODE_NOT_ACCEPTABLE;
  }
  Address remote = connections_.GetAddress(handle);

  if (security_manager_.ReadKey(remote) == 0) {
    return bluetooth::hci::ErrorCode::PIN_OR_KEY_MISSING;
  }

  ScheduleTask(milliseconds(5), [this, remote, handle, encryption_enable]() {
    HandleSetConnectionEncryption(remote, handle, encryption_enable);
  });
  return bluetooth::hci::ErrorCode::SUCCESS;
}

bluetooth::hci::ErrorCode LinkLayerController::AcceptConnectionRequest(
    const Address& addr, bool try_role_switch) {
  if (!connections_.HasPendingConnection(addr)) {
    LOG_INFO("%s: No pending connection for %s", __func__, addr.ToString().c_str());
    return bluetooth::hci::ErrorCode::UNKNOWN_CONNECTION;
  }

  LOG_INFO("%s: Accept in 200ms", __func__);
  ScheduleTask(milliseconds(200), [this, addr, try_role_switch]() {
    LOG_INFO("%s: Accepted", __func__);
    MakeSlaveConnection(addr, try_role_switch);
  });

  return bluetooth::hci::ErrorCode::SUCCESS;
}

void LinkLayerController::MakeSlaveConnection(const Address& addr, bool try_role_switch) {
  LOG_INFO("%s sending page response to %s", __func__, addr.ToString().c_str());
  auto to_send = model::packets::PageResponseBuilder::Create(
      properties_.GetAddress(), addr, try_role_switch);
  SendLinkLayerPacket(std::move(to_send));

  uint16_t handle = connections_.CreateConnection(addr);
  if (handle == acl::kReservedHandle) {
    LOG_INFO("%s CreateConnection failed", __func__);
    return;
  }
  LOG_INFO("%s CreateConnection returned handle 0x%x", __func__, handle);
  auto packet = bluetooth::hci::ConnectionCompleteBuilder::Create(
      bluetooth::hci::ErrorCode::SUCCESS, handle, addr,
      bluetooth::hci::LinkType::ACL, bluetooth::hci::Enable::DISABLED);
  send_event_(std::move(packet));
}

bluetooth::hci::ErrorCode LinkLayerController::RejectConnectionRequest(
    const Address& addr, uint8_t reason) {
  if (!connections_.HasPendingConnection(addr)) {
    LOG_INFO("%s: No pending connection for %s", __func__, addr.ToString().c_str());
    return bluetooth::hci::ErrorCode::UNKNOWN_CONNECTION;
  }

  LOG_INFO("%s: Reject in 200ms", __func__);
  ScheduleTask(milliseconds(200), [this, addr, reason]() {
    LOG_INFO("%s: Reject", __func__);
    RejectSlaveConnection(addr, reason);
  });

  return bluetooth::hci::ErrorCode::SUCCESS;
}

void LinkLayerController::RejectSlaveConnection(const Address& addr, uint8_t reason) {
  auto to_send = model::packets::PageRejectBuilder::Create(
      properties_.GetAddress(), addr, reason);
  LOG_INFO("%s sending page reject to %s", __func__, addr.ToString().c_str());
  SendLinkLayerPacket(std::move(to_send));

  ASSERT(reason >= 0x0d && reason <= 0x0f);
  auto packet = bluetooth::hci::ConnectionCompleteBuilder::Create(
      static_cast<bluetooth::hci::ErrorCode>(reason), 0xeff, addr,
      bluetooth::hci::LinkType::ACL, bluetooth::hci::Enable::DISABLED);
  send_event_(std::move(packet));
}

bluetooth::hci::ErrorCode LinkLayerController::CreateConnection(
    const Address& addr, uint16_t, uint8_t, uint16_t,
    uint8_t allow_role_switch) {
  if (!connections_.CreatePendingConnection(addr)) {
    return bluetooth::hci::ErrorCode::CONTROLLER_BUSY;
  }

  auto page = model::packets::PageBuilder::Create(
      properties_.GetAddress(), addr, properties_.GetClassOfDevice(),
      allow_role_switch);
  SendLinkLayerPacket(std::move(page));

  return bluetooth::hci::ErrorCode::SUCCESS;
}

bluetooth::hci::ErrorCode LinkLayerController::CreateConnectionCancel(
    const Address& addr) {
  if (!connections_.CancelPendingConnection(addr)) {
    return bluetooth::hci::ErrorCode::UNKNOWN_CONNECTION;
  }
  return bluetooth::hci::ErrorCode::SUCCESS;
}

bluetooth::hci::ErrorCode LinkLayerController::Disconnect(uint16_t handle,
                                                          uint8_t reason) {
  // TODO: Handle LE
  if (!connections_.HasHandle(handle)) {
    return bluetooth::hci::ErrorCode::UNKNOWN_CONNECTION;
  }

  const Address& remote = connections_.GetAddress(handle);
  auto packet = model::packets::DisconnectBuilder::Create(
      properties_.GetAddress(), remote, reason);
  SendLinkLayerPacket(std::move(packet));
  ASSERT_LOG(connections_.Disconnect(handle), "Disconnecting %hx", handle);

  ScheduleTask(milliseconds(20), [this, handle]() {
    DisconnectCleanup(handle, static_cast<uint8_t>(hci::Status::CONNECTION_TERMINATED_BY_LOCAL_HOST));
  });

  return bluetooth::hci::ErrorCode::SUCCESS;
}

void LinkLayerController::DisconnectCleanup(uint16_t handle, uint8_t reason) {
  // TODO: Clean up other connection state.
  auto packet = bluetooth::hci::DisconnectionCompleteBuilder::Create(
      bluetooth::hci::ErrorCode::SUCCESS, handle,
      static_cast<bluetooth::hci::ErrorCode>(reason));
  send_event_(std::move(packet));
}

bluetooth::hci::ErrorCode LinkLayerController::ChangeConnectionPacketType(
    uint16_t handle, uint16_t types) {
  if (!connections_.HasHandle(handle)) {
    return bluetooth::hci::ErrorCode::UNKNOWN_CONNECTION;
  }
  auto packet = bluetooth::hci::ConnectionPacketTypeChangedBuilder::Create(
      bluetooth::hci::ErrorCode::SUCCESS, handle, types);
  std::shared_ptr<bluetooth::hci::ConnectionPacketTypeChangedBuilder>
      shared_packet = std::move(packet);
  ScheduleTask(milliseconds(20), [this, shared_packet]() {
    send_event_(std::move(shared_packet));
  });

  return bluetooth::hci::ErrorCode::SUCCESS;
}

bluetooth::hci::ErrorCode LinkLayerController::ChangeConnectionLinkKey(
    uint16_t handle) {
  if (!connections_.HasHandle(handle)) {
    return bluetooth::hci::ErrorCode::UNKNOWN_CONNECTION;
  }

  // TODO: implement real logic
  return bluetooth::hci::ErrorCode::COMMAND_DISALLOWED;
}

bluetooth::hci::ErrorCode LinkLayerController::MasterLinkKey(
    uint8_t /* key_flag */) {
  // TODO: implement real logic
  return bluetooth::hci::ErrorCode::COMMAND_DISALLOWED;
}

bluetooth::hci::ErrorCode LinkLayerController::HoldMode(
    uint16_t handle, uint16_t hold_mode_max_interval,
    uint16_t hold_mode_min_interval) {
  if (!connections_.HasHandle(handle)) {
    return bluetooth::hci::ErrorCode::UNKNOWN_CONNECTION;
  }

  if (hold_mode_max_interval < hold_mode_min_interval) {
    return bluetooth::hci::ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
  }

  // TODO: implement real logic
  return bluetooth::hci::ErrorCode::COMMAND_DISALLOWED;
}

bluetooth::hci::ErrorCode LinkLayerController::SniffMode(
    uint16_t handle, uint16_t sniff_max_interval, uint16_t sniff_min_interval,
    uint16_t sniff_attempt, uint16_t sniff_timeout) {
  if (!connections_.HasHandle(handle)) {
    return bluetooth::hci::ErrorCode::UNKNOWN_CONNECTION;
  }

  if (sniff_max_interval < sniff_min_interval || sniff_attempt < 0x0001 || sniff_attempt > 0x7FFF ||
      sniff_timeout > 0x7FFF) {
    return bluetooth::hci::ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
  }

  // TODO: implement real logic
  return bluetooth::hci::ErrorCode::COMMAND_DISALLOWED;
}

bluetooth::hci::ErrorCode LinkLayerController::ExitSniffMode(uint16_t handle) {
  if (!connections_.HasHandle(handle)) {
    return bluetooth::hci::ErrorCode::UNKNOWN_CONNECTION;
  }

  // TODO: implement real logic
  return bluetooth::hci::ErrorCode::COMMAND_DISALLOWED;
}

bluetooth::hci::ErrorCode LinkLayerController::QosSetup(
    uint16_t handle, uint8_t service_type, uint32_t /* token_rate */,
    uint32_t /* peak_bandwidth */, uint32_t /* latency */,
    uint32_t /* delay_variation */) {
  if (!connections_.HasHandle(handle)) {
    return bluetooth::hci::ErrorCode::UNKNOWN_CONNECTION;
  }

  if (service_type > 0x02) {
    return bluetooth::hci::ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
  }

  // TODO: implement real logic
  return bluetooth::hci::ErrorCode::COMMAND_DISALLOWED;
}

bluetooth::hci::ErrorCode LinkLayerController::SwitchRole(Address /* bd_addr */,
                                                          uint8_t /* role */) {
  // TODO: implement real logic
  return bluetooth::hci::ErrorCode::COMMAND_DISALLOWED;
}

bluetooth::hci::ErrorCode LinkLayerController::WriteLinkPolicySettings(
    uint16_t handle, uint16_t) {
  if (!connections_.HasHandle(handle)) {
    return bluetooth::hci::ErrorCode::UNKNOWN_CONNECTION;
  }
  return bluetooth::hci::ErrorCode::SUCCESS;
}

bluetooth::hci::ErrorCode LinkLayerController::FlowSpecification(
    uint16_t handle, uint8_t flow_direction, uint8_t service_type,
    uint32_t /* token_rate */, uint32_t /* token_bucket_size */,
    uint32_t /* peak_bandwidth */, uint32_t /* access_latency */) {
  if (!connections_.HasHandle(handle)) {
    return bluetooth::hci::ErrorCode::UNKNOWN_CONNECTION;
  }

  if (flow_direction > 0x01 || service_type > 0x02) {
    return bluetooth::hci::ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
  }

  // TODO: implement real logic
  return bluetooth::hci::ErrorCode::COMMAND_DISALLOWED;
}

bluetooth::hci::ErrorCode LinkLayerController::WriteLinkSupervisionTimeout(
    uint16_t handle, uint16_t) {
  if (!connections_.HasHandle(handle)) {
    return bluetooth::hci::ErrorCode::UNKNOWN_CONNECTION;
  }
  return bluetooth::hci::ErrorCode::SUCCESS;
}

void LinkLayerController::LeWhiteListClear() {
  le_white_list_.clear();
}

void LinkLayerController::LeResolvingListClear() { le_resolving_list_.clear(); }

void LinkLayerController::LeWhiteListAddDevice(Address addr, uint8_t addr_type) {
  std::tuple<Address, uint8_t> new_tuple = std::make_tuple(addr, addr_type);
  for (auto dev : le_white_list_) {
    if (dev == new_tuple) {
      return;
    }
  }
  le_white_list_.emplace_back(new_tuple);
}

void LinkLayerController::LeResolvingListAddDevice(
    Address addr, uint8_t addr_type, std::array<uint8_t, kIrk_size> peerIrk,
    std::array<uint8_t, kIrk_size> localIrk) {
  std::tuple<Address, uint8_t, std::array<uint8_t, kIrk_size>,
             std::array<uint8_t, kIrk_size>>
      new_tuple = std::make_tuple(addr, addr_type, peerIrk, localIrk);
  for (size_t i = 0; i < le_white_list_.size(); i++) {
    auto curr = le_white_list_[i];
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

void LinkLayerController::LeWhiteListRemoveDevice(Address addr, uint8_t addr_type) {
  // TODO: Add checks to see if advertising, scanning, or a connection request
  // with the white list is ongoing.
  std::tuple<Address, uint8_t> erase_tuple = std::make_tuple(addr, addr_type);
  for (size_t i = 0; i < le_white_list_.size(); i++) {
    if (le_white_list_[i] == erase_tuple) {
      le_white_list_.erase(le_white_list_.begin() + i);
    }
  }
}

void LinkLayerController::LeResolvingListRemoveDevice(Address addr,
                                                      uint8_t addr_type) {
  // TODO: Add checks to see if advertising, scanning, or a connection request
  // with the white list is ongoing.
  for (size_t i = 0; i < le_white_list_.size(); i++) {
    auto curr = le_white_list_[i];
    if (std::get<0>(curr) == addr && std::get<1>(curr) == addr_type) {
      le_resolving_list_.erase(le_resolving_list_.begin() + i);
    }
  }
}

bool LinkLayerController::LeWhiteListContainsDevice(Address addr, uint8_t addr_type) {
  std::tuple<Address, uint8_t> sought_tuple = std::make_tuple(addr, addr_type);
  for (size_t i = 0; i < le_white_list_.size(); i++) {
    if (le_white_list_[i] == sought_tuple) {
      return true;
    }
  }
  return false;
}

bool LinkLayerController::LeResolvingListContainsDevice(Address addr,
                                                        uint8_t addr_type) {
  for (size_t i = 0; i < le_white_list_.size(); i++) {
    auto curr = le_white_list_[i];
    if (std::get<0>(curr) == addr && std::get<1>(curr) == addr_type) {
      return true;
    }
  }
  return false;
}

bool LinkLayerController::LeWhiteListFull() {
  return le_white_list_.size() >= properties_.GetLeWhiteListSize();
}

bool LinkLayerController::LeResolvingListFull() {
  return le_resolving_list_.size() >= properties_.GetLeResolvingListSize();
}

void LinkLayerController::Reset() {
  inquiry_state_ = Inquiry::InquiryState::STANDBY;
  last_inquiry_ = steady_clock::now();
  le_scan_enable_ = 0;
  le_advertising_enable_ = 0;
  le_connect_ = 0;
}

void LinkLayerController::PageScan() {}

void LinkLayerController::StartInquiry(milliseconds timeout) {
  ScheduleTask(milliseconds(timeout), [this]() { LinkLayerController::InquiryTimeout(); });
  inquiry_state_ = Inquiry::InquiryState::INQUIRY;
  LOG_INFO("InquiryState = %d ", static_cast<int>(inquiry_state_));
}

void LinkLayerController::InquiryCancel() {
  ASSERT(inquiry_state_ == Inquiry::InquiryState::INQUIRY);
  inquiry_state_ = Inquiry::InquiryState::STANDBY;
}

void LinkLayerController::InquiryTimeout() {
  if (inquiry_state_ == Inquiry::InquiryState::INQUIRY) {
    inquiry_state_ = Inquiry::InquiryState::STANDBY;
    auto packet = bluetooth::hci::InquiryCompleteBuilder::Create(
        bluetooth::hci::ErrorCode::SUCCESS);
    send_event_(std::move(packet));
  }
}

void LinkLayerController::SetInquiryMode(uint8_t mode) {
  inquiry_mode_ = static_cast<model::packets::InquiryType>(mode);
}

void LinkLayerController::SetInquiryLAP(uint64_t lap) {
  inquiry_lap_ = lap;
}

void LinkLayerController::SetInquiryMaxResponses(uint8_t max) {
  inquiry_max_responses_ = max;
}

void LinkLayerController::Inquiry() {
  steady_clock::time_point now = steady_clock::now();
  if (duration_cast<milliseconds>(now - last_inquiry_) < milliseconds(2000)) {
    return;
  }
  LOG_INFO("Inquiry ");

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
