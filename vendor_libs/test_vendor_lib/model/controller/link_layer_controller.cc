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
#include "os/log.h"
#include "packets/hci/acl_packet_builder.h"
#include "packets/hci/command_packet_view.h"
#include "packets/hci/event_packet_builder.h"
#include "packets/hci/sco_packet_builder.h"

#include "packet/raw_builder.h"
#include "packets/link_layer_packets.h"

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

hci::Status LinkLayerController::SendCommandToRemoteByAddress(hci::OpCode opcode, PacketView<true> args,
                                                              const Address& remote, bool use_public_address) {
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
  return hci::Status::SUCCESS;
}

hci::Status LinkLayerController::SendCommandToRemoteByHandle(hci::OpCode opcode, PacketView<true> args,
                                                             uint16_t handle) {
  // TODO: Handle LE connections
  bool use_public_address = true;
  if (!connections_.HasHandle(handle)) {
    return hci::Status::UNKNOWN_CONNECTION;
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
    send_event_(EventPacketBuilder::CreateNumberOfCompletedPacketsEvent(handle, 1)->ToVector());
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

  switch (opcode) {
    case (hci::OpCode::REMOTE_NAME_REQUEST): {
      std::vector<uint8_t> name = properties_.GetName();
      LOG_INFO("Remote Name (Local Name) %d", static_cast<int>(name.size()));
      response_data.push_back(static_cast<uint8_t>(hci::Status::SUCCESS));
      response_data.push_back(name.size());
      uint64_t word = 0;
      for (size_t i = 0; i < name.size(); i++) {
        if (i > 0 && (i % 8 == 0)) {
          response_data.push_back(word);
          word = 0;
        }
        word |= static_cast<uint64_t>(name[i]) << (8 * (i % 8));
      }
      response_data.push_back(word);
    } break;
    case (hci::OpCode::READ_REMOTE_SUPPORTED_FEATURES):
      LOG_INFO("(%s) Remote Supported Features Requested by: %s %x",
               incoming.GetDestinationAddress().ToString().c_str(), incoming.GetSourceAddress().ToString().c_str(),
               static_cast<int>(properties_.GetSupportedFeatures()));
      response_data.push_back(static_cast<uint8_t>(hci::Status::SUCCESS));
      response_data.push_back(properties_.GetSupportedFeatures());
      break;
    case (hci::OpCode::READ_REMOTE_EXTENDED_FEATURES): {
      uint8_t page_number = (args + 2).extract<uint8_t>();  // skip the handle
      LOG_INFO("(%s) Remote Extended Features %d Requested by: %s", incoming.GetDestinationAddress().ToString().c_str(),
               page_number, incoming.GetSourceAddress().ToString().c_str());
      uint8_t max_page_number = properties_.GetExtendedFeaturesMaximumPageNumber();
      if (page_number > max_page_number) {
        response_data.push_back(static_cast<uint8_t>(hci::Status::INVALID_HCI_COMMAND_PARAMETERS));
        response_data.push_back(page_number);
        response_data.push_back(max_page_number);
        response_data.push_back(0);
      } else {
        response_data.push_back(static_cast<uint8_t>(hci::Status::SUCCESS));
        response_data.push_back(page_number);
        response_data.push_back(max_page_number);
        response_data.push_back(properties_.GetExtendedFeatures(page_number));
      }
    } break;
    case (hci::OpCode::READ_REMOTE_VERSION_INFORMATION):
      response_data.push_back(static_cast<uint8_t>(hci::Status::SUCCESS));
      response_data.push_back(properties_.GetLmpPalVersion());
      response_data.push_back(properties_.GetManufacturerName());
      response_data.push_back(properties_.GetLmpPalSubversion());
      break;
    case (hci::OpCode::READ_CLOCK_OFFSET):
      response_data.push_back(static_cast<uint8_t>(hci::Status::SUCCESS));
      response_data.push_back(properties_.GetClockOffset());
      break;
    default:
      LOG_INFO("Dropping unhandled command 0x%04x", static_cast<uint16_t>(opcode));
      return;
  }

  std::unique_ptr<bluetooth::packet::RawBuilder> raw_builder_ptr =
      std::make_unique<bluetooth::packet::RawBuilder>();
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
  send_event_(EventPacketBuilder::CreateEncryptionChange(hci::Status::SUCCESS, handle, 1)->ToVector());
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
  send_event_(EventPacketBuilder::CreateEncryptionChange(hci::Status::SUCCESS, handle, 1)->ToVector());
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
      std::unique_ptr<EventPacketBuilder> inquiry_result =
          EventPacketBuilder::CreateInquiryResultEvent();
      bool result_added = inquiry_result->AddInquiryResult(
          inquiry_response.GetSourceAddress(),
          inquiry_response.GetPageScanRepetitionMode(),
          inquiry_response.GetClassOfDevice(),
          inquiry_response.GetClockOffset());
      CHECK(result_added);
      send_event_(inquiry_result->ToVector());
    } break;

    case (model::packets::InquiryType::RSSI): {
      LOG_WARN("Incoming RSSI Inquiry Response");
      auto inquiry_response =
          model::packets::InquiryResponseWithRssiView::Create(
              basic_inquiry_response);
      ASSERT(inquiry_response.IsValid());
      send_event_(EventPacketBuilder::CreateExtendedInquiryResultEvent(
                      incoming.GetSourceAddress(),
                      inquiry_response.GetPageScanRepetitionMode(),
                      inquiry_response.GetClassOfDevice(),
                      inquiry_response.GetClockOffset(),
                      inquiry_response.GetRssi(), eir)
                      ->ToVector());
    } break;

    case (model::packets::InquiryType::EXTENDED): {
      LOG_WARN("Incoming Extended Inquiry Response");
      auto inquiry_response =
          model::packets::ExtendedInquiryResponseView::Create(
              basic_inquiry_response);
      ASSERT(inquiry_response.IsValid());
      eir = inquiry_response.GetExtendedData();
      send_event_(EventPacketBuilder::CreateExtendedInquiryResultEvent(
                      incoming.GetSourceAddress(),
                      inquiry_response.GetPageScanRepetitionMode(),
                      inquiry_response.GetClassOfDevice(),
                      inquiry_response.GetClockOffset(), GetRssi(), eir)
                      ->ToVector());
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

  send_event_(EventPacketBuilder::CreateIoCapabilityResponseEvent(peer, io_capability, oob_data_present,
                                                                  authentication_requirements)
                  ->ToVector());

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

  send_event_(
      EventPacketBuilder::CreateIoCapabilityResponseEvent(
          peer, io_capability, oob_data_present, authentication_requirements)
          ->ToVector());

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

    std::unique_ptr<EventPacketBuilder> le_adverts = EventPacketBuilder::CreateLeAdvertisingReportEvent();

    if (!le_adverts->AddLeAdvertisingReport(adv_type, address_type, address, ad, GetRssi())) {
      LOG_INFO("Couldn't add the advertising report.");
    } else {
      send_event_(le_adverts->ToVector());
    }
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
  send_event_(EventPacketBuilder::CreateLeConnectionCompleteEvent(
                  hci::Status::SUCCESS, handle, role, static_cast<uint8_t>(address_type), address, connection_interval,
                  connection_latency, supervision_timeout)
                  ->ToVector());
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

  std::unique_ptr<EventPacketBuilder> le_adverts = EventPacketBuilder::CreateLeAdvertisingReportEvent();

  if (!le_adverts->AddLeAdvertisingReport(
          adv_type, address_type, incoming.GetSourceAddress(), ad, GetRssi())) {
    LOG_INFO("Couldn't add the scan response.");
  } else {
    send_event_(le_adverts->ToVector());
  }
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

  send_event_(EventPacketBuilder::CreateConnectionRequestEvent(incoming.GetSourceAddress(), page.GetClassOfDevice(),
                                                               hci::LinkType::ACL)
                  ->ToVector());
}

void LinkLayerController::IncomingPageRejectPacket(
    model::packets::LinkLayerPacketView incoming) {
  LOG_INFO("%s: %s", __func__, incoming.GetSourceAddress().ToString().c_str());
  auto reject = model::packets::PageRejectView::Create(incoming);
  ASSERT(reject.IsValid());
  LOG_INFO("%s: Sending CreateConnectionComplete", __func__);
  send_event_(EventPacketBuilder::CreateConnectionCompleteEvent(static_cast<hci::Status>(reject.GetReason()), 0x0eff,
                                                                incoming.GetSourceAddress(), hci::LinkType::ACL, false)
                  ->ToVector());
}

void LinkLayerController::IncomingPageResponsePacket(
    model::packets::LinkLayerPacketView incoming) {
  LOG_INFO("%s: %s", __func__, incoming.GetSourceAddress().ToString().c_str());
  uint16_t handle = connections_.CreateConnection(incoming.GetSourceAddress());
  if (handle == acl::kReservedHandle) {
    LOG_WARN("%s: No free handles", __func__);
    return;
  }
  send_event_(EventPacketBuilder::CreateConnectionCompleteEvent(hci::Status::SUCCESS, handle,
                                                                incoming.GetSourceAddress(), hci::LinkType::ACL, false)
                  ->ToVector());
}

void LinkLayerController::IncomingResponsePacket(
    model::packets::LinkLayerPacketView incoming) {
  auto response = model::packets::ResponseView::Create(incoming);
  ASSERT(response.IsValid());

  // TODO: Check to see if I'm expecting this response.

  hci::OpCode opcode = static_cast<hci::OpCode>(response.GetOpcode());
  auto args = response.GetPayload().begin();
  hci::Status status = static_cast<hci::Status>(args.extract<uint64_t>());

  uint16_t handle = connections_.GetHandle(incoming.GetSourceAddress());

  switch (opcode) {
    case (hci::OpCode::REMOTE_NAME_REQUEST): {
      std::string remote_name = "";
      size_t length = args.extract<uint64_t>();
      uint64_t word = 0;
      for (size_t b = 0; b < length; b++) {
        size_t byte = b % 8;
        if (byte == 0) {
          word = args.extract<uint64_t>();
        }
        remote_name += static_cast<uint8_t>(word >> (byte * 8));
      }
      send_event_(
          EventPacketBuilder::CreateRemoteNameRequestCompleteEvent(status, incoming.GetSourceAddress(), remote_name)
              ->ToVector());
    } break;
    case (hci::OpCode::READ_REMOTE_SUPPORTED_FEATURES): {
      send_event_(
          EventPacketBuilder::CreateRemoteSupportedFeaturesEvent(status, handle, args.extract<uint64_t>())->ToVector());
    } break;
    case (hci::OpCode::READ_REMOTE_EXTENDED_FEATURES): {
      if (status == hci::Status::SUCCESS) {
        send_event_(EventPacketBuilder::CreateReadRemoteExtendedFeaturesEvent(
                        status, handle, args.extract<uint64_t>(), args.extract<uint64_t>(), args.extract<uint64_t>())
                        ->ToVector());
      } else {
        send_event_(EventPacketBuilder::CreateReadRemoteExtendedFeaturesEvent(status, handle, 0, 0, 0)->ToVector());
      }
    } break;
    case (hci::OpCode::READ_REMOTE_VERSION_INFORMATION): {
      send_event_(EventPacketBuilder::CreateReadRemoteVersionInformationEvent(
                      status, handle, args.extract<uint64_t>(), args.extract<uint64_t>(), args.extract<uint64_t>())
                      ->ToVector());
      LOG_INFO("Read remote version handle 0x%04x", handle);
    } break;
    case (hci::OpCode::READ_CLOCK_OFFSET): {
      send_event_(EventPacketBuilder::CreateReadClockOffsetEvent(status, handle, args.extract<uint64_t>())->ToVector());
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
    const std::function<void(std::shared_ptr<std::vector<uint8_t>>)>& callback) {
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
  send_event_(EventPacketBuilder::CreateIoCapabilityRequestEvent(address)->ToVector());

  // Get a Key, then authenticate
  // PublicKeyExchange(address);
  // AuthenticateRemoteStage1(address);
  // AuthenticateRemoteStage2(address);
}

void LinkLayerController::AuthenticateRemoteStage1(const Address& peer, PairingType pairing_type) {
  ASSERT(security_manager_.GetAuthenticationAddress() == peer);
  // TODO: Public key exchange first?
  switch (pairing_type) {
    case PairingType::AUTO_CONFIRMATION:
      send_event_(EventPacketBuilder::CreateUserConfirmationRequestEvent(peer, 123456)->ToVector());
      break;
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
  send_event_(EventPacketBuilder::CreateAuthenticationCompleteEvent(hci::Status::SUCCESS, handle)->ToVector());
}

hci::Status LinkLayerController::LinkKeyRequestReply(const Address& peer, PacketView<true> key) {
  std::vector<uint8_t> key_vec(key.begin(), key.end());
  security_manager_.WriteKey(peer, key_vec);
  security_manager_.AuthenticationRequestFinished();

  ScheduleTask(milliseconds(5), [this, peer]() { AuthenticateRemoteStage2(peer); });

  return hci::Status::SUCCESS;
}

hci::Status LinkLayerController::LinkKeyRequestNegativeReply(const Address& address) {
  security_manager_.DeleteKey(address);
  // Simple pairing to get a key
  uint16_t handle = connections_.GetHandle(address);
  if (handle == acl::kReservedHandle) {
    LOG_INFO("%s: Device not connected %s", __func__, address.ToString().c_str());
    return hci::Status::UNKNOWN_CONNECTION;
  }

  security_manager_.AuthenticationRequest(address, handle);

  ScheduleTask(milliseconds(5), [this, address]() { StartSimplePairing(address); });
  return hci::Status::SUCCESS;
}

hci::Status LinkLayerController::IoCapabilityRequestReply(const Address& peer, uint8_t io_capability,
                                                          uint8_t oob_data_present_flag,
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

  return hci::Status::SUCCESS;
}

hci::Status LinkLayerController::IoCapabilityRequestNegativeReply(const Address& peer, hci::Status reason) {
  if (security_manager_.GetAuthenticationAddress() != peer) {
    return hci::Status::AUTHENTICATION_FAILURE;
  }

  security_manager_.InvalidateIoCapabilities();

  auto packet = model::packets::IoCapabilityNegativeResponseBuilder::Create(
      properties_.GetAddress(), peer, static_cast<uint8_t>(reason));
  SendLinkLayerPacket(std::move(packet));

  return hci::Status::SUCCESS;
}

hci::Status LinkLayerController::UserConfirmationRequestReply(const Address& peer) {
  if (security_manager_.GetAuthenticationAddress() != peer) {
    return hci::Status::AUTHENTICATION_FAILURE;
  }
  // TODO: Key could be calculated here.
  std::vector<uint8_t> key_vec{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
  security_manager_.WriteKey(peer, key_vec);

  security_manager_.AuthenticationRequestFinished();

  ScheduleTask(milliseconds(5), [this, peer]() { AuthenticateRemoteStage2(peer); });
  return hci::Status::SUCCESS;
}

hci::Status LinkLayerController::UserConfirmationRequestNegativeReply(const Address& peer) {
  if (security_manager_.GetAuthenticationAddress() != peer) {
    return hci::Status::AUTHENTICATION_FAILURE;
  }
  return hci::Status::SUCCESS;
}

hci::Status LinkLayerController::UserPasskeyRequestReply(const Address& peer, uint32_t numeric_value) {
  if (security_manager_.GetAuthenticationAddress() != peer) {
    return hci::Status::AUTHENTICATION_FAILURE;
  }
  LOG_INFO("TODO:Do something with the passkey %06d", numeric_value);
  return hci::Status::SUCCESS;
}

hci::Status LinkLayerController::UserPasskeyRequestNegativeReply(const Address& peer) {
  if (security_manager_.GetAuthenticationAddress() != peer) {
    return hci::Status::AUTHENTICATION_FAILURE;
  }
  return hci::Status::SUCCESS;
}

hci::Status LinkLayerController::RemoteOobDataRequestReply(const Address& peer, const std::vector<uint8_t>& c,
                                                           const std::vector<uint8_t>& r) {
  if (security_manager_.GetAuthenticationAddress() != peer) {
    return hci::Status::AUTHENTICATION_FAILURE;
  }
  LOG_INFO("TODO:Do something with the OOB data c=%d r=%d", c[0], r[0]);
  return hci::Status::SUCCESS;
}

hci::Status LinkLayerController::RemoteOobDataRequestNegativeReply(const Address& peer) {
  if (security_manager_.GetAuthenticationAddress() != peer) {
    return hci::Status::AUTHENTICATION_FAILURE;
  }
  return hci::Status::SUCCESS;
}

void LinkLayerController::HandleAuthenticationRequest(const Address& address, uint16_t handle) {
  if (simple_pairing_mode_enabled_ == true) {
    security_manager_.AuthenticationRequest(address, handle);
    send_event_(EventPacketBuilder::CreateLinkKeyRequestEvent(address)->ToVector());
  } else {  // Should never happen for our phones
    // Check for a key, try to authenticate, ask for a PIN.
    send_event_(
        EventPacketBuilder::CreateAuthenticationCompleteEvent(hci::Status::AUTHENTICATION_FAILURE, handle)->ToVector());
  }
}

hci::Status LinkLayerController::AuthenticationRequested(uint16_t handle) {
  if (!connections_.HasHandle(handle)) {
    LOG_INFO("Authentication Requested for unknown handle %04x", handle);
    return hci::Status::UNKNOWN_CONNECTION;
  }

  Address remote = connections_.GetAddress(handle);

  ScheduleTask(milliseconds(5), [this, remote, handle]() { HandleAuthenticationRequest(remote, handle); });

  return hci::Status::SUCCESS;
}

void LinkLayerController::HandleSetConnectionEncryption(const Address& peer, uint16_t handle,
                                                        uint8_t encryption_enable) {
  // TODO: Block ACL traffic or at least guard against it

  if (connections_.IsEncrypted(handle) && encryption_enable) {
    send_event_(
        EventPacketBuilder::CreateEncryptionChange(hci::Status::SUCCESS, handle, encryption_enable)->ToVector());
    return;
  }

  auto packet = model::packets::EncryptConnectionBuilder::Create(
      properties_.GetAddress(), peer, security_manager_.GetKey(peer));
  SendLinkLayerPacket(std::move(packet));
}

hci::Status LinkLayerController::SetConnectionEncryption(uint16_t handle, uint8_t encryption_enable) {
  if (!connections_.HasHandle(handle)) {
    LOG_INFO("Set Connection Encryption for unknown handle %04x", handle);
    return hci::Status::UNKNOWN_CONNECTION;
  }

  if (connections_.IsEncrypted(handle) && !encryption_enable) {
    return hci::Status::ENCRYPTION_MODE_NOT_ACCEPTABLE;
  }
  Address remote = connections_.GetAddress(handle);

  if (security_manager_.ReadKey(remote) == 0) {
    return hci::Status::PIN_OR_KEY_MISSING;
  }

  ScheduleTask(milliseconds(5), [this, remote, handle, encryption_enable]() {
    HandleSetConnectionEncryption(remote, handle, encryption_enable);
  });
  return hci::Status::SUCCESS;
}

hci::Status LinkLayerController::AcceptConnectionRequest(const Address& addr, bool try_role_switch) {
  if (!connections_.HasPendingConnection(addr)) {
    LOG_INFO("%s: No pending connection for %s", __func__, addr.ToString().c_str());
    return hci::Status::UNKNOWN_CONNECTION;
  }

  LOG_INFO("%s: Accept in 200ms", __func__);
  ScheduleTask(milliseconds(200), [this, addr, try_role_switch]() {
    LOG_INFO("%s: Accepted", __func__);
    MakeSlaveConnection(addr, try_role_switch);
  });

  return hci::Status::SUCCESS;
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
  send_event_(
      EventPacketBuilder::CreateConnectionCompleteEvent(hci::Status::SUCCESS, handle, addr, hci::LinkType::ACL, false)
          ->ToVector());
}

hci::Status LinkLayerController::RejectConnectionRequest(const Address& addr, uint8_t reason) {
  if (!connections_.HasPendingConnection(addr)) {
    LOG_INFO("%s: No pending connection for %s", __func__, addr.ToString().c_str());
    return hci::Status::UNKNOWN_CONNECTION;
  }

  LOG_INFO("%s: Reject in 200ms", __func__);
  ScheduleTask(milliseconds(200), [this, addr, reason]() {
    LOG_INFO("%s: Reject", __func__);
    RejectSlaveConnection(addr, reason);
  });

  return hci::Status::SUCCESS;
}

void LinkLayerController::RejectSlaveConnection(const Address& addr, uint8_t reason) {
  auto to_send = model::packets::PageRejectBuilder::Create(
      properties_.GetAddress(), addr, reason);
  LOG_INFO("%s sending page reject to %s", __func__, addr.ToString().c_str());
  SendLinkLayerPacket(std::move(to_send));

  ASSERT(reason >= 0x0d && reason <= 0x0f);
  send_event_(EventPacketBuilder::CreateConnectionCompleteEvent(static_cast<hci::Status>(reason), 0xeff, addr,
                                                                hci::LinkType::ACL, false)
                  ->ToVector());
}

hci::Status LinkLayerController::CreateConnection(const Address& addr, uint16_t, uint8_t, uint16_t,
                                                  uint8_t allow_role_switch) {
  if (!connections_.CreatePendingConnection(addr)) {
    return hci::Status::CONTROLLER_BUSY;
  }

  auto page = model::packets::PageBuilder::Create(
      properties_.GetAddress(), addr, properties_.GetClassOfDevice(),
      allow_role_switch);
  SendLinkLayerPacket(std::move(page));

  return hci::Status::SUCCESS;
}

hci::Status LinkLayerController::CreateConnectionCancel(const Address& addr) {
  if (!connections_.CancelPendingConnection(addr)) {
    return hci::Status::UNKNOWN_CONNECTION;
  }
  return hci::Status::SUCCESS;
}

hci::Status LinkLayerController::Disconnect(uint16_t handle, uint8_t reason) {
  // TODO: Handle LE
  if (!connections_.HasHandle(handle)) {
    return hci::Status::UNKNOWN_CONNECTION;
  }

  const Address& remote = connections_.GetAddress(handle);
  auto packet = model::packets::DisconnectBuilder::Create(
      properties_.GetAddress(), remote, reason);
  SendLinkLayerPacket(std::move(packet));
  ASSERT_LOG(connections_.Disconnect(handle), "Disconnecting %hx", handle);

  ScheduleTask(milliseconds(20), [this, handle]() {
    DisconnectCleanup(handle, static_cast<uint8_t>(hci::Status::CONNECTION_TERMINATED_BY_LOCAL_HOST));
  });

  return hci::Status::SUCCESS;
}

void LinkLayerController::DisconnectCleanup(uint16_t handle, uint8_t reason) {
  // TODO: Clean up other connection state.
  send_event_(EventPacketBuilder::CreateDisconnectionCompleteEvent(hci::Status::SUCCESS, handle, reason)->ToVector());
}

hci::Status LinkLayerController::ChangeConnectionPacketType(uint16_t handle, uint16_t types) {
  if (!connections_.HasHandle(handle)) {
    return hci::Status::UNKNOWN_CONNECTION;
  }
  std::unique_ptr<EventPacketBuilder> packet =
      EventPacketBuilder::CreateConnectionPacketTypeChangedEvent(hci::Status::SUCCESS, handle, types);
  std::shared_ptr<std::vector<uint8_t>> raw_packet = packet->ToVector();
  ScheduleTask(milliseconds(20), [this, raw_packet]() { send_event_(raw_packet); });

  return hci::Status::SUCCESS;
}

hci::Status LinkLayerController::ChangeConnectionLinkKey(uint16_t handle) {
  if (!connections_.HasHandle(handle)) {
    return hci::Status::UNKNOWN_CONNECTION;
  }

  // TODO: implement real logic
  return hci::Status::COMMAND_DISALLOWED;
}

hci::Status LinkLayerController::MasterLinkKey(uint8_t /* key_flag */) {
  // TODO: implement real logic
  return hci::Status::COMMAND_DISALLOWED;
}

hci::Status LinkLayerController::HoldMode(uint16_t handle, uint16_t hold_mode_max_interval,
                                          uint16_t hold_mode_min_interval) {
  if (!connections_.HasHandle(handle)) {
    return hci::Status::UNKNOWN_CONNECTION;
  }

  if (hold_mode_max_interval < hold_mode_min_interval) {
    return hci::Status::INVALID_HCI_COMMAND_PARAMETERS;
  }

  // TODO: implement real logic
  return hci::Status::COMMAND_DISALLOWED;
}

hci::Status LinkLayerController::SniffMode(uint16_t handle, uint16_t sniff_max_interval, uint16_t sniff_min_interval,
                                           uint16_t sniff_attempt, uint16_t sniff_timeout) {
  if (!connections_.HasHandle(handle)) {
    return hci::Status::UNKNOWN_CONNECTION;
  }

  if (sniff_max_interval < sniff_min_interval || sniff_attempt < 0x0001 || sniff_attempt > 0x7FFF ||
      sniff_timeout > 0x7FFF) {
    return hci::Status::INVALID_HCI_COMMAND_PARAMETERS;
  }

  // TODO: implement real logic
  return hci::Status::COMMAND_DISALLOWED;
}

hci::Status LinkLayerController::ExitSniffMode(uint16_t handle) {
  if (!connections_.HasHandle(handle)) {
    return hci::Status::UNKNOWN_CONNECTION;
  }

  // TODO: implement real logic
  return hci::Status::COMMAND_DISALLOWED;
}

hci::Status LinkLayerController::QosSetup(uint16_t handle, uint8_t service_type, uint32_t /* token_rate */,
                                          uint32_t /* peak_bandwidth */, uint32_t /* latency */,
                                          uint32_t /* delay_variation */) {
  if (!connections_.HasHandle(handle)) {
    return hci::Status::UNKNOWN_CONNECTION;
  }

  if (service_type > 0x02) {
    return hci::Status::INVALID_HCI_COMMAND_PARAMETERS;
  }

  // TODO: implement real logic
  return hci::Status::COMMAND_DISALLOWED;
}

hci::Status LinkLayerController::SwitchRole(Address /* bd_addr */, uint8_t /* role */) {
  // TODO: implement real logic
  return hci::Status::COMMAND_DISALLOWED;
}

hci::Status LinkLayerController::WriteLinkPolicySettings(uint16_t handle, uint16_t) {
  if (!connections_.HasHandle(handle)) {
    return hci::Status::UNKNOWN_CONNECTION;
  }
  return hci::Status::SUCCESS;
}

hci::Status LinkLayerController::FlowSpecification(uint16_t handle, uint8_t flow_direction, uint8_t service_type,
                                                   uint32_t /* token_rate */, uint32_t /* token_bucket_size */,
                                                   uint32_t /* peak_bandwidth */, uint32_t /* access_latency */) {
  if (!connections_.HasHandle(handle)) {
    return hci::Status::UNKNOWN_CONNECTION;
  }

  if (flow_direction > 0x01 || service_type > 0x02) {
    return hci::Status::INVALID_HCI_COMMAND_PARAMETERS;
  }

  // TODO: implement real logic
  return hci::Status::COMMAND_DISALLOWED;
}

hci::Status LinkLayerController::WriteLinkSupervisionTimeout(uint16_t handle, uint16_t) {
  if (!connections_.HasHandle(handle)) {
    return hci::Status::UNKNOWN_CONNECTION;
  }
  return hci::Status::SUCCESS;
}

void LinkLayerController::LeWhiteListClear() {
  le_white_list_.clear();
}

void LinkLayerController::LeWhiteListAddDevice(Address addr, uint8_t addr_type) {
  std::tuple<Address, uint8_t> new_tuple = std::make_tuple(addr, addr_type);
  for (auto dev : le_white_list_) {
    if (dev == new_tuple) {
      return;
    }
  }
  le_white_list_.emplace_back(new_tuple);
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

bool LinkLayerController::LeWhiteListContainsDevice(Address addr, uint8_t addr_type) {
  std::tuple<Address, uint8_t> sought_tuple = std::make_tuple(addr, addr_type);
  for (size_t i = 0; i < le_white_list_.size(); i++) {
    if (le_white_list_[i] == sought_tuple) {
      return true;
    }
  }
  return false;
}

bool LinkLayerController::LeWhiteListFull() {
  return le_white_list_.size() >= properties_.GetLeWhiteListSize();
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
    send_event_(EventPacketBuilder::CreateInquiryCompleteEvent(hci::Status::SUCCESS)->ToVector());
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
