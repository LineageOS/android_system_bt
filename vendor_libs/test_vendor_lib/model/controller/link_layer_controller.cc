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
#include "packets/link_layer/command_builder.h"
#include "packets/link_layer/command_view.h"
#include "packets/link_layer/disconnect_view.h"
#include "packets/link_layer/encrypt_connection_view.h"
#include "packets/link_layer/inquiry_response_view.h"
#include "packets/link_layer/inquiry_view.h"
#include "packets/link_layer/io_capability_view.h"
#include "packets/link_layer/le_advertisement_view.h"
#include "packets/link_layer/le_connect_complete_view.h"
#include "packets/link_layer/le_connect_view.h"
#include "packets/link_layer/page_reject_view.h"
#include "packets/link_layer/page_response_view.h"
#include "packets/link_layer/page_view.h"
#include "packets/link_layer/response_view.h"

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

void LinkLayerController::SendLeLinkLayerPacket(std::shared_ptr<LinkLayerPacketBuilder> packet) {
  ScheduleTask(milliseconds(50), [this, packet]() { send_to_remote_(packet, Phy::Type::LOW_ENERGY); });
}

void LinkLayerController::SendLinkLayerPacket(std::shared_ptr<LinkLayerPacketBuilder> packet) {
  ScheduleTask(milliseconds(50), [this, packet]() { send_to_remote_(packet, Phy::Type::BR_EDR); });
}

hci::Status LinkLayerController::SendCommandToRemoteByAddress(hci::OpCode opcode, PacketView<true> args,
                                                              const Address& remote, bool use_public_address) {
  std::shared_ptr<LinkLayerPacketBuilder> command;
  Address local_address;
  if (use_public_address) {
    local_address = properties_.GetAddress();
  } else {
    local_address = properties_.GetLeAddress();
  }
  command = LinkLayerPacketBuilder::WrapCommand(CommandBuilder::Create(static_cast<uint16_t>(opcode), args),
                                                local_address, remote);
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

  std::unique_ptr<ViewForwarderBuilder> acl_builder = ViewForwarderBuilder::Create(acl_packet);

  Address my_address = properties_.GetAddress();
  Address destination = connections_.GetAddress(handle);
  if (connections_.GetOwnAddressType(handle) != 0) {  // If it's not public, it must be LE
    my_address = properties_.GetLeAddress();
  }
  std::shared_ptr<LinkLayerPacketBuilder> acl =
      LinkLayerPacketBuilder::WrapAcl(std::move(acl_builder), my_address, destination);

  LOG_INFO("%s(%s): handle 0x%x size %d", __func__, properties_.GetAddress().ToString().c_str(), handle,
           static_cast<int>(acl_packet.size()));

  ScheduleTask(milliseconds(5), [this, handle]() {
    send_event_(EventPacketBuilder::CreateNumberOfCompletedPacketsEvent(handle, 1)->ToVector());
  });
  SendLinkLayerPacket(acl);
  return hci::Status::SUCCESS;
}

void LinkLayerController::IncomingPacket(LinkLayerPacketView incoming) {
  // TODO: Resolvable private addresses?
  if (incoming.GetDestinationAddress() != properties_.GetAddress() &&
      incoming.GetDestinationAddress() != properties_.GetLeAddress() &&
      incoming.GetDestinationAddress() != Address::kEmpty) {
    // Drop packets not addressed to me
    return;
  }

  switch (incoming.GetType()) {
    case Link::PacketType::ACL:
      IncomingAclPacket(incoming);
      break;
    case Link::PacketType::COMMAND:
      IncomingCommandPacket(incoming);
      break;
    case Link::PacketType::DISCONNECT:
      IncomingDisconnectPacket(incoming);
      break;
    case Link::PacketType::ENCRYPT_CONNECTION:
      IncomingEncryptConnection(incoming);
      break;
    case Link::PacketType::ENCRYPT_CONNECTION_RESPONSE:
      IncomingEncryptConnectionResponse(incoming);
      break;
    case Link::PacketType::INQUIRY:
      if (inquiry_scans_enabled_) {
        IncomingInquiryPacket(incoming);
      }
      break;
    case Link::PacketType::INQUIRY_RESPONSE:
      IncomingInquiryResponsePacket(incoming);
      break;
    case Link::PacketType::IO_CAPABILITY_REQUEST:
      IncomingIoCapabilityRequestPacket(incoming);
      break;
    case Link::PacketType::IO_CAPABILITY_RESPONSE:
      IncomingIoCapabilityResponsePacket(incoming);
      break;
    case Link::PacketType::IO_CAPABILITY_NEGATIVE_RESPONSE:
      IncomingIoCapabilityNegativeResponsePacket(incoming);
      break;
    case Link::PacketType::LE_ADVERTISEMENT:
      if (le_scan_enable_ || le_connect_) {
        IncomingLeAdvertisementPacket(incoming);
      }
      break;
    case Link::PacketType::LE_CONNECT:
      IncomingLeConnectPacket(incoming);
      break;
    case Link::PacketType::LE_CONNECT_COMPLETE:
      IncomingLeConnectCompletePacket(incoming);
      break;
    case Link::PacketType::LE_SCAN:
      // TODO: Check Advertising flags and see if we are scannable.
      IncomingLeScanPacket(incoming);
      break;
    case Link::PacketType::LE_SCAN_RESPONSE:
      if (le_scan_enable_ && le_scan_type_ == 1) {
        IncomingLeScanResponsePacket(incoming);
      }
      break;
    case Link::PacketType::PAGE:
      if (page_scans_enabled_) {
        IncomingPagePacket(incoming);
      }
      break;
    case Link::PacketType::PAGE_REJECT:
      IncomingPageRejectPacket(incoming);
      break;
    case Link::PacketType::PAGE_RESPONSE:
      IncomingPageResponsePacket(incoming);
      break;
    case Link::PacketType::RESPONSE:
      IncomingResponsePacket(incoming);
      break;
    default:
      LOG_WARN("Dropping unhandled packet of type %d", static_cast<int32_t>(incoming.GetType()));
  }
}

void LinkLayerController::IncomingAclPacket(LinkLayerPacketView incoming) {
  LOG_INFO("Acl Packet %s -> %s", incoming.GetSourceAddress().ToString().c_str(),
           incoming.GetDestinationAddress().ToString().c_str());
  AclPacketView acl_view = AclPacketView::Create(incoming.GetPayload());
  LOG_INFO("%s: remote handle 0x%x size %d", __func__, acl_view.GetHandle(), static_cast<int>(acl_view.size()));
  uint16_t local_handle = connections_.GetHandle(incoming.GetSourceAddress());
  LOG_INFO("%s: local handle 0x%x", __func__, local_handle);

  acl::PacketBoundaryFlagsType boundary_flags = acl_view.GetPacketBoundaryFlags();
  acl::BroadcastFlagsType broadcast_flags = acl_view.GetBroadcastFlags();
  std::unique_ptr<ViewForwarderBuilder> builder = ViewForwarderBuilder::Create(acl_view.GetPayload());
  send_acl_(AclPacketBuilder::Create(local_handle, boundary_flags, broadcast_flags, std::move(builder))->ToVector());
}

void LinkLayerController::IncomingCommandPacket(LinkLayerPacketView incoming) {
  // TODO: Check the destination address to see if this packet is for me.
  CommandView command = CommandView::GetCommand(incoming);
  hci::OpCode opcode = static_cast<hci::OpCode>(command.GetOpcode());
  auto args = command.GetData();
  std::vector<uint64_t> response_data;

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
  SendLinkLayerPacket(
      LinkLayerPacketBuilder::WrapResponse(ResponseBuilder::Create(static_cast<uint16_t>(opcode), response_data),
                                           properties_.GetAddress(), incoming.GetSourceAddress()));
}

void LinkLayerController::IncomingDisconnectPacket(LinkLayerPacketView incoming) {
  LOG_INFO("Disconnect Packet");
  DisconnectView disconnect = DisconnectView::GetDisconnect(incoming);
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

void LinkLayerController::IncomingEncryptConnection(LinkLayerPacketView incoming) {
  LOG_INFO("%s", __func__);
  // TODO: Check keys
  Address peer = incoming.GetSourceAddress();
  uint16_t handle = connections_.GetHandle(peer);
  if (handle == acl::kReservedHandle) {
    LOG_INFO("%s: Unknown connection @%s", __func__, peer.ToString().c_str());
    return;
  }
  send_event_(EventPacketBuilder::CreateEncryptionChange(hci::Status::SUCCESS, handle, 1)->ToVector());
  SendLinkLayerPacket(LinkLayerPacketBuilder::WrapEncryptConnectionResponse(
      EncryptConnectionBuilder::Create(security_manager_.GetKey(peer)), properties_.GetAddress(), peer));
}

void LinkLayerController::IncomingEncryptConnectionResponse(LinkLayerPacketView incoming) {
  LOG_INFO("%s", __func__);
  // TODO: Check keys
  uint16_t handle = connections_.GetHandle(incoming.GetSourceAddress());
  if (handle == acl::kReservedHandle) {
    LOG_INFO("%s: Unknown connection @%s", __func__, incoming.GetSourceAddress().ToString().c_str());
    return;
  }
  send_event_(EventPacketBuilder::CreateEncryptionChange(hci::Status::SUCCESS, handle, 1)->ToVector());
}

void LinkLayerController::IncomingInquiryPacket(LinkLayerPacketView incoming) {
  InquiryView inquiry = InquiryView::GetInquiry(incoming);
  std::unique_ptr<InquiryResponseBuilder> inquiry_response;
  switch (inquiry.GetType()) {
    case (Inquiry::InquiryType::STANDARD):
      inquiry_response = InquiryResponseBuilder::CreateStandard(
          properties_.GetPageScanRepetitionMode(), properties_.GetClassOfDevice(), properties_.GetClockOffset());
      break;

    case (Inquiry::InquiryType::RSSI):
      inquiry_response =
          InquiryResponseBuilder::CreateRssi(properties_.GetPageScanRepetitionMode(), properties_.GetClassOfDevice(),
                                             properties_.GetClockOffset(), GetRssi());
      break;

    case (Inquiry::InquiryType::EXTENDED):
      inquiry_response = InquiryResponseBuilder::CreateExtended(
          properties_.GetPageScanRepetitionMode(), properties_.GetClassOfDevice(), properties_.GetClockOffset(),
          GetRssi(), properties_.GetExtendedInquiryData());
      break;
    default:
      LOG_WARN("Unhandled Incoming Inquiry of type %d", static_cast<int>(inquiry.GetType()));
      return;
  }
  SendLinkLayerPacket(LinkLayerPacketBuilder::WrapInquiryResponse(std::move(inquiry_response), properties_.GetAddress(),
                                                                  incoming.GetSourceAddress()));
  // TODO: Send an Inquriy Response Notification Event 7.7.74
}

void LinkLayerController::IncomingInquiryResponsePacket(LinkLayerPacketView incoming) {
  InquiryResponseView inquiry_response = InquiryResponseView::GetInquiryResponse(incoming);
  std::vector<uint8_t> eir;

  switch (inquiry_response.GetType()) {
    case (Inquiry::InquiryType::STANDARD): {
      LOG_WARN("Incoming Standard Inquiry Response");
      // TODO: Support multiple inquiries in the same packet.
      std::unique_ptr<EventPacketBuilder> inquiry_result = EventPacketBuilder::CreateInquiryResultEvent();
      bool result_added =
          inquiry_result->AddInquiryResult(incoming.GetSourceAddress(), inquiry_response.GetPageScanRepetitionMode(),
                                           inquiry_response.GetClassOfDevice(), inquiry_response.GetClockOffset());
      ASSERT(result_added);
      send_event_(inquiry_result->ToVector());
    } break;

    case (Inquiry::InquiryType::RSSI):
      LOG_WARN("Incoming RSSI Inquiry Response");
      send_event_(EventPacketBuilder::CreateExtendedInquiryResultEvent(
                      incoming.GetSourceAddress(), inquiry_response.GetPageScanRepetitionMode(),
                      inquiry_response.GetClassOfDevice(), inquiry_response.GetClockOffset(), GetRssi(), eir)
                      ->ToVector());
      break;

    case (Inquiry::InquiryType::EXTENDED): {
      LOG_WARN("Incoming Extended Inquiry Response");
      auto eir_itr = inquiry_response.GetExtendedData();
      size_t eir_bytes = eir_itr.NumBytesRemaining();
      LOG_WARN("Payload size = %d", static_cast<int>(eir_bytes));
      for (size_t i = 0; i < eir_bytes; i++) {
        eir.push_back(eir_itr.extract<uint8_t>());
      }
      send_event_(EventPacketBuilder::CreateExtendedInquiryResultEvent(
                      incoming.GetSourceAddress(), inquiry_response.GetPageScanRepetitionMode(),
                      inquiry_response.GetClassOfDevice(), inquiry_response.GetClockOffset(), GetRssi(), eir)
                      ->ToVector());
    } break;
    default:
      LOG_WARN("Unhandled Incoming Inquiry Response of type %d", static_cast<int>(inquiry_response.GetType()));
  }
}

void LinkLayerController::IncomingIoCapabilityRequestPacket(LinkLayerPacketView incoming) {
  LOG_DEBUG("%s", __func__);
  if (!simple_pairing_mode_enabled_) {
    LOG_WARN("%s: Only simple pairing mode is implemented", __func__);
    return;
  }
  auto request = IoCapabilityView::GetIoCapability(incoming);
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

void LinkLayerController::IncomingIoCapabilityResponsePacket(LinkLayerPacketView incoming) {
  LOG_DEBUG("%s", __func__);
  auto response = IoCapabilityView::GetIoCapability(incoming);
  Address peer = incoming.GetSourceAddress();
  uint8_t io_capability = response.GetIoCapability();
  uint8_t oob_data_present = response.GetOobDataPresent();
  uint8_t authentication_requirements = response.GetAuthenticationRequirements();

  security_manager_.SetPeerIoCapability(peer, io_capability, oob_data_present, authentication_requirements);

  send_event_(EventPacketBuilder::CreateIoCapabilityResponseEvent(peer, io_capability, oob_data_present,
                                                                  authentication_requirements)
                  ->ToVector());

  PairingType pairing_type = security_manager_.GetSimplePairingType();
  if (pairing_type != PairingType::INVALID) {
    ScheduleTask(milliseconds(5), [this, peer, pairing_type]() { AuthenticateRemoteStage1(peer, pairing_type); });
  } else {
    LOG_INFO("%s: Security Manager returned INVALID", __func__);
  }
}

void LinkLayerController::IncomingIoCapabilityNegativeResponsePacket(LinkLayerPacketView incoming) {
  LOG_DEBUG("%s", __func__);
  Address peer = incoming.GetSourceAddress();

  ASSERT(security_manager_.GetAuthenticationAddress() == peer);

  security_manager_.InvalidateIoCapabilities();
}

void LinkLayerController::IncomingLeAdvertisementPacket(LinkLayerPacketView incoming) {
  // TODO: Handle multiple advertisements per packet.

  Address address = incoming.GetSourceAddress();
  LeAdvertisementView advertisement = LeAdvertisementView::GetLeAdvertisementView(incoming);
  LeAdvertisement::AdvertisementType adv_type = advertisement.GetAdvertisementType();
  LeAdvertisement::AddressType address_type = advertisement.GetAddressType();

  if (le_scan_enable_) {
    vector<uint8_t> ad;
    auto itr = advertisement.GetData();
    size_t ad_size = itr.NumBytesRemaining();
    for (size_t i = 0; i < ad_size; i++) {
      ad.push_back(itr.extract<uint8_t>());
    }
    std::unique_ptr<EventPacketBuilder> le_adverts = EventPacketBuilder::CreateLeAdvertisingReportEvent();

    if (!le_adverts->AddLeAdvertisingReport(adv_type, address_type, address, ad, GetRssi())) {
      LOG_INFO("Couldn't add the advertising report.");
    } else {
      send_event_(le_adverts->ToVector());
    }
  }

  // Active scanning
  if (le_scan_enable_ && le_scan_type_ == 1) {
    std::shared_ptr<LinkLayerPacketBuilder> to_send =
        LinkLayerPacketBuilder::WrapLeScan(properties_.GetLeAddress(), address);
    SendLeLinkLayerPacket(to_send);
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

    std::shared_ptr<LinkLayerPacketBuilder> to_send = LinkLayerPacketBuilder::WrapLeConnect(
        LeConnectBuilder::Create(le_connection_interval_min_, le_connection_interval_max_, le_connection_latency_,
                                 le_connection_supervision_timeout_, static_cast<uint8_t>(le_address_type_)),
        properties_.GetLeAddress(), incoming.GetSourceAddress());
    SendLeLinkLayerPacket(to_send);
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

void LinkLayerController::IncomingLeConnectPacket(LinkLayerPacketView incoming) {
  auto connect = LeConnectView::GetLeConnect(incoming);
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
  std::shared_ptr<LinkLayerPacketBuilder> to_send = LinkLayerPacketBuilder::WrapLeConnectComplete(
      LeConnectCompleteBuilder::Create(connection_interval, connect.GetLeConnectionLatency(),
                                       connect.GetLeConnectionSupervisionTimeout(),
                                       properties_.GetLeAdvertisingOwnAddressType()),
      incoming.GetDestinationAddress(), incoming.GetSourceAddress());
  SendLeLinkLayerPacket(to_send);
}

void LinkLayerController::IncomingLeConnectCompletePacket(LinkLayerPacketView incoming) {
  auto complete = LeConnectCompleteView::GetLeConnectComplete(incoming);
  HandleLeConnection(incoming.GetSourceAddress(), static_cast<uint8_t>(complete.GetAddressType()),
                     static_cast<uint8_t>(le_address_type_), static_cast<uint8_t>(hci::Role::MASTER),
                     complete.GetLeConnectionInterval(), complete.GetLeConnectionLatency(),
                     complete.GetLeConnectionSupervisionTimeout());
}

void LinkLayerController::IncomingLeScanPacket(LinkLayerPacketView incoming) {
  LOG_INFO("LE Scan Packet");
  std::unique_ptr<LeAdvertisementBuilder> response = LeAdvertisementBuilder::Create(
      static_cast<LeAdvertisement::AddressType>(properties_.GetLeAddressType()),
      static_cast<LeAdvertisement::AdvertisementType>(properties_.GetLeAdvertisementType()),
      properties_.GetLeScanResponse());
  std::shared_ptr<LinkLayerPacketBuilder> to_send = LinkLayerPacketBuilder::WrapLeScanResponse(
      std::move(response), properties_.GetLeAddress(), incoming.GetSourceAddress());
  SendLeLinkLayerPacket(to_send);
}

void LinkLayerController::IncomingLeScanResponsePacket(LinkLayerPacketView incoming) {
  LeAdvertisementView scan_response = LeAdvertisementView::GetLeAdvertisementView(incoming);
  vector<uint8_t> ad;
  auto itr = scan_response.GetData();
  size_t scan_size = itr.NumBytesRemaining();
  for (size_t i = 0; i < scan_size; i++) {
    ad.push_back(itr.extract<uint8_t>());
  }

  std::unique_ptr<EventPacketBuilder> le_adverts = EventPacketBuilder::CreateLeAdvertisingReportEvent();

  if (!le_adverts->AddLeAdvertisingReport(scan_response.GetAdvertisementType(), scan_response.GetAddressType(),
                                          incoming.GetSourceAddress(), ad, GetRssi())) {
    LOG_INFO("Couldn't add the scan response.");
  } else {
    send_event_(le_adverts->ToVector());
  }
}

void LinkLayerController::IncomingPagePacket(LinkLayerPacketView incoming) {
  PageView page = PageView::GetPage(incoming);
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

void LinkLayerController::IncomingPageRejectPacket(LinkLayerPacketView incoming) {
  LOG_INFO("%s: %s", __func__, incoming.GetSourceAddress().ToString().c_str());
  PageRejectView reject = PageRejectView::GetPageReject(incoming);
  LOG_INFO("%s: Sending CreateConnectionComplete", __func__);
  send_event_(EventPacketBuilder::CreateConnectionCompleteEvent(static_cast<hci::Status>(reject.GetReason()), 0x0eff,
                                                                incoming.GetSourceAddress(), hci::LinkType::ACL, false)
                  ->ToVector());
}

void LinkLayerController::IncomingPageResponsePacket(LinkLayerPacketView incoming) {
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

void LinkLayerController::IncomingResponsePacket(LinkLayerPacketView incoming) {
  ResponseView response = ResponseView::GetResponse(incoming);

  // TODO: Check to see if I'm expecting this response.

  hci::OpCode opcode = static_cast<hci::OpCode>(response.GetOpcode());
  auto args = response.GetResponseData();
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

  LeAdvertisement::AddressType own_address_type =
      static_cast<LeAdvertisement::AddressType>(properties_.GetLeAdvertisingOwnAddressType());
  std::shared_ptr<packets::LinkLayerPacketBuilder> to_send;
  std::unique_ptr<packets::LeAdvertisementBuilder> ad;
  Address advertising_address = Address::kEmpty;
  if (own_address_type == LeAdvertisement::AddressType::PUBLIC) {
    advertising_address = properties_.GetAddress();
  } else if (own_address_type == LeAdvertisement::AddressType::RANDOM) {
    advertising_address = properties_.GetLeAddress();
  }
  ASSERT(advertising_address != Address::kEmpty);
  ad = packets::LeAdvertisementBuilder::Create(own_address_type,
                                               static_cast<LeAdvertisement::AdvertisementType>(own_address_type),
                                               properties_.GetLeAdvertisement());
  to_send = packets::LinkLayerPacketBuilder::WrapLeAdvertisement(std::move(ad), advertising_address);
  SendLeLinkLayerPacket(to_send);
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
    const std::function<void(std::shared_ptr<LinkLayerPacketBuilder>, Phy::Type)>& callback) {
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
    SendLinkLayerPacket(LinkLayerPacketBuilder::WrapIoCapabilityResponse(
        IoCapabilityBuilder::Create(io_capability, oob_data_present_flag, authentication_requirements),
        properties_.GetAddress(), peer));
  } else {
    LOG_INFO("%s: Requesting remote capability", __func__);
    SendLinkLayerPacket(LinkLayerPacketBuilder::WrapIoCapabilityRequest(
        IoCapabilityBuilder::Create(io_capability, oob_data_present_flag, authentication_requirements),
        properties_.GetAddress(), peer));
  }

  return hci::Status::SUCCESS;
}

hci::Status LinkLayerController::IoCapabilityRequestNegativeReply(const Address& peer, hci::Status reason) {
  if (security_manager_.GetAuthenticationAddress() != peer) {
    return hci::Status::AUTHENTICATION_FAILURE;
  }

  security_manager_.InvalidateIoCapabilities();

  SendLinkLayerPacket(LinkLayerPacketBuilder::WrapIoCapabilityNegativeResponse(
      IoCapabilityNegativeResponseBuilder::Create(static_cast<uint8_t>(reason)), properties_.GetAddress(), peer));

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

  SendLinkLayerPacket(LinkLayerPacketBuilder::WrapEncryptConnection(
      EncryptConnectionBuilder::Create(security_manager_.GetKey(peer)), properties_.GetAddress(), peer));
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
  std::shared_ptr<LinkLayerPacketBuilder> to_send = LinkLayerPacketBuilder::WrapPageResponse(
      PageResponseBuilder::Create(try_role_switch), properties_.GetAddress(), addr);
  LOG_INFO("%s sending page response to %s", __func__, addr.ToString().c_str());
  SendLinkLayerPacket(to_send);

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
  std::shared_ptr<LinkLayerPacketBuilder> to_send =
      LinkLayerPacketBuilder::WrapPageReject(PageRejectBuilder::Create(reason), properties_.GetAddress(), addr);
  LOG_INFO("%s sending page reject to %s", __func__, addr.ToString().c_str());
  SendLinkLayerPacket(to_send);

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

  std::unique_ptr<PageBuilder> page = PageBuilder::Create(properties_.GetClassOfDevice(), allow_role_switch);
  SendLinkLayerPacket(LinkLayerPacketBuilder::WrapPage(std::move(page), properties_.GetAddress(), addr));

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
  std::shared_ptr<LinkLayerPacketBuilder> to_send =
      LinkLayerPacketBuilder::WrapDisconnect(DisconnectBuilder::Create(reason), properties_.GetAddress(), remote);
  SendLinkLayerPacket(to_send);
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
    send_event_(EventPacketBuilder::CreateInquiryCompleteEvent(hci::Status::SUCCESS)->ToVector());
  }
}

void LinkLayerController::SetInquiryMode(uint8_t mode) {
  inquiry_mode_ = static_cast<Inquiry::InquiryType>(mode);
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
  std::unique_ptr<InquiryBuilder> inquiry = InquiryBuilder::Create(inquiry_mode_);
  std::shared_ptr<LinkLayerPacketBuilder> to_send =
      LinkLayerPacketBuilder::WrapInquiry(std::move(inquiry), properties_.GetAddress());
  SendLinkLayerPacket(to_send);
  last_inquiry_ = now;
}

void LinkLayerController::SetInquiryScanEnable(bool enable) {
  inquiry_scans_enabled_ = enable;
}

void LinkLayerController::SetPageScanEnable(bool enable) {
  page_scans_enabled_ = enable;
}

}  // namespace test_vendor_lib
