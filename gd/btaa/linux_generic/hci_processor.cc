/*
 * Copyright 2021 The Android Open Source Project
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

#include "btaa/hci_processor.h"

#include "os/log.h"

namespace bluetooth {
namespace activity_attribution {

void DeviceParser::match_handle_with_address(uint16_t connection_handle, hci::Address& address) {
  if (connection_handle && !address.IsEmpty()) {
    connection_lookup_table_[connection_handle] = address;
  } else if (connection_handle) {
    if (connection_lookup_table_.find(connection_handle) != connection_lookup_table_.end()) {
      address = connection_lookup_table_[connection_handle];
    }
  }
}

void HciProcessor::process_le_event(
    std::vector<BtaaHciPacket>& btaa_hci_packets, int16_t byte_count, hci::EventView& event) {
  uint16_t connection_handle_value = 0;
  hci::Address address_value;

  auto le_packet_view = hci::LeMetaEventView::Create(event);
  if (!le_packet_view.IsValid()) {
    return;
  }

  auto subevent_code = le_packet_view.GetSubeventCode();
  auto le_event_info = lookup_le_event(subevent_code);

  if (le_event_info.activity != Activity::UNKNOWN) {
    // lookup_le_event returns all simple classic event which does not require additional processing.
    if (le_event_info.connection_handle_pos) {
      auto connection_handle_it = event.begin() + le_event_info.connection_handle_pos;
      connection_handle_value = connection_handle_it.extract<uint16_t>();
    }
    if (le_event_info.address_pos) {
      auto address_value_it = event.begin() + le_event_info.address_pos;
      address_value = address_value_it.extract<hci::Address>();
    }
    device_parser_.match_handle_with_address(connection_handle_value, address_value);
    btaa_hci_packets.push_back(BtaaHciPacket(le_event_info.activity, address_value, byte_count));
  }
}

void HciProcessor::process_special_event(
    std::vector<BtaaHciPacket>& btaa_hci_packets,
    hci::EventCode event_code,
    uint16_t byte_count,
    hci::EventView& event) {
  uint16_t avg_byte_count;
  hci::Address address_value;

  switch (event_code) {
    case hci::EventCode::INQUIRY_RESULT:
    case hci::EventCode::INQUIRY_RESULT_WITH_RSSI: {
      auto packet_view = hci::InquiryResultView::Create(event);
      if (!packet_view.IsValid()) {
        return;
      }
      auto inquiry_results = packet_view.GetInquiryResults();
      avg_byte_count = byte_count / inquiry_results.size();
      for (auto& inquiry_result : inquiry_results) {
        btaa_hci_packets.push_back(BtaaHciPacket(Activity::SCAN, inquiry_result.bd_addr_, avg_byte_count));
      }
    } break;

    case hci::EventCode::NUMBER_OF_COMPLETED_PACKETS: {
      auto packet_view = hci::NumberOfCompletedPacketsView::Create(event);
      if (!packet_view.IsValid()) {
        return;
      }
      auto completed_packets = packet_view.GetCompletedPackets();
      avg_byte_count = byte_count / completed_packets.size();
      for (auto& completed_packet : completed_packets) {
        device_parser_.match_handle_with_address(completed_packet.connection_handle_, address_value);
        btaa_hci_packets.push_back(BtaaHciPacket(Activity::CONNECT, address_value, avg_byte_count));
      }
    } break;

    case hci::EventCode::RETURN_LINK_KEYS: {
      auto packet_view = hci::ReturnLinkKeysView::Create(event);
      if (!packet_view.IsValid()) {
        return;
      }
      auto keys_and_addresses = packet_view.GetKeys();
      avg_byte_count = byte_count / keys_and_addresses.size();
      for (auto& key_and_address : keys_and_addresses) {
        btaa_hci_packets.push_back(BtaaHciPacket(Activity::CONNECT, key_and_address.address_, avg_byte_count));
      }
    } break;

    default: {
      btaa_hci_packets.push_back(BtaaHciPacket(Activity::UNKNOWN, address_value, byte_count));
    } break;
  }
}

void HciProcessor::process_command(
    std::vector<BtaaHciPacket>& btaa_hci_packets,
    packet::PacketView<packet::kLittleEndian>& packet_view,
    uint16_t byte_count) {
  hci::CommandView command = hci::CommandView::Create(packet_view);
  if (!command.IsValid()) {
    return;
  }

  uint16_t connection_handle_value = 0;
  hci::Address address_value;
  auto opcode = command.GetOpCode();
  auto cmd_info = lookup_cmd(opcode);

  if (cmd_info.connection_handle_pos) {
    auto connection_handle_it = command.begin() + cmd_info.connection_handle_pos;
    connection_handle_value = connection_handle_it.extract<uint16_t>();
  }
  if (cmd_info.address_pos) {
    auto address_value_it = command.begin() + cmd_info.address_pos;
    address_value = address_value_it.extract<hci::Address>();
  }
  device_parser_.match_handle_with_address(connection_handle_value, address_value);
  pending_command_.btaa_hci_packet = BtaaHciPacket(cmd_info.activity, address_value, byte_count);

  pending_command_.opcode = opcode;
}

void HciProcessor::process_event(
    std::vector<BtaaHciPacket>& btaa_hci_packets,
    packet::PacketView<packet::kLittleEndian>& packet_view,
    uint16_t byte_count) {
  hci::EventView event = hci::EventView::Create(packet_view);
  if (!event.IsValid()) {
    return;
  }

  uint16_t connection_handle_value = 0;
  hci::Address address_value;
  auto event_code = event.GetEventCode();
  auto event_info = lookup_event(event_code);

  if (event_info.activity != Activity::UNKNOWN) {
    // lookup_event returns all simple classic event which does not require additional processing.
    if (event_info.connection_handle_pos) {
      auto connection_handle_it = event.begin() + event_info.connection_handle_pos;
      connection_handle_value = connection_handle_it.extract<uint16_t>();
    }
    if (event_info.address_pos) {
      auto address_value_it = event.begin() + event_info.address_pos;
      address_value = address_value_it.extract<hci::Address>();
    }
    device_parser_.match_handle_with_address(connection_handle_value, address_value);
    btaa_hci_packets.push_back(BtaaHciPacket(event_info.activity, address_value, byte_count));
  } else {
    // The event requires additional processing.
    switch (event_code) {
      case hci::EventCode::COMMAND_COMPLETE: {
        auto packet_view = hci::CommandCompleteView::Create(event);
        if (packet_view.IsValid() && packet_view.GetCommandOpCode() == pending_command_.opcode) {
          pending_command_.btaa_hci_packet.byte_count += byte_count;
          btaa_hci_packets.push_back(std::move(pending_command_.btaa_hci_packet));
        } else {
          btaa_hci_packets.push_back(BtaaHciPacket(Activity::UNKNOWN, address_value, byte_count));
        }
      } break;
      case hci::EventCode::COMMAND_STATUS: {
        auto packet_view = hci::CommandStatusView::Create(event);
        if (packet_view.IsValid() && packet_view.GetCommandOpCode() == pending_command_.opcode) {
          pending_command_.btaa_hci_packet.byte_count += byte_count;
          btaa_hci_packets.push_back(std::move(pending_command_.btaa_hci_packet));
        } else {
          btaa_hci_packets.push_back(BtaaHciPacket(Activity::UNKNOWN, address_value, byte_count));
        }
        break;
      }
      case hci::EventCode::LE_META_EVENT:
        process_le_event(btaa_hci_packets, byte_count, event);
        break;
      case hci::EventCode::VENDOR_SPECIFIC:
        btaa_hci_packets.push_back(BtaaHciPacket(Activity::VENDOR, address_value, byte_count));
        break;
      default:
        process_special_event(btaa_hci_packets, event_code, byte_count, event);
        break;
    }
  }
}

void HciProcessor::process_acl(
    std::vector<BtaaHciPacket>& btaa_hci_packets,
    packet::PacketView<packet::kLittleEndian>& packet_view,
    uint16_t byte_count) {
  hci::AclView acl = hci::AclView::Create(packet_view);
  auto connection_handle = acl.begin();
  // Connection handle is extracted from the 12 least significant bit.
  uint16_t connection_handle_value = connection_handle.extract<uint16_t>() & 0xfff;
  hci::Address address_value;
  device_parser_.match_handle_with_address(connection_handle_value, address_value);
  btaa_hci_packets.push_back(BtaaHciPacket(Activity::ACL, address_value, byte_count));
}

void HciProcessor::process_sco(
    std::vector<BtaaHciPacket>& btaa_hci_packets,
    packet::PacketView<packet::kLittleEndian>& packet_view,
    uint16_t byte_count) {
  hci::ScoView sco = hci::ScoView::Create(packet_view);
  auto connection_handle = sco.begin();
  // Connection handle is extracted from the 12 least significant bit.
  uint16_t connection_handle_value = connection_handle.extract<uint16_t>() & 0xfff;
  hci::Address address_value;
  device_parser_.match_handle_with_address(connection_handle_value, address_value);
  btaa_hci_packets.push_back(BtaaHciPacket(Activity::HFP, address_value, byte_count));
}

void HciProcessor::process_iso(
    std::vector<BtaaHciPacket>& btaa_hci_packets,
    packet::PacketView<packet::kLittleEndian>& packet_view,
    uint16_t byte_count) {
  hci::IsoView iso = hci::IsoView::Create(packet_view);
  auto connection_handle = iso.begin();
  // Connection handle is extracted from the 12 least significant bit.
  uint16_t connection_handle_value = connection_handle.extract<uint16_t>() & 0xfff;
  hci::Address address_value;
  device_parser_.match_handle_with_address(connection_handle_value, address_value);
  btaa_hci_packets.push_back(BtaaHciPacket(Activity::ISO, address_value, byte_count));
}

std::vector<BtaaHciPacket> HciProcessor::OnHciPacket(
    hal::HciPacket packet, hal::SnoopLogger::PacketType type, uint16_t length) {
  std::vector<BtaaHciPacket> btaa_hci_packets;
  auto packet_view = packet::PacketView<packet::kLittleEndian>(std::make_shared<std::vector<uint8_t>>(packet));
  switch (type) {
    case hal::SnoopLogger::PacketType::CMD:
      process_command(btaa_hci_packets, packet_view, length);
      break;
    case hal::SnoopLogger::PacketType::EVT:
      process_event(btaa_hci_packets, packet_view, length);
      break;
    case hal::SnoopLogger::PacketType::ACL:
      process_acl(btaa_hci_packets, packet_view, length);
      break;
    case hal::SnoopLogger::PacketType::SCO:
      process_sco(btaa_hci_packets, packet_view, length);
      break;
    case hal::SnoopLogger::PacketType::ISO:
      process_iso(btaa_hci_packets, packet_view, length);
      break;
  }
  return btaa_hci_packets;
}

}  // namespace activity_attribution
}  // namespace bluetooth
