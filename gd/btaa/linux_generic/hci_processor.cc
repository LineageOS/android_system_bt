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

#include "btaa/cmd_evt_classification.h"
#include "os/log.h"

namespace bluetooth {
namespace activity_attribution {

class DeviceParser {
 public:
  void match_handle_with_address(uint16_t connection_handle, hci::Address& address) {
    if (connection_handle && !address.IsEmpty()) {
      connection_lookup_table[connection_handle] = address;
    } else if (connection_handle) {
      if (connection_lookup_table.find(connection_handle) != connection_lookup_table.end()) {
        address = connection_lookup_table[connection_handle];
      }
    }
  }

 private:
  std::map<uint16_t, hci::Address> connection_lookup_table;
};

struct PendingCommand {
  hci::OpCode opcode;
  BtaaHciPacket btaa_hci_packet;
};

static DeviceParser device_parser;
static PendingCommand pending_command;

static void process_command(
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
  device_parser.match_handle_with_address(connection_handle_value, address_value);
  pending_command.btaa_hci_packet = BtaaHciPacket(cmd_info.activity, address_value, byte_count);

  pending_command.opcode = opcode;
}

static void process_event(
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
    device_parser.match_handle_with_address(connection_handle_value, address_value);
    btaa_hci_packets.push_back(BtaaHciPacket(event_info.activity, address_value, byte_count));
  } else {
    // The event requires additional processing.
    switch (event_code) {
      case hci::EventCode::COMMAND_COMPLETE: {
        auto packet_view = hci::CommandCompleteView::Create(event);
        if (packet_view.IsValid() && packet_view.GetCommandOpCode() == pending_command.opcode) {
          pending_command.btaa_hci_packet.byte_count += byte_count;
          btaa_hci_packets.push_back(std::move(pending_command.btaa_hci_packet));
        } else {
          btaa_hci_packets.push_back(BtaaHciPacket(Activity::UNKNOWN, address_value, byte_count));
        }
      } break;
      case hci::EventCode::COMMAND_STATUS: {
        auto packet_view = hci::CommandStatusView::Create(event);
        if (packet_view.IsValid() && packet_view.GetCommandOpCode() == pending_command.opcode) {
          pending_command.btaa_hci_packet.byte_count += byte_count;
          btaa_hci_packets.push_back(std::move(pending_command.btaa_hci_packet));
        } else {
          btaa_hci_packets.push_back(BtaaHciPacket(Activity::UNKNOWN, address_value, byte_count));
        }
        break;
      }
      case hci::EventCode::LE_META_EVENT:
        break;
      case hci::EventCode::VENDOR_SPECIFIC:
        btaa_hci_packets.push_back(BtaaHciPacket(Activity::VENDOR, address_value, byte_count));
        break;
      default:
        break;
    }
  }
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
      break;
    case hal::SnoopLogger::PacketType::SCO:
      break;
    case hal::SnoopLogger::PacketType::ISO:
      break;
  }
  return btaa_hci_packets;
}

}  // namespace activity_attribution
}  // namespace bluetooth
