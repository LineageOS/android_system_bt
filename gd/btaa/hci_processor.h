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

#pragma once

#include "btaa/activity_attribution.h"
#include "btaa/cmd_evt_classification.h"
#include "hal/snoop_logger.h"
#include "hci/address.h"

namespace bluetooth {
namespace activity_attribution {

struct BtaaHciPacket {
  Activity activity;
  hci::Address address;
  uint16_t byte_count;

  BtaaHciPacket() {}
  BtaaHciPacket(Activity activity, hci::Address address, uint16_t byte_count)
      : activity(activity), address(address), byte_count(byte_count) {}
};

class DeviceParser {
 public:
  void match_handle_with_address(uint16_t connection_handle, hci::Address& address);

 private:
  std::map<uint16_t, hci::Address> connection_lookup_table_;
};

struct PendingCommand {
  hci::OpCode opcode;
  BtaaHciPacket btaa_hci_packet;
};

class HciProcessor {
 public:
  std::vector<BtaaHciPacket> OnHciPacket(hal::HciPacket packet, hal::SnoopLogger::PacketType type, uint16_t length);

 private:
  void process_le_event(std::vector<BtaaHciPacket>& btaa_hci_packets, int16_t byte_count, hci::EventView& event);
  void process_special_event(
      std::vector<BtaaHciPacket>& btaa_hci_packets,
      hci::EventCode event_code,
      uint16_t byte_count,
      hci::EventView& event);
  void process_command(
      std::vector<BtaaHciPacket>& btaa_hci_packets,
      packet::PacketView<packet::kLittleEndian>& packet_view,
      uint16_t byte_count);
  void process_event(
      std::vector<BtaaHciPacket>& btaa_hci_packets,
      packet::PacketView<packet::kLittleEndian>& packet_view,
      uint16_t byte_count);
  void process_acl(
      std::vector<BtaaHciPacket>& btaa_hci_packets,
      packet::PacketView<packet::kLittleEndian>& packet_view,
      uint16_t byte_count);
  void process_sco(
      std::vector<BtaaHciPacket>& btaa_hci_packets,
      packet::PacketView<packet::kLittleEndian>& packet_view,
      uint16_t byte_count);
  void process_iso(
      std::vector<BtaaHciPacket>& btaa_hci_packets,
      packet::PacketView<packet::kLittleEndian>& packet_view,
      uint16_t byte_count);

  DeviceParser device_parser_;
  PendingCommand pending_command_;
};

}  // namespace activity_attribution
}  // namespace bluetooth
