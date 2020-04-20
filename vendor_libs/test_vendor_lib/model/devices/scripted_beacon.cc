/*
 * Copyright 2016 The Android Open Source Project
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

#include "scripted_beacon.h"

// #include "hci/hci_packets.h" // To use error-checking packets
#include "model/setup/device_boutique.h"

using std::vector;

namespace test_vendor_lib {
bool ScriptedBeacon::registered_ =
    DeviceBoutique::Register("scripted_beacon", &ScriptedBeacon::Create);

ScriptedBeacon::ScriptedBeacon() {
  advertising_interval_ms_ = std::chrono::milliseconds(1280);
  properties_.SetLeAdvertisementType(0x03 /* NON_CONNECT */);
  properties_.SetLeAdvertisement({
      0x18,  // Length
      0x09 /* TYPE_NAME_CMPL */,
      'g',
      'D',
      'e',
      'v',
      'i',
      'c',
      'e',
      '-',
      's',
      'c',
      'r',
      'i',
      'p',
      't',
      'e',
      'd',
      '-',
      'b',
      'e',
      'a',
      'c',
      'o',
      'n',
      0x02,  // Length
      0x01 /* TYPE_FLAG */,
      0x4 /* BREDR_NOT_SPT */ | 0x2 /* GEN_DISC_FLAG */,
  });

  properties_.SetLeScanResponse({0x06,  // Length
                                 0x07,  // TYPE_NAME_SHORT
                                 'g', 'b', 'e', 'a'});
}

void ScriptedBeacon::Initialize(const vector<std::string>& args) {
  if (args.size() < 2) return;

  Address addr{};
  if (Address::FromString(args[1], addr)) properties_.SetLeAddress(addr);

  if (args.size() < 3) return;

  config_file_ = args[2];
}

void ScriptedBeacon::TimerTick() {
  if (!scanned_once_) {
    Beacon::TimerTick();
  } else {
    std::shared_ptr<model::packets::LinkLayerPacketBuilder> to_send;
    std::chrono::steady_clock::time_point now =
        std::chrono::steady_clock::now();
    elapsed_time_ += now - last_timer_tick_;
    while (next_ad_.ad_time < now) {
      auto ad = model::packets::LeAdvertisementBuilder::Create(
          next_ad_.address, Address::kEmpty /* Destination */,
          model::packets::AddressType::RANDOM,
          model::packets::AdvertisementType::ADV_NONCONN_IND, next_ad_.ad);
      to_send = std::move(ad);
      for (auto phy : phy_layers_[Phy::Type::LOW_ENERGY]) {
        phy->Send(to_send);
      }
      get_next_advertisement();
    }
    last_timer_tick_ = now;
  }
}

void ScriptedBeacon::IncomingPacket(
    model::packets::LinkLayerPacketView packet) {
  if (!scanned_once_) {
    if (packet.GetDestinationAddress() == properties_.GetLeAddress() &&
        packet.GetType() == model::packets::PacketType::LE_SCAN) {
      auto scan_response = model::packets::LeScanResponseBuilder::Create(
          properties_.GetLeAddress(), packet.GetSourceAddress(),
          static_cast<model::packets::AddressType>(
              properties_.GetLeAddressType()),
          model::packets::AdvertisementType::SCAN_RESPONSE,
          properties_.GetLeScanResponse());
      std::shared_ptr<model::packets::LinkLayerPacketBuilder> to_send =
          std::move(scan_response);
      scanned_once_ = true;
      Address::FromString("12:34:56:78:9A:BC", next_ad_.address);
      open_config_file();
      for (auto phy : phy_layers_[Phy::Type::LOW_ENERGY]) {
        phy->Send(to_send);
      }
    }
  }
}

void ScriptedBeacon::get_next_advertisement() {
  next_ad_.address.address[2]++;
  /* For more recent versions:
   * using bluetooth::hci::GapData;
   * using bluetooth::hci::GapDataType;
   * GapData flags;
   * flags.data_type_ = GapDataType::FLAGS;
   * flags.data_ = {0x1A};
   * GapData service;
   * service.data_type_ = GapDataType::COMPLETE_LIST_16_BIT_UUIDS;
   * service.data_ = {0x6F, 0xFD}; // 0xFD6F Contact Detection Service
   * GapData proximity_id;
   * proximity_id.data_type = GapDataType::SERVICE_DATA_128_BIT_UUIDS;
   * proximity_id.data_ = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
   *                       0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
   *                       };
   */
  // For older/all versions:
  next_ad_.ad = {
      0x02,  // Size
      0x01,  // Flag
      0x1A,
      0x03,  // Size
      0x03,  // Complete 16-bit Service UUID
      0x6F,
      0xFD,
      0x13,  // Size
      0x16,  // Service Data - 16 bit UUID
      0x6F,  // FD6F
      0xFD,
      0x00,  // ID
      0x01,
      next_ad_.address.address[2],  // make it different from the others
      0x03,
      0x04,
      0x05,
      0x06,
      0x07,
      0x08,
      0x09,
      0x0a,
      0x0b,
      0x0c,
      0x0d,
      0x0e,
      0x0f,
  };
}

void ScriptedBeacon::open_config_file() {
  // Open the config file and read it all?
}
}  // namespace test_vendor_lib
