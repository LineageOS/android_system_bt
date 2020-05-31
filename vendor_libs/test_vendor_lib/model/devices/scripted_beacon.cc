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

#include <fstream>
#include <cstdint>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/inotify.h>

#include "model/devices/scripted_beacon_ble_payload.pb.h"
#include "model/setup/device_boutique.h"
#include "os/log.h"

using std::vector;

namespace test_vendor_lib {
bool ScriptedBeacon::registered_ =
    DeviceBoutique::Register("scripted_beacon", &ScriptedBeacon::Create);
ScriptedBeacon::ScriptedBeacon() {
  advertising_interval_ms_ = std::chrono::milliseconds(1280);
  properties_.SetLeAdvertisementType(0x02 /* SCANNABLE */);
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

  properties_.SetLeScanResponse({0x05,  // Length
                                 0x08,  // TYPE_NAME_SHORT
                                 'g', 'b', 'e', 'a'});
}

bool ScriptedBeacon::is_config_file_ready() {
  static bool file_absence_logged = false;
  if (access(config_file_.c_str(), F_OK) == -1) {
   if (!file_absence_logged) {
     LOG_INFO("%s: playback file %s not available",
              __func__,
              config_file_.c_str());
     file_absence_logged = true;
   }
   return false;
 }

 if (access(config_file_.c_str(), R_OK) == -1) {
   LOG_ERROR("%s: playback file %s is not readable",
            __func__,
            config_file_.c_str());
   return false;
 }
 LOG_INFO("%s: playback file %s is available and readable",
            __func__,
            config_file_.c_str());
 return true;
}

bool has_time_elapsed(std::chrono::steady_clock::time_point time_point) {
  std::chrono::steady_clock::time_point now =
        std::chrono::steady_clock::now();
  if (now > time_point) {
    return true;
  } else {
    return false;
  }
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
    static std::chrono::steady_clock::time_point next_check_time =
      std::chrono::steady_clock::now();
    if (!play_back_on_) {
      if (!has_time_elapsed(next_check_time)) {
        return;
      }
      if (!is_config_file_ready()) {
        next_check_time = std::chrono::steady_clock::now() +
            std::chrono::steady_clock::duration(std::chrono::seconds(1));
        return;
      }
      // Give time for the file to be written completely before being read
      {
        static std::chrono::steady_clock::time_point write_delay_next_check_time =
            std::chrono::steady_clock::now() +
            std::chrono::steady_clock::duration(std::chrono::seconds(1));
         if (!has_time_elapsed(write_delay_next_check_time)) {
           return;
         }
      }

      std::fstream input(config_file_, std::ios::in | std::ios::binary);
      if (!ble_ad_list_.ParseFromIstream(&input)) {
        LOG_ERROR("%s: Cannot parse playback file %s", __func__, config_file_.c_str());
        return;
      }
      LOG_INFO("%s: Starting Ble advertisement playback from file: %s", __func__, config_file_.c_str());
      play_back_on_ = true;
      get_next_advertisement();
    }
    std::shared_ptr<model::packets::LinkLayerPacketBuilder> to_send;
    std::chrono::steady_clock::time_point now =
        std::chrono::steady_clock::now();
    elapsed_time_ += now - last_timer_tick_;
    while (play_back_on_ && !play_back_complete_ && next_ad_.ad_time < now) {
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
      for (auto phy : phy_layers_[Phy::Type::LOW_ENERGY]) {
        phy->Send(to_send);
      }
    }
  }
}

void ScriptedBeacon::get_next_advertisement() {
  static int packet_num = 0;

  if (packet_num < ble_ad_list_.advertisements().size()) {
    std::string payload = ble_ad_list_.advertisements(packet_num).payload();
    std::string mac_address = ble_ad_list_.advertisements(packet_num).mac_address();
    uint32_t delay_before_send_ms =
        ble_ad_list_.advertisements(packet_num).delay_before_send_ms();
    next_ad_.ad.assign(payload.begin(), payload.end());
    Address::FromString(mac_address, next_ad_.address);
    next_ad_.ad_time = std::chrono::steady_clock::now() +
                      std::chrono::steady_clock::duration(
                          std::chrono::milliseconds(delay_before_send_ms));
    packet_num++;
  } else {
    play_back_complete_ = true;
    LOG_INFO("%s: Completed Ble advertisement playback from file: %s", __func__, config_file_.c_str());
  }
}
}  // namespace test_vendor_lib
