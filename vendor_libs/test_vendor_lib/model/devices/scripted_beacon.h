/*
 * Copyright 2020 The Android Open Source Project
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

#include <cstdint>
#include <vector>

#include "beacon.h"

namespace test_vendor_lib {

// Pretend to be a lot of beacons by advertising from a file.
class ScriptedBeacon : public Beacon {
 public:
  ScriptedBeacon();
  virtual ~ScriptedBeacon() = default;

  static std::shared_ptr<Device> Create() {
    return std::make_shared<ScriptedBeacon>();
  }

  // Return a string representation of the type of device.
  virtual std::string GetTypeString() const override {
    return "scripted_beacon";
  }

  virtual std::string ToString() const override {
    return "scripted_beacon " + config_file_;
  }

  // Set the address and advertising interval from string args.
  void Initialize(const std::vector<std::string>& args) override;

  void TimerTick() override;

  void IncomingPacket(model::packets::LinkLayerPacketView packet_view) override;

 private:
  static bool registered_;
  bool scanned_once_{false};
  std::chrono::steady_clock::duration elapsed_time_{};
  std::chrono::steady_clock::time_point last_timer_tick_{};
  std::string config_file_{};
  void open_config_file();
  struct Advertisement {
    std::vector<uint8_t> ad;
    Address address;
    std::chrono::steady_clock::time_point ad_time;
  };

  void get_next_advertisement();

  Advertisement next_ad_{};
};

}  // namespace test_vendor_lib
