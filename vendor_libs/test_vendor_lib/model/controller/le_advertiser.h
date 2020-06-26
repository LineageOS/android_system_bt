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

#include <chrono>
#include <cstdint>
#include <memory>

#include "hci/address_with_type.h"
#include "hci/hci_packets.h"
#include "packets/link_layer_packets.h"

namespace test_vendor_lib {

// Track a single advertising instance
class LeAdvertiser {
 public:
  LeAdvertiser() = default;
  virtual ~LeAdvertiser() = default;

  void Initialize(bluetooth::hci::AddressWithType address,
                  bluetooth::hci::AddressWithType peer_address,
                  bluetooth::hci::LeScanningFilterPolicy filter_policy,
                  model::packets::AdvertisementType type,
                  const std::vector<uint8_t>& advertisement,
                  const std::vector<uint8_t>& scan_response,
                  std::chrono::steady_clock::duration interval);

  void InitializeExtended(bluetooth::hci::AddressType address_type,
                          bluetooth::hci::AddressWithType peer_address,
                          bluetooth::hci::LeScanningFilterPolicy filter_policy,
                          model::packets::AdvertisementType type,
                          std::chrono::steady_clock::duration interval);

  void SetAddress(bluetooth::hci::Address address);

  void SetData(const std::vector<uint8_t>& data);

  std::unique_ptr<model::packets::LeAdvertisementBuilder> GetAdvertisement(
      std::chrono::steady_clock::time_point);

  std::unique_ptr<model::packets::LeScanResponseBuilder> GetScanResponse(
      bluetooth::hci::Address scanned_address,
      bluetooth::hci::Address scanner_address);

  void Clear();

  void Disable();

  void Enable();

  void EnableExtended(std::chrono::steady_clock::duration duration);

  bool IsEnabled() const;

  bluetooth::hci::AddressWithType GetAddress() const;

 private:
  bluetooth::hci::AddressWithType address_{};
  bluetooth::hci::AddressWithType
      peer_address_{};  // For directed advertisements
  bluetooth::hci::LeScanningFilterPolicy filter_policy_{};
  model::packets::AdvertisementType type_{};
  std::vector<uint8_t> advertisement_;
  std::vector<uint8_t> scan_response_;
  std::chrono::steady_clock::duration interval_{};
  std::chrono::steady_clock::time_point ending_time_{};
  bool enabled_{false};
  std::chrono::steady_clock::time_point last_le_advertisement_;
};

}  // namespace test_vendor_lib
