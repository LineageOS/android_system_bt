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

#include "le_advertiser.h"

using namespace bluetooth::hci;

namespace test_vendor_lib {
void LeAdvertiser::Initialize(AddressWithType address,
                              AddressWithType peer_address,
                              LeScanningFilterPolicy filter_policy,
                              model::packets::AdvertisementType type,
                              const std::vector<uint8_t>& advertisement,
                              const std::vector<uint8_t>& scan_response,
                              std::chrono::steady_clock::duration interval) {
  address_ = address;
  peer_address_ = peer_address;
  filter_policy_ = filter_policy;
  type_ = type;
  advertisement_ = advertisement;
  scan_response_ = scan_response;
  interval_ = interval;
}

void LeAdvertiser::InitializeExtended(
    AddressType address_type, AddressWithType peer_address,
    LeScanningFilterPolicy filter_policy,
    model::packets::AdvertisementType type,
    std::chrono::steady_clock::duration interval) {
  address_ = AddressWithType(address_.GetAddress(), address_type);
  peer_address_ = peer_address;
  filter_policy_ = filter_policy;
  type_ = type;
  interval_ = interval;
  LOG_INFO("%s -> %s type = %hhx interval = %d ms", address_.ToString().c_str(),
           peer_address.ToString().c_str(), type_,
           static_cast<int>(interval_.count()));
}

void LeAdvertiser::Clear() {
  address_ = AddressWithType{};
  peer_address_ = AddressWithType{};
  filter_policy_ = LeScanningFilterPolicy::ACCEPT_ALL;
  type_ = model::packets::AdvertisementType::ADV_IND;
  advertisement_.clear();
  scan_response_.clear();
  interval_ = std::chrono::milliseconds(0);
  enabled_ = false;
}

void LeAdvertiser::SetAddress(Address address) {
  LOG_INFO("set address %s", address_.ToString().c_str());
  address_ = AddressWithType(address, address_.GetAddressType());
}

AddressWithType LeAdvertiser::GetAddress() const { return address_; }

void LeAdvertiser::SetData(const std::vector<uint8_t>& data) {
  advertisement_ = data;
}

void LeAdvertiser::Enable() {
  enabled_ = true;
  last_le_advertisement_ = std::chrono::steady_clock::now() - interval_;
  LOG_INFO("%s -> %s type = %hhx ad length %zu, scan length %zu",
           address_.ToString().c_str(), peer_address_.ToString().c_str(), type_,
           advertisement_.size(), scan_response_.size());
}

void LeAdvertiser::EnableExtended(
    std::chrono::steady_clock::duration duration) {
  last_le_advertisement_ = std::chrono::steady_clock::now();
  if (duration != std::chrono::milliseconds(0)) {
    ending_time_ = std::chrono::steady_clock::now() + duration;
  }
  enabled_ = true;
  LOG_INFO("%s -> %s type = %hhx ad length %zu, scan length %zu",
           address_.ToString().c_str(), peer_address_.ToString().c_str(), type_,
           advertisement_.size(), scan_response_.size());
}

void LeAdvertiser::Disable() { enabled_ = false; }

bool LeAdvertiser::IsEnabled() const { return enabled_; }

std::unique_ptr<model::packets::LeAdvertisementBuilder>
LeAdvertiser::GetAdvertisement(std::chrono::steady_clock::time_point now) {
  if (!enabled_) {
    return nullptr;
  }

  if (now - last_le_advertisement_ < interval_) {
    return nullptr;
  }

  if (last_le_advertisement_ < ending_time_ && ending_time_ < now) {
    enabled_ = false;
    return nullptr;
  }

  last_le_advertisement_ = now;
  return model::packets::LeAdvertisementBuilder::Create(
      address_.GetAddress(), peer_address_.GetAddress(),
      static_cast<model::packets::AddressType>(address_.GetAddressType()),
      type_, advertisement_);
}

std::unique_ptr<model::packets::LeScanResponseBuilder>
LeAdvertiser::GetScanResponse(bluetooth::hci::Address scanned,
                              bluetooth::hci::Address scanner) {
  if (scanned != address_.GetAddress() || !enabled_ || scan_response_.empty()) {
    return nullptr;
  }
  switch (filter_policy_) {
    case bluetooth::hci::LeScanningFilterPolicy::
        WHITE_LIST_AND_INITIATORS_IDENTITY:
    case bluetooth::hci::LeScanningFilterPolicy::WHITE_LIST_ONLY:
      LOG_WARN("ScanResponses don't handle white list filters");
      return nullptr;
    case bluetooth::hci::LeScanningFilterPolicy::CHECK_INITIATORS_IDENTITY:
      if (scanner != peer_address_.GetAddress()) {
        return nullptr;
      }
      break;
    case bluetooth::hci::LeScanningFilterPolicy::ACCEPT_ALL:
      break;
  }
  return model::packets::LeScanResponseBuilder::Create(
      address_.GetAddress(), peer_address_.GetAddress(),
      static_cast<model::packets::AddressType>(address_.GetAddressType()),
      model::packets::AdvertisementType::SCAN_RESPONSE, scan_response_);
}

}  // namespace test_vendor_lib
