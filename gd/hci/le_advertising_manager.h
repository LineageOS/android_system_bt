/*
 * Copyright 2019 The Android Open Source Project
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

#include <memory>

#include "hci/address_with_type.h"
#include "hci/hci_packets.h"
#include "module.h"

namespace bluetooth {
namespace hci {

class AdvertisingConfig {
 public:
  std::vector<GapData> advertisement;
  std::vector<GapData> scan_response;
  uint16_t interval_min;
  uint16_t interval_max;
  AdvertisingType event_type;
  AddressType address_type;
  PeerAddressType peer_address_type;
  Address peer_address;
  uint8_t channel_map;
  AdvertisingFilterPolicy filter_policy;
  uint8_t tx_power;  // -127 to +20 (0x7f is no preference)
};

class ExtendedAdvertisingConfig : public AdvertisingConfig {
 public:
  bool connectable = false;
  bool scannable = false;
  bool directed = false;
  bool high_duty_directed_connectable = false;
  bool legacy_pdus = false;
  bool anonymous = false;
  bool include_tx_power = false;
  bool use_le_coded_phy;       // Primary advertisement PHY is LE Coded
  uint8_t secondary_max_skip;  // maximum advertising events to be skipped, 0x0 send AUX_ADV_IND prior ot the next event
  SecondaryPhyType secondary_advertising_phy;
  uint8_t sid = 0x00;
  Enable enable_scan_request_notifications = Enable::DISABLED;
  OwnAddressType own_address_type;
  Operation operation;  // TODO(b/149221472): Support fragmentation
  FragmentPreference fragment_preference = FragmentPreference::CONTROLLER_SHOULD_NOT;
  ExtendedAdvertisingConfig() = default;
  ExtendedAdvertisingConfig(const AdvertisingConfig& config);
};

using AdvertiserId = uint8_t;

class AdvertisingCallback {
 public:
  enum AdvertisingStatus {
    SUCCESS,
    DATA_TOO_LARGE,
    TOO_MANY_ADVERTISERS,
    ALREADY_STARTED,
    INTERNAL_ERROR,
    FEATURE_UNSUPPORTED
  };

  virtual ~AdvertisingCallback() = default;
  virtual void OnAdvertisingSetStarted(uint8_t advertiser_id, int8_t tx_power, AdvertisingStatus status) = 0;
  virtual void onAdvertisingEnabled(uint8_t advertiser_id, bool enable, uint8_t status) = 0;
};

class LeAdvertisingManager : public bluetooth::Module {
 public:
  static constexpr AdvertiserId kInvalidId = 0xFF;
  static constexpr uint8_t kInvalidHandle = 0xFF;
  LeAdvertisingManager();

  size_t GetNumberOfAdvertisingInstances() const;

  // Return -1 if the advertiser was not created, otherwise the advertiser ID.
  AdvertiserId CreateAdvertiser(const AdvertisingConfig& config,
                                const common::Callback<void(Address, AddressType)>& scan_callback,
                                const common::Callback<void(ErrorCode, uint8_t, uint8_t)>& set_terminated_callback,
                                os::Handler* handler);
  AdvertiserId ExtendedCreateAdvertiser(
      const ExtendedAdvertisingConfig& config, const common::Callback<void(Address, AddressType)>& scan_callback,
      const common::Callback<void(ErrorCode, uint8_t, uint8_t)>& set_terminated_callback, os::Handler* handler);

  void RemoveAdvertiser(AdvertiserId id);

  void RegisterAdvertisingCallback(AdvertisingCallback* advertising_callback);

  virtual void RegisterSetTerminatedCallback(
      common::ContextualCallback<void(ErrorCode, uint16_t, hci::AddressWithType)> set_terminated_callback);

  static const ModuleFactory Factory;

 protected:
  void ListDependencies(ModuleList* list) override;

  void Start() override;

  void Stop() override;

  std::string ToString() const override;

 private:
  struct impl;
  std::unique_ptr<impl> pimpl_;
  DISALLOW_COPY_AND_ASSIGN(LeAdvertisingManager);
};

}  // namespace hci
}  // namespace bluetooth