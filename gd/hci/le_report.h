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

#include "hci/hci_packets.h"

namespace bluetooth::hci {

class LeReport {
 public:
  explicit LeReport(const LeAdvertisingReport& advertisement)
      : report_type_(ReportType::ADVERTISING_EVENT),
        advertising_event_type_(advertisement.event_type_),
        address_(advertisement.address_),
        address_type_(static_cast<DirectAdvertisingAddressType>(advertisement.address_type_)),
        rssi_(advertisement.rssi_),
        gap_data_(advertisement.advertising_data_) {}
  explicit LeReport(const LeDirectedAdvertisingReport& advertisement)
      : report_type_(ReportType::DIRECTED_ADVERTISING_EVENT),
        address_(advertisement.address_),
        address_type_(advertisement.address_type_),
        rssi_(advertisement.rssi_) {}
  explicit LeReport(const LeExtendedAdvertisingReport& advertisement)
      : report_type_(ReportType::EXTENDED_ADVERTISING_EVENT),
        address_(advertisement.address_),
        address_type_(advertisement.address_type_),
        rssi_(advertisement.rssi_),
        gap_data_(advertisement.advertising_data_) {}
  virtual ~LeReport() = default;

  enum class ReportType {
    ADVERTISING_EVENT = 1,
    DIRECTED_ADVERTISING_EVENT = 2,
    EXTENDED_ADVERTISING_EVENT = 3,
  };
  const ReportType report_type_;

  ReportType GetReportType() const {
    return report_type_;
  }

  // Advertising Event
  const AdvertisingEventType advertising_event_type_{};
  const Address address_{};
  const DirectAdvertisingAddressType address_type_{};
  const int8_t rssi_;
  const std::vector<GapData> gap_data_{};
};

class DirectedLeReport : public LeReport {
 public:
  explicit DirectedLeReport(const LeDirectedAdvertisingReport& advertisement)
      : LeReport(advertisement), direct_address_type_(advertisement.address_type_),
        direct_address_(advertisement.direct_address_) {}
  explicit DirectedLeReport(const LeExtendedAdvertisingReport& advertisement)
      : LeReport(advertisement), direct_address_type_(advertisement.address_type_),
        direct_address_(advertisement.direct_address_) {}

  const DirectAdvertisingAddressType direct_address_type_{};
  const Address direct_address_{};
};

class ExtendedLeReport : public DirectedLeReport {
 public:
  explicit ExtendedLeReport(const LeExtendedAdvertisingReport& advertisement)
      : DirectedLeReport(advertisement),
        connectable_(advertisement.connectable_),
        scannable_(advertisement.scannable_),
        directed_(advertisement.directed_),
        scan_response_(advertisement.scan_response_),
        legacy_(advertisement.legacy_),
        complete_(advertisement.data_status_ == DataStatus::COMPLETE),
        truncated_(advertisement.data_status_ == DataStatus::TRUNCATED),
        primary_phy_(static_cast<uint8_t>(advertisement.primary_phy_)),
        secondary_phy_(static_cast<uint8_t>(advertisement.secondary_phy_)),
        tx_power_(advertisement.tx_power_) {}

  // Extended
  bool connectable_;
  bool scannable_;
  bool directed_;
  bool scan_response_;
  bool legacy_;
  bool complete_;
  bool truncated_;
  uint8_t primary_phy_;
  uint8_t secondary_phy_;
  int8_t tx_power_;
};
}  // namespace bluetooth::hci