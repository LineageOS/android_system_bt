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

#include "common/callback.h"
#include "hci/hci_packets.h"
#include "hci/le_report.h"
#include "hci/uuid.h"
#include "module.h"

namespace bluetooth {
namespace hci {

using ScannerId = uint8_t;

class ScanningCallback {
 public:
  enum ScanningStatus {
    SUCCESS,
    NO_RESOURCES = 0x80,
    INTERNAL_ERROR = 0x85,
  };

  virtual ~ScanningCallback() = default;
  virtual void OnScannerRegistered(
      const bluetooth::hci::Uuid app_uuid, ScannerId scanner_id, ScanningStatus status) = 0;
  virtual void OnScanResult(
      uint16_t event_type,
      uint8_t address_type,
      Address address,
      uint8_t primary_phy,
      uint8_t secondary_phy,
      uint8_t advertising_sid,
      int8_t tx_power,
      int8_t rssi,
      uint16_t periodic_advertising_interval,
      std::vector<GapData> advertising_data) = 0;
  virtual void OnTrackAdvFoundLost() = 0;
  virtual void OnBatchScanReports(
      int client_if, int status, int report_format, int num_records, std::vector<uint8_t> data) = 0;
  virtual void OnTimeout() = 0;
};

class LeScanningManager : public bluetooth::Module {
 public:
  static constexpr uint8_t kMaxAppNum = 32;
  static constexpr uint8_t kAdvertisingDataInfoNotPresent = 0xff;
  static constexpr uint8_t kTxPowerInformationNotPresent = 0x7f;
  static constexpr uint8_t kNotPeriodicAdvertisement = 0x00;
  LeScanningManager();

  void RegisterScanner(const Uuid app_uuid);

  void Unregister(ScannerId scanner_id);

  void Scan(bool start);

  void RegisterScanningCallback(ScanningCallback* scanning_callback);

  static const ModuleFactory Factory;

 protected:
  void ListDependencies(ModuleList* list) override;

  void Start() override;

  void Stop() override;

  std::string ToString() const override;

 private:
  struct impl;
  std::unique_ptr<impl> pimpl_;
  DISALLOW_COPY_AND_ASSIGN(LeScanningManager);
};

}  // namespace hci
}  // namespace bluetooth
