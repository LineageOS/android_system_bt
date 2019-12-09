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
#define LOG_TAG "bt_gd_shim"

#include <functional>
#include <memory>

#include "common/bind.h"
#include "hci/address.h"
#include "hci/hci_packets.h"
#include "hci/le_report.h"
#include "hci/le_scanning_manager.h"
#include "module.h"
#include "os/handler.h"
#include "os/log.h"
#include "shim/scanning.h"

namespace bluetooth {
namespace shim {

constexpr size_t kAdvertisingReportBufferSize = 1024;

struct Scanning::impl : public hci::LeScanningManagerCallbacks {
  void StartScanning(bool set_active, AdvertisingReportCallback advertising_callback,
                     DirectedAdvertisingReportCallback directed_advertising_callback,
                     ExtendedAdvertisingReportCallback extended_advertising_callback,
                     ScanningTimeoutCallback timeout_callback);
  void StopScanning();

  void on_advertisements(std::vector<std::shared_ptr<hci::LeReport>>) override;
  void on_timeout() override;
  os::Handler* Handler() override;

  void OnStopped();

  impl(hci::LeScanningManager* scanning_manager, os::Handler* handler);
  ~impl();

 private:
  hci::LeScanningManager* scanning_manager_{nullptr};
  os::Handler* handler_;
  bool active_scanning_{true};

  AdvertisingReportCallback advertising_callback_;
  DirectedAdvertisingReportCallback directed_advertising_callback_;
  ExtendedAdvertisingReportCallback extended_advertising_callback_;
  ScanningTimeoutCallback timeout_callback_;
};

const ModuleFactory Scanning::Factory = ModuleFactory([]() { return new Scanning(); });

Scanning::impl::impl(hci::LeScanningManager* scanning_manager, os::Handler* handler)
    : scanning_manager_(scanning_manager), handler_(handler) {}

Scanning::impl::~impl() {}

struct ExtendedEventTypeOptions {
  bool connectable{false};
  bool scannable{false};
  bool directed{false};
  bool scan_response{false};
  bool legacy{false};
  bool continuing{false};
  bool truncated{false};
};

constexpr uint16_t kBleEventConnectableBit = (0x0001 << 0);   // BLE_EVT_CONNECTABLE_BIT
constexpr uint16_t kBleEventScannableBit = (0x0001 << 1);     // BLE_EVT_SCANNABLE_BIT
constexpr uint16_t kBleEventDirectedBit = (0x0001 << 2);      // BLE_EVT_DIRECTED_BIT
constexpr uint16_t kBleEventScanResponseBit = (0x0001 << 3);  // BLE_EVT_SCAN_RESPONSE_BIT
constexpr uint16_t kBleEventLegacyBit = (0x0001 << 4);        // BLE_EVT_LEGACY_BIT
constexpr uint16_t kBleEventIncompleteContinuing = (0x0001 << 5);
constexpr uint16_t kBleEventIncompleteTruncated = (0x0001 << 6);

static void TransformToExtendedEventType(uint16_t* extended_event_type, ExtendedEventTypeOptions o) {
  ASSERT(extended_event_type != nullptr);
  *extended_event_type = (o.connectable ? kBleEventConnectableBit : 0) | (o.scannable ? kBleEventScannableBit : 0) |
                         (o.directed ? kBleEventDirectedBit : 0) | (o.scan_response ? kBleEventScanResponseBit : 0) |
                         (o.legacy ? kBleEventLegacyBit : 0) | (o.continuing ? kBleEventIncompleteContinuing : 0) |
                         (o.truncated ? kBleEventIncompleteTruncated : 0);
}

void Scanning::impl::on_advertisements(std::vector<std::shared_ptr<hci::LeReport>> reports) {
  for (auto le_report : reports) {
    AdvertisingReport report{
        .string_address = le_report->address_.ToString(),
        .address_type = static_cast<uint8_t>(le_report->address_type_),
        .rssi = le_report->rssi_,
        .extended_event_type = 0,
        .data = nullptr,
        .len = 0,
    };

    uint8_t advertising_data_buffer[kAdvertisingReportBufferSize];
    // Copy gap data, if any, into temporary buffer as payload for legacy stack.
    if (!le_report->gap_data_.empty()) {
      bzero(advertising_data_buffer, kAdvertisingReportBufferSize);
      uint8_t* p = advertising_data_buffer;
      for (auto gap_data : le_report->gap_data_) {
        *p++ = gap_data.data_.size() + sizeof(gap_data.data_type_);
        *p++ = static_cast<uint8_t>(gap_data.data_type_);
        p = (uint8_t*)memcpy(p, &gap_data.data_[0], gap_data.data_.size()) + gap_data.data_.size();
      }
      report.data = advertising_data_buffer;
      report.len = p - report.data;
    }

    switch (le_report->GetReportType()) {
      case hci::LeReport::ReportType::ADVERTISING_EVENT:
        switch (le_report->advertising_event_type_) {
          case hci::AdvertisingEventType::ADV_IND:
            TransformToExtendedEventType(&report.extended_event_type,
                                         {.connectable = true, .scannable = true, .legacy = true});
            break;
          case hci::AdvertisingEventType::ADV_DIRECT_IND:
            TransformToExtendedEventType(&report.extended_event_type,
                                         {.connectable = true, .directed = true, .legacy = true});
            break;
          case hci::AdvertisingEventType::ADV_SCAN_IND:
            TransformToExtendedEventType(&report.extended_event_type, {.scannable = true, .legacy = true});
            break;
          case hci::AdvertisingEventType::ADV_NONCONN_IND:
            TransformToExtendedEventType(&report.extended_event_type, {.legacy = true});
            break;
          case hci::AdvertisingEventType::ADV_DIRECT_IND_LOW:  // SCAN_RESPONSE
            TransformToExtendedEventType(
                &report.extended_event_type,
                {.connectable = true, .scannable = true, .scan_response = true, .legacy = true});
            break;
          default:
            LOG_WARN("%s Unsupported event type:%s", __func__,
                     AdvertisingEventTypeText(le_report->advertising_event_type_).c_str());
            return;
        }
        if (!advertising_callback_) {
          LOG_INFO("Discarding advertising packet after scan stopped");
        } else {
          advertising_callback_(report);
        }
        break;

      case hci::LeReport::ReportType::DIRECTED_ADVERTISING_EVENT: {
        DirectedAdvertisingReport directed_report(report);
        std::shared_ptr<hci::DirectedLeReport> directed_le_report =
            std::static_pointer_cast<hci::DirectedLeReport>(le_report);
        directed_report.directed_advertising_type = static_cast<uint8_t>(directed_le_report->direct_address_type_);
        if (!directed_advertising_callback_) {
          LOG_INFO("Discarding directed advertising packet after scan stopped");
        } else {
          directed_advertising_callback_(directed_report);
        }
      } break;

      case hci::LeReport::ReportType::EXTENDED_ADVERTISING_EVENT: {
        ExtendedAdvertisingReport extended_report(report);
        std::shared_ptr<hci::ExtendedLeReport> extended_le_report =
            std::static_pointer_cast<hci::ExtendedLeReport>(le_report);
        TransformToExtendedEventType(&report.extended_event_type, {.connectable = extended_le_report->connectable_,
                                                                   .scannable = extended_le_report->scannable_,
                                                                   .directed = extended_le_report->directed_,
                                                                   .scan_response = extended_le_report->scan_response_,
                                                                   .legacy = false,
                                                                   .continuing = !extended_le_report->complete_,
                                                                   .truncated = extended_le_report->truncated_});
        if (!extended_advertising_callback_) {
          LOG_INFO("Discarding extended advertising packet after scan stopped");
        } else {
          extended_advertising_callback_(extended_report);
        }
      } break;
    }
  }
}

void Scanning::impl::on_timeout() {
  timeout_callback_();
}

os::Handler* Scanning::impl::Handler() {
  return handler_;
}

void Scanning::impl::StartScanning(bool set_active, AdvertisingReportCallback advertising_callback,
                                   DirectedAdvertisingReportCallback directed_advertising_callback,
                                   ExtendedAdvertisingReportCallback extended_advertising_callback,
                                   ScanningTimeoutCallback timeout_callback) {
  active_scanning_ = set_active;
  advertising_callback_ = advertising_callback;
  directed_advertising_callback_ = directed_advertising_callback;
  extended_advertising_callback_ = extended_advertising_callback;
  timeout_callback_ = timeout_callback;

  scanning_manager_->StartScan(this);
  LOG_DEBUG("%s Started le %s scanning", __func__, (active_scanning_) ? "active" : "passive");
}

void Scanning::impl::StopScanning() {
  LOG_DEBUG("%s Stopping le %s scanning", __func__, (active_scanning_) ? "active" : "passive");
  scanning_manager_->StopScan(common::Bind(&impl::OnStopped, common::Unretained(this)));
  advertising_callback_ = {};
  directed_advertising_callback_ = {};
  extended_advertising_callback_ = {};
  timeout_callback_ = {};
}

void Scanning::impl::OnStopped() {
  LOG_DEBUG("%s Stopped le %s scanning", __func__, (active_scanning_) ? "active" : "passive");
}

void Scanning::StartScanning(bool set_active, AdvertisingReportCallback advertising_callback,
                             DirectedAdvertisingReportCallback directed_advertising_callback,
                             ExtendedAdvertisingReportCallback extended_advertising_callback,
                             ScanningTimeoutCallback timeout_callback) {
  pimpl_->StartScanning(set_active, advertising_callback, directed_advertising_callback, extended_advertising_callback,
                        timeout_callback);
}

void Scanning::StopScanning() {
  pimpl_->StopScanning();
}

/**
 * Module methods
 */
void Scanning::ListDependencies(ModuleList* list) {
  list->add<hci::LeScanningManager>();
}

void Scanning::Start() {
  pimpl_ = std::make_unique<impl>(GetDependency<hci::LeScanningManager>(), GetHandler());
}

void Scanning::Stop() {
  pimpl_.reset();
}

}  // namespace shim
}  // namespace bluetooth
