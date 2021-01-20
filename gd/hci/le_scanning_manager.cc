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
#include <memory>
#include <mutex>
#include <set>

#include "hci/acl_manager.h"
#include "hci/controller.h"
#include "hci/hci_layer.h"
#include "hci/hci_packets.h"
#include "hci/le_scanning_interface.h"
#include "hci/le_scanning_manager.h"
#include "module.h"
#include "os/handler.h"
#include "os/log.h"

namespace bluetooth {
namespace hci {

constexpr uint16_t kDefaultLeScanWindow = 4800;
constexpr uint16_t kDefaultLeScanInterval = 4800;

constexpr uint8_t kScannableBit = 1;
constexpr uint8_t kDirectedBit = 2;
constexpr uint8_t kScanResponseBit = 3;
constexpr uint8_t kLegacyBit = 4;
constexpr uint8_t kDataStatusBits = 5;

const ModuleFactory LeScanningManager::Factory = ModuleFactory([]() { return new LeScanningManager(); });

enum class ScanApiType {
  LEGACY = 1,
  ANDROID_HCI = 2,
  EXTENDED = 3,
};

struct Scanner {
  Uuid app_uuid;
  bool in_use;
};

class AdvertisingCache {
 public:
  const std::vector<uint8_t>& Set(const AddressWithType& address_with_type, std::vector<uint8_t> data) {
    auto it = Find(address_with_type);
    if (it != items.end()) {
      it->data = std::move(data);
      return it->data;
    }

    if (items.size() > cache_max) {
      items.pop_back();
    }

    items.emplace_front(address_with_type, std::move(data));
    return items.front().data;
  }

  bool Exist(const AddressWithType& address_with_type) {
    auto it = Find(address_with_type);
    if (it == items.end()) {
      return false;
    }
    return true;
  }

  const std::vector<uint8_t>& Append(const AddressWithType& address_with_type, std::vector<uint8_t> data) {
    auto it = Find(address_with_type);
    if (it != items.end()) {
      it->data.insert(it->data.end(), data.begin(), data.end());
      return it->data;
    }

    if (items.size() > cache_max) {
      items.pop_back();
    }

    items.emplace_front(address_with_type, std::move(data));
    return items.front().data;
  }

  /* Clear data for device |addr_type, addr| */
  void Clear(AddressWithType address_with_type) {
    auto it = Find(address_with_type);
    if (it != items.end()) {
      items.erase(it);
    }
  }

  void ClearAll() {
    items.clear();
  }

  struct Item {
    AddressWithType address_with_type;
    std::vector<uint8_t> data;

    Item(const AddressWithType& address_with_type, std::vector<uint8_t> data)
        : address_with_type(address_with_type), data(data) {}
  };

  std::list<Item>::iterator Find(const AddressWithType& address_with_type) {
    for (auto it = items.begin(); it != items.end(); it++) {
      if (it->address_with_type == address_with_type) {
        return it;
      }
    }
    return items.end();
  }

  /* we keep maximum 7 devices in the cache */
  const size_t cache_max = 1000;
  std::list<Item> items;
};

struct LeScanningManager::impl : public bluetooth::hci::LeAddressManagerCallback {
  impl(Module* module) : module_(module), le_scanning_interface_(nullptr) {}

  ~impl() {
    if (address_manager_registered_) {
      le_address_manager_->Unregister(this);
    }
  }

  void start(os::Handler* handler, hci::HciLayer* hci_layer, hci::Controller* controller,
             hci::AclManager* acl_manager) {
    module_handler_ = handler;
    hci_layer_ = hci_layer;
    controller_ = controller;
    le_address_manager_ = acl_manager->GetLeAddressManager();
    le_scanning_interface_ = hci_layer_->GetLeScanningInterface(
        module_handler_->BindOn(this, &LeScanningManager::impl::handle_scan_results));
    if (controller_->IsSupported(OpCode::LE_SET_EXTENDED_SCAN_PARAMETERS)) {
      api_type_ = ScanApiType::EXTENDED;
    } else if (controller_->IsSupported(OpCode::LE_EXTENDED_SCAN_PARAMS)) {
      api_type_ = ScanApiType::ANDROID_HCI;
    } else {
      api_type_ = ScanApiType::LEGACY;
    }
    scanners_ = std::vector<Scanner>(kMaxAppNum + 1);
    for (size_t i = 0; i < scanners_.size(); i++) {
      scanners_[i].app_uuid = Uuid::kEmpty;
      scanners_[i].in_use = false;
    }
    configure_scan();
  }

  void handle_scan_results(LeMetaEventView event) {
    switch (event.GetSubeventCode()) {
      case hci::SubeventCode::ADVERTISING_REPORT:
        handle_advertising_report(LeAdvertisingReportView::Create(event));
        break;
      case hci::SubeventCode::DIRECTED_ADVERTISING_REPORT:
        handle_directed_advertising_report(LeDirectedAdvertisingReportView::Create(event));
        break;
      case hci::SubeventCode::EXTENDED_ADVERTISING_REPORT:
        handle_extended_advertising_report(LeExtendedAdvertisingReportView::Create(event));
        break;
      case hci::SubeventCode::SCAN_TIMEOUT:
        if (scanning_callbacks_ != nullptr) {
          scanning_callbacks_->OnTimeout();
        }
        break;
      default:
        LOG_ALWAYS_FATAL("Unknown advertising subevent %s", hci::SubeventCodeText(event.GetSubeventCode()).c_str());
    }
  }

  struct ExtendedEventTypeOptions {
    bool connectable{false};
    bool scannable{false};
    bool directed{false};
    bool scan_response{false};
    bool legacy{false};
    bool continuing{false};
    bool truncated{false};
  };

  void transform_to_extended_event_type(uint16_t* extended_event_type, ExtendedEventTypeOptions o) {
    ASSERT(extended_event_type != nullptr);
    *extended_event_type = (o.connectable ? 0x0001 << 0 : 0) | (o.scannable ? 0x0001 << 1 : 0) |
                           (o.directed ? 0x0001 << 2 : 0) | (o.scan_response ? 0x0001 << 3 : 0) |
                           (o.legacy ? 0x0001 << 4 : 0) | (o.continuing ? 0x0001 << 5 : 0) |
                           (o.truncated ? 0x0001 << 6 : 0);
  }

  void handle_advertising_report(LeAdvertisingReportView event_view) {
    if (scanning_callbacks_ == nullptr) {
      LOG_INFO("Dropping advertising event (no registered handler)");
      return;
    }
    if (!event_view.IsValid()) {
      LOG_INFO("Dropping invalid advertising event");
      return;
    }
    std::vector<LeAdvertisingReport> reports = event_view.GetAdvertisingReports();
    if (reports.empty()) {
      LOG_INFO("Zero results in advertising event");
      return;
    }

    for (LeAdvertisingReport report : reports) {
      uint16_t extended_event_type = 0;
      switch (report.event_type_) {
        case hci::AdvertisingEventType::ADV_IND:
          transform_to_extended_event_type(
              &extended_event_type, {.connectable = true, .scannable = true, .legacy = true});
          break;
        case hci::AdvertisingEventType::ADV_DIRECT_IND:
          transform_to_extended_event_type(
              &extended_event_type, {.connectable = true, .directed = true, .legacy = true});
          break;
        case hci::AdvertisingEventType::ADV_SCAN_IND:
          transform_to_extended_event_type(&extended_event_type, {.scannable = true, .legacy = true});
          break;
        case hci::AdvertisingEventType::ADV_NONCONN_IND:
          transform_to_extended_event_type(&extended_event_type, {.legacy = true});
          break;
        case hci::AdvertisingEventType::SCAN_RESPONSE:
          transform_to_extended_event_type(
              &extended_event_type, {.connectable = true, .scannable = true, .scan_response = true, .legacy = true});
          break;
        default:
          LOG_WARN("Unsupported event type:%d", (uint16_t)report.event_type_);
          return;
      }

      std::vector<uint8_t> advertising_data = {};
      for (auto gap_data : report.advertising_data_) {
        advertising_data.push_back((uint8_t)gap_data.size() - 1);
        advertising_data.push_back((uint8_t)gap_data.data_type_);
        advertising_data.insert(advertising_data.end(), gap_data.data_.begin(), gap_data.data_.end());
      }

      process_advertising_package_content(
          extended_event_type,
          (uint8_t)report.address_type_,
          report.address_,
          (uint8_t)PrimaryPhyType::LE_1M,
          (uint8_t)SecondaryPhyType::NO_PACKETS,
          kAdvertisingDataInfoNotPresent,
          kTxPowerInformationNotPresent,
          report.rssi_,
          kNotPeriodicAdvertisement,
          advertising_data);
    }
  }

  void handle_directed_advertising_report(LeDirectedAdvertisingReportView event_view) {
    if (scanning_callbacks_ == nullptr) {
      LOG_INFO("Dropping advertising event (no registered handler)");
      return;
    }
    if (!event_view.IsValid()) {
      LOG_INFO("Dropping invalid advertising event");
      return;
    }
    std::vector<LeDirectedAdvertisingReport> reports = event_view.GetAdvertisingReports();
    if (reports.empty()) {
      LOG_INFO("Zero results in advertising event");
      return;
    }
    uint16_t extended_event_type = 0;
    transform_to_extended_event_type(&extended_event_type, {.connectable = true, .directed = true, .legacy = true});
    // TODO: parse report
  }

  void handle_extended_advertising_report(LeExtendedAdvertisingReportView event_view) {
    if (scanning_callbacks_ == nullptr) {
      LOG_INFO("Dropping advertising event (no registered handler)");
      return;
    }
    if (!event_view.IsValid()) {
      LOG_INFO("Dropping invalid advertising event");
      return;
    }
    std::vector<LeExtendedAdvertisingReport> reports = event_view.GetAdvertisingReports();
    if (reports.empty()) {
      LOG_INFO("Zero results in advertising event");
      return;
    }

    for (LeExtendedAdvertisingReport report : reports) {
      uint16_t event_type = report.connectable_ | (report.scannable_ << kScannableBit) |
                            (report.directed_ << kDirectedBit) | (report.scan_response_ << kScanResponseBit) |
                            (report.legacy_ << kLegacyBit) | ((uint16_t)report.data_status_ << kDataStatusBits);
      process_advertising_package_content(
          event_type,
          (uint8_t)report.address_type_,
          report.address_,
          (uint8_t)report.primary_phy_,
          (uint8_t)report.secondary_phy_,
          report.advertising_sid_,
          report.tx_power_,
          report.rssi_,
          report.periodic_advertising_interval_,
          report.advertising_data_);
    }
  }

  void process_advertising_package_content(
      uint16_t event_type,
      uint8_t address_type,
      Address address,
      uint8_t primary_phy,
      uint8_t secondary_phy,
      uint8_t advertising_sid,
      int8_t tx_power,
      int8_t rssi,
      uint16_t periodic_advertising_interval,
      std::vector<uint8_t> advertising_data) {
    bool is_scannable = event_type & (1 << kScannableBit);
    bool is_scan_response = event_type & (1 << kScanResponseBit);
    bool is_legacy = event_type & (1 << kLegacyBit);
    // TODO handle anonymous advertisement (0xFF)
    AddressWithType address_with_type(address, (AddressType)address_type);

    if (is_legacy && is_scan_response && !advertising_cache_.Exist(address_with_type)) {
      return;
    }

    bool is_start = is_legacy && is_scannable && !is_scan_response;

    std::vector<uint8_t> const& adv_data = is_start ? advertising_cache_.Set(address_with_type, advertising_data)
                                                    : advertising_cache_.Append(address_with_type, advertising_data);

    uint8_t data_status = event_type >> kDataStatusBits;
    if (data_status == (uint8_t)DataStatus::CONTINUING) {
      // Waiting for whole data
      return;
    }

    if (is_scannable && !is_scan_response) {
      // Waiting for scan response
      return;
    }

    scanning_callbacks_->OnScanResult(
        event_type,
        address_type,
        address,
        primary_phy,
        secondary_phy,
        advertising_sid,
        tx_power,
        rssi,
        periodic_advertising_interval,
        adv_data);

    advertising_cache_.Clear(address_with_type);
  }

  void configure_scan() {
    std::vector<PhyScanParameters> parameter_vector;
    PhyScanParameters phy_scan_parameters;
    phy_scan_parameters.le_scan_window_ = kDefaultLeScanWindow;
    phy_scan_parameters.le_scan_interval_ = kDefaultLeScanInterval;
    phy_scan_parameters.le_scan_type_ = LeScanType::ACTIVE;
    parameter_vector.push_back(phy_scan_parameters);
    uint8_t phys_in_use = 1;

    switch (api_type_) {
      case ScanApiType::EXTENDED:
        le_scanning_interface_->EnqueueCommand(hci::LeSetExtendedScanParametersBuilder::Create(
                                                   own_address_type_, filter_policy_, phys_in_use, parameter_vector),
                                               module_handler_->BindOnce(impl::check_status));
        break;
      case ScanApiType::ANDROID_HCI:
        le_scanning_interface_->EnqueueCommand(
            hci::LeExtendedScanParamsBuilder::Create(LeScanType::ACTIVE, interval_ms_, window_ms_, own_address_type_,
                                                     filter_policy_),
            module_handler_->BindOnce(impl::check_status));

        break;
      case ScanApiType::LEGACY:
        le_scanning_interface_->EnqueueCommand(
            hci::LeSetScanParametersBuilder::Create(LeScanType::ACTIVE, interval_ms_, window_ms_, own_address_type_,
                                                    filter_policy_),
            module_handler_->BindOnce(impl::check_status));
        break;
    }
  }

  void register_scanner(const Uuid app_uuid) {
    for (uint8_t i = 1; i <= kMaxAppNum; i++) {
      if (scanners_[i].in_use && scanners_[i].app_uuid == app_uuid) {
        LOG_ERROR("Application already registered %s", app_uuid.ToString().c_str());
        scanning_callbacks_->OnScannerRegistered(app_uuid, 0x00, ScanningCallback::ScanningStatus::INTERNAL_ERROR);
        return;
      }
    }

    // valid value of scanner id : 1 ~ kMaxAppNum
    for (uint8_t i = 1; i <= kMaxAppNum; i++) {
      if (!scanners_[i].in_use) {
        scanners_[i].app_uuid = app_uuid;
        scanners_[i].in_use = true;
        scanning_callbacks_->OnScannerRegistered(app_uuid, i, ScanningCallback::ScanningStatus::SUCCESS);
        return;
      }
    }

    LOG_ERROR("Unable to register scanner, max client reached:%d", kMaxAppNum);
    scanning_callbacks_->OnScannerRegistered(app_uuid, 0x00, ScanningCallback::ScanningStatus::NO_RESOURCES);
  }

  void unregister_scanner(ScannerId scanner_id) {
    if (scanner_id <= 0 || scanner_id > kMaxAppNum) {
      LOG_WARN("Invalid scanner id");
      return;
    }

    if (scanners_[scanner_id].in_use) {
      scanners_[scanner_id].in_use = false;
      scanners_[scanner_id].app_uuid = Uuid::kEmpty;
    } else {
      LOG_WARN("Unregister scanner with unused scanner id");
    }
  }

  void scan(bool start) {
    if (start) {
      start_scan();
    } else {
      if (address_manager_registered_) {
        le_address_manager_->Unregister(this);
        address_manager_registered_ = false;
      }
      stop_scan();
    }
  }

  void start_scan() {
    // If we receive start_scan during paused, set scan_on_resume_ to true
    if (paused_) {
      scan_on_resume_ = true;
      return;
    }
    is_scanning_ = true;
    if (!address_manager_registered_) {
      le_address_manager_->Register(this);
      address_manager_registered_ = true;
    }

    switch (api_type_) {
      case ScanApiType::EXTENDED:
        le_scanning_interface_->EnqueueCommand(
            hci::LeSetExtendedScanEnableBuilder::Create(
                Enable::ENABLED, FilterDuplicates::DISABLED /* filter duplicates */, 0, 0),
            module_handler_->BindOnce(impl::check_status));
        break;
      case ScanApiType::ANDROID_HCI:
      case ScanApiType::LEGACY:
        le_scanning_interface_->EnqueueCommand(
            hci::LeSetScanEnableBuilder::Create(Enable::ENABLED, Enable::DISABLED /* filter duplicates */),
            module_handler_->BindOnce(impl::check_status));
        break;
    }
  }

  void stop_scan() {
    is_scanning_ = false;

    switch (api_type_) {
      case ScanApiType::EXTENDED:
        le_scanning_interface_->EnqueueCommand(
            hci::LeSetExtendedScanEnableBuilder::Create(
                Enable::DISABLED, FilterDuplicates::DISABLED /* filter duplicates */, 0, 0),
            module_handler_->BindOnce(impl::check_status));
        break;
      case ScanApiType::ANDROID_HCI:
      case ScanApiType::LEGACY:
        le_scanning_interface_->EnqueueCommand(
            hci::LeSetScanEnableBuilder::Create(Enable::DISABLED, Enable::DISABLED /* filter duplicates */),
            module_handler_->BindOnce(impl::check_status));
        break;
    }
  }

  void register_scanning_callback(ScanningCallback* scanning_callbacks) {
    scanning_callbacks_ = scanning_callbacks;
  }

  void OnPause() override {
    paused_ = true;
    scan_on_resume_ = is_scanning_;
    stop_scan();
    ack_pause();
  }

  void ack_pause() {
    le_address_manager_->AckPause(this);
  }

  void OnResume() override {
    paused_ = false;
    if (scan_on_resume_ == true) {
      start_scan();
    }
    le_address_manager_->AckResume(this);
  }

  ScanApiType api_type_;

  Module* module_;
  os::Handler* module_handler_;
  hci::HciLayer* hci_layer_;
  hci::Controller* controller_;
  hci::LeScanningInterface* le_scanning_interface_;
  hci::LeAddressManager* le_address_manager_;
  bool address_manager_registered_ = false;
  ScanningCallback* scanning_callbacks_ = nullptr;
  std::vector<Scanner> scanners_;
  bool is_scanning_ = false;
  bool scan_on_resume_ = false;
  bool paused_ = false;
  AdvertisingCache advertising_cache_;

  uint32_t interval_ms_{1000};
  uint16_t window_ms_{1000};
  OwnAddressType own_address_type_{OwnAddressType::PUBLIC_DEVICE_ADDRESS};
  LeScanningFilterPolicy filter_policy_{LeScanningFilterPolicy::ACCEPT_ALL};

  static void check_status(CommandCompleteView view) {
    switch (view.GetCommandOpCode()) {
      case (OpCode::LE_SET_SCAN_ENABLE): {
        auto status_view = LeSetScanEnableCompleteView::Create(view);
        ASSERT(status_view.IsValid());
        ASSERT(status_view.GetStatus() == ErrorCode::SUCCESS);
      } break;
      case (OpCode::LE_SET_EXTENDED_SCAN_ENABLE): {
        auto status_view = LeSetExtendedScanEnableCompleteView::Create(view);
        ASSERT(status_view.IsValid());
        ASSERT(status_view.GetStatus() == ErrorCode::SUCCESS);
      } break;
      case (OpCode::LE_SET_SCAN_PARAMETERS): {
        auto status_view = LeSetScanParametersCompleteView::Create(view);
        ASSERT(status_view.IsValid());
        ASSERT(status_view.GetStatus() == ErrorCode::SUCCESS);
      } break;
      case (OpCode::LE_EXTENDED_SCAN_PARAMS): {
        auto status_view = LeExtendedScanParamsCompleteView::Create(view);
        ASSERT(status_view.IsValid());
        ASSERT(status_view.GetStatus() == ErrorCode::SUCCESS);
      } break;
      case (OpCode::LE_SET_EXTENDED_SCAN_PARAMETERS): {
        auto status_view = LeSetExtendedScanParametersCompleteView::Create(view);
        ASSERT(status_view.IsValid());
        ASSERT(status_view.GetStatus() == ErrorCode::SUCCESS);
      } break;
      default:
        LOG_ALWAYS_FATAL("Unhandled event %s", OpCodeText(view.GetCommandOpCode()).c_str());
    }
  }
};

LeScanningManager::LeScanningManager() {
  pimpl_ = std::make_unique<impl>(this);
}

void LeScanningManager::ListDependencies(ModuleList* list) {
  list->add<hci::HciLayer>();
  list->add<hci::Controller>();
  list->add<hci::AclManager>();
}

void LeScanningManager::Start() {
  pimpl_->start(GetHandler(), GetDependency<hci::HciLayer>(), GetDependency<hci::Controller>(),
                GetDependency<AclManager>());
}

void LeScanningManager::Stop() {
  pimpl_.reset();
}

std::string LeScanningManager::ToString() const {
  return "Le Scanning Manager";
}

void LeScanningManager::RegisterScanner(Uuid app_uuid) {
  CallOn(pimpl_.get(), &impl::register_scanner, app_uuid);
}

void LeScanningManager::Unregister(ScannerId scanner_id) {
  CallOn(pimpl_.get(), &impl::unregister_scanner, scanner_id);
}

void LeScanningManager::Scan(bool start) {
  CallOn(pimpl_.get(), &impl::scan, start);
}

void LeScanningManager::RegisterScanningCallback(ScanningCallback* scanning_callback) {
  CallOn(pimpl_.get(), &impl::register_scanning_callback, scanning_callback);
}

}  // namespace hci
}  // namespace bluetooth
