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

constexpr uint16_t kLeScanWindowMin = 0x0004;
constexpr uint16_t kLeScanWindowMax = 0x4000;
constexpr uint16_t kDefaultLeExtendedScanWindow = 4800;
constexpr uint16_t kLeExtendedScanWindowMax = 0xFFFF;
constexpr uint16_t kLeScanIntervalMin = 0x0004;
constexpr uint16_t kLeScanIntervalMax = 0x4000;
constexpr uint16_t kDefaultLeExtendedScanInterval = 4800;
constexpr uint16_t kLeExtendedScanIntervalMax = 0xFFFF;

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

class NullScanningCallback : public ScanningCallback {
  void OnScannerRegistered(const bluetooth::hci::Uuid app_uuid, ScannerId scanner_id, ScanningStatus status) {
    LOG_INFO("OnScannerRegistered in NullScanningCallback");
  }
  void OnScanResult(
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
    LOG_INFO("OnScanResult in NullScanningCallback");
  }
  void OnTrackAdvFoundLost() {
    LOG_INFO("OnTrackAdvFoundLost in NullScanningCallback");
  }
  void OnBatchScanReports(int client_if, int status, int report_format, int num_records, std::vector<uint8_t> data) {
    LOG_INFO("OnBatchScanReports in NullScanningCallback");
  }
  void OnTimeout() {
    LOG_INFO("OnTimeout in NullScanningCallback");
  }
  void OnFilterEnable(Enable enable, uint8_t status) {
    LOG_INFO("OnFilterEnable in NullScanningCallback");
  }
  void OnFilterParamSetup(uint8_t available_spaces, ApcfAction action, uint8_t status) {
    LOG_INFO("OnFilterParamSetup in NullScanningCallback");
  }
  void OnFilterConfigCallback(
      ApcfFilterType filter_type, uint8_t available_spaces, ApcfAction action, uint8_t status) {
    LOG_INFO("OnFilterConfigCallback in NullScanningCallback");
  }
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
      interval_ms_ = kDefaultLeExtendedScanInterval;
      window_ms_ = kDefaultLeExtendedScanWindow;
    } else if (controller_->IsSupported(OpCode::LE_EXTENDED_SCAN_PARAMS)) {
      api_type_ = ScanApiType::ANDROID_HCI;
    } else {
      api_type_ = ScanApiType::LEGACY;
    }
    is_filter_support_ = controller_->IsSupported(OpCode::LE_ADV_FILTER);
    scanners_ = std::vector<Scanner>(kMaxAppNum + 1);
    for (size_t i = 0; i < scanners_.size(); i++) {
      scanners_[i].app_uuid = Uuid::kEmpty;
      scanners_[i].in_use = false;
    }
    configure_scan();
  }

  void stop() {
    for (auto subevent_code : LeScanningEvents) {
      hci_layer_->UnregisterLeEventHandler(subevent_code);
    }
    scanning_callbacks_ = &null_scanning_callback_;
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
        scanning_callbacks_->OnTimeout();
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

    if (address_type == (uint8_t)DirectAdvertisingAddressType::NO_ADDRESS) {
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
          advertising_data);
      return;
    } else if (address == Address::kEmpty) {
      LOG_WARN("Receive non-anonymous advertising report with empty address, skip!");
      return;
    }

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
    phy_scan_parameters.le_scan_window_ = window_ms_;
    phy_scan_parameters.le_scan_interval_ = interval_ms_;
    phy_scan_parameters.le_scan_type_ = le_scan_type_;
    parameter_vector.push_back(phy_scan_parameters);
    uint8_t phys_in_use = 1;

    // The Host shall not issue set scan parameter command when scanning is enabled
    stop_scan();

    if (le_address_manager_->GetAddressPolicy() != LeAddressManager::USE_PUBLIC_ADDRESS) {
      own_address_type_ = OwnAddressType::RANDOM_DEVICE_ADDRESS;
    }

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
      configure_scan();
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

  void set_scan_parameters(LeScanType scan_type, uint16_t scan_interval, uint16_t scan_window) {
    uint32_t max_scan_interval = kLeScanIntervalMax;
    uint32_t max_scan_window = kLeScanWindowMax;
    if (api_type_ == ScanApiType::EXTENDED) {
      max_scan_interval = kLeExtendedScanIntervalMax;
      max_scan_window = kLeExtendedScanWindowMax;
    }

    if (scan_type != LeScanType::ACTIVE && scan_type != LeScanType::PASSIVE) {
      LOG_ERROR("Invalid scan type");
      return;
    }
    if (scan_interval > max_scan_interval || scan_interval < kLeScanIntervalMin) {
      LOG_ERROR("Invalid scan_interval %d", scan_interval);
      return;
    }
    if (scan_window > max_scan_window || scan_window < kLeScanWindowMin) {
      LOG_ERROR("Invalid scan_window %d", scan_window);
      return;
    }
    le_scan_type_ = scan_type;
    interval_ms_ = scan_interval;
    window_ms_ = scan_window;
  }

  void scan_filter_enable(bool enable) {
    if (!is_filter_support_) {
      LOG_WARN("Advertising filter is not supported");
      return;
    }

    Enable apcf_enable = enable ? Enable::ENABLED : Enable::DISABLED;
    le_scanning_interface_->EnqueueCommand(
        LeAdvFilterEnableBuilder::Create(apcf_enable),
        module_handler_->BindOnceOn(this, &impl::on_advertising_filter_complete));
  }

  void scan_filter_parameter_setup(
      ApcfAction action, uint8_t filter_index, AdvertisingFilterParameter advertising_filter_parameter) {
    if (!is_filter_support_) {
      LOG_WARN("Advertising filter is not supported");
      return;
    }

    switch (action) {
      case ApcfAction::ADD:
        le_scanning_interface_->EnqueueCommand(
            LeAdvFilterAddFilteringParametersBuilder::Create(
                filter_index,
                advertising_filter_parameter.feature_selection,
                advertising_filter_parameter.list_logic_type,
                advertising_filter_parameter.filter_logic_type,
                advertising_filter_parameter.rssi_high_thresh,
                advertising_filter_parameter.delivery_mode,
                advertising_filter_parameter.onfound_timeout,
                advertising_filter_parameter.onfound_timeout_cnt,
                advertising_filter_parameter.rssi_low_thres,
                advertising_filter_parameter.onlost_timeout,
                advertising_filter_parameter.num_of_tracking_entries),
            module_handler_->BindOnceOn(this, &impl::on_advertising_filter_complete));
        break;
      case ApcfAction::DELETE:
        le_scanning_interface_->EnqueueCommand(
            LeAdvFilterDeleteFilteringParametersBuilder::Create(filter_index),
            module_handler_->BindOnceOn(this, &impl::on_advertising_filter_complete));
        break;
      case ApcfAction::CLEAR:
        le_scanning_interface_->EnqueueCommand(
            LeAdvFilterClearFilteringParametersBuilder::Create(),
            module_handler_->BindOnceOn(this, &impl::on_advertising_filter_complete));
        break;
      default:
        LOG_ERROR("Unknown action type: %d", (uint16_t)action);
        break;
    }
  }

  void scan_filter_add(uint8_t filter_index, std::vector<AdvertisingPacketContentFilterCommand> filters) {
    if (!is_filter_support_) {
      LOG_WARN("Advertising filter is not supported");
      return;
    }

    ApcfAction apcf_action = ApcfAction::ADD;
    for (auto filter : filters) {
      /* If data is passed, both mask and data have to be the same length */
      if (filter.data.size() != filter.data_mask.size() && filter.data.size() != 0 && filter.data_mask.size() != 0) {
        LOG_ERROR("data and data_mask are of different size");
        continue;
      }

      switch (filter.filter_type) {
        case ApcfFilterType::BROADCASTER_ADDRESS: {
          update_address_filter(apcf_action, filter_index, filter.address, filter.application_address_type);
          break;
        }
        case ApcfFilterType::SERVICE_UUID:
        case ApcfFilterType::SERVICE_SOLICITATION_UUID: {
          update_uuid_filter(apcf_action, filter_index, filter.filter_type, filter.uuid, filter.uuid_mask);
          break;
        }
        case ApcfFilterType::LOCAL_NAME: {
          update_local_name_filter(apcf_action, filter_index, filter.name);
          break;
        }
        case ApcfFilterType::MANUFACTURER_DATA: {
          update_manufacturer_data_filter(
              apcf_action, filter_index, filter.company, filter.company_mask, filter.data, filter.data_mask);
          break;
        }
        case ApcfFilterType::SERVICE_DATA: {
          update_service_data_filter(apcf_action, filter_index, filter.data, filter.data_mask);
          break;
        }
        default:
          LOG_ERROR("Unknown filter type: %d", (uint16_t)filter.filter_type);
          break;
      }
    }
  }

  void update_address_filter(
      ApcfAction action, uint8_t filter_index, Address address, ApcfApplicationAddressType address_type) {
    if (action != ApcfAction::CLEAR) {
      le_scanning_interface_->EnqueueCommand(
          LeAdvFilterBroadcasterAddressBuilder::Create(action, filter_index, address, address_type),
          module_handler_->BindOnceOn(this, &impl::on_advertising_filter_complete));
    } else {
      le_scanning_interface_->EnqueueCommand(
          LeAdvFilterClearBroadcasterAddressBuilder::Create(filter_index),
          module_handler_->BindOnceOn(this, &impl::on_advertising_filter_complete));
    }
  }

  void update_uuid_filter(
      ApcfAction action, uint8_t filter_index, ApcfFilterType filter_type, Uuid uuid, Uuid uuid_mask) {
    std::vector<uint8_t> combined_data = {};
    if (action != ApcfAction::CLEAR) {
      uint8_t uuid_len = uuid.GetShortestRepresentationSize();
      if (uuid_len == Uuid::kNumBytes16) {
        uint16_t data = uuid.As16Bit();
        combined_data.push_back((uint8_t)data);
        combined_data.push_back((uint8_t)(data >> 8));
      } else if (uuid_len == Uuid::kNumBytes32) {
        uint16_t data = uuid.As32Bit();
        combined_data.push_back((uint8_t)data);
        combined_data.push_back((uint8_t)(data >> 8));
        combined_data.push_back((uint8_t)(data >> 16));
        combined_data.push_back((uint8_t)(data >> 24));
      } else if (uuid_len == Uuid::kNumBytes128) {
        auto data = uuid.To128BitLE();
        combined_data.insert(combined_data.end(), data.begin(), data.end());
      } else {
        LOG_ERROR("illegal UUID length: %d", (uint16_t)uuid_len);
        return;
      }

      if (!uuid_mask.IsEmpty()) {
        if (uuid_len == Uuid::kNumBytes16) {
          uint16_t data = uuid_mask.As16Bit();
          combined_data.push_back((uint8_t)data);
          combined_data.push_back((uint8_t)(data >> 8));
        } else if (uuid_len == Uuid::kNumBytes32) {
          uint16_t data = uuid_mask.As32Bit();
          combined_data.push_back((uint8_t)data);
          combined_data.push_back((uint8_t)(data >> 8));
          combined_data.push_back((uint8_t)(data >> 16));
          combined_data.push_back((uint8_t)(data >> 24));
        } else if (uuid_len == Uuid::kNumBytes128) {
          auto data = uuid_mask.To128BitLE();
          combined_data.insert(combined_data.end(), data.begin(), data.end());
        }
      } else {
        std::vector<uint8_t> data(uuid_len, 0xFF);
        combined_data.insert(combined_data.end(), data.begin(), data.end());
      }
    }

    if (filter_type == ApcfFilterType::SERVICE_UUID) {
      le_scanning_interface_->EnqueueCommand(
          LeAdvFilterServiceUuidBuilder::Create(action, filter_index, combined_data),
          module_handler_->BindOnceOn(this, &impl::on_advertising_filter_complete));
    } else {
      le_scanning_interface_->EnqueueCommand(
          LeAdvFilterSolicitationUuidBuilder::Create(action, filter_index, combined_data),
          module_handler_->BindOnceOn(this, &impl::on_advertising_filter_complete));
    }
  }

  void update_local_name_filter(ApcfAction action, uint8_t filter_index, std::vector<uint8_t> name) {
    le_scanning_interface_->EnqueueCommand(
        LeAdvFilterLocalNameBuilder::Create(action, filter_index, name),
        module_handler_->BindOnceOn(this, &impl::on_advertising_filter_complete));
  }

  void update_manufacturer_data_filter(
      ApcfAction action,
      uint8_t filter_index,
      uint16_t company_id,
      uint16_t company_id_mask,
      std::vector<uint8_t> data,
      std::vector<uint8_t> data_mask) {
    if (data.size() != data_mask.size()) {
      LOG_ERROR("manufacturer data mask should have the same length as manufacturer data");
      return;
    }
    std::vector<uint8_t> combined_data = {};
    if (action != ApcfAction::CLEAR) {
      combined_data.push_back((uint8_t)company_id);
      combined_data.push_back((uint8_t)(company_id >> 8));
      if (data.size() != 0) {
        combined_data.insert(combined_data.end(), data.begin(), data.end());
      }
      if (company_id_mask != 0) {
        combined_data.push_back((uint8_t)company_id_mask);
        combined_data.push_back((uint8_t)(company_id_mask >> 8));
      } else {
        combined_data.push_back(0xFF);
        combined_data.push_back(0xFF);
      }
      if (data_mask.size() != 0) {
        combined_data.insert(combined_data.end(), data_mask.begin(), data_mask.end());
      }
    }

    le_scanning_interface_->EnqueueCommand(
        LeAdvFilterManufacturerDataBuilder::Create(action, filter_index, combined_data),
        module_handler_->BindOnceOn(this, &impl::on_advertising_filter_complete));
  }

  void update_service_data_filter(
      ApcfAction action, uint8_t filter_index, std::vector<uint8_t> data, std::vector<uint8_t> data_mask) {
    if (data.size() != data_mask.size()) {
      LOG_ERROR("service data mask should have the same length as service data");
      return;
    }
    std::vector<uint8_t> combined_data = {};
    if (action != ApcfAction::CLEAR && data.size() != 0) {
      combined_data.insert(combined_data.end(), data.begin(), data.end());
      combined_data.insert(combined_data.end(), data_mask.begin(), data_mask.end());
    }

    le_scanning_interface_->EnqueueCommand(
        LeAdvFilterServiceDataBuilder::Create(action, filter_index, combined_data),
        module_handler_->BindOnceOn(this, &impl::on_advertising_filter_complete));
  }

  void register_scanning_callback(ScanningCallback* scanning_callbacks) {
    scanning_callbacks_ = scanning_callbacks;
  }

  void on_advertising_filter_complete(CommandCompleteView view) {
    ASSERT(view.IsValid());
    auto status_view = LeAdvFilterCompleteView::Create(view);
    ASSERT(status_view.IsValid());
    if (status_view.GetStatus() != ErrorCode::SUCCESS) {
      LOG_INFO(
          "Got a Command complete %s, status %s",
          OpCodeText(view.GetCommandOpCode()).c_str(),
          ErrorCodeText(status_view.GetStatus()).c_str());
    }

    ApcfOpcode apcf_opcode = status_view.GetApcfOpcode();
    switch (apcf_opcode) {
      case ApcfOpcode::ENABLE: {
        auto complete_view = LeAdvFilterEnableCompleteView::Create(status_view);
        ASSERT(complete_view.IsValid());
        scanning_callbacks_->OnFilterEnable(complete_view.GetApcfEnable(), (uint8_t)complete_view.GetStatus());
      } break;
      case ApcfOpcode::SET_FILTERING_PARAMETERS: {
        auto complete_view = LeAdvFilterSetFilteringParametersCompleteView::Create(status_view);
        ASSERT(complete_view.IsValid());
        scanning_callbacks_->OnFilterParamSetup(
            complete_view.GetApcfAvailableSpaces(), complete_view.GetApcfAction(), (uint8_t)complete_view.GetStatus());
      } break;
      case ApcfOpcode::BROADCASTER_ADDRESS: {
        auto complete_view = LeAdvFilterBroadcasterAddressCompleteView::Create(status_view);
        ASSERT(complete_view.IsValid());
        scanning_callbacks_->OnFilterConfigCallback(
            ApcfFilterType::BROADCASTER_ADDRESS,
            complete_view.GetApcfAvailableSpaces(),
            complete_view.GetApcfAction(),
            (uint8_t)complete_view.GetStatus());
      } break;
      case ApcfOpcode::SERVICE_UUID: {
        auto complete_view = LeAdvFilterServiceUuidCompleteView::Create(status_view);
        ASSERT(complete_view.IsValid());
        scanning_callbacks_->OnFilterConfigCallback(
            ApcfFilterType::SERVICE_UUID,
            complete_view.GetApcfAvailableSpaces(),
            complete_view.GetApcfAction(),
            (uint8_t)complete_view.GetStatus());
      } break;
      case ApcfOpcode::SERVICE_SOLICITATION_UUID: {
        auto complete_view = LeAdvFilterSolicitationUuidCompleteView::Create(status_view);
        ASSERT(complete_view.IsValid());
        scanning_callbacks_->OnFilterConfigCallback(
            ApcfFilterType::SERVICE_SOLICITATION_UUID,
            complete_view.GetApcfAvailableSpaces(),
            complete_view.GetApcfAction(),
            (uint8_t)complete_view.GetStatus());
      } break;
      case ApcfOpcode::LOCAL_NAME: {
        auto complete_view = LeAdvFilterLocalNameCompleteView::Create(status_view);
        ASSERT(complete_view.IsValid());
        scanning_callbacks_->OnFilterConfigCallback(
            ApcfFilterType::LOCAL_NAME,
            complete_view.GetApcfAvailableSpaces(),
            complete_view.GetApcfAction(),
            (uint8_t)complete_view.GetStatus());
      } break;
      case ApcfOpcode::MANUFACTURER_DATA: {
        auto complete_view = LeAdvFilterManufacturerDataCompleteView::Create(status_view);
        ASSERT(complete_view.IsValid());
        scanning_callbacks_->OnFilterConfigCallback(
            ApcfFilterType::MANUFACTURER_DATA,
            complete_view.GetApcfAvailableSpaces(),
            complete_view.GetApcfAction(),
            (uint8_t)complete_view.GetStatus());
      } break;
      case ApcfOpcode::SERVICE_DATA: {
        auto complete_view = LeAdvFilterServiceDataCompleteView::Create(status_view);
        ASSERT(complete_view.IsValid());
        scanning_callbacks_->OnFilterConfigCallback(
            ApcfFilterType::SERVICE_DATA,
            complete_view.GetApcfAvailableSpaces(),
            complete_view.GetApcfAction(),
            (uint8_t)complete_view.GetStatus());
      } break;
      default:
        LOG_WARN("Unexpected event type %s", OpCodeText(view.GetCommandOpCode()).c_str());
    }
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
  NullScanningCallback null_scanning_callback_;
  ScanningCallback* scanning_callbacks_ = &null_scanning_callback_;
  std::vector<Scanner> scanners_;
  bool is_scanning_ = false;
  bool scan_on_resume_ = false;
  bool paused_ = false;
  AdvertisingCache advertising_cache_;
  bool is_filter_support_ = false;

  LeScanType le_scan_type_ = LeScanType::ACTIVE;
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
  pimpl_->stop();
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

void LeScanningManager::SetScanParameters(LeScanType scan_type, uint16_t scan_interval, uint16_t scan_window) {
  CallOn(pimpl_.get(), &impl::set_scan_parameters, scan_type, scan_interval, scan_window);
}

void LeScanningManager::ScanFilterEnable(bool enable) {
  CallOn(pimpl_.get(), &impl::scan_filter_enable, enable);
}

void LeScanningManager::ScanFilterParameterSetup(
    ApcfAction action, uint8_t filter_index, AdvertisingFilterParameter advertising_filter_parameter) {
  CallOn(pimpl_.get(), &impl::scan_filter_parameter_setup, action, filter_index, advertising_filter_parameter);
}

void LeScanningManager::ScanFilterAdd(
    uint8_t filter_index, std::vector<AdvertisingPacketContentFilterCommand> filters) {
  CallOn(pimpl_.get(), &impl::scan_filter_add, filter_index, filters);
}

void LeScanningManager::RegisterScanningCallback(ScanningCallback* scanning_callback) {
  CallOn(pimpl_.get(), &impl::register_scanning_callback, scanning_callback);
}

}  // namespace hci
}  // namespace bluetooth
