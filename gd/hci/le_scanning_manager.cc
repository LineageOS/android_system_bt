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

struct LeScanningManager::impl : public bluetooth::hci::LeAddressManagerCallback {
  impl(Module* module) : module_(module), le_scanning_interface_(nullptr) {}

  ~impl() {
    if (address_manager_registered) {
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
        handle_advertising_report<LeAdvertisingReportView, LeAdvertisingReport, LeReport>(
            LeAdvertisingReportView::Create(event));
        break;
      case hci::SubeventCode::DIRECTED_ADVERTISING_REPORT:
        handle_advertising_report<LeDirectedAdvertisingReportView, LeDirectedAdvertisingReport, DirectedLeReport>(
            LeDirectedAdvertisingReportView::Create(event));
        break;
      case hci::SubeventCode::EXTENDED_ADVERTISING_REPORT:
        handle_advertising_report<LeExtendedAdvertisingReportView, LeExtendedAdvertisingReport, ExtendedLeReport>(
            LeExtendedAdvertisingReportView::Create(event));
        handle_extended_advertising_report(LeExtendedAdvertisingReportView::Create(event));
        break;
      case hci::SubeventCode::SCAN_TIMEOUT:
        if (registered_callback_ != nullptr) {
          registered_callback_->Handler()->Post(
              common::BindOnce(&LeScanningManagerCallbacks::on_timeout, common::Unretained(registered_callback_)));
          registered_callback_ = nullptr;
        }
        break;
      default:
        LOG_ALWAYS_FATAL("Unknown advertising subevent %s", hci::SubeventCodeText(event.GetSubeventCode()).c_str());
    }
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

    // TODO: handle AdvertisingCache for scan response
    for (LeExtendedAdvertisingReport report : reports) {
      uint16_t event_type = report.connectable_ | (report.scannable_ << 1) | (report.directed_ << 2) |
                            (report.scan_response_ << 3) | (report.legacy_ << 4) | ((uint16_t)report.data_status_ << 5);

      scanning_callbacks_->OnScanResult(
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

  template <class EventType, class ReportStructType, class ReportType>
  void handle_advertising_report(EventType event_view) {
    if (registered_callback_ == nullptr) {
      LOG_INFO("Dropping advertising event (no registered handler)");
      return;
    }
    if (!event_view.IsValid()) {
      LOG_INFO("Dropping invalid advertising event");
      return;
    }
    std::vector<ReportStructType> report_vector = event_view.GetAdvertisingReports();
    if (report_vector.empty()) {
      LOG_INFO("Zero results in advertising event");
      return;
    }
    std::vector<std::shared_ptr<LeReport>> param;
    param.reserve(report_vector.size());
    for (const ReportStructType& report : report_vector) {
      param.push_back(std::shared_ptr<LeReport>(static_cast<LeReport*>(new ReportType(report))));
    }
    registered_callback_->Handler()->Post(common::BindOnce(&LeScanningManagerCallbacks::on_advertisements,
                                                           common::Unretained(registered_callback_), param));
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
      stop_scan();
    }
  }

  void start_scan() {
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
    switch (api_type_) {
      case ScanApiType::EXTENDED:
        le_scanning_interface_->EnqueueCommand(
            hci::LeSetExtendedScanEnableBuilder::Create(
                Enable::DISABLED, FilterDuplicates::DISABLED /* filter duplicates */, 0, 0),
            module_handler_->BindOnce(impl::check_status));
        registered_callback_ = nullptr;
        break;
      case ScanApiType::ANDROID_HCI:
      case ScanApiType::LEGACY:
        le_scanning_interface_->EnqueueCommand(
            hci::LeSetScanEnableBuilder::Create(Enable::DISABLED, Enable::DISABLED /* filter duplicates */),
            module_handler_->BindOnce(impl::check_status));
        registered_callback_ = nullptr;
        break;
    }
  }

  // TODO remove
  void start_scan_old(LeScanningManagerCallbacks* le_scanning_manager_callbacks) {
    registered_callback_ = le_scanning_manager_callbacks;

    if (!address_manager_registered) {
      le_address_manager_->Register(this);
      address_manager_registered = true;
    }

    // If we receive start_scan during paused, replace the cached_registered_callback_ for OnResume
    if (cached_registered_callback_ != nullptr) {
      cached_registered_callback_ = registered_callback_;
      return;
    }

    switch (api_type_) {
      case ScanApiType::EXTENDED:
        le_scanning_interface_->EnqueueCommand(
            hci::LeSetExtendedScanEnableBuilder::Create(Enable::ENABLED,
                                                        FilterDuplicates::DISABLED /* filter duplicates */, 0, 0),
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

  // TODO remove
  void stop_scan_old(common::Callback<void()> on_stopped, bool from_on_pause) {
    if (address_manager_registered && !from_on_pause) {
      cached_registered_callback_ = nullptr;
      le_address_manager_->Unregister(this);
      address_manager_registered = false;
    }
    if (registered_callback_ == nullptr) {
      return;
    }
    registered_callback_->Handler()->Post(std::move(on_stopped));
    switch (api_type_) {
      case ScanApiType::EXTENDED:
        le_scanning_interface_->EnqueueCommand(
            hci::LeSetExtendedScanEnableBuilder::Create(Enable::DISABLED,
                                                        FilterDuplicates::DISABLED /* filter duplicates */, 0, 0),
            module_handler_->BindOnce(impl::check_status));
        registered_callback_ = nullptr;
        break;
      case ScanApiType::ANDROID_HCI:
      case ScanApiType::LEGACY:
        le_scanning_interface_->EnqueueCommand(
            hci::LeSetScanEnableBuilder::Create(Enable::DISABLED, Enable::DISABLED /* filter duplicates */),
            module_handler_->BindOnce(impl::check_status));
        registered_callback_ = nullptr;
        break;
    }
  }

  void register_scanning_callback(ScanningCallback* scanning_callbacks) {
    scanning_callbacks_ = scanning_callbacks;
  }

  void OnPause() override {
    cached_registered_callback_ = registered_callback_;
    stop_scan_old(common::Bind(&impl::ack_pause, common::Unretained(this)), true);
  }

  void ack_pause() {
    le_address_manager_->AckPause(this);
  }

  void OnResume() override {
    if (cached_registered_callback_ != nullptr) {
      auto cached_registered_callback = cached_registered_callback_;
      cached_registered_callback_ = nullptr;
      start_scan_old(cached_registered_callback);
    }
    le_address_manager_->AckResume(this);
  }

  ScanApiType api_type_;

  LeScanningManagerCallbacks* registered_callback_ = nullptr;
  LeScanningManagerCallbacks* cached_registered_callback_ = nullptr;
  Module* module_;
  os::Handler* module_handler_;
  hci::HciLayer* hci_layer_;
  hci::Controller* controller_;
  hci::LeScanningInterface* le_scanning_interface_;
  hci::LeAddressManager* le_address_manager_;
  bool address_manager_registered = false;
  ScanningCallback* scanning_callbacks_ = nullptr;
  std::vector<Scanner> scanners_;

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

void LeScanningManager::StartScan(LeScanningManagerCallbacks* callbacks) {
  GetHandler()->Post(common::Bind(&impl::start_scan_old, common::Unretained(pimpl_.get()), callbacks));
}

void LeScanningManager::StopScan(common::Callback<void()> on_stopped) {
  GetHandler()->Post(common::Bind(&impl::stop_scan_old, common::Unretained(pimpl_.get()), on_stopped, false));
}

void LeScanningManager::RegisterScanningCallback(ScanningCallback* scanning_callback) {
  CallOn(pimpl_.get(), &impl::register_scanning_callback, scanning_callback);
}

}  // namespace hci
}  // namespace bluetooth
