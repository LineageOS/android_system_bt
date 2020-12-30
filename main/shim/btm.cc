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

#define LOG_TAG "bt_shim_btm"

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <mutex>

#include "bta/include/bta_api.h"
#include "main/shim/btm.h"
#include "main/shim/controller.h"
#include "main/shim/entry.h"
#include "main/shim/helpers.h"
#include "main/shim/shim.h"
#include "stack/btm/btm_dev.h"
#include "stack/btm/btm_int_types.h"
#include "types/bt_transport.h"
#include "types/raw_address.h"

#include "gd/hci/le_advertising_manager.h"
#include "gd/hci/le_scanning_manager.h"
#include "gd/neighbor/connectability.h"
#include "gd/neighbor/discoverability.h"
#include "gd/neighbor/inquiry.h"
#include "gd/neighbor/name.h"
#include "gd/neighbor/page.h"
#include "gd/security/security_module.h"

extern tBTM_CB btm_cb;

static constexpr size_t kRemoteDeviceNameLength = 248;

static constexpr uint8_t kAdvDataInfoNotPresent = 0xff;
static constexpr uint8_t kTxPowerInformationNotPresent = 0x7f;
static constexpr uint8_t kNotPeriodicAdvertisement = 0x00;

static constexpr bool kActiveScanning = true;
static constexpr bool kPassiveScanning = false;

using BtmRemoteDeviceName = tBTM_REMOTE_DEV_NAME;

extern void btm_process_cancel_complete(uint8_t status, uint8_t mode);
extern void btm_process_inq_complete(uint8_t status, uint8_t result_type);
extern void btm_ble_process_adv_addr(RawAddress& raw_address,
                                     tBLE_ADDR_TYPE* address_type);
extern void btm_ble_process_adv_pkt_cont(
    uint16_t event_type, uint8_t address_type, const RawAddress& raw_address,
    uint8_t primary_phy, uint8_t secondary_phy, uint8_t advertising_sid,
    int8_t tx_power, int8_t rssi, uint16_t periodic_adv_int, uint8_t data_len,
    uint8_t* data);

extern void btm_api_process_inquiry_result(const RawAddress& raw_address,
                                           uint8_t page_scan_rep_mode,
                                           DEV_CLASS device_class,
                                           uint16_t clock_offset);

extern void btm_api_process_inquiry_result_with_rssi(RawAddress raw_address,
                                                     uint8_t page_scan_rep_mode,
                                                     DEV_CLASS device_class,
                                                     uint16_t clock_offset,
                                                     int8_t rssi);

extern void btm_api_process_extended_inquiry_result(
    RawAddress raw_address, uint8_t page_scan_rep_mode, DEV_CLASS device_class,
    uint16_t clock_offset, int8_t rssi, const uint8_t* eir_data,
    size_t eir_len);

namespace bluetooth {

namespace shim {

constexpr int kAdvertisingReportBufferSize = 1024;

struct ExtendedEventTypeOptions {
  bool connectable{false};
  bool scannable{false};
  bool directed{false};
  bool scan_response{false};
  bool legacy{false};
  bool continuing{false};
  bool truncated{false};
};

constexpr uint16_t kBleEventConnectableBit =
    (0x0001 << 0);  // BLE_EVT_CONNECTABLE_BIT
constexpr uint16_t kBleEventScannableBit =
    (0x0001 << 1);  // BLE_EVT_SCANNABLE_BIT
constexpr uint16_t kBleEventDirectedBit =
    (0x0001 << 2);  // BLE_EVT_DIRECTED_BIT
constexpr uint16_t kBleEventScanResponseBit =
    (0x0001 << 3);  // BLE_EVT_SCAN_RESPONSE_BIT
constexpr uint16_t kBleEventLegacyBit = (0x0001 << 4);  // BLE_EVT_LEGACY_BIT
constexpr uint16_t kBleEventIncompleteContinuing = (0x0001 << 5);
constexpr uint16_t kBleEventIncompleteTruncated = (0x0001 << 6);

static void TransformToExtendedEventType(uint16_t* extended_event_type,
                                         ExtendedEventTypeOptions o) {
  ASSERT(extended_event_type != nullptr);
  *extended_event_type = (o.connectable ? kBleEventConnectableBit : 0) |
                         (o.scannable ? kBleEventScannableBit : 0) |
                         (o.directed ? kBleEventDirectedBit : 0) |
                         (o.scan_response ? kBleEventScanResponseBit : 0) |
                         (o.legacy ? kBleEventLegacyBit : 0) |
                         (o.continuing ? kBleEventIncompleteContinuing : 0) |
                         (o.truncated ? kBleEventIncompleteTruncated : 0);
}

bool Btm::ReadRemoteName::Start(RawAddress raw_address) {
  std::unique_lock<std::mutex> lock(mutex_);
  if (in_progress_) {
    return false;
  }
  raw_address_ = raw_address;
  in_progress_ = true;
  return true;
}

void Btm::ReadRemoteName::Stop() {
  std::unique_lock<std::mutex> lock(mutex_);
  raw_address_ = RawAddress::kEmpty;
  in_progress_ = false;
}

bool Btm::ReadRemoteName::IsInProgress() const { return in_progress_; }
std::string Btm::ReadRemoteName::AddressString() const {
  return raw_address_.ToString();
}

static std::unordered_map<RawAddress, tBLE_ADDR_TYPE> le_address_type_cache_;

static void store_le_address_type(RawAddress address, tBLE_ADDR_TYPE type) {
  if (le_address_type_cache_.count(address) == 0) {
    le_address_type_cache_[address] = type;
  }
}

void Btm::ScanningCallbacks::on_advertisements(
    std::vector<std::shared_ptr<hci::LeReport>> reports) {
  for (auto le_report : reports) {
    tBLE_ADDR_TYPE address_type =
        static_cast<tBLE_ADDR_TYPE>(le_report->address_type_);
    uint16_t extended_event_type = 0;
    uint8_t* report_data = nullptr;
    size_t report_len = 0;

    uint8_t advertising_data_buffer[kAdvertisingReportBufferSize];
    // Copy gap data, if any, into temporary buffer as payload for legacy
    // stack.
    if (!le_report->gap_data_.empty()) {
      bzero(advertising_data_buffer, kAdvertisingReportBufferSize);
      uint8_t* p = advertising_data_buffer;
      for (auto gap_data : le_report->gap_data_) {
        *p++ = gap_data.data_.size() + sizeof(gap_data.data_type_);
        *p++ = static_cast<uint8_t>(gap_data.data_type_);
        p = (uint8_t*)memcpy(p, &gap_data.data_[0], gap_data.data_.size()) +
            gap_data.data_.size();
      }
      report_data = advertising_data_buffer;
      report_len = p - report_data;
    }

    switch (le_report->GetReportType()) {
      case hci::LeReport::ReportType::ADVERTISING_EVENT: {
        switch (le_report->advertising_event_type_) {
          case hci::AdvertisingEventType::ADV_IND:
            TransformToExtendedEventType(
                &extended_event_type,
                {.connectable = true, .scannable = true, .legacy = true});
            break;
          case hci::AdvertisingEventType::ADV_DIRECT_IND:
            TransformToExtendedEventType(
                &extended_event_type,
                {.connectable = true, .directed = true, .legacy = true});
            break;
          case hci::AdvertisingEventType::ADV_SCAN_IND:
            TransformToExtendedEventType(&extended_event_type,
                                         {.scannable = true, .legacy = true});
            break;
          case hci::AdvertisingEventType::ADV_NONCONN_IND:
            TransformToExtendedEventType(&extended_event_type,
                                         {.legacy = true});
            break;
          case hci::AdvertisingEventType::SCAN_RESPONSE:
            TransformToExtendedEventType(&extended_event_type,
                                         {.connectable = true,
                                          .scannable = true,
                                          .scan_response = true,
                                          .legacy = true});
            break;
          default:
            LOG_WARN(
                "%s Unsupported event type:%s", __func__,
                AdvertisingEventTypeText(le_report->advertising_event_type_)
                    .c_str());
            return;
        }

        RawAddress raw_address = ToRawAddress(le_report->address_);

        btm_ble_process_adv_addr(raw_address, &address_type);
        btm_ble_process_adv_pkt_cont(
            extended_event_type, address_type, raw_address, kPhyConnectionLe1M,
            kPhyConnectionNone, kAdvDataInfoNotPresent,
            kTxPowerInformationNotPresent, le_report->rssi_,
            kNotPeriodicAdvertisement, report_len, report_data);
        store_le_address_type(raw_address, address_type);
      } break;

      case hci::LeReport::ReportType::DIRECTED_ADVERTISING_EVENT:
        LOG_WARN("%s Directed advertising is unsupported from device:%s",
                 __func__, le_report->address_.ToString().c_str());
        break;

      case hci::LeReport::ReportType::EXTENDED_ADVERTISING_EVENT: {
        std::shared_ptr<hci::ExtendedLeReport> extended_le_report =
            std::static_pointer_cast<hci::ExtendedLeReport>(le_report);
        TransformToExtendedEventType(
            &extended_event_type,
            {.connectable = extended_le_report->connectable_,
             .scannable = extended_le_report->scannable_,
             .directed = extended_le_report->directed_,
             .scan_response = extended_le_report->scan_response_,
             .legacy = extended_le_report->legacy_,
             .continuing = !extended_le_report->complete_,
             .truncated = extended_le_report->truncated_});
        RawAddress raw_address = ToRawAddress(le_report->address_);
        if (address_type != BLE_ADDR_ANONYMOUS) {
          btm_ble_process_adv_addr(raw_address, &address_type);
        }
        btm_ble_process_adv_pkt_cont(
            extended_event_type, address_type, raw_address,
            extended_le_report->primary_phy_,
            extended_le_report->secondary_phy_, kAdvDataInfoNotPresent,
            extended_le_report->tx_power_, extended_le_report->rssi_,
            kNotPeriodicAdvertisement, report_len, report_data);
        store_le_address_type(raw_address, address_type);
      } break;
    }
  }
}

void Btm::ScanningCallbacks::on_timeout() {
  LOG_WARN("%s Scanning timeout", __func__);
}
os::Handler* Btm::ScanningCallbacks::Handler() {
  return shim::GetGdShimHandler();
}

Btm::Btm(os::Handler* handler, neighbor::InquiryModule* inquiry)
    : scanning_timer_(handler), observing_timer_(handler) {
  ASSERT(handler != nullptr);
  ASSERT(inquiry != nullptr);
  bluetooth::neighbor::InquiryCallbacks inquiry_callbacks = {
      .result = std::bind(&Btm::OnInquiryResult, this, std::placeholders::_1),
      .result_with_rssi =
          std::bind(&Btm::OnInquiryResultWithRssi, this, std::placeholders::_1),
      .extended_result =
          std::bind(&Btm::OnExtendedInquiryResult, this, std::placeholders::_1),
      .complete =
          std::bind(&Btm::OnInquiryComplete, this, std::placeholders::_1)};
  inquiry->RegisterCallbacks(std::move(inquiry_callbacks));
}

void Btm::OnInquiryResult(bluetooth::hci::InquiryResultView view) {
  for (auto& response : view.GetInquiryResults()) {
    btm_api_process_inquiry_result(
        ToRawAddress(response.bd_addr_),
        static_cast<uint8_t>(response.page_scan_repetition_mode_),
        response.class_of_device_.data(), response.clock_offset_);
  }
}

void Btm::OnInquiryResultWithRssi(
    bluetooth::hci::InquiryResultWithRssiView view) {
  for (auto& response : view.GetInquiryResults()) {
    btm_api_process_inquiry_result_with_rssi(
        ToRawAddress(response.address_),
        static_cast<uint8_t>(response.page_scan_repetition_mode_),
        response.class_of_device_.data(), response.clock_offset_,
        response.rssi_);
  }
}

void Btm::OnExtendedInquiryResult(
    bluetooth::hci::ExtendedInquiryResultView view) {
  constexpr size_t kMaxExtendedInquiryResponse = 240;
  uint8_t gap_data_buffer[kMaxExtendedInquiryResponse];
  uint8_t* data = nullptr;
  size_t data_len = 0;

  if (!view.GetExtendedInquiryResponse().empty()) {
    bzero(gap_data_buffer, sizeof(gap_data_buffer));
    uint8_t* p = gap_data_buffer;
    for (auto gap_data : view.GetExtendedInquiryResponse()) {
      *p++ = gap_data.data_.size() + sizeof(gap_data.data_type_);
      *p++ = static_cast<uint8_t>(gap_data.data_type_);
      p = (uint8_t*)memcpy(p, &gap_data.data_[0], gap_data.data_.size()) +
          gap_data.data_.size();
    }
    data = gap_data_buffer;
    data_len = p - data;
  }

  btm_api_process_extended_inquiry_result(
      ToRawAddress(view.GetAddress()),
      static_cast<uint8_t>(view.GetPageScanRepetitionMode()),
      view.GetClassOfDevice().data(), view.GetClockOffset(), view.GetRssi(),
      data, data_len);
}

void Btm::OnInquiryComplete(bluetooth::hci::ErrorCode status) {
  limited_inquiry_active_ = false;
  general_inquiry_active_ = false;
  legacy_inquiry_complete_callback_((static_cast<uint16_t>(status) == 0)
                                        ? (BTM_SUCCESS)
                                        : (BTM_ERR_PROCESSING),
                                    active_inquiry_mode_);

  active_inquiry_mode_ = kInquiryModeOff;
}

void Btm::SetStandardInquiryResultMode() {
  GetInquiry()->SetStandardInquiryResultMode();
}

void Btm::SetInquiryWithRssiResultMode() {
  GetInquiry()->SetInquiryWithRssiResultMode();
}

void Btm::SetExtendedInquiryResultMode() {
  GetInquiry()->SetExtendedInquiryResultMode();
}

void Btm::SetInterlacedInquiryScan() { GetInquiry()->SetInterlacedScan(); }

void Btm::SetStandardInquiryScan() { GetInquiry()->SetStandardScan(); }

bool Btm::IsInterlacedScanSupported() const {
  return controller_get_interface()->supports_interlaced_inquiry_scan();
}

/**
 * One shot inquiry
 */
bool Btm::StartInquiry(
    uint8_t mode, uint8_t duration, uint8_t max_responses,
    LegacyInquiryCompleteCallback legacy_inquiry_complete_callback) {
  switch (mode) {
    case kInquiryModeOff:
      LOG_INFO("%s Stopping inquiry mode", __func__);
      if (limited_inquiry_active_ || general_inquiry_active_) {
        GetInquiry()->StopInquiry();
        limited_inquiry_active_ = false;
        general_inquiry_active_ = false;
      }
      active_inquiry_mode_ = kInquiryModeOff;
      break;

    case kLimitedInquiryMode:
    case kGeneralInquiryMode: {
      if (mode == kLimitedInquiryMode) {
        LOG_INFO(

            "%s Starting limited inquiry mode duration:%hhd max responses:%hhd",
            __func__, duration, max_responses);
        limited_inquiry_active_ = true;
        GetInquiry()->StartLimitedInquiry(duration, max_responses);
        active_inquiry_mode_ = kLimitedInquiryMode;
      } else {
        LOG_INFO(

            "%s Starting general inquiry mode duration:%hhd max responses:%hhd",
            __func__, duration, max_responses);
        general_inquiry_active_ = true;
        GetInquiry()->StartGeneralInquiry(duration, max_responses);
        legacy_inquiry_complete_callback_ = legacy_inquiry_complete_callback;
      }
    } break;

    default:
      LOG_WARN("%s Unknown inquiry mode:%d", __func__, mode);
      return false;
  }
  return true;
}

void Btm::CancelInquiry() {
  LOG_INFO("%s", __func__);
  if (limited_inquiry_active_ || general_inquiry_active_) {
    GetInquiry()->StopInquiry();
    limited_inquiry_active_ = false;
    general_inquiry_active_ = false;
  }
}

bool Btm::IsInquiryActive() const {
  return IsGeneralInquiryActive() || IsLimitedInquiryActive();
}

bool Btm::IsGeneralInquiryActive() const { return general_inquiry_active_; }

bool Btm::IsLimitedInquiryActive() const { return limited_inquiry_active_; }

/**
 * Periodic
 */
bool Btm::StartPeriodicInquiry(uint8_t mode, uint8_t duration,
                               uint8_t max_responses, uint16_t max_delay,
                               uint16_t min_delay,
                               tBTM_INQ_RESULTS_CB* p_results_cb) {
  switch (mode) {
    case kInquiryModeOff:
      limited_periodic_inquiry_active_ = false;
      general_periodic_inquiry_active_ = false;
      GetInquiry()->StopPeriodicInquiry();
      break;

    case kLimitedInquiryMode:
    case kGeneralInquiryMode: {
      if (mode == kLimitedInquiryMode) {
        LOG_INFO("%s Starting limited periodic inquiry mode", __func__);
        limited_periodic_inquiry_active_ = true;
        GetInquiry()->StartLimitedPeriodicInquiry(duration, max_responses,
                                                  max_delay, min_delay);
      } else {
        LOG_INFO("%s Starting general periodic inquiry mode", __func__);
        general_periodic_inquiry_active_ = true;
        GetInquiry()->StartGeneralPeriodicInquiry(duration, max_responses,
                                                  max_delay, min_delay);
      }
    } break;

    default:
      LOG_WARN("%s Unknown inquiry mode:%d", __func__, mode);
      return false;
  }
  return true;
}

bool Btm::IsGeneralPeriodicInquiryActive() const {
  return general_periodic_inquiry_active_;
}

bool Btm::IsLimitedPeriodicInquiryActive() const {
  return limited_periodic_inquiry_active_;
}

/**
 * Discoverability
 */

bluetooth::neighbor::ScanParameters params_{
    .interval = 0,
    .window = 0,
};

void Btm::SetClassicGeneralDiscoverability(uint16_t window, uint16_t interval) {
  params_.window = window;
  params_.interval = interval;

  GetInquiry()->SetScanActivity(params_);
  GetDiscoverability()->StartGeneralDiscoverability();
}

void Btm::SetClassicLimitedDiscoverability(uint16_t window, uint16_t interval) {
  params_.window = window;
  params_.interval = interval;
  GetInquiry()->SetScanActivity(params_);
  GetDiscoverability()->StartLimitedDiscoverability();
}

void Btm::SetClassicDiscoverabilityOff() {
  GetDiscoverability()->StopDiscoverability();
}

DiscoverabilityState Btm::GetClassicDiscoverabilityState() const {
  DiscoverabilityState state{.mode = BTM_NON_DISCOVERABLE,
                             .interval = params_.interval,
                             .window = params_.window};

  if (GetDiscoverability()->IsGeneralDiscoverabilityEnabled()) {
    state.mode = BTM_GENERAL_DISCOVERABLE;
  } else if (GetDiscoverability()->IsLimitedDiscoverabilityEnabled()) {
    state.mode = BTM_LIMITED_DISCOVERABLE;
  }
  return state;
}

void Btm::SetLeGeneralDiscoverability() {
  LOG_WARN("UNIMPLEMENTED %s", __func__);
}

void Btm::SetLeLimitedDiscoverability() {
  LOG_WARN("UNIMPLEMENTED %s", __func__);
}

void Btm::SetLeDiscoverabilityOff() { LOG_WARN("UNIMPLEMENTED %s", __func__); }

DiscoverabilityState Btm::GetLeDiscoverabilityState() const {
  DiscoverabilityState state{
      .mode = kDiscoverableModeOff,
      .interval = 0,
      .window = 0,
  };
  LOG_WARN("UNIMPLEMENTED %s", __func__);
  return state;
}

/**
 * Connectability
 */
void Btm::SetClassicConnectibleOn() {
  GetConnectability()->StartConnectability();
}

void Btm::SetClassicConnectibleOff() {
  GetConnectability()->StopConnectability();
}

ConnectabilityState Btm::GetClassicConnectabilityState() const {
  ConnectabilityState state{.interval = params_.interval,
                            .window = params_.window};

  if (GetConnectability()->IsConnectable()) {
    state.mode = BTM_CONNECTABLE;
  } else {
    state.mode = BTM_NON_CONNECTABLE;
  }
  return state;
}

void Btm::SetInterlacedPageScan() { GetPage()->SetInterlacedScan(); }

void Btm::SetStandardPageScan() { GetPage()->SetStandardScan(); }

void Btm::SetLeConnectibleOn() { LOG_WARN("UNIMPLEMENTED %s", __func__); }

void Btm::SetLeConnectibleOff() { LOG_WARN("UNIMPLEMENTED %s", __func__); }

ConnectabilityState Btm::GetLeConnectabilityState() const {
  ConnectabilityState state{
      .mode = kConnectibleModeOff,
      .interval = 0,
      .window = 0,
  };
  LOG_WARN("UNIMPLEMENTED %s", __func__);
  return state;
}

bool Btm::UseLeLink(const RawAddress& raw_address) const {
  if (GetAclManager()->HACK_GetHandle(ToGdAddress(raw_address)) != 0xFFFF) {
    return false;
  }
  if (GetAclManager()->HACK_GetLeHandle(ToGdAddress(raw_address)) != 0xFFFF) {
    return true;
  }
  // TODO(hsz): use correct transport by using storage records.  For now assume
  // LE for GATT and HID.
  return true;
}

BtmStatus Btm::ReadClassicRemoteDeviceName(const RawAddress& raw_address,
                                           tBTM_CMPL_CB* callback) {
  if (!CheckClassicAclLink(raw_address)) {
    return BTM_UNKNOWN_ADDR;
  }

  if (!classic_read_remote_name_.Start(raw_address)) {
    LOG_INFO("%s Read remote name is currently busy address:%s", __func__,
             raw_address.ToString().c_str());
    return BTM_BUSY;
  }

  LOG_INFO("%s Start read name from address:%s", __func__,
           raw_address.ToString().c_str());
  GetName()->ReadRemoteNameRequest(
      ToGdAddress(raw_address), hci::PageScanRepetitionMode::R1,
      0 /* clock_offset */, hci::ClockOffsetValid::INVALID,

      base::Bind(
          [](tBTM_CMPL_CB* callback, ReadRemoteName* classic_read_remote_name,
             hci::ErrorCode status, hci::Address address,
             std::array<uint8_t, kRemoteDeviceNameLength> remote_name) {
            RawAddress raw_address = ToRawAddress(address);

            BtmRemoteDeviceName name{
                .status = (static_cast<uint8_t>(status) == 0)
                              ? (BTM_SUCCESS)
                              : (BTM_BAD_VALUE_RET),
                .bd_addr = raw_address,
                .length = kRemoteDeviceNameLength,
            };
            std::copy(remote_name.begin(), remote_name.end(),
                      name.remote_bd_name);
            LOG_INFO("%s Finish read name from address:%s name:%s", __func__,
                     address.ToString().c_str(), name.remote_bd_name);
            callback(&name);
            classic_read_remote_name->Stop();
          },
          callback, &classic_read_remote_name_),
      GetGdShimHandler());
  return BTM_CMD_STARTED;
}

BtmStatus Btm::ReadLeRemoteDeviceName(const RawAddress& raw_address,
                                      tBTM_CMPL_CB* callback) {
  if (!CheckLeAclLink(raw_address)) {
    return BTM_UNKNOWN_ADDR;
  }

  if (!le_read_remote_name_.Start(raw_address)) {
    return BTM_BUSY;
  }

  LOG_INFO("UNIMPLEMENTED %s need access to GATT module", __func__);
  return BTM_UNKNOWN_ADDR;
}

BtmStatus Btm::CancelAllReadRemoteDeviceName() {
  if (classic_read_remote_name_.IsInProgress() ||
      le_read_remote_name_.IsInProgress()) {
    if (classic_read_remote_name_.IsInProgress()) {
      hci::Address address;
      hci::Address::FromString(classic_read_remote_name_.AddressString(),
                               address);

      GetName()->CancelRemoteNameRequest(
          address,
          common::BindOnce(
              [](ReadRemoteName* classic_read_remote_name,
                 hci::ErrorCode status,
                 hci::Address address) { classic_read_remote_name->Stop(); },
              &classic_read_remote_name_),
          GetGdShimHandler());
    }
    if (le_read_remote_name_.IsInProgress()) {
      LOG_INFO("UNIMPLEMENTED %s need access to GATT module", __func__);
    }
    return BTM_UNKNOWN_ADDR;
  }
  LOG_WARN("%s Cancelling classic remote device name without one in progress",
           __func__);
  return BTM_WRONG_MODE;
}

void Btm::StartAdvertising() {
  if (advertiser_id_ == hci::LeAdvertisingManager::kInvalidId) {
    LOG_WARN("%s Already advertising; please stop prior to starting again",
             __func__);
    return;
  }

  hci::ExtendedAdvertisingConfig config = {};
  advertiser_id_ = GetAdvertising()->ExtendedCreateAdvertiser(
      0x00, config,
      common::Bind([](hci::Address, hci::AddressType) { /*OnScan*/ }),
      common::Bind([](hci::ErrorCode, uint8_t, uint8_t) { /*OnTerminated*/ }),
      0, 0, GetGdShimHandler());
  if (advertiser_id_ == hci::LeAdvertisingManager::kInvalidId) {
    LOG_WARN("%s Unable to start advertising", __func__);
    return;
  }
  LOG_INFO("%s Started advertising", __func__);
}

void Btm::StopAdvertising() {
  if (advertiser_id_ == hci::LeAdvertisingManager::kInvalidId) {
    LOG_WARN("%s No active advertising", __func__);
    return;
  }
  GetAdvertising()->RemoveAdvertiser(advertiser_id_);
  advertiser_id_ = hci::LeAdvertisingManager::kInvalidId;
  LOG_INFO("%s Stopped advertising", __func__);
}

void Btm::StartConnectability() { StartAdvertising(); }

void Btm::StopConnectability() { StopAdvertising(); }

void Btm::StartActiveScanning() { StartScanning(kActiveScanning); }

void Btm::StopActiveScanning() {
  GetScanning()->StopScan(base::Bind([]() {}));
}

void Btm::SetScanningTimer(uint64_t duration_ms,
                           common::OnceCallback<void()> callback) {
  scanning_timer_.Schedule(std::move(callback),
                           std::chrono::milliseconds(duration_ms));
}

void Btm::CancelScanningTimer() { scanning_timer_.Cancel(); }

void Btm::StartObserving() { StartScanning(kPassiveScanning); }

void Btm::StopObserving() { StopActiveScanning(); }

void Btm::SetObservingTimer(uint64_t duration_ms,
                            common::OnceCallback<void()> callback) {
  observing_timer_.Schedule(std::move(callback),
                            std::chrono::milliseconds(duration_ms));
}

void Btm::CancelObservingTimer() { observing_timer_.Cancel(); }

void Btm::StartScanning(bool use_active_scanning) {
  GetScanning()->StartScan(&scanning_callbacks_);
}

size_t Btm::GetNumberOfAdvertisingInstances() const {
  return GetAdvertising()->GetNumberOfAdvertisingInstances();
}

tBTM_STATUS Btm::CreateBond(const RawAddress& bd_addr, tBLE_ADDR_TYPE addr_type,
                            tBT_TRANSPORT transport, int device_type) {
  if (transport == BT_TRANSPORT_UNKNOWN) {
    if (device_type & BT_DEVICE_TYPE_BLE) {
      transport = BT_TRANSPORT_LE;
    } else if (device_type & BT_DEVICE_TYPE_BREDR) {
      transport = BT_TRANSPORT_BR_EDR;
    }
    LOG_INFO("%s guessing transport as %02x ", __func__, transport);
  }

  auto security_manager = GetSecurityModule()->GetSecurityManager();
  switch (transport) {
    case BT_TRANSPORT_BR_EDR:
      security_manager->CreateBond(ToAddressWithType(bd_addr, BLE_ADDR_PUBLIC));
      break;
    case BT_TRANSPORT_LE:
      security_manager->CreateBondLe(ToAddressWithType(bd_addr, addr_type));
      break;
    default:
      return BTM_ILLEGAL_VALUE;
  }
  return BTM_CMD_STARTED;
}

bool Btm::CancelBond(const RawAddress& bd_addr) {
  auto security_manager = GetSecurityModule()->GetSecurityManager();
  security_manager->CancelBond(ToAddressWithType(bd_addr, BLE_ADDR_PUBLIC));
  return true;
}

bool Btm::RemoveBond(const RawAddress& bd_addr) {
  // TODO(cmanton) Check if acl is connected
  auto security_manager = GetSecurityModule()->GetSecurityManager();
  security_manager->RemoveBond(ToAddressWithType(bd_addr, BLE_ADDR_PUBLIC));
  return true;
}

uint16_t Btm::GetAclHandle(const RawAddress& remote_bda,
                           tBT_TRANSPORT transport) {
  auto acl_manager = GetAclManager();
  if (transport == BT_TRANSPORT_BR_EDR) {
    return acl_manager->HACK_GetHandle(ToGdAddress(remote_bda));
  } else {
    return acl_manager->HACK_GetLeHandle(ToGdAddress(remote_bda));
  }
}

tBLE_ADDR_TYPE Btm::GetAddressType(const RawAddress& bd_addr) {
  tBTM_SEC_DEV_REC* p_dev_rec = btm_find_dev(bd_addr);
  if (p_dev_rec != NULL && p_dev_rec->device_type & BT_DEVICE_TYPE_BLE) {
    if (!p_dev_rec->ble.identity_address_with_type.bda.IsEmpty()) {
      return p_dev_rec->ble.identity_address_with_type.type;
    } else {
      return p_dev_rec->ble.ble_addr_type;
    }
  }
  if (le_address_type_cache_.count(bd_addr) == 0) {
    LOG(ERROR) << "Unknown bd_addr. Use public address";
    return BLE_ADDR_PUBLIC;
  }
  return le_address_type_cache_[bd_addr];
}

void Btm::StoreAddressType(const RawAddress& bd_addr, tBLE_ADDR_TYPE type) {
  store_le_address_type(bd_addr, type);
}

}  // namespace shim

}  // namespace bluetooth
