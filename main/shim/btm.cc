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
#include <cstddef>
#include <cstdint>
#include <cstring>

#include "main/shim/btm.h"
#include "main/shim/controller.h"
#include "main/shim/entry.h"
#include "main/shim/shim.h"
#include "osi/include/log.h"
#include "stack/btm/btm_int_types.h"
#include "types/class_of_device.h"
#include "types/raw_address.h"

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
                                     uint8_t* address_type);
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

void bluetooth::shim::Btm::StartUp(bluetooth::shim::Btm* btm) {
  CHECK(btm != nullptr);
  CHECK(btm->observing_timer_ == nullptr);
  CHECK(btm->scanning_timer_ == nullptr);
  btm->observing_timer_ = new bluetooth::shim::Timer("observing_timer");
  btm->scanning_timer_ = new bluetooth::shim::Timer("scanning_timer");
}

void bluetooth::shim::Btm::ShutDown(bluetooth::shim::Btm* btm) {
  CHECK(btm != nullptr);
  CHECK(btm->observing_timer_ != nullptr);
  CHECK(btm->scanning_timer_ != nullptr);
  delete btm->scanning_timer_;
  delete btm->observing_timer_;
}

void bluetooth::shim::Btm::OnInquiryResult(std::string string_address,
                                           uint8_t page_scan_rep_mode,
                                           std::string string_class_of_device,
                                           uint16_t clock_offset) {
  RawAddress raw_address;
  RawAddress::FromString(string_address, raw_address);
  ClassOfDevice class_of_device;
  ClassOfDevice::FromString(string_class_of_device, class_of_device);

  btm_api_process_inquiry_result(raw_address, page_scan_rep_mode,
                                 class_of_device.cod, clock_offset);
}

void bluetooth::shim::Btm::OnInquiryResultWithRssi(
    std::string string_address, uint8_t page_scan_rep_mode,
    std::string string_class_of_device, uint16_t clock_offset, int8_t rssi) {
  RawAddress raw_address;
  RawAddress::FromString(string_address, raw_address);
  ClassOfDevice class_of_device;
  ClassOfDevice::FromString(string_class_of_device, class_of_device);

  btm_api_process_inquiry_result_with_rssi(
      raw_address, page_scan_rep_mode, class_of_device.cod, clock_offset, rssi);
}

void bluetooth::shim::Btm::OnExtendedInquiryResult(
    std::string string_address, uint8_t page_scan_rep_mode,
    std::string string_class_of_device, uint16_t clock_offset, int8_t rssi,
    const uint8_t* gap_data, size_t gap_data_len) {
  RawAddress raw_address;
  RawAddress::FromString(string_address, raw_address);
  ClassOfDevice class_of_device;
  ClassOfDevice::FromString(string_class_of_device, class_of_device);

  btm_api_process_extended_inquiry_result(raw_address, page_scan_rep_mode,
                                          class_of_device.cod, clock_offset,
                                          rssi, gap_data, gap_data_len);
}

void bluetooth::shim::Btm::OnInquiryComplete(uint16_t status) {
  legacy_inquiry_complete_callback_(
      (status == 0) ? (BTM_SUCCESS) : (BTM_ERR_PROCESSING),
      active_inquiry_mode_);
  active_inquiry_mode_ = kInquiryModeOff;
}

bool bluetooth::shim::Btm::SetInquiryFilter(uint8_t mode, uint8_t type,
                                            tBTM_INQ_FILT_COND data) {
  switch (mode) {
    case kInquiryModeOff:
      break;
    case kLimitedInquiryMode:
      LOG_WARN(LOG_TAG, "UNIMPLEMENTED %s", __func__);
      break;
    case kGeneralInquiryMode:
      LOG_WARN(LOG_TAG, "UNIMPLEMENTED %s", __func__);
      break;
    default:
      LOG_WARN(LOG_TAG, "%s Unknown inquiry mode:%d", __func__, mode);
      return false;
  }
  return true;
}

void bluetooth::shim::Btm::SetFilterInquiryOnAddress() {
  LOG_WARN(LOG_TAG, "UNIMPLEMENTED %s", __func__);
}

void bluetooth::shim::Btm::SetFilterInquiryOnDevice() {
  LOG_WARN(LOG_TAG, "UNIMPLEMENTED %s", __func__);
}

void bluetooth::shim::Btm::ClearInquiryFilter() {
  LOG_WARN(LOG_TAG, "UNIMPLEMENTED %s", __func__);
}

void bluetooth::shim::Btm::SetStandardInquiryResultMode() {
  bluetooth::shim::GetInquiry()->SetStandardInquiryResultMode();
}

void bluetooth::shim::Btm::SetInquiryWithRssiResultMode() {
  bluetooth::shim::GetInquiry()->SetInquiryWithRssiResultMode();
}

void bluetooth::shim::Btm::SetExtendedInquiryResultMode() {
  bluetooth::shim::GetInquiry()->SetExtendedInquiryResultMode();
}

void bluetooth::shim::Btm::SetInterlacedInquiryScan() {
  bluetooth::shim::GetInquiry()->SetInterlacedScan();
}

void bluetooth::shim::Btm::SetStandardInquiryScan() {
  bluetooth::shim::GetInquiry()->SetStandardScan();
}

bool bluetooth::shim::Btm::IsInterlacedScanSupported() const {
  return controller_get_interface()->supports_interlaced_inquiry_scan();
}

/**
 * One shot inquiry
 */
bool bluetooth::shim::Btm::StartInquiry(
    uint8_t mode, uint8_t duration, uint8_t max_responses,
    LegacyInquiryCompleteCallback legacy_inquiry_complete_callback) {
  switch (mode) {
    case kInquiryModeOff:
      LOG_DEBUG(LOG_TAG, "%s Stopping inquiry mode", __func__);
      bluetooth::shim::GetInquiry()->StopInquiry();
      active_inquiry_mode_ = kInquiryModeOff;
      break;

    case kLimitedInquiryMode:
    case kGeneralInquiryMode: {
      LegacyInquiryCallbacks legacy_inquiry_callbacks{
          .result_callback =
              std::bind(&Btm::OnInquiryResult, this, std::placeholders::_1,
                        std::placeholders::_2, std::placeholders::_3,
                        std::placeholders::_4),
          .result_with_rssi_callback = std::bind(
              &Btm::OnInquiryResultWithRssi, this, std::placeholders::_1,
              std::placeholders::_2, std::placeholders::_3,
              std::placeholders::_4, std::placeholders::_5),
          .extended_result_callback = std::bind(
              &Btm::OnExtendedInquiryResult, this, std::placeholders::_1,
              std::placeholders::_2, std::placeholders::_3,
              std::placeholders::_4, std::placeholders::_5,
              std::placeholders::_6, std::placeholders::_7),
          .complete_callback =
              std::bind(&Btm::OnInquiryComplete, this, std::placeholders::_1),
      };

      if (mode == kLimitedInquiryMode) {
        LOG_DEBUG(
            LOG_TAG,
            "%s Starting limited inquiry mode duration:%hhd max responses:%hhd",
            __func__, duration, max_responses);
        bluetooth::shim::GetInquiry()->StartLimitedInquiry(
            duration, max_responses, legacy_inquiry_callbacks);
        active_inquiry_mode_ = kLimitedInquiryMode;
      } else {
        LOG_DEBUG(
            LOG_TAG,
            "%s Starting general inquiry mode duration:%hhd max responses:%hhd",
            __func__, duration, max_responses);
        bluetooth::shim::GetInquiry()->StartGeneralInquiry(
            duration, max_responses, legacy_inquiry_callbacks);
        legacy_inquiry_complete_callback_ = legacy_inquiry_complete_callback;
      }
    } break;

    default:
      LOG_WARN(LOG_TAG, "%s Unknown inquiry mode:%d", __func__, mode);
      return false;
  }
  return true;
}

void bluetooth::shim::Btm::CancelInquiry() {
  LOG_DEBUG(LOG_TAG, "%s", __func__);
  bluetooth::shim::GetInquiry()->StopInquiry();
}

bool bluetooth::shim::Btm::IsInquiryActive() const {
  return IsGeneralInquiryActive() || IsLimitedInquiryActive();
}

bool bluetooth::shim::Btm::IsGeneralInquiryActive() const {
  return bluetooth::shim::GetInquiry()->IsGeneralInquiryActive();
}

bool bluetooth::shim::Btm::IsLimitedInquiryActive() const {
  return bluetooth::shim::GetInquiry()->IsLimitedInquiryActive();
}

/**
 * Periodic
 */
bool bluetooth::shim::Btm::StartPeriodicInquiry(
    uint8_t mode, uint8_t duration, uint8_t max_responses, uint16_t max_delay,
    uint16_t min_delay, tBTM_INQ_RESULTS_CB* p_results_cb) {
  switch (mode) {
    case kInquiryModeOff:
      bluetooth::shim::GetInquiry()->StopPeriodicInquiry();
      break;

    case kLimitedInquiryMode:
    case kGeneralInquiryMode: {
      LegacyInquiryCallbacks legacy_inquiry_callbacks{
          .result_callback =
              std::bind(&Btm::OnInquiryResult, this, std::placeholders::_1,
                        std::placeholders::_2, std::placeholders::_3,
                        std::placeholders::_4),
          .result_with_rssi_callback = std::bind(
              &Btm::OnInquiryResultWithRssi, this, std::placeholders::_1,
              std::placeholders::_2, std::placeholders::_3,
              std::placeholders::_4, std::placeholders::_5),
          .extended_result_callback = std::bind(
              &Btm::OnExtendedInquiryResult, this, std::placeholders::_1,
              std::placeholders::_2, std::placeholders::_3,
              std::placeholders::_4, std::placeholders::_5,
              std::placeholders::_6, std::placeholders::_7),
          .complete_callback =
              std::bind(&Btm::OnInquiryComplete, this, std::placeholders::_1),
      };
      if (mode == kLimitedInquiryMode) {
        LOG_DEBUG(LOG_TAG, "%s Starting limited periodic inquiry mode",
                  __func__);
        bluetooth::shim::GetInquiry()->StartLimitedPeriodicInquiry(
            duration, max_responses, max_delay, min_delay,
            legacy_inquiry_callbacks);
      } else {
        LOG_DEBUG(LOG_TAG, "%s Starting general periodic inquiry mode",
                  __func__);
        bluetooth::shim::GetInquiry()->StartGeneralPeriodicInquiry(
            duration, max_responses, max_delay, min_delay,
            legacy_inquiry_callbacks);
      }
    } break;

    default:
      LOG_WARN(LOG_TAG, "%s Unknown inquiry mode:%d", __func__, mode);
      return false;
  }
  return true;
}

void bluetooth::shim::Btm::CancelPeriodicInquiry() {
  bluetooth::shim::GetInquiry()->StopPeriodicInquiry();
}

bool bluetooth::shim::Btm::IsGeneralPeriodicInquiryActive() const {
  return bluetooth::shim::GetInquiry()->IsGeneralPeriodicInquiryActive();
}

bool bluetooth::shim::Btm::IsLimitedPeriodicInquiryActive() const {
  return bluetooth::shim::GetInquiry()->IsLimitedPeriodicInquiryActive();
}

/**
 * Discoverability
 */
void bluetooth::shim::Btm::SetClassicGeneralDiscoverability(uint16_t window,
                                                            uint16_t interval) {
  bluetooth::shim::GetInquiry()->SetScanActivity(interval, window);
  bluetooth::shim::GetDiscoverability()->StartGeneralDiscoverability();
}

void bluetooth::shim::Btm::SetClassicLimitedDiscoverability(uint16_t window,
                                                            uint16_t interval) {
  bluetooth::shim::GetInquiry()->SetScanActivity(interval, window);
  bluetooth::shim::GetDiscoverability()->StartLimitedDiscoverability();
}

void bluetooth::shim::Btm::SetClassicDiscoverabilityOff() {
  bluetooth::shim::GetDiscoverability()->StopDiscoverability();
}

DiscoverabilityState bluetooth::shim::Btm::GetClassicDiscoverabilityState()
    const {
  DiscoverabilityState state{.mode = BTM_NON_DISCOVERABLE};
  bluetooth::shim::GetInquiry()->GetScanActivity(state.interval, state.window);

  if (bluetooth::shim::GetDiscoverability()
          ->IsGeneralDiscoverabilityEnabled()) {
    state.mode = BTM_GENERAL_DISCOVERABLE;
  } else if (bluetooth::shim::GetDiscoverability()
                 ->IsLimitedDiscoverabilityEnabled()) {
    state.mode = BTM_LIMITED_DISCOVERABLE;
  }
  return state;
}

void bluetooth::shim::Btm::SetLeGeneralDiscoverability() {
  LOG_WARN(LOG_TAG, "UNIMPLEMENTED %s", __func__);
}

void bluetooth::shim::Btm::SetLeLimitedDiscoverability() {
  LOG_WARN(LOG_TAG, "UNIMPLEMENTED %s", __func__);
}

void bluetooth::shim::Btm::SetLeDiscoverabilityOff() {
  LOG_WARN(LOG_TAG, "UNIMPLEMENTED %s", __func__);
}

DiscoverabilityState bluetooth::shim::Btm::GetLeDiscoverabilityState() const {
  DiscoverabilityState state{
      .mode = kDiscoverableModeOff,
      .interval = 0,
      .window = 0,
  };
  LOG_WARN(LOG_TAG, "UNIMPLEMENTED %s", __func__);
  return state;
}

/**
 * Connectability
 */
void bluetooth::shim::Btm::SetClassicConnectibleOn() {
  bluetooth::shim::GetConnectability()->StartConnectability();
}

void bluetooth::shim::Btm::SetClassicConnectibleOff() {
  bluetooth::shim::GetConnectability()->StopConnectability();
}

ConnectabilityState bluetooth::shim::Btm::GetClassicConnectabilityState()
    const {
  ConnectabilityState state;
  bluetooth::shim::GetPage()->GetScanActivity(state.interval, state.window);

  if (bluetooth::shim::GetConnectability()->IsConnectable()) {
    state.mode = BTM_CONNECTABLE;
  } else {
    state.mode = BTM_NON_CONNECTABLE;
  }
  return state;
}

void bluetooth::shim::Btm::SetInterlacedPageScan() {
  bluetooth::shim::GetPage()->SetInterlacedScan();
}

void bluetooth::shim::Btm::SetStandardPageScan() {
  bluetooth::shim::GetPage()->SetStandardScan();
}

void bluetooth::shim::Btm::SetLeConnectibleOn() {
  LOG_WARN(LOG_TAG, "UNIMPLEMENTED %s", __func__);
}

void bluetooth::shim::Btm::SetLeConnectibleOff() {
  LOG_WARN(LOG_TAG, "UNIMPLEMENTED %s", __func__);
}

ConnectabilityState bluetooth::shim::Btm::GetLeConnectabilityState() const {
  ConnectabilityState state{
      .mode = kConnectibleModeOff,
      .interval = 0,
      .window = 0,
  };
  LOG_WARN(LOG_TAG, "UNIMPLEMENTED %s", __func__);
  return state;
}

bool bluetooth::shim::Btm::IsLeAclConnected(
    const RawAddress& raw_address) const {
  // TODO(cmanton) Check current acl's for this address and indicate if there is
  // an LE option.  For now ignore and default to classic.
  LOG_INFO(LOG_TAG, "%s Le acl connection check is temporarily unsupported",
           __func__);
  return false;
}

bluetooth::shim::BtmStatus bluetooth::shim::Btm::ReadClassicRemoteDeviceName(
    const RawAddress& raw_address, tBTM_CMPL_CB* callback) {
  if (!CheckClassicAclLink(raw_address)) {
    return bluetooth::shim::BTM_UNKNOWN_ADDR;
  }

  if (!classic_read_remote_name_.Start(raw_address)) {
    LOG_INFO(LOG_TAG, "%s Read remote name is currently busy address:%s",
             __func__, raw_address.ToString().c_str());
    return bluetooth::shim::BTM_BUSY;
  }

  LOG_DEBUG(LOG_TAG, "%s Start read name from address:%s", __func__,
            raw_address.ToString().c_str());
  bluetooth::shim::GetName()->ReadRemoteNameRequest(
      classic_read_remote_name_.AddressString(),
      [this, callback](
          std::string address_string, uint8_t hci_status,
          std::array<uint8_t, kRemoteDeviceNameLength> remote_name) {
        RawAddress raw_address;
        RawAddress::FromString(address_string, raw_address);

        BtmRemoteDeviceName name{
            .status = (hci_status == 0) ? (BTM_SUCCESS) : (BTM_BAD_VALUE_RET),
            .bd_addr = raw_address,
            .length = kRemoteDeviceNameLength,
        };
        std::copy(remote_name.begin(), remote_name.end(), name.remote_bd_name);
        LOG_DEBUG(LOG_TAG, "%s Finish read name from address:%s name:%s",
                  __func__, address_string.c_str(), name.remote_bd_name);
        callback(&name);
        classic_read_remote_name_.Stop();
      });
  return bluetooth::shim::BTM_CMD_STARTED;
}

bluetooth::shim::BtmStatus bluetooth::shim::Btm::ReadLeRemoteDeviceName(
    const RawAddress& raw_address, tBTM_CMPL_CB* callback) {
  if (!CheckLeAclLink(raw_address)) {
    return bluetooth::shim::BTM_UNKNOWN_ADDR;
  }

  if (!le_read_remote_name_.Start(raw_address)) {
    return bluetooth::shim::BTM_BUSY;
  }

  LOG_INFO(LOG_TAG, "UNIMPLEMENTED %s need access to GATT module", __func__);
  return bluetooth::shim::BTM_UNKNOWN_ADDR;
}

bluetooth::shim::BtmStatus
bluetooth::shim::Btm::CancelAllReadRemoteDeviceName() {
  if (classic_read_remote_name_.IsInProgress() ||
      le_read_remote_name_.IsInProgress()) {
    if (classic_read_remote_name_.IsInProgress()) {
      bluetooth::shim::GetName()->CancelRemoteNameRequest(
          classic_read_remote_name_.AddressString(),
          [this](std::string address_string, uint8_t status) {
            classic_read_remote_name_.Stop();
          });
    }
    if (le_read_remote_name_.IsInProgress()) {
      LOG_INFO(LOG_TAG, "UNIMPLEMENTED %s need access to GATT module",
               __func__);
    }
    return bluetooth::shim::BTM_UNKNOWN_ADDR;
  }
  LOG_WARN(LOG_TAG,
           "%s Cancelling classic remote device name without one in progress",
           __func__);
  return bluetooth::shim::BTM_WRONG_MODE;
}

void bluetooth::shim::Btm::StartAdvertising() {
  bluetooth::shim::GetAdvertising()->StartAdvertising();
}

void bluetooth::shim::Btm::StopAdvertising() {
  bluetooth::shim::GetAdvertising()->StopAdvertising();
}

void bluetooth::shim::Btm::StartConnectability() {
  bluetooth::shim::GetAdvertising()->StartAdvertising();
}

void bluetooth::shim::Btm::StopConnectability() {
  bluetooth::shim::GetAdvertising()->StopAdvertising();
}

void bluetooth::shim::Btm::StartActiveScanning() {
  StartScanning(kActiveScanning);
}

void bluetooth::shim::Btm::StopActiveScanning() {
  bluetooth::shim::GetScanning()->StopScanning();
}

void bluetooth::shim::Btm::SetScanningTimer(uint64_t duration_ms,
                                            std::function<void()> func) {
  scanning_timer_->Set(duration_ms, func);
}

void bluetooth::shim::Btm::CancelScanningTimer() { scanning_timer_->Cancel(); }

void bluetooth::shim::Btm::StartObserving() { StartScanning(kPassiveScanning); }

void bluetooth::shim::Btm::StopObserving() { StopActiveScanning(); }

void bluetooth::shim::Btm::SetObservingTimer(uint64_t duration_ms,
                                             std::function<void()> func) {
  observing_timer_->Set(duration_ms, func);
}

void bluetooth::shim::Btm::CancelObservingTimer() {
  observing_timer_->Cancel();
}

void bluetooth::shim::Btm::StartScanning(bool use_active_scanning) {
  bluetooth::shim::GetScanning()->StartScanning(
      use_active_scanning,
      [](AdvertisingReport report) {
        RawAddress raw_address;
        RawAddress::FromString(report.string_address, raw_address);

        btm_ble_process_adv_addr(raw_address, &report.address_type);
        btm_ble_process_adv_pkt_cont(
            report.extended_event_type, report.address_type, raw_address,
            kPhyConnectionLe1M, kPhyConnectionNone, kAdvDataInfoNotPresent,
            kTxPowerInformationNotPresent, report.rssi,
            kNotPeriodicAdvertisement, report.len, report.data);
      },
      [](DirectedAdvertisingReport report) {
        LOG_WARN(LOG_TAG,
                 "%s Directed advertising is unsupported from device:%s",
                 __func__, report.string_address.c_str());
      },
      [](ExtendedAdvertisingReport report) {
        RawAddress raw_address;
        RawAddress::FromString(report.string_address, raw_address);
        if (report.address_type != BLE_ADDR_ANONYMOUS) {
          btm_ble_process_adv_addr(raw_address, &report.address_type);
        }
        btm_ble_process_adv_pkt_cont(
            report.extended_event_type, report.address_type, raw_address,
            kPhyConnectionLe1M, kPhyConnectionNone, kAdvDataInfoNotPresent,
            kTxPowerInformationNotPresent, report.rssi,
            kNotPeriodicAdvertisement, report.len, report.data);
      },
      []() { LOG_WARN(LOG_TAG, "%s Scanning timeout", __func__); });
}

size_t bluetooth::shim::Btm::GetNumberOfAdvertisingInstances() const {
  return bluetooth::shim::GetAdvertising()->GetNumberOfAdvertisingInstances();
}
