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

#include <cstddef>
#include <cstdint>
#include <functional>
#include <mutex>
#include <unordered_map>
#include <vector>

#include "hci/hci_packets.h"

#include "stack/btm/neighbor_inquiry.h"
#include "stack/include/btm_api_types.h"
#include "types/raw_address.h"

#include "gd/common/callback.h"
#include "gd/hci/le_advertising_manager.h"
#include "gd/hci/le_scanning_manager.h"
#include "gd/neighbor/inquiry.h"
#include "gd/os/alarm.h"

//
// NOTE: limited and general constants for inquiry and discoverable are swapped
//

/* Discoverable modes */
static constexpr int kDiscoverableModeOff = 0;      // BTM_NON_DISCOVERABLE
static constexpr int kLimitedDiscoverableMode = 1;  // BTM_LIMITED_DISCOVERABLE
static constexpr int kGeneralDiscoverableMode = 2;  // BTM_GENERAL_DISCOVERABLE

/* Inquiry modes */
static constexpr uint8_t kInquiryModeOff = 0;      // BTM_INQUIRY_NONE
static constexpr uint8_t kGeneralInquiryMode = 1;  // BTM_GENERAL_INQUIRY
static constexpr uint8_t kLimitedInquiryMode = 2;  // BTM_LIMITED_INQUIRY

/* Connectable modes */
static constexpr int kConnectibleModeOff = 0;  // BTM_NON_CONNECTABLE
static constexpr int kConnectibleModeOn = 1;   // BTM_CONNECTABLE

/* Inquiry and page scan modes */
static constexpr int kStandardScanType = 0;
static constexpr int kInterlacedScanType = 1;

/* Inquiry result modes */
static constexpr int kStandardInquiryResult = 0;
static constexpr int kInquiryResultWithRssi = 1;
static constexpr int kExtendedInquiryResult = 2;

static constexpr uint8_t kPhyConnectionNone = 0x00;
static constexpr uint8_t kPhyConnectionLe1M = 0x01;
static constexpr uint8_t kPhyConnectionLe2M = 0x02;
static constexpr uint8_t kPhyConnectionLeCoded = 0x03;

using LegacyInquiryCompleteCallback =
    std::function<void(tBTM_STATUS status, uint8_t inquiry_mode)>;

using DiscoverabilityState = struct {
  int mode;
  uint16_t interval;
  uint16_t window;
};
using ConnectabilityState = DiscoverabilityState;

using HACK_ScoDisconnectCallback = std::function<void(uint16_t, uint8_t)>;

using BtmStatus = tBTM_STATUS;

namespace bluetooth {
namespace shim {

class Btm {
 public:
  // |handler| is used to run timer tasks and scan callbacks
  Btm(os::Handler* handler, neighbor::InquiryModule* inquiry);
  ~Btm() = default;

  // Inquiry result callbacks
  void OnInquiryResult(bluetooth::hci::InquiryResultView view);
  void OnInquiryResultWithRssi(bluetooth::hci::InquiryResultWithRssiView view);
  void OnExtendedInquiryResult(bluetooth::hci::ExtendedInquiryResultView view);
  void OnInquiryComplete(bluetooth::hci::ErrorCode status);

  void SetStandardInquiryResultMode();
  void SetInquiryWithRssiResultMode();
  void SetExtendedInquiryResultMode();

  void SetInterlacedInquiryScan();
  void SetStandardInquiryScan();
  bool IsInterlacedScanSupported() const;

  bool StartInquiry(uint8_t mode, uint8_t duration, uint8_t max_responses,
                    LegacyInquiryCompleteCallback inquiry_complete_callback);
  void CancelInquiry();
  bool IsInquiryActive() const;
  bool IsGeneralInquiryActive() const;
  bool IsLimitedInquiryActive() const;

  bool StartPeriodicInquiry(uint8_t mode, uint8_t duration,
                            uint8_t max_responses, uint16_t max_delay,
                            uint16_t min_delay,
                            tBTM_INQ_RESULTS_CB* p_results_cb);
  void CancelPeriodicInquiry();
  bool IsGeneralPeriodicInquiryActive() const;
  bool IsLimitedPeriodicInquiryActive() const;

  // Discoverability API
  bool general_inquiry_active_{false};
  bool limited_inquiry_active_{false};
  bool general_periodic_inquiry_active_{false};
  bool limited_periodic_inquiry_active_{false};
  void SetClassicGeneralDiscoverability(uint16_t window, uint16_t interval);
  void SetClassicLimitedDiscoverability(uint16_t window, uint16_t interval);
  void SetClassicDiscoverabilityOff();
  DiscoverabilityState GetClassicDiscoverabilityState() const;

  void SetLeGeneralDiscoverability();
  void SetLeLimitedDiscoverability();
  void SetLeDiscoverabilityOff();
  DiscoverabilityState GetLeDiscoverabilityState() const;

  void SetClassicConnectibleOn();
  void SetClassicConnectibleOff();
  ConnectabilityState GetClassicConnectabilityState() const;
  void SetInterlacedPageScan();
  void SetStandardPageScan();

  void SetLeConnectibleOn();
  void SetLeConnectibleOff();
  ConnectabilityState GetLeConnectabilityState() const;

  bool UseLeLink(const RawAddress& raw_address) const;

  // Remote device name API
  BtmStatus ReadClassicRemoteDeviceName(const RawAddress& raw_address,
                                        tBTM_CMPL_CB* callback);
  BtmStatus ReadLeRemoteDeviceName(const RawAddress& raw_address,
                                   tBTM_CMPL_CB* callback);
  BtmStatus CancelAllReadRemoteDeviceName();

  // Le neighbor interaction API
  bluetooth::hci::AdvertiserId advertiser_id_{
      hci::LeAdvertisingManager::kInvalidId};
  void StartAdvertising();
  void StopAdvertising();
  void StartConnectability();
  void StopConnectability();

  void StartActiveScanning();
  void StopActiveScanning();

  void StartObserving();
  void StopObserving();

  size_t GetNumberOfAdvertisingInstances() const;

  void SetObservingTimer(uint64_t duration_ms,
                         common::OnceCallback<void()> callback);
  void CancelObservingTimer();
  void SetScanningTimer(uint64_t duration_ms,
                        common::OnceCallback<void()> callback);
  void CancelScanningTimer();

  tBTM_STATUS CreateBond(const RawAddress& bd_addr, tBLE_ADDR_TYPE addr_type,
                         tBT_TRANSPORT transport, int device_type);
  bool CancelBond(const RawAddress& bd_addr);
  bool RemoveBond(const RawAddress& bd_addr);

  uint16_t GetAclHandle(const RawAddress& remote_bda, tBT_TRANSPORT transport);

  void Register_HACK_SetScoDisconnectCallback(
      HACK_ScoDisconnectCallback callback);

  static hci::AddressWithType GetAddressAndType(const RawAddress& bd_addr);

 private:
  os::Alarm scanning_timer_;
  os::Alarm observing_timer_;

  LegacyInquiryCompleteCallback legacy_inquiry_complete_callback_{};
  uint8_t active_inquiry_mode_ = 0;

  class ReadRemoteName {
   public:
    ReadRemoteName() = default;
    bool Start(RawAddress raw_address);
    void Stop();
    bool IsInProgress() const;
    std::string AddressString() const;

   private:
    std::mutex mutex_;
    bool in_progress_ = false;
    RawAddress raw_address_ = RawAddress::kEmpty;
  };
  ReadRemoteName le_read_remote_name_;
  ReadRemoteName classic_read_remote_name_;

  class ScanningCallbacks : public hci::ScanningCallback {
    void OnScannerRegistered(const bluetooth::hci::Uuid app_uuid,
                             bluetooth::hci::ScannerId scanner_id,
                             ScanningStatus status);
    void OnScanResult(uint16_t event_type, uint8_t address_type,
                      bluetooth::hci::Address address, uint8_t primary_phy,
                      uint8_t secondary_phy, uint8_t advertising_sid,
                      int8_t tx_power, int8_t rssi,
                      uint16_t periodic_advertising_interval,
                      std::vector<uint8_t> advertising_data);
    void OnTrackAdvFoundLost(bluetooth::hci::AdvertisingFilterOnFoundOnLostInfo
                                 on_found_on_lost_info);
    void OnBatchScanReports(int client_if, int status, int report_format,
                            int num_records, std::vector<uint8_t> data);
    void OnBatchScanThresholdCrossed(int client_if);
    void OnTimeout();
    void OnFilterEnable(bluetooth::hci::Enable enable, uint8_t status);
    void OnFilterParamSetup(uint8_t available_spaces,
                            bluetooth::hci::ApcfAction action, uint8_t status);
    void OnFilterConfigCallback(bluetooth::hci::ApcfFilterType filter_type,
                                uint8_t available_spaces,
                                bluetooth::hci::ApcfAction action,
                                uint8_t status);
  };
  ScanningCallbacks scanning_callbacks_;

  // TODO(cmanton) abort if there is no classic acl link up
  bool CheckClassicAclLink(const RawAddress& raw_address) { return true; }
  bool CheckLeAclLink(const RawAddress& raw_address) { return true; }
  void StartScanning(bool use_active_scanning);
};

}  // namespace shim
}  // namespace bluetooth
