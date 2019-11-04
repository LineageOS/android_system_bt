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

#include <cstdint>
#include <unordered_map>
#include <vector>

#include "stack/include/btm_api_types.h"

/* Discoverable modes */
static constexpr int kDiscoverableModeOff = 0;
static constexpr int kLimitedDiscoverableMode = 1;
static constexpr int kGeneralDiscoverableMode = 2;

/* Inquiry modes */
// NOTE: The inquiry general/limited are reversed from the discoverability
// constants
static constexpr int kInquiryModeOff = 0;
static constexpr int kGeneralInquiryMode = 1;
static constexpr int kLimitedInquiryMode = 2;

/* Connectable modes */
static constexpr int kConnectibleModeOff = 0;
static constexpr int kConnectibleModeOn = 1;

/* Inquiry and page scan modes */
static constexpr int kStandardScanType = 0;
static constexpr int kInterlacedScanType = 1;

/* Inquiry result modes */
static constexpr int kStandardInquiryResult = 0;
static constexpr int kInquiryResultWithRssi = 1;
static constexpr int kExtendedInquiryResult = 2;

/* Inquiry filter types */
static constexpr int kClearInquiryFilter = 0;
static constexpr int kFilterOnDeviceClass = 1;
static constexpr int kFilterOnAddress = 2;

using DiscoverabilityState = struct {
  int mode;
  uint16_t interval;
  uint16_t window;
};
using ConnectabilityState = DiscoverabilityState;

namespace bluetooth {
namespace shim {

class Btm {
 public:
  Btm();

  // Callbacks
  void OnInquiryResult(std::vector<const uint8_t> result);
  void OnInquiryResultWithRssi(std::vector<const uint8_t> result);
  void OnExtendedInquiryResult(std::vector<const uint8_t> result);
  void OnInquiryComplete(uint16_t status);

  // Inquiry API
  bool SetInquiryFilter(uint8_t mode, uint8_t type, tBTM_INQ_FILT_COND data);
  void SetFilterInquiryOnAddress();
  void SetFilterInquiryOnDevice();
  void ClearInquiryFilter();

  bool SetStandardInquiryResultMode();
  bool SetInquiryWithRssiResultMode();
  bool SetExtendedInquiryResultMode();

  void SetInterlacedInquiryScan();
  void SetStandardInquiryScan();
  bool IsInterlacedScanSupported() const;

  bool StartInquiry(uint8_t mode, uint8_t duration, uint8_t max_responses);
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

 private:
  //  DiscoverabilityState classic_;
  //  DiscoverabilityState le_;

  //  ConnectabilityState classic_connectibility_state_;
  //  ConnectabilityState le_connectibility_state_;

  //  bool DoSetEventFilter();
  //  void DoSetDiscoverability();
  //  bool DoSetInquiryMode();
};

}  // namespace shim
}  // namespace bluetooth
