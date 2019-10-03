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

#include "stack/include/l2c_api.h"

/* Discoverable modes */
static constexpr int kDiscoverableModeOff = 0;
static constexpr int kLimitedDiscoverableMode = 1;
static constexpr int kGeneralDiscoverableMode = 2;

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
  uint16_t window;
  uint16_t interval;
};
using ConnectibilityState = DiscoverabilityState;

namespace bluetooth {
namespace shim {

class Btm {
 public:
  Btm();

  void SetLeDiscoverabilityOff();
  void SetLeLimitedDiscoverability();
  void SetLeGeneralDiscoverability();

  void SetClassicDiscoverabilityOff();
  void SetClassicLimitedDiscoverability(uint16_t window, uint16_t interval);
  void SetClassicGeneralDiscoverability(uint16_t window, uint16_t interval);

  bool IsInterlacedScanSupported() const;

  bool SetInterlacedInquiryScan();
  bool SetStandardInquiryScan();

  bool SetInterlacedPageScan();
  bool SetStandardPageScan();

  bool SetStandardInquiryMode();
  bool SetInquiryModeWithRssi();
  bool SetExtendedInquiryMode();

  bool IsInquiryActive() const;
  bool CancelPeriodicInquiry();
  bool ClearInquiryFilter();
  bool SetFilterInquiryOnDevice();
  bool SetFilterInquiryOnAddress();

  DiscoverabilityState GetClassicDiscoverabilityState() const;
  DiscoverabilityState GetLeDiscoverabilityState() const;

  ConnectibilityState GetClassicConnectibilityState() const;
  ConnectibilityState GetLeConnectibilityState() const;

  bool SetClassicConnectibleOff();
  bool SetClassicConnectibleOn();
  bool SetLeConnectibleOff();
  bool SetLeConnectibleOn();

  bool StartInquiry();

 private:
  DiscoverabilityState classic_;
  DiscoverabilityState le_;

  ConnectibilityState classic_connectibility_state_;
  ConnectibilityState le_connectibility_state_;

  bool DoSetEventFilter();
  bool DoSetConnectible();
  void DoSetDiscoverability();
  bool DoSetInquiryMode();
};

}  // namespace shim
}  // namespace bluetooth
