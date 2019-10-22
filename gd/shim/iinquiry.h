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
#include <functional>
#include <vector>

/**
 * The gd API exported to the legacy api
 */
namespace bluetooth {
namespace shim {

using InquiryResultCallback = std::function<void(std::vector<const uint8_t> data)>;
using InquiryResultWithRssiCallback = std::function<void(std::vector<const uint8_t> data)>;
using ExtendedInquiryResultCallback = std::function<void(std::vector<const uint8_t> data)>;
using InquiryCompleteCallback = std::function<void(uint16_t status)>;
using InquiryCancelCompleteCallback = std::function<void(uint8_t mode)>;

struct IInquiry {
  virtual void StartGeneralInquiry(uint8_t duration, uint8_t max_responses) = 0;
  virtual void StartLimitedInquiry(uint8_t duration, uint8_t max_responses) = 0;
  virtual void StopInquiry() = 0;
  virtual bool IsGeneralInquiryActive() const = 0;
  virtual bool IsLimitedInquiryActive() const = 0;

  virtual void StartGeneralPeriodicInquiry(uint8_t duration, uint8_t max_responses, uint16_t max_delay,
                                           uint16_t min_delay) = 0;
  virtual void StartLimitedPeriodicInquiry(uint8_t duration, uint8_t max_responses, uint16_t max_delay,
                                           uint16_t min_delay) = 0;
  virtual void StopPeriodicInquiry() = 0;
  virtual bool IsGeneralPeriodicInquiryActive() const = 0;
  virtual bool IsLimitedPeriodicInquiryActive() const = 0;

  virtual void SetInterlacedScan() = 0;
  virtual void SetStandardScan() = 0;

  virtual void SetScanActivity(uint16_t interval, uint16_t window) = 0;
  virtual void GetScanActivity(uint16_t& interval, uint16_t& window) const = 0;

  virtual void SetStandardInquiryResultMode() = 0;
  virtual void SetInquiryWithRssiResultMode() = 0;
  virtual void SetExtendedInquiryResultMode() = 0;

  virtual void RegisterInquiryResult(InquiryResultCallback callback) = 0;
  virtual void UnregisterInquiryResult() = 0;
  virtual void RegisterInquiryResultWithRssi(InquiryResultWithRssiCallback callback) = 0;
  virtual void UnregisterInquiryResultWithRssi() = 0;
  virtual void RegisterExtendedInquiryResult(ExtendedInquiryResultCallback callback) = 0;
  virtual void UnregisterExtendedInquiryResult() = 0;
  virtual void RegisterInquiryComplete(InquiryCompleteCallback callback) = 0;
  virtual void UnregisterInquiryComplete() = 0;
  virtual void RegisterInquiryCancelComplete(InquiryCancelCompleteCallback callback) = 0;
  virtual void UnregisterInquiryCancelComplete() = 0;

  virtual ~IInquiry() {}
};

}  // namespace shim
}  // namespace bluetooth
