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

#include <memory>
#include <string>

#include "module.h"

namespace bluetooth {
namespace shim {

using InquiryResultCallback = std::function<void(std::string string_address, uint8_t page_scan_rep_mode,
                                                 std::string string_class_of_device, uint16_t clock_offset)>;
using InquiryResultWithRssiCallback =
    std::function<void(std::string string_address, uint8_t page_scan_rep_mode, std::string string_class_of_device,
                       uint16_t clock_offset, int8_t rssi)>;
using ExtendedInquiryResultCallback =
    std::function<void(std::string string_address, uint8_t page_scan_rep_mode, std::string string_class_of_device,
                       uint16_t clock_offset, int8_t rssi, const uint8_t* gap_data, size_t gap_data_len)>;
using InquiryCompleteCallback = std::function<void(uint16_t status)>;

struct LegacyInquiryCallbacks {
  InquiryResultCallback result_callback;
  InquiryResultWithRssiCallback result_with_rssi_callback;
  ExtendedInquiryResultCallback extended_result_callback;
  InquiryCompleteCallback complete_callback;
};

class Inquiry : public bluetooth::Module {
 public:
  void StartGeneralInquiry(uint8_t duration, uint8_t max_responses, LegacyInquiryCallbacks callbacks);
  void StartLimitedInquiry(uint8_t duration, uint8_t max_responses, LegacyInquiryCallbacks callbacks);
  void StopInquiry();
  bool IsGeneralInquiryActive() const;
  bool IsLimitedInquiryActive() const;

  void StartGeneralPeriodicInquiry(uint8_t duration, uint8_t max_responses, uint16_t max_delay, uint16_t min_delay,
                                   LegacyInquiryCallbacks callbacks);
  void StartLimitedPeriodicInquiry(uint8_t duration, uint8_t max_responses, uint16_t max_delay, uint16_t min_delay,
                                   LegacyInquiryCallbacks callbacks);
  void StopPeriodicInquiry();
  bool IsGeneralPeriodicInquiryActive() const;
  bool IsLimitedPeriodicInquiryActive() const;

  void SetInterlacedScan();
  void SetStandardScan();

  void SetScanActivity(uint16_t interval, uint16_t window);
  void GetScanActivity(uint16_t& interval, uint16_t& window) const;

  void SetStandardInquiryResultMode();
  void SetInquiryWithRssiResultMode();
  void SetExtendedInquiryResultMode();

  Inquiry() = default;
  ~Inquiry() = default;

  static const ModuleFactory Factory;

 protected:
  void ListDependencies(ModuleList* list) override;  // Module
  void Start() override;                             // Module
  void Stop() override;                              // Module
  std::string ToString() const override;             // Module

 private:
  struct impl;
  std::unique_ptr<impl> pimpl_;
  DISALLOW_COPY_AND_ASSIGN(Inquiry);
};

}  // namespace shim
}  // namespace bluetooth
