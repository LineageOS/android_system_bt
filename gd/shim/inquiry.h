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
#include "shim/iinquiry.h"

namespace bluetooth {
namespace shim {

class Inquiry : public bluetooth::Module, public bluetooth::shim::IInquiry {
 public:
  void StartGeneralInquiry(uint8_t duration, uint8_t max_responses) override;
  void StartLimitedInquiry(uint8_t duration, uint8_t max_responses) override;
  void StopInquiry() override;
  bool IsGeneralInquiryActive() const override;
  bool IsLimitedInquiryActive() const override;

  void StartGeneralPeriodicInquiry(uint8_t duration, uint8_t max_responses, uint16_t max_delay,
                                   uint16_t min_delay) override;
  void StartLimitedPeriodicInquiry(uint8_t duration, uint8_t max_responses, uint16_t max_delay,
                                   uint16_t min_delay) override;
  void StopPeriodicInquiry() override;
  bool IsGeneralPeriodicInquiryActive() const override;
  bool IsLimitedPeriodicInquiryActive() const override;

  void SetInterlacedScan() override;
  void SetStandardScan() override;

  void SetScanActivity(uint16_t interval, uint16_t window) override;
  void GetScanActivity(uint16_t& interval, uint16_t& window) const override;

  void SetStandardInquiryResultMode() override;
  void SetInquiryWithRssiResultMode() override;
  void SetExtendedInquiryResultMode() override;

  void RegisterInquiryResult(InquiryResultCallback callback) override;
  void UnregisterInquiryResult() override;
  void RegisterInquiryResultWithRssi(InquiryResultWithRssiCallback callback) override;
  void UnregisterInquiryResultWithRssi() override;
  void RegisterExtendedInquiryResult(ExtendedInquiryResultCallback callback) override;
  void UnregisterExtendedInquiryResult() override;
  void RegisterInquiryComplete(InquiryCompleteCallback callback) override;
  void UnregisterInquiryComplete() override;
  void RegisterInquiryCancelComplete(InquiryCancelCompleteCallback callback) override;
  void UnregisterInquiryCancelComplete() override;

  Inquiry() = default;
  ~Inquiry() = default;

  static const ModuleFactory Factory;

 protected:
  void ListDependencies(ModuleList* list) override;  // Module
  void Start() override;                             // Module
  void Stop() override;                              // Module

 private:
  struct impl;
  std::unique_ptr<impl> pimpl_;
  DISALLOW_COPY_AND_ASSIGN(Inquiry);
};

}  // namespace shim
}  // namespace bluetooth
