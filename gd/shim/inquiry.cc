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
#define LOG_TAG "bt_gd_shim"

#include <functional>
#include <memory>

#include "common/bidi_queue.h"
#include "hci/address.h"
#include "hci/controller.h"
#include "hci/hci_packets.h"
#include "module.h"
#include "neighbor/inquiry.h"
#include "neighbor/scan_parameters.h"
#include "os/handler.h"
#include "os/log.h"
#include "shim/inquiry.h"

namespace bluetooth {
namespace shim {

struct Inquiry::impl {
  void Result(hci::InquiryResultView view);
  void ResultWithRssi(hci::InquiryResultWithRssiView view);
  void ExtendedResult(hci::ExtendedInquiryResultView view);
  void Complete(hci::ErrorCode status);

  void RegisterInquiryResult(InquiryResultCallback callback);
  void UnregisterInquiryResult();
  void RegisterInquiryResultWithRssi(InquiryResultWithRssiCallback callback);
  void UnregisterInquiryResultWithRssi();
  void RegisterExtendedInquiryResult(ExtendedInquiryResultCallback callback);
  void UnregisterExtendedInquiryResult();
  void RegisterInquiryComplete(InquiryCompleteCallback callback);
  void UnregisterInquiryComplete();
  void RegisterInquiryCancelComplete(InquiryCancelCompleteCallback callback);
  void UnregisterInquiryCancelComplete();

  InquiryResultCallback shim_result_callback_;
  InquiryResultWithRssiCallback shim_result_with_rssi_callback_;
  ExtendedInquiryResultCallback shim_extended_result_callback_;
  InquiryCompleteCallback shim_complete_callback_;
  InquiryCancelCompleteCallback shim_cancel_complete_callback_;

  neighbor::InquiryModule* module_{nullptr};

  impl(neighbor::InquiryModule* module);
  ~impl();
};

const ModuleFactory Inquiry::Factory = ModuleFactory([]() { return new Inquiry(); });

void Inquiry::impl::Result(hci::InquiryResultView view) {
  ASSERT(view.size() >= sizeof(uint16_t));
  ASSERT(shim_result_callback_ != nullptr);
  std::vector<const uint8_t> v(view.begin() + sizeof(uint16_t), view.end());
  shim_result_callback_(v);
}

void Inquiry::impl::ResultWithRssi(hci::InquiryResultWithRssiView view) {
  ASSERT(view.size() >= sizeof(uint16_t));
  ASSERT(shim_result_with_rssi_callback_ != nullptr);
  std::vector<const uint8_t> v(view.begin() + sizeof(uint16_t), view.end());
  shim_result_with_rssi_callback_(v);
}

void Inquiry::impl::ExtendedResult(hci::ExtendedInquiryResultView view) {
  ASSERT(view.size() >= sizeof(uint16_t));
  ASSERT(shim_extended_result_callback_ != nullptr);
  std::vector<const uint8_t> v(view.begin() + sizeof(uint16_t), view.end());
  shim_extended_result_callback_(v);
}

void Inquiry::impl::Complete(hci::ErrorCode status) {
  ASSERT(shim_complete_callback_ != nullptr);
  shim_complete_callback_(static_cast<uint16_t>(status));
}

void Inquiry::impl::RegisterInquiryResult(shim::InquiryResultCallback callback) {
  if (shim_result_callback_ != nullptr) {
    LOG_WARN("Registering inquiry result without unregistering");
  }
  shim_result_callback_ = callback;
}

void Inquiry::impl::UnregisterInquiryResult() {
  if (shim_result_callback_ == nullptr) {
    LOG_WARN("Unregistering inquiry result without registering");
  }
  shim_result_callback_ = nullptr;
}

void Inquiry::impl::RegisterInquiryResultWithRssi(shim::InquiryResultWithRssiCallback callback) {
  if (shim_result_with_rssi_callback_ != nullptr) {
    LOG_WARN("Registering inquiry result with rssi without unregistering");
  }
  shim_result_with_rssi_callback_ = callback;
}

void Inquiry::impl::UnregisterInquiryResultWithRssi() {
  if (shim_result_with_rssi_callback_ == nullptr) {
    LOG_WARN("Unregistering inquiry result with rssi without registering");
  }
  shim_result_with_rssi_callback_ = nullptr;
}

void Inquiry::impl::RegisterExtendedInquiryResult(shim::ExtendedInquiryResultCallback callback) {
  if (shim_result_with_rssi_callback_ != nullptr) {
    LOG_WARN("Registering extended inquiry result without unregistering");
  }
  shim_extended_result_callback_ = callback;
}

void Inquiry::impl::UnregisterExtendedInquiryResult() {
  if (shim_extended_result_callback_ == nullptr) {
    LOG_WARN("Unregistering extended inquiry result without registering");
  }
  shim_extended_result_callback_ = nullptr;
}

void Inquiry::impl::RegisterInquiryComplete(shim::InquiryCompleteCallback callback) {
  if (shim_result_with_rssi_callback_ != nullptr) {
    LOG_WARN("Registering inquiry complete without unregistering");
  }
  shim_complete_callback_ = callback;
}

void Inquiry::impl::UnregisterInquiryComplete() {
  if (shim_result_with_rssi_callback_ == nullptr) {
    LOG_WARN("Unregistering inquiry complete without registering");
  }
  shim_complete_callback_ = nullptr;
}

void Inquiry::impl::RegisterInquiryCancelComplete(shim::InquiryCancelCompleteCallback callback) {
  if (shim_cancel_complete_callback_ != nullptr) {
    LOG_WARN("Registering inquiry cancel complete without unregistering");
  }
  shim_cancel_complete_callback_ = callback;
}

void Inquiry::impl::UnregisterInquiryCancelComplete() {
  if (shim_cancel_complete_callback_ == nullptr) {
    LOG_WARN("Unregistering inquiry cancel complete without registering");
  }
  shim_cancel_complete_callback_ = nullptr;
}

Inquiry::impl::impl(neighbor::InquiryModule* inquiry_module) : module_(inquiry_module) {
  neighbor::InquiryCallbacks inquiry_callbacks;
  inquiry_callbacks.result = std::bind(&Inquiry::impl::Result, this, std::placeholders::_1);
  inquiry_callbacks.result_with_rssi = std::bind(&Inquiry::impl::ResultWithRssi, this, std::placeholders::_1);
  inquiry_callbacks.extended_result = std::bind(&Inquiry::impl::ExtendedResult, this, std::placeholders::_1);
  inquiry_callbacks.complete = std::bind(&Inquiry::impl::Complete, this, std::placeholders::_1);

  module_->RegisterCallbacks(inquiry_callbacks);
}

Inquiry::impl::~impl() {
  module_->UnregisterCallbacks();
}

void Inquiry::StartGeneralInquiry(uint8_t inquiry_length, uint8_t num_responses) {
  return pimpl_->module_->StartGeneralInquiry(inquiry_length, num_responses);
}

void Inquiry::StartLimitedInquiry(uint8_t inquiry_length, uint8_t num_responses) {
  return pimpl_->module_->StartLimitedInquiry(inquiry_length, num_responses);
}

void Inquiry::StopInquiry() {
  return pimpl_->module_->StopInquiry();
}

bool Inquiry::IsGeneralInquiryActive() const {
  return pimpl_->module_->IsGeneralInquiryActive();
}

bool Inquiry::IsLimitedInquiryActive() const {
  return pimpl_->module_->IsLimitedInquiryActive();
}

void Inquiry::StartGeneralPeriodicInquiry(uint8_t inquiry_length, uint8_t num_responses, uint16_t max_delay,
                                          uint16_t min_delay) {
  return pimpl_->module_->StartGeneralPeriodicInquiry(inquiry_length, num_responses, max_delay, min_delay);
}

void Inquiry::StartLimitedPeriodicInquiry(uint8_t inquiry_length, uint8_t num_responses, uint16_t max_delay,
                                          uint16_t min_delay) {
  return pimpl_->module_->StartLimitedPeriodicInquiry(inquiry_length, num_responses, max_delay, min_delay);
}

void Inquiry::StopPeriodicInquiry() {
  return pimpl_->module_->StopPeriodicInquiry();
}

bool Inquiry::IsGeneralPeriodicInquiryActive() const {
  return pimpl_->module_->IsGeneralPeriodicInquiryActive();
}

bool Inquiry::IsLimitedPeriodicInquiryActive() const {
  return pimpl_->module_->IsLimitedPeriodicInquiryActive();
}

void Inquiry::SetInterlacedScan() {
  pimpl_->module_->SetInterlacedScan();
}

void Inquiry::SetStandardScan() {
  pimpl_->module_->SetStandardScan();
}

void Inquiry::SetScanActivity(uint16_t interval, uint16_t window) {
  neighbor::ScanParameters params{
      .interval = static_cast<neighbor::ScanInterval>(interval),
      .window = static_cast<neighbor::ScanWindow>(window),
  };
  pimpl_->module_->SetScanActivity(params);
}

void Inquiry::GetScanActivity(uint16_t& interval, uint16_t& window) const {
  neighbor::ScanParameters params = pimpl_->module_->GetScanActivity();

  interval = static_cast<uint16_t>(params.interval);
  window = static_cast<uint16_t>(params.window);
}

void Inquiry::SetStandardInquiryResultMode() {
  pimpl_->module_->SetStandardInquiryResultMode();
}

void Inquiry::SetInquiryWithRssiResultMode() {
  pimpl_->module_->SetInquiryWithRssiResultMode();
}

void Inquiry::SetExtendedInquiryResultMode() {
  pimpl_->module_->SetExtendedInquiryResultMode();
}

void Inquiry::RegisterInquiryResult(shim::InquiryResultCallback callback) {
  pimpl_->RegisterInquiryResult(callback);
}

void Inquiry::UnregisterInquiryResult() {
  pimpl_->UnregisterInquiryResult();
}

void Inquiry::RegisterInquiryResultWithRssi(shim::InquiryResultWithRssiCallback callback) {
  pimpl_->RegisterInquiryResultWithRssi(callback);
}

void Inquiry::UnregisterInquiryResultWithRssi() {
  pimpl_->UnregisterInquiryResultWithRssi();
}

void Inquiry::RegisterExtendedInquiryResult(shim::ExtendedInquiryResultCallback callback) {
  pimpl_->RegisterExtendedInquiryResult(callback);
}

void Inquiry::UnregisterExtendedInquiryResult() {
  pimpl_->UnregisterExtendedInquiryResult();
}

void Inquiry::RegisterInquiryComplete(InquiryCompleteCallback callback) {
  pimpl_->RegisterInquiryComplete(callback);
}

void Inquiry::UnregisterInquiryComplete() {
  pimpl_->UnregisterInquiryComplete();
}

void Inquiry::RegisterInquiryCancelComplete(InquiryCancelCompleteCallback callback) {
  pimpl_->RegisterInquiryCancelComplete(callback);
}

void Inquiry::UnregisterInquiryCancelComplete() {
  pimpl_->UnregisterInquiryCancelComplete();
}

/**
 * Module methods
 */
void Inquiry::ListDependencies(ModuleList* list) {
  list->add<neighbor::InquiryModule>();
}

void Inquiry::Start() {
  pimpl_ = std::make_unique<impl>(GetDependency<neighbor::InquiryModule>());
}

void Inquiry::Stop() {
  pimpl_.reset();
}

}  // namespace shim
}  // namespace bluetooth
