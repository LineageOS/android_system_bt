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
#define LOG_TAG "bt_gd_neigh"

#include "neighbor/inquiry.h"

#include <memory>

#include "common/bind.h"
#include "hci/hci_layer.h"
#include "hci/hci_packets.h"
#include "module.h"
#include "os/handler.h"
#include "os/log.h"

namespace bluetooth {
namespace neighbor {

static constexpr uint8_t kGeneralInquiryAccessCode = 0x33;
static constexpr uint8_t kLimitedInquiryAccessCode = 0x00;

static inline std::string LapText(uint8_t lap) {
  switch (lap) {
    case kGeneralInquiryAccessCode:
      return "General Lap";
    case kLimitedInquiryAccessCode:
      return "Limited Lap";
    default:
      return "Unknown Lap";
  }
}

static hci::Lap general_lap_;
static hci::Lap limited_lap_;

struct InquiryModule::impl {
  void RegisterCallbacks(InquiryCallbacks inquiry_callbacks);
  void UnregisterCallbacks();

  void StartOneShotInquiry(hci::Lap& lap, InquiryLength inquiry_length, NumResponses num_responses);
  void StopOneShotInquiry();

  void StartPeriodicInquiry(hci::Lap& lap, InquiryLength inquiry_length, NumResponses num_responses,
                            PeriodLength max_delay, PeriodLength min_delay);
  void StopPeriodicInquiry();

  bool IsInquiryActive() const;
  bool IsOneShotInquiryActive(hci::Lap& lap) const;
  bool IsPeriodicInquiryActive(hci::Lap& lap) const;

  void SetScanActivity(ScanParameters params);
  ScanParameters GetScanActivity() const;

  void SetScanType(hci::InquiryScanType scan_type);

  void SetInquiryMode(hci::InquiryMode mode);

  void Start();
  void Stop();

  bool HasCallbacks() const;

  impl(InquiryModule& inquiry_module);

 private:
  InquiryCallbacks inquiry_callbacks_;

  InquiryModule& module_;

  hci::Lap* active_one_shot_{nullptr};
  hci::Lap* active_periodic_{nullptr};

  ScanParameters inquiry_scan_;
  hci::InquiryMode inquiry_mode_;
  hci::InquiryScanType inquiry_scan_type_;
  int8_t inquiry_response_tx_power_;

  void OnCommandComplete(hci::CommandCompleteView view);
  void OnCommandStatus(hci::CommandStatusView status);
  void OnEvent(hci::EventPacketView view);

  hci::HciLayer* hci_layer_;
  os::Handler* handler_;
};

const ModuleFactory neighbor::InquiryModule::Factory = ModuleFactory([]() { return new neighbor::InquiryModule(); });

neighbor::InquiryModule::impl::impl(neighbor::InquiryModule& module) : module_(module) {
  general_lap_.lap_ = kGeneralInquiryAccessCode;
  limited_lap_.lap_ = kLimitedInquiryAccessCode;
}

void neighbor::InquiryModule::impl::OnCommandComplete(hci::CommandCompleteView view) {
  switch (view.GetCommandOpCode()) {
    case hci::OpCode::INQUIRY_CANCEL: {
      auto packet = hci::InquiryCancelCompleteView::Create(view);
      ASSERT(packet.IsValid());
      ASSERT(packet.GetStatus() == hci::ErrorCode::SUCCESS);
      if (active_one_shot_ == nullptr) {
        LOG_WARN("Received inquiry cancel without a one shot inquiry in progress");
      }
      active_one_shot_ = nullptr;
    } break;

    case hci::OpCode::PERIODIC_INQUIRY_MODE: {
      auto packet = hci::PeriodicInquiryModeCompleteView::Create(view);
      ASSERT(packet.IsValid());
      ASSERT(packet.GetStatus() == hci::ErrorCode::SUCCESS);
    }

    case hci::OpCode::EXIT_PERIODIC_INQUIRY_MODE: {
      auto packet = hci::ExitPeriodicInquiryModeCompleteView::Create(view);
      ASSERT(packet.IsValid());
      ASSERT(packet.GetStatus() == hci::ErrorCode::SUCCESS);
      if (active_periodic_ == nullptr) {
        LOG_WARN("Received exit periodic inquiry without a periodic inquiry in progress");
      }
      active_periodic_ = nullptr;
    }

    case hci::OpCode::WRITE_INQUIRY_MODE: {
      auto packet = hci::WriteInquiryModeCompleteView::Create(view);
      ASSERT(packet.IsValid());
      ASSERT(packet.GetStatus() == hci::ErrorCode::SUCCESS);
    } break;

    case hci::OpCode::READ_INQUIRY_MODE: {
      auto packet = hci::ReadInquiryModeCompleteView::Create(view);
      ASSERT(packet.IsValid());
      ASSERT(packet.GetStatus() == hci::ErrorCode::SUCCESS);
      inquiry_mode_ = packet.GetInquiryMode();
    } break;

    case hci::OpCode::READ_INQUIRY_RESPONSE_TRANSMIT_POWER_LEVEL: {
      auto packet = hci::ReadInquiryResponseTransmitPowerLevelCompleteView::Create(view);
      ASSERT(packet.IsValid());
      ASSERT(packet.GetStatus() == hci::ErrorCode::SUCCESS);
      inquiry_response_tx_power_ = packet.GetTxPower();
    } break;

    case hci::OpCode::WRITE_INQUIRY_SCAN_ACTIVITY: {
      auto packet = hci::WriteInquiryScanActivityCompleteView::Create(view);
      ASSERT(packet.IsValid());
      ASSERT(packet.GetStatus() == hci::ErrorCode::SUCCESS);
    } break;

    case hci::OpCode::READ_INQUIRY_SCAN_ACTIVITY: {
      auto packet = hci::ReadInquiryScanActivityCompleteView::Create(view);
      ASSERT(packet.IsValid());
      ASSERT(packet.GetStatus() == hci::ErrorCode::SUCCESS);
      inquiry_scan_.interval = packet.GetInquiryScanInterval();
      inquiry_scan_.window = packet.GetInquiryScanWindow();
    } break;

    case hci::OpCode::WRITE_INQUIRY_SCAN_TYPE: {
      auto packet = hci::WriteInquiryScanTypeCompleteView::Create(view);
      ASSERT(packet.IsValid());
      ASSERT(packet.GetStatus() == hci::ErrorCode::SUCCESS);
    } break;

    case hci::OpCode::READ_INQUIRY_SCAN_TYPE: {
      auto packet = hci::ReadInquiryScanTypeCompleteView::Create(view);
      ASSERT(packet.IsValid());
      ASSERT(packet.GetStatus() == hci::ErrorCode::SUCCESS);
      inquiry_scan_type_ = packet.GetInquiryScanType();
    } break;

    default:
      LOG_WARN("Unhandled command:%s", hci::OpCodeText(view.GetCommandOpCode()).c_str());
      break;
  }
}

void neighbor::InquiryModule::impl::OnCommandStatus(hci::CommandStatusView status) {
  ASSERT(status.GetStatus() == hci::ErrorCode::SUCCESS);
  ASSERT(status.GetNumHciCommandPackets() == 1);

  switch (status.GetCommandOpCode()) {
    case hci::OpCode::INQUIRY: {
      auto packet = hci::InquiryStatusView::Create(status);
      ASSERT(packet.IsValid());
      ASSERT(active_one_shot_ != nullptr);
      LOG_DEBUG("Inquiry started lap:%s", LapText(active_one_shot_->lap_).c_str());
    } break;

    default:
      LOG_WARN("Unhandled command:%s", hci::OpCodeText(status.GetCommandOpCode()).c_str());
      break;
  }
}

void neighbor::InquiryModule::impl::OnEvent(hci::EventPacketView view) {
  switch (view.GetEventCode()) {
    case hci::EventCode::INQUIRY_COMPLETE: {
      auto packet = hci::InquiryCompleteView::Create(view);
      ASSERT(packet.IsValid());
      active_one_shot_ = nullptr;
      inquiry_callbacks_.complete(packet.GetStatus());
    } break;

    case hci::EventCode::INQUIRY_RESULT: {
      auto packet = hci::InquiryResultView::Create(view);
      ASSERT(packet.IsValid());
      LOG_DEBUG("Inquiry result num_responses:%d addr:%s repetition_mode:%s cod:%s clock_offset:%d",
                packet.GetNumResponses(), packet.GetBdAddr().ToString().c_str(),
                hci::PageScanRepetitionModeText(packet.GetPageScanRepetitionMode()).c_str(),
                packet.GetClassOfDevice().ToString().c_str(), packet.GetClockOffset());
      inquiry_callbacks_.result(packet);
    } break;

    case hci::EventCode::INQUIRY_RESULT_WITH_RSSI: {
      auto packet = hci::InquiryResultWithRssiView::Create(view);
      ASSERT(packet.IsValid());
      LOG_DEBUG("Inquiry result with rssi num_responses:%d addr:%s repetition_mode:%s cod:%s clock_offset:%d",
                packet.GetNumResponses(), packet.GetAddress().ToString().c_str(),
                hci::PageScanRepetitionModeText(packet.GetPageScanRepetitionMode()).c_str(),
                packet.GetClassOfDevice().ToString().c_str(), packet.GetClockOffset());
      inquiry_callbacks_.result_with_rssi(packet);
    } break;

    case hci::EventCode::EXTENDED_INQUIRY_RESULT: {
      auto packet = hci::ExtendedInquiryResultView::Create(view);
      ASSERT(packet.IsValid());
      LOG_DEBUG("Extended inquiry result addr:%s repetition_mode:%s cod:%s clock_offset:%d rssi:%hhd",
                packet.GetAddress().ToString().c_str(),
                hci::PageScanRepetitionModeText(packet.GetPageScanRepetitionMode()).c_str(),
                packet.GetClassOfDevice().ToString().c_str(), packet.GetClockOffset(), packet.GetRssi());
      inquiry_callbacks_.extended_result(packet);
    } break;

    default:
      LOG_ERROR("Unhandled event:%s", hci::EventCodeText(view.GetEventCode()).c_str());
      break;
  }
}

/**
 * impl
 */
void neighbor::InquiryModule::impl::RegisterCallbacks(InquiryCallbacks callbacks) {
  inquiry_callbacks_ = callbacks;
}

void neighbor::InquiryModule::impl::UnregisterCallbacks() {
  inquiry_callbacks_ = {nullptr, nullptr, nullptr, nullptr};
}

void neighbor::InquiryModule::impl::StartOneShotInquiry(hci::Lap& lap, InquiryLength inquiry_length,
                                                        NumResponses num_responses) {
  ASSERT(active_one_shot_ == nullptr);
  ASSERT(HasCallbacks());
  hci_layer_->EnqueueCommand(hci::InquiryBuilder::Create(lap, inquiry_length, num_responses),
                             common::BindOnce(&impl::OnCommandStatus, common::Unretained(this)), handler_);
  active_one_shot_ = &lap;
}

void neighbor::InquiryModule::impl::StopOneShotInquiry() {
  ASSERT(HasCallbacks());
  hci_layer_->EnqueueCommand(hci::InquiryCancelBuilder::Create(),
                             common::BindOnce(&impl::OnCommandComplete, common::Unretained(this)), handler_);
  ASSERT(active_one_shot_ != nullptr);
  active_one_shot_ = nullptr;
}

bool neighbor::InquiryModule::impl::IsOneShotInquiryActive(hci::Lap& lap) const {
  return active_one_shot_ == &lap;
}

void neighbor::InquiryModule::impl::StartPeriodicInquiry(hci::Lap& lap, InquiryLength inquiry_length,
                                                         NumResponses num_responses, PeriodLength max_delay,
                                                         PeriodLength min_delay) {
  ASSERT(active_periodic_ == nullptr);
  ASSERT(HasCallbacks());
  hci_layer_->EnqueueCommand(
      hci::PeriodicInquiryModeBuilder::Create(inquiry_length, num_responses, lap, max_delay, min_delay),
      common::BindOnce(&impl::OnCommandStatus, common::Unretained(this)), handler_);
  active_periodic_ = &lap;
}

void neighbor::InquiryModule::impl::StopPeriodicInquiry() {
  ASSERT(active_periodic_ != nullptr);
  ASSERT(HasCallbacks());
  hci_layer_->EnqueueCommand(hci::ExitPeriodicInquiryModeBuilder::Create(),
                             common::BindOnce(&impl::OnCommandComplete, common::Unretained(this)), handler_);
  active_periodic_ = nullptr;
}

bool neighbor::InquiryModule::impl::IsPeriodicInquiryActive(hci::Lap& lap) const {
  return active_periodic_ == &lap;
}

bool neighbor::InquiryModule::impl::IsInquiryActive() const {
  return active_one_shot_ != nullptr || active_periodic_ != nullptr;
}

void neighbor::InquiryModule::impl::Start() {
  hci_layer_ = module_.GetDependency<hci::HciLayer>();
  handler_ = module_.GetHandler();

  hci_layer_->RegisterEventHandler(hci::EventCode::INQUIRY_RESULT,
                                   common::Bind(&InquiryModule::impl::OnEvent, common::Unretained(this)), handler_);
  hci_layer_->RegisterEventHandler(hci::EventCode::INQUIRY_RESULT_WITH_RSSI,
                                   common::Bind(&InquiryModule::impl::OnEvent, common::Unretained(this)), handler_);
  hci_layer_->RegisterEventHandler(hci::EventCode::EXTENDED_INQUIRY_RESULT,
                                   common::Bind(&InquiryModule::impl::OnEvent, common::Unretained(this)), handler_);
  hci_layer_->RegisterEventHandler(hci::EventCode::INQUIRY_COMPLETE,
                                   common::Bind(&InquiryModule::impl::OnEvent, common::Unretained(this)), handler_);

  hci_layer_->EnqueueCommand(hci::ReadInquiryResponseTransmitPowerLevelBuilder::Create(),
                             common::BindOnce(&impl::OnCommandComplete, common::Unretained(this)), handler_);
  hci_layer_->EnqueueCommand(hci::ReadInquiryScanActivityBuilder::Create(),
                             common::BindOnce(&impl::OnCommandComplete, common::Unretained(this)), handler_);
  hci_layer_->EnqueueCommand(hci::ReadInquiryScanTypeBuilder::Create(),
                             common::BindOnce(&impl::OnCommandComplete, common::Unretained(this)), handler_);
  LOG_DEBUG("Started inquiry module");
}

void neighbor::InquiryModule::impl::Stop() {
  hci_layer_->UnregisterEventHandler(hci::EventCode::INQUIRY_COMPLETE);
  hci_layer_->UnregisterEventHandler(hci::EventCode::EXTENDED_INQUIRY_RESULT);
  hci_layer_->UnregisterEventHandler(hci::EventCode::INQUIRY_RESULT_WITH_RSSI);
  hci_layer_->UnregisterEventHandler(hci::EventCode::INQUIRY_RESULT);

  LOG_INFO("Inquiry scan interval:%hd window:%hd", inquiry_scan_.interval, inquiry_scan_.window);
  LOG_INFO("Inquiry mode:%s scan_type:%s", hci::InquiryModeText(inquiry_mode_).c_str(),
           hci::InquiryScanTypeText(inquiry_scan_type_).c_str());
  LOG_INFO("Inquiry response tx power:%hhd", inquiry_response_tx_power_);
  LOG_DEBUG("Stopped inquiry module");
}

void neighbor::InquiryModule::impl::SetInquiryMode(hci::InquiryMode mode) {
  hci_layer_->EnqueueCommand(hci::WriteInquiryModeBuilder::Create(mode),
                             common::BindOnce(&impl::OnCommandComplete, common::Unretained(this)), handler_);
  inquiry_mode_ = mode;
  LOG_DEBUG("Set inquiry mode");
}

void neighbor::InquiryModule::impl::SetScanActivity(ScanParameters params) {
  hci_layer_->EnqueueCommand(hci::WriteInquiryScanActivityBuilder::Create(params.interval, params.window),
                             common::BindOnce(&impl::OnCommandComplete, common::Unretained(this)), handler_);

  hci_layer_->EnqueueCommand(hci::ReadInquiryScanActivityBuilder::Create(),
                             common::BindOnce(&impl::OnCommandComplete, common::Unretained(this)), handler_);
  LOG_DEBUG("Set scan activity interval:0x%x/%.02fms window:0x%x/%.02fms", params.interval,
            ScanIntervalTimeMs(params.interval), params.window, ScanWindowTimeMs(params.window));
}

ScanParameters neighbor::InquiryModule::impl::GetScanActivity() const {
  return inquiry_scan_;
}

void neighbor::InquiryModule::impl::SetScanType(hci::InquiryScanType scan_type) {
  hci_layer_->EnqueueCommand(hci::WriteInquiryScanTypeBuilder::Create(scan_type),
                             common::BindOnce(&impl::OnCommandComplete, common::Unretained(this)), handler_);
  hci_layer_->EnqueueCommand(hci::ReadInquiryScanTypeBuilder::Create(),
                             common::BindOnce(&impl::OnCommandComplete, common::Unretained(this)), handler_);
  LOG_DEBUG("Set scan type:%s", hci::InquiryScanTypeText(scan_type).c_str());
}

bool neighbor::InquiryModule::impl::HasCallbacks() const {
  return inquiry_callbacks_.result != nullptr && inquiry_callbacks_.result_with_rssi != nullptr &&
         inquiry_callbacks_.extended_result != nullptr && inquiry_callbacks_.complete != nullptr;
}

/**
 * General API here
 */
neighbor::InquiryModule::InquiryModule() : pimpl_(std::make_unique<impl>(*this)) {}

neighbor::InquiryModule::~InquiryModule() {
  pimpl_.reset();
}

void neighbor::InquiryModule::RegisterCallbacks(InquiryCallbacks callbacks) {
  pimpl_->RegisterCallbacks(callbacks);
}

void neighbor::InquiryModule::UnregisterCallbacks() {
  pimpl_->UnregisterCallbacks();
}

void neighbor::InquiryModule::StartGeneralInquiry(InquiryLength inquiry_length, NumResponses num_responses) {
  if (pimpl_->IsInquiryActive()) {
    LOG_WARN("Ignoring start general one shot inquiry as an inquiry is already active");
    return;
  }
  pimpl_->StartOneShotInquiry(general_lap_, inquiry_length, num_responses);
  LOG_DEBUG("Started general one shot inquiry");
}

void neighbor::InquiryModule::StartLimitedInquiry(InquiryLength inquiry_length, NumResponses num_responses) {
  if (pimpl_->IsInquiryActive()) {
    LOG_WARN("Ignoring start limited one shot inquiry as an inquiry is already active");
    return;
  }
  pimpl_->StartOneShotInquiry(limited_lap_, inquiry_length, num_responses);
  LOG_DEBUG("Started limited one shot inquiry");
}

void neighbor::InquiryModule::StopInquiry() {
  if (pimpl_->IsInquiryActive()) {
    LOG_WARN("Ignoring stop one shot inquiry as an inquiry is not active");
    return;
  }
  pimpl_->StopOneShotInquiry();
  LOG_DEBUG("Stopped one shot inquiry");
}

bool neighbor::InquiryModule::IsGeneralInquiryActive() const {
  return pimpl_->IsOneShotInquiryActive(general_lap_);
}

bool neighbor::InquiryModule::IsLimitedInquiryActive() const {
  return pimpl_->IsOneShotInquiryActive(limited_lap_);
}

void neighbor::InquiryModule::StartGeneralPeriodicInquiry(InquiryLength inquiry_length, NumResponses num_responses,
                                                          PeriodLength max_delay, PeriodLength min_delay) {
  if (pimpl_->IsInquiryActive()) {
    LOG_WARN("Ignoring start general periodic inquiry as an inquiry is already active");
    return;
  }
  pimpl_->StartPeriodicInquiry(general_lap_, inquiry_length, num_responses, max_delay, min_delay);
  LOG_DEBUG("Started general periodic inquiry");
}

void neighbor::InquiryModule::StartLimitedPeriodicInquiry(InquiryLength inquiry_length, NumResponses num_responses,
                                                          PeriodLength max_delay, PeriodLength min_delay) {
  if (pimpl_->IsInquiryActive()) {
    LOG_WARN("Ignoring start limited periodic inquiry as an inquiry is already active");
    return;
  }
  pimpl_->StartPeriodicInquiry(limited_lap_, inquiry_length, num_responses, max_delay, min_delay);
  LOG_DEBUG("Started limited periodic inquiry");
}

void neighbor::InquiryModule::StopPeriodicInquiry() {
  if (pimpl_->IsInquiryActive()) {
    LOG_WARN("Ignoring stop periodic inquiry as an inquiry is not active");
    return;
  }
  pimpl_->StopPeriodicInquiry();
  LOG_DEBUG("Stopped periodic inquiry");
}

bool neighbor::InquiryModule::IsGeneralPeriodicInquiryActive() const {
  return pimpl_->IsPeriodicInquiryActive(general_lap_);
}

bool neighbor::InquiryModule::IsLimitedPeriodicInquiryActive() const {
  return pimpl_->IsPeriodicInquiryActive(limited_lap_);
}

void neighbor::InquiryModule::SetScanActivity(ScanParameters params) {
  pimpl_->SetScanActivity(params);
}

ScanParameters neighbor::InquiryModule::GetScanActivity() const {
  return pimpl_->GetScanActivity();
}

void neighbor::InquiryModule::SetInterlacedScan() {
  pimpl_->SetScanType(hci::InquiryScanType::INTERLACED);
}

void neighbor::InquiryModule::SetStandardScan() {
  pimpl_->SetScanType(hci::InquiryScanType::STANDARD);
}

void neighbor::InquiryModule::SetStandardInquiryResultMode() {
  pimpl_->SetInquiryMode(hci::InquiryMode::STANDARD);
}

void neighbor::InquiryModule::SetInquiryWithRssiResultMode() {
  pimpl_->SetInquiryMode(hci::InquiryMode::RSSI);
}

void neighbor::InquiryModule::SetExtendedInquiryResultMode() {
  pimpl_->SetInquiryMode(hci::InquiryMode::RSSI_OR_EXTENDED);
}

/**
 * Module methods here
 */
void neighbor::InquiryModule::ListDependencies(ModuleList* list) {
  list->add<hci::HciLayer>();
}

void neighbor::InquiryModule::Start() {
  pimpl_->Start();
}

void neighbor::InquiryModule::Stop() {
  pimpl_->Stop();
}

}  // namespace neighbor
}  // namespace bluetooth
