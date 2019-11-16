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
#include <cstring>

#include "main/shim/btm.h"
#include "main/shim/entry.h"
#include "main/shim/shim.h"
#include "osi/include/log.h"

bluetooth::shim::Btm::Btm() {}

static constexpr size_t kMaxInquiryResultSize = 4096;
static uint8_t inquiry_result_buf[kMaxInquiryResultSize];

static int inquiry_type_ = 0;

static constexpr uint8_t kInquiryResultMode = 0;
static constexpr uint8_t kInquiryResultWithRssiMode = 1;
static constexpr uint8_t kExtendedInquiryResultMode = 2;

static constexpr size_t kRemoteDeviceNameLength = 248;

extern void btm_process_cancel_complete(uint8_t status, uint8_t mode);
extern void btm_process_inq_complete(uint8_t status, uint8_t result_type);
extern void btm_process_inq_results(uint8_t* p, uint8_t result_mode);

using BtmRemoteDeviceName = tBTM_REMOTE_DEV_NAME;

/**
 *
 */
void bluetooth::shim::Btm::OnInquiryResult(std::vector<const uint8_t> result) {
  CHECK(result.size() < kMaxInquiryResultSize);

  std::copy(result.begin(), result.end(), inquiry_result_buf);
  btm_process_inq_results(inquiry_result_buf, kInquiryResultMode);
}

void bluetooth::shim::Btm::OnInquiryResultWithRssi(
    std::vector<const uint8_t> result) {
  CHECK(result.size() < kMaxInquiryResultSize);

  std::copy(result.begin(), result.end(), inquiry_result_buf);
  btm_process_inq_results(inquiry_result_buf, kInquiryResultWithRssiMode);
}

void bluetooth::shim::Btm::OnExtendedInquiryResult(
    std::vector<const uint8_t> result) {
  CHECK(result.size() < kMaxInquiryResultSize);

  std::copy(result.begin(), result.end(), inquiry_result_buf);
  btm_process_inq_results(inquiry_result_buf, kExtendedInquiryResultMode);
}

void bluetooth::shim::Btm::OnInquiryComplete(uint16_t status) {
  btm_process_inq_complete(status, inquiry_type_);
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

bool bluetooth::shim::Btm::SetStandardInquiryResultMode() {
  bluetooth::shim::GetInquiry()->SetStandardInquiryResultMode();
  return true;
}

bool bluetooth::shim::Btm::SetInquiryWithRssiResultMode() {
  bluetooth::shim::GetInquiry()->SetInquiryWithRssiResultMode();
  return true;
}

bool bluetooth::shim::Btm::SetExtendedInquiryResultMode() {
  bluetooth::shim::GetInquiry()->SetExtendedInquiryResultMode();
  return true;
}

void bluetooth::shim::Btm::SetInterlacedInquiryScan() {
  bluetooth::shim::GetInquiry()->SetInterlacedScan();
}

void bluetooth::shim::Btm::SetStandardInquiryScan() {
  bluetooth::shim::GetInquiry()->SetStandardScan();
}

bool bluetooth::shim::Btm::IsInterlacedScanSupported() const {
  // TODO(cmanton) This is a controller query
  LOG_WARN(LOG_TAG, "UNIMPLEMENTED %s", __func__);
  return true;
}

/**
 * One shot inquiry
 */
bool bluetooth::shim::Btm::StartInquiry(uint8_t mode, uint8_t duration,
                                        uint8_t max_responses) {
  switch (mode) {
    case kInquiryModeOff:
      LOG_DEBUG(LOG_TAG, "%s Stopping inquiry mode", __func__);
      bluetooth::shim::GetInquiry()->StopInquiry();
      bluetooth::shim::GetInquiry()->UnregisterInquiryResult();
      bluetooth::shim::GetInquiry()->UnregisterInquiryResultWithRssi();
      bluetooth::shim::GetInquiry()->UnregisterExtendedInquiryResult();
      bluetooth::shim::GetInquiry()->UnregisterInquiryComplete();
      break;

    case kLimitedInquiryMode:
    case kGeneralInquiryMode:
      bluetooth::shim::GetInquiry()->RegisterInquiryResult(
          std::bind(&Btm::OnInquiryResult, this, std::placeholders::_1));
      bluetooth::shim::GetInquiry()->RegisterInquiryResultWithRssi(std::bind(
          &Btm::OnInquiryResultWithRssi, this, std::placeholders::_1));
      bluetooth::shim::GetInquiry()->RegisterExtendedInquiryResult(std::bind(
          &Btm::OnExtendedInquiryResult, this, std::placeholders::_1));
      bluetooth::shim::GetInquiry()->RegisterInquiryComplete(
          std::bind(&Btm::OnInquiryComplete, this, std::placeholders::_1));

      if (mode == kLimitedInquiryMode) {
        LOG_DEBUG(
            LOG_TAG,
            "%s Starting limited inquiry mode duration:%hhd max responses:%hhd",
            __func__, duration, max_responses);
        bluetooth::shim::GetInquiry()->StartLimitedInquiry(duration,
                                                           max_responses);
      } else {
        LOG_DEBUG(
            LOG_TAG,
            "%s Starting general inquiry mode duration:%hhd max responses:%hhd",
            __func__, duration, max_responses);
        bluetooth::shim::GetInquiry()->StartGeneralInquiry(duration,
                                                           max_responses);
      }
      break;

    default:
      LOG_WARN(LOG_TAG, "%s Unknown inquiry mode:%d", __func__, mode);
      return false;
  }
  return true;
}

void bluetooth::shim::Btm::CancelInquiry() {
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
    case kGeneralInquiryMode:
      if (mode == kLimitedInquiryMode) {
        LOG_DEBUG(LOG_TAG, "%s Starting limited periodic inquiry mode",
                  __func__);
        bluetooth::shim::GetInquiry()->StartLimitedPeriodicInquiry(
            duration, max_responses, max_delay, min_delay);
      } else {
        LOG_DEBUG(LOG_TAG, "%s Starting general periodic inquiry mode",
                  __func__);
        bluetooth::shim::GetInquiry()->StartGeneralPeriodicInquiry(
            duration, max_responses, max_delay, min_delay);
      }
      break;

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
  LOG_INFO(LOG_TAG,
           "%s Cancelling classic remote device name without one in progress",
           __func__);
  return bluetooth::shim::BTM_WRONG_MODE;
}
