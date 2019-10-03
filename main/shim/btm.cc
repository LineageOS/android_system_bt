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

#include "main/shim/btm.h"
#include "osi/include/log.h"

bluetooth::shim::Btm::Btm() {}

void bluetooth::shim::Btm::SetLeDiscoverabilityOff() {
  LOG_INFO(LOG_TAG, "UNIMPLEMENTED %s", __func__);
  le_.mode = kDiscoverableModeOff;
}

void bluetooth::shim::Btm::SetLeLimitedDiscoverability() {
  LOG_INFO(LOG_TAG, "UNIMPLEMENTED %s", __func__);
  le_.mode = kLimitedDiscoverableMode;
}

void bluetooth::shim::Btm::SetLeGeneralDiscoverability() {
  LOG_INFO(LOG_TAG, "UNIMPLEMENTED %s", __func__);
  le_.mode = kGeneralDiscoverableMode;
  return DoSetDiscoverability();
}

// private
void bluetooth::shim::Btm::DoSetDiscoverability() {
  LOG_INFO(LOG_TAG, "UNIMPLEMENTED %s", __func__);
  // TODO(cmanton) actually set discoverability here
}

DiscoverabilityState bluetooth::shim::Btm::GetLeDiscoverabilityState() const {
  return le_;
}

void bluetooth::shim::Btm::SetClassicDiscoverabilityOff() {
  classic_.mode = kDiscoverableModeOff;
  LOG_INFO(LOG_TAG, "UNIMPLEMENTED %s", __func__);
}

void bluetooth::shim::Btm::SetClassicLimitedDiscoverability(uint16_t window,
                                                            uint16_t interval) {
  classic_.mode = kLimitedDiscoverableMode;
  classic_.window = window;
  classic_.interval = interval;
  LOG_INFO(LOG_TAG, "UNIMPLEMENTED %s", __func__);
}

void bluetooth::shim::Btm::SetClassicGeneralDiscoverability(uint16_t window,
                                                            uint16_t interval) {
  classic_.mode = kGeneralDiscoverableMode;
  classic_.window = window;
  classic_.interval = interval;
  LOG_INFO(LOG_TAG, "UNIMPLEMENTED %s", __func__);
}

DiscoverabilityState bluetooth::shim::Btm::GetClassicDiscoverabilityState()
    const {
  return classic_;
}

bool bluetooth::shim::Btm::IsInterlacedScanSupported() const {
  // TODO(cmanton) Check controller to ensure interlaced scan is actually
  // supported
  LOG_INFO(LOG_TAG, "UNIMPLEMENTED %s", __func__);
  return true;
}

bool bluetooth::shim::Btm::SetInterlacedInquiryScan() {
  LOG_INFO(LOG_TAG, "UNIMPLEMENTED %s", __func__);
  return false;
}

bool bluetooth::shim::Btm::SetStandardInquiryScan() {
  LOG_INFO(LOG_TAG, "UNIMPLEMENTED %s", __func__);
  return false;
}

bool bluetooth::shim::Btm::SetInterlacedPageScan() {
  LOG_INFO(LOG_TAG, "UNIMPLEMENTED %s", __func__);
  return false;
}

bool bluetooth::shim::Btm::SetStandardPageScan() {
  LOG_INFO(LOG_TAG, "UNIMPLEMENTED %s", __func__);
  return false;
}

bool bluetooth::shim::Btm::SetStandardInquiryMode() {
  LOG_INFO(LOG_TAG, "UNIMPLEMENTED %s", __func__);
  return DoSetInquiryMode();
}

bool bluetooth::shim::Btm::SetInquiryModeWithRssi() {
  LOG_INFO(LOG_TAG, "UNIMPLEMENTED %s", __func__);
  return DoSetInquiryMode();
}

bool bluetooth::shim::Btm::SetExtendedInquiryMode() {
  LOG_INFO(LOG_TAG, "UNIMPLEMENTED %s", __func__);
  return DoSetInquiryMode();
}

// private
bool bluetooth::shim::Btm::DoSetInquiryMode() {
  LOG_INFO(LOG_TAG, "UNIMPLEMENTED %s", __func__);
  return false;
}

bool bluetooth::shim::Btm::IsInquiryActive() const {
  LOG_INFO(LOG_TAG, "UNIMPLEMENTED %s", __func__);
  return false;
}

bool bluetooth::shim::Btm::ClearInquiryFilter() {
  LOG_INFO(LOG_TAG, "UNIMPLEMENTED %s", __func__);
  return DoSetEventFilter();
}

bool bluetooth::shim::Btm::SetFilterInquiryOnDevice() {
  LOG_INFO(LOG_TAG, "UNIMPLEMENTED %s", __func__);
  return DoSetEventFilter();
}

bool bluetooth::shim::Btm::SetFilterInquiryOnAddress() {
  LOG_INFO(LOG_TAG, "UNIMPLEMENTED %s", __func__);
  return DoSetEventFilter();
}

bool bluetooth::shim::Btm::CancelPeriodicInquiry() {
  LOG_INFO(LOG_TAG, "UNIMPLEMENTED %s", __func__);
  return false;
}

// private
bool bluetooth::shim::Btm::DoSetEventFilter() {
  LOG_INFO(LOG_TAG, "UNIMPLEMENTED %s", __func__);
  // TODO(cmanton) Actually set/clear event filter here
  return false;
}

bool bluetooth::shim::Btm::SetClassicConnectibleOff() {
  return DoSetConnectible();
}

bool bluetooth::shim::Btm::SetClassicConnectibleOn() {
  return DoSetConnectible();
}

bool bluetooth::shim::Btm::SetLeConnectibleOff() { return DoSetConnectible(); }

bool bluetooth::shim::Btm::SetLeConnectibleOn() { return DoSetConnectible(); }

ConnectibilityState bluetooth::shim::Btm::GetClassicConnectibilityState()
    const {
  return le_connectibility_state_;
}

ConnectibilityState bluetooth::shim::Btm::GetLeConnectibilityState() const {
  return classic_connectibility_state_;
}

bool bluetooth::shim::Btm::StartInquiry() {
  LOG_INFO(LOG_TAG, "UNIMPLEMENTED %s", __func__);
  return false;
}

// private
bool bluetooth::shim::Btm::DoSetConnectible() {
  LOG_INFO(LOG_TAG, "UNIMPLEMENTED %s", __func__);
  // TODO(cmanton) Actually set/clear connectibility here
  return false;
}
