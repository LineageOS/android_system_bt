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
#include "neighbor/page.h"
#include "neighbor/scan_parameters.h"
#include "os/handler.h"
#include "os/log.h"
#include "shim/page.h"

namespace bluetooth {
namespace shim {

const ModuleFactory Page::Factory = ModuleFactory([]() { return new Page(); });

struct Page::impl {
  impl(neighbor::PageModule* module);
  ~impl();

  neighbor::PageModule* module_{nullptr};
};

Page::impl::impl(neighbor::PageModule* module) : module_(module) {}

Page::impl::~impl() {}

void Page::SetScanActivity(uint16_t interval, uint16_t window) {
  neighbor::ScanParameters params{.interval = static_cast<neighbor::ScanInterval>(interval),
                                  .window = static_cast<neighbor::ScanWindow>(window)};
  return pimpl_->module_->SetScanActivity(params);
}

void Page::GetScanActivity(uint16_t& interval, uint16_t& window) const {
  neighbor::ScanParameters params = pimpl_->module_->GetScanActivity();

  interval = static_cast<uint16_t>(params.interval);
  window = static_cast<uint16_t>(params.window);
}

void Page::SetInterlacedScan() {
  return pimpl_->module_->SetInterlacedScan();
}
void Page::SetStandardScan() {
  return pimpl_->module_->SetStandardScan();
}

/**
 * Module methods
 */
void Page::ListDependencies(ModuleList* list) {
  list->add<neighbor::PageModule>();
}

void Page::Start() {
  pimpl_ = std::make_unique<impl>(GetDependency<neighbor::PageModule>());
}

void Page::Stop() {
  pimpl_.reset();
}

}  // namespace shim
}  // namespace bluetooth
