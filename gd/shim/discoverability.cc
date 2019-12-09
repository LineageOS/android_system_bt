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

#include <memory>

#include "common/bidi_queue.h"
#include "hci/address.h"
#include "hci/controller.h"
#include "hci/hci_packets.h"
#include "module.h"
#include "neighbor/discoverability.h"
#include "os/handler.h"
#include "os/log.h"
#include "shim/discoverability.h"

namespace bluetooth {
namespace shim {

const ModuleFactory Discoverability::Factory = ModuleFactory([]() { return new Discoverability(); });

struct Discoverability::impl {
  impl(neighbor::DiscoverabilityModule* module) : module_(module) {}

  neighbor::DiscoverabilityModule* module_{nullptr};

  bool general_discoverability_enabled_{false};
  bool limited_discoverability_enabled_{false};
};

void Discoverability::StopDiscoverability() {
  if (pimpl_->general_discoverability_enabled_ || pimpl_->limited_discoverability_enabled_) {
    pimpl_->module_->StopDiscoverability();
    LOG_DEBUG("%s Stopped discoverability", __func__);
  } else {
    LOG_WARN("%s Discoverability not enabled", __func__);
  }
}

void Discoverability::StartLimitedDiscoverability() {
  if (pimpl_->general_discoverability_enabled_ || pimpl_->limited_discoverability_enabled_) {
    LOG_WARN("%s Please stop discoverability before re-enabling", __func__);
    return;
  }
  pimpl_->module_->StartLimitedDiscoverability();
  LOG_DEBUG("%s Started limited discoverability", __func__);
}

void Discoverability::StartGeneralDiscoverability() {
  if (pimpl_->general_discoverability_enabled_ || pimpl_->limited_discoverability_enabled_) {
    LOG_WARN("%s Please stop discoverability before re-enabling", __func__);
    return;
  }
  pimpl_->module_->StartGeneralDiscoverability();
  LOG_DEBUG("%s Started general discoverability", __func__);
}

bool Discoverability::IsGeneralDiscoverabilityEnabled() const {
  return pimpl_->general_discoverability_enabled_;
}

bool Discoverability::IsLimitedDiscoverabilityEnabled() const {
  return pimpl_->limited_discoverability_enabled_;
}

/**
 * Module methods
 */
void Discoverability::ListDependencies(ModuleList* list) {
  list->add<neighbor::DiscoverabilityModule>();
}

void Discoverability::Start() {
  pimpl_ = std::make_unique<impl>(GetDependency<neighbor::DiscoverabilityModule>());
}

void Discoverability::Stop() {
  pimpl_.reset();
}

}  // namespace shim
}  // namespace bluetooth
