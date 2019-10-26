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
};

void Discoverability::StopDiscoverability() {
  return pimpl_->module_->StopDiscoverability();
}

void Discoverability::StartLimitedDiscoverability() {
  return pimpl_->module_->StartLimitedDiscoverability();
}

void Discoverability::StartGeneralDiscoverability() {
  return pimpl_->module_->StartGeneralDiscoverability();
}

bool Discoverability::IsGeneralDiscoverabilityEnabled() const {
  return pimpl_->module_->IsGeneralDiscoverabilityEnabled();
}

bool Discoverability::IsLimitedDiscoverabilityEnabled() const {
  return pimpl_->module_->IsLimitedDiscoverabilityEnabled();
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
