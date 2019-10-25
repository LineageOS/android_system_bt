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
#include "neighbor/connectability.h"
#include "os/handler.h"
#include "os/log.h"
#include "shim/connectability.h"

namespace bluetooth {
namespace shim {

const ModuleFactory Connectability::Factory = ModuleFactory([]() { return new Connectability(); });

struct Connectability::impl {
  impl(neighbor::ConnectabilityModule* module) : module_(module) {}

  neighbor::ConnectabilityModule* module_{nullptr};
};

void Connectability::StartConnectability() {
  pimpl_->module_->StartConnectability();
}

void Connectability::StopConnectability() {
  pimpl_->module_->StopConnectability();
}

bool Connectability::IsConnectable() const {
  return pimpl_->module_->IsConnectable();
}

/**
 * Module methods
 */
void Connectability::ListDependencies(ModuleList* list) {
  list->add<neighbor::ConnectabilityModule>();
}

void Connectability::Start() {
  pimpl_ = std::make_unique<impl>(GetDependency<neighbor::ConnectabilityModule>());
}

void Connectability::Stop() {
  pimpl_.reset();
}

}  // namespace shim
}  // namespace bluetooth
