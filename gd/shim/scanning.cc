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

#include "hci/address.h"
#include "hci/hci_packets.h"
#include "hci/le_scanning_manager.h"
#include "module.h"
#include "os/handler.h"
#include "os/log.h"
#include "shim/scanning.h"

namespace bluetooth {
namespace shim {

struct Scanning::impl {
  hci::LeScanningManager* module_{nullptr};

  impl(hci::LeScanningManager* module);
  ~impl();
};

const ModuleFactory Scanning::Factory = ModuleFactory([]() { return new Scanning(); });

Scanning::impl::impl(hci::LeScanningManager* scanning_manager) : module_(scanning_manager) {}

Scanning::impl::~impl() {}

/**
 * Module methods
 */
void Scanning::ListDependencies(ModuleList* list) {
  list->add<hci::LeScanningManager>();
}

void Scanning::Start() {
  pimpl_ = std::make_unique<impl>(GetDependency<hci::LeScanningManager>());
}

void Scanning::Stop() {
  pimpl_.reset();
}

}  // namespace shim
}  // namespace bluetooth
