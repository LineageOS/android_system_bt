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
#include "hci/le_advertising_manager.h"
#include "module.h"
#include "os/handler.h"
#include "os/log.h"
#include "shim/advertising.h"

namespace bluetooth {
namespace shim {

struct Advertising::impl {
  hci::LeAdvertisingManager* module_{nullptr};

  impl(hci::LeAdvertisingManager* module);
  ~impl();
};

const ModuleFactory Advertising::Factory = ModuleFactory([]() { return new Advertising(); });

Advertising::impl::impl(hci::LeAdvertisingManager* advertising_manager) : module_(advertising_manager) {}

Advertising::impl::~impl() {}

/**
 * Module methods
 */
void Advertising::ListDependencies(ModuleList* list) {
  list->add<hci::LeAdvertisingManager>();
}

void Advertising::Start() {
  pimpl_ = std::make_unique<impl>(GetDependency<hci::LeAdvertisingManager>());
}

void Advertising::Stop() {
  pimpl_.reset();
}

}  // namespace shim
}  // namespace bluetooth
