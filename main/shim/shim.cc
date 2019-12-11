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

#include <cstdint>

#define LOG_TAG "bt_shim"

#include "common/message_loop_thread.h"
#include "main/shim/entry.h"
#include "main/shim/shim.h"
#include "osi/include/log.h"
#include "osi/include/properties.h"

static const char* kPropertyKey = "bluetooth.gd.enabled";

static bluetooth::common::MessageLoopThread bt_shim_thread("bt_shim_thread");

static bool gd_shim_enabled_ = false;
static bool gd_shim_property_checked_ = false;

future_t* ShimModuleStartUp() {
  bt_shim_thread.StartUp();
  CHECK(bt_shim_thread.IsRunning())
      << "Unable to start bt shim message loop thread.";
  bluetooth::shim::StartGabeldorscheStack();
  return nullptr;
}

future_t* ShimModuleShutDown() {
  bluetooth::shim::StopGabeldorscheStack();
  bt_shim_thread.ShutDown();
  return nullptr;
}

EXPORT_SYMBOL extern const module_t gd_shim_module = {
    .name = GD_SHIM_MODULE,
    .init = nullptr,
    .start_up = ShimModuleStartUp,
    .shut_down = ShimModuleShutDown,
    .clean_up = NULL,
    .dependencies = {NULL}};

void bluetooth::shim::Post(base::OnceClosure task) {
  bt_shim_thread.DoInThread(FROM_HERE, std::move(task));
}

bool bluetooth::shim::is_gd_shim_enabled() {
  if (!gd_shim_property_checked_) {
    gd_shim_property_checked_ = true;
    gd_shim_enabled_ = (osi_property_get_int32(kPropertyKey, 0) == 1);
  }
  return gd_shim_enabled_;
}
