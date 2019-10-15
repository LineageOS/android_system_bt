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

#include "main/shim/entry.h"
#include "main/shim/shim.h"
#include "osi/include/properties.h"

static const char* kPropertyKey = "bluetooth.gd.enabled";

static bool gd_shim_enabled_ = false;
static bool gd_shim_property_checked_ = false;

EXPORT_SYMBOL extern const module_t gd_shim_module = {
    .name = GD_SHIM_MODULE,
    .init = nullptr,
    .start_up = bluetooth::shim::StartGabeldorscheStack,
    .shut_down = bluetooth::shim::StopGabeldorscheStack,
    .clean_up = NULL,
    .dependencies = {NULL}};

bool bluetooth::shim::is_gd_shim_enabled() {
  if (!gd_shim_property_checked_) {
    gd_shim_property_checked_ = true;
    gd_shim_enabled_ = (osi_property_get_int32(kPropertyKey, 0) == 1);
  }
  return gd_shim_enabled_;
}
