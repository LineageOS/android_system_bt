/*
 * Copyright 2021 The Android Open Source Project
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

#include "gd/module.h"

#include "btif/include/btif_activity_attribution.h"
#include "main/shim/activity_attribution.h"
#include "main/shim/shim.h"

ActivityAttributionInterface*
bluetooth::activity_attribution::get_activity_attribution_instance() {
  return nullptr;
}

ActivityAttributionInterface*
bluetooth::shim::get_activity_attribution_instance() {
  return nullptr;
}

const bluetooth::ModuleFactory
    bluetooth::activity_attribution::ActivityAttribution::Factory =
        bluetooth::ModuleFactory([]() { return nullptr; });
