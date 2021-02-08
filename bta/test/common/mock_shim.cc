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

#define LOG_TAG "bt_shim"

#include "gd/common/init_flags.h"
#include "main/shim/shim.h"

future_t* IdleModuleStartUp() { return kReturnImmediate; }

future_t* ShimModuleStartUp() { return kReturnImmediate; }

future_t* GeneralShutDown() { return kReturnImmediate; }

bool bluetooth::shim::is_gd_advertising_enabled() { return false; }

bool bluetooth::shim::is_gd_scanning_enabled() { return false; }

bool bluetooth::shim::is_gd_security_enabled() { return false; }

bool bluetooth::shim::is_gd_acl_enabled() { return false; }

bool bluetooth::shim::is_gd_link_policy_enabled() { return false; }

bool bluetooth::shim::is_gd_hci_enabled() { return false; }

bool bluetooth::shim::is_gd_controller_enabled() { return false; }

bool bluetooth::shim::is_gd_l2cap_enabled() { return false; }

bool bluetooth::shim::is_gd_shim_enabled() {
  return bluetooth::common::init_flags::gd_core_is_enabled();
}

bool bluetooth::shim::is_any_gd_enabled() { return false; }

bool bluetooth::shim::is_gd_stack_started_up() { return false; }
