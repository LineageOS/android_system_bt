/******************************************************************************
 *
 *  Copyright 2019 The Android Open Source Project
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at:
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 ******************************************************************************/

#include "init_flags.h"

#include <string>

#include "os/log.h"

namespace bluetooth {
namespace common {

const std::string kGdHciFlag = "INIT_gd_hci";
bool InitFlags::gd_hci_enabled = false;

const std::string kGdControllerFlag = "INIT_gd_controller";
bool InitFlags::gd_controller_enabled = false;

const std::string kGdCoreFlag = "INIT_gd_core";
bool InitFlags::gd_core_enabled = false;

void InitFlags::Load(const char** flags) {
  gd_core_enabled = false;
  gd_hci_enabled = false;
  while (flags != nullptr && *flags != nullptr) {
    if (kGdCoreFlag == *flags) {
      gd_core_enabled = true;
    } else if (kGdHciFlag == *flags) {
      gd_hci_enabled = true;
    } else if (kGdControllerFlag == *flags) {
      gd_controller_enabled = true;
    }
    flags++;
  }

  if (gd_core_enabled && !gd_controller_enabled) {
    gd_controller_enabled = true;
  }
  if (gd_controller_enabled && !gd_hci_enabled) {
    gd_hci_enabled = true;
  }

  LOG_INFO(
      "Flags loaded: gd_hci_enabled: %s, gd_controller_enabled: %s, gd_core_enabled: %s",
      gd_hci_enabled ? "true" : "false",
      gd_controller_enabled ? "true" : "false",
      gd_core_enabled ? "true" : "false");
}

}  // namespace common
}  // namespace bluetooth
