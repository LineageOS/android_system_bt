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

const std::string kGdCoreFlag = "INIT_gd_core";
bool InitFlags::gd_core_enabled = false;

void InitFlags::Load(const char** flags) {
  gd_core_enabled = false;
  while (flags != nullptr && *flags != nullptr) {
    if (kGdCoreFlag == *flags) {
      gd_core_enabled = true;
    }
    flags++;
  }

  LOG_INFO("Flags loaded: gd_core_enabled: %s", gd_core_enabled ? "true" : "false");
}

}  // namespace common
}  // namespace bluetooth
