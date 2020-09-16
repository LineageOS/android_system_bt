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

const std::string kGdAdvertisingFlag = "INIT_gd_advertising";
bool InitFlags::gd_advertising_enabled = false;

const std::string kGdSecurityFlag = "INIT_gd_security";
bool InitFlags::gd_security_enabled = false;

const std::string kGdAclFlag = "INIT_gd_acl";
bool InitFlags::gd_acl_enabled = false;

const std::string kGdHciFlag = "INIT_gd_hci";
bool InitFlags::gd_hci_enabled = false;

const std::string kGdControllerFlag = "INIT_gd_controller";
bool InitFlags::gd_controller_enabled = false;

const std::string kGdCoreFlag = "INIT_gd_core";
bool InitFlags::gd_core_enabled = false;

const std::string kGattRobustCachingFlag = "INIT_gatt_robust_caching";
bool InitFlags::gatt_robust_caching_enabled = false;

void InitFlags::Load(const char** flags) {
  SetAll(false);
  while (flags != nullptr && *flags != nullptr) {
    if (kGdCoreFlag == *flags) {
      gd_core_enabled = true;
    } else if (kGdAdvertisingFlag == *flags) {
      // TODO enable when module ready
      // gd_advertising_enabled = true;
    } else if (kGdSecurityFlag == *flags) {
      gd_security_enabled = true;
    } else if (kGdAclFlag == *flags) {
      gd_acl_enabled = true;
    } else if (kGdHciFlag == *flags) {
      gd_hci_enabled = true;
    } else if (kGdControllerFlag == *flags) {
      gd_controller_enabled = true;
    } else if (kGattRobustCachingFlag == *flags) {
      gatt_robust_caching_enabled = true;
    }
    flags++;
  }

  if (gd_core_enabled && !gd_security_enabled) {
    gd_security_enabled = true;
  }
  if (gd_security_enabled && !gd_acl_enabled) {
    gd_acl_enabled = true;
  }
  if (gd_acl_enabled && !gd_controller_enabled) {
    gd_controller_enabled = true;
  }
  if (gd_controller_enabled && !gd_hci_enabled) {
    gd_hci_enabled = true;
  }

  LOG_INFO(
      "Flags loaded: gd_advertising_enabled %s, gd_security_enabled: %s, gd_acl_enabled: %s, gd_hci_enabled: %s, "
      "gd_controller_enabled: %s, "
      "gd_core_enabled: %s",
      gd_advertising_enabled ? "true" : "false",
      gd_security_enabled ? "true" : "false",
      gd_acl_enabled ? "true" : "false",
      gd_hci_enabled ? "true" : "false",
      gd_controller_enabled ? "true" : "false",
      gd_core_enabled ? "true" : "false");
}

void InitFlags::SetAll(bool value) {
  gd_core_enabled = value;
  gd_advertising_enabled = value;
  gd_acl_enabled = value;
  gd_security_enabled = value;
  gd_controller_enabled = value;
  gd_hci_enabled = value;
  gatt_robust_caching_enabled = value;
}

void InitFlags::SetAllForTesting() {
  SetAll(true);
}

}  // namespace common
}  // namespace bluetooth
