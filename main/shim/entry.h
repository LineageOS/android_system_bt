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

#pragma once

/**
 * Entrypoints called into Gabeldorsche from legacy stack
 *
 * Any marshalling/unmarshalling, data transformation of APIs to
 * or from the Gabeldorsche stack may be placed here.
 *
 * The idea is to effectively provide a binary interface to prevent cross
 * contamination of data structures and the like between the stacks.
 *
 * **ABSOLUTELY** No reference to Gabeldorsche stack other than well defined
 * interfaces may be made here
 */

#include "osi/include/future.h"

namespace bluetooth {
namespace os {
class Handler;
}
namespace activity_attribution {
class ActivityAttribution;
}
namespace neighbor {
class ConnectabilityModule;
class DiscoverabilityModule;
class InquiryModule;
class NameModule;
class PageModule;
}
namespace hci {
class Controller;
class HciLayer;
class AclManager;
class LeAdvertisingManager;
class LeScanningManager;
class VendorSpecificEventManager;
}

namespace l2cap {
namespace classic {
class L2capClassicModule;
}  // namespace classic
namespace le {
class L2capLeModule;
}  // namespace le
}  // namespace l2cap

namespace security {
class SecurityModule;
}
namespace storage {
class StorageModule;
}

namespace shim {
class Dumpsys;

/* This returns a handler that might be used in shim to receive callbacks from
 * within the stack. */
os::Handler* GetGdShimHandler();
hci::LeAdvertisingManager* GetAdvertising();
bluetooth::hci::Controller* GetController();
neighbor::DiscoverabilityModule* GetDiscoverability();
neighbor::ConnectabilityModule* GetConnectability();
Dumpsys* GetDumpsys();
neighbor::InquiryModule* GetInquiry();
hci::HciLayer* GetHciLayer();
l2cap::classic::L2capClassicModule* GetL2capClassicModule();
l2cap::le::L2capLeModule* GetL2capLeModule();
neighbor::NameModule* GetName();
neighbor::PageModule* GetPage();
hci::LeScanningManager* GetScanning();
bluetooth::security::SecurityModule* GetSecurityModule();
storage::StorageModule* GetStorage();
hci::AclManager* GetAclManager();
hci::VendorSpecificEventManager* GetVendorSpecificEventManager();
activity_attribution::ActivityAttribution* GetActivityAttribution();

}  // namespace shim
}  // namespace bluetooth
