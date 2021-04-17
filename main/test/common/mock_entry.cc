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

#include "gd/btaa/activity_attribution.h"
#include "gd/hci/acl_manager_mock.h"
#include "gd/hci/controller_mock.h"
#include "gd/hci/hci_layer.h"
#include "gd/hci/le_advertising_manager.h"
#include "gd/hci/le_scanning_manager.h"
#include "gd/neighbor/connectability.h"
#include "gd/neighbor/discoverability.h"
#include "gd/neighbor/inquiry.h"
#include "gd/neighbor/inquiry_mock.h"
#include "gd/neighbor/name.h"
#include "gd/neighbor/page.h"
#include "gd/os/handler.h"
#include "gd/security/security_module.h"
#include "gd/shim/dumpsys.h"
#include "gd/storage/storage_module.h"
#include "hci/acl_manager.h"
#include "main/shim/entry.h"
#include "main/shim/stack.h"

namespace bluetooth {
namespace hci {
namespace testing {

MockAclManager* mock_acl_manager_{nullptr};
MockController* mock_controller_{nullptr};

}  // namespace testing
}  // namespace hci

namespace shim {

Dumpsys* GetDumpsys() { return nullptr; }
activity_attribution::ActivityAttribution* GetActivityAttribution() {
  return nullptr;
}
hci::AclManager* GetAclManager() { return hci::testing::mock_acl_manager_; }
hci::Controller* GetController() { return hci::testing::mock_controller_; }
hci::HciLayer* GetHciLayer() { return nullptr; }
hci::LeAdvertisingManager* GetAdvertising() { return nullptr; }
hci::LeScanningManager* GetScanning() { return nullptr; }
l2cap::classic::L2capClassicModule* GetL2capClassicModule() { return nullptr; }
l2cap::le::L2capLeModule* GetL2capLeModule() { return nullptr; }
neighbor::ConnectabilityModule* GetConnectability() { return nullptr; }
neighbor::DiscoverabilityModule* GetDiscoverability() { return nullptr; }
neighbor::InquiryModule* GetInquiry() { return nullptr; }
neighbor::NameModule* GetName() { return nullptr; }
neighbor::PageModule* GetPage() { return nullptr; }
os::Handler* GetGdShimHandler() { return Stack::GetInstance()->GetHandler(); }
security::SecurityModule* GetSecurityModule() { return nullptr; }
storage::StorageModule* GetStorage() { return nullptr; }

}  // namespace shim
}  // namespace bluetooth
