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

#include "main/shim/entry.h"
#include "osi/include/future.h"

#include "hci/controller.h"
#include "neighbor/discoverability.h"
#include "security/security_module.h"
#include "shim/advertising.h"
#include "shim/connectability.h"
#include "shim/dumpsys.h"
#include "shim/hci_layer.h"
#include "shim/inquiry.h"
#include "shim/l2cap.h"
#include "shim/name.h"
#include "shim/name_db.h"
#include "shim/page.h"
#include "shim/scanning.h"
#include "shim/stack.h"
#include "shim/storage.h"
#include "stack_manager.h"

using bluetooth::shim::GetGabeldorscheStack;

future_t* bluetooth::shim::StartGabeldorscheStack() {
  GetGabeldorscheStack()->Start();
  return (future_t*)nullptr;
}

future_t* bluetooth::shim::StopGabeldorscheStack() {
  GetGabeldorscheStack()->Stop();
  return (future_t*)nullptr;
}

bluetooth::shim::Advertising* bluetooth::shim::GetAdvertising() {
  return GetGabeldorscheStack()
      ->GetStackManager()
      ->GetInstance<bluetooth::shim::Advertising>();
}

bluetooth::hci::Controller* bluetooth::shim::GetController() {
  return GetGabeldorscheStack()
      ->GetStackManager()
      ->GetInstance<bluetooth::hci::Controller>();
}

bluetooth::shim::Connectability* bluetooth::shim::GetConnectability() {
  return GetGabeldorscheStack()
      ->GetStackManager()
      ->GetInstance<bluetooth::shim::Connectability>();
}

bluetooth::neighbor::DiscoverabilityModule*
bluetooth::shim::GetDiscoverability() {
  return GetGabeldorscheStack()
      ->GetStackManager()
      ->GetInstance<bluetooth::neighbor::DiscoverabilityModule>();
}

bluetooth::shim::Dumpsys* bluetooth::shim::GetDumpsys() {
  return GetGabeldorscheStack()
      ->GetStackManager()
      ->GetInstance<bluetooth::shim::Dumpsys>();
}

bluetooth::shim::Inquiry* bluetooth::shim::GetInquiry() {
  return GetGabeldorscheStack()
      ->GetStackManager()
      ->GetInstance<bluetooth::shim::Inquiry>();
}

bluetooth::shim::HciLayer* bluetooth::shim::GetHciLayer() {
  return GetGabeldorscheStack()
      ->GetStackManager()
      ->GetInstance<bluetooth::shim::HciLayer>();
}

bluetooth::shim::L2cap* bluetooth::shim::GetL2cap() {
  return GetGabeldorscheStack()
      ->GetStackManager()
      ->GetInstance<bluetooth::shim::L2cap>();
}

bluetooth::shim::Name* bluetooth::shim::GetName() {
  return GetGabeldorscheStack()
      ->GetStackManager()
      ->GetInstance<bluetooth::shim::Name>();
}

bluetooth::shim::NameDb* bluetooth::shim::GetNameDb() {
  return GetGabeldorscheStack()
      ->GetStackManager()
      ->GetInstance<bluetooth::shim::NameDb>();
}

bluetooth::shim::Page* bluetooth::shim::GetPage() {
  return GetGabeldorscheStack()
      ->GetStackManager()
      ->GetInstance<bluetooth::shim::Page>();
}

bluetooth::shim::Scanning* bluetooth::shim::GetScanning() {
  return GetGabeldorscheStack()
      ->GetStackManager()
      ->GetInstance<bluetooth::shim::Scanning>();
}

bluetooth::shim::Security* bluetooth::shim::GetSecurity() {
  return GetGabeldorscheStack()
      ->GetStackManager()
      ->GetInstance<bluetooth::shim::Security>();
}

bluetooth::security::SecurityModule* bluetooth::shim::GetSecurityModule() {
  return GetGabeldorscheStack()
      ->GetStackManager()
      ->GetInstance<bluetooth::security::SecurityModule>();
}

bluetooth::shim::Storage* bluetooth::shim::GetStorage() {
  return GetGabeldorscheStack()
      ->GetStackManager()
      ->GetInstance<bluetooth::shim::Storage>();
}
