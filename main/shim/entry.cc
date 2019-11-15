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
#include "gd/shim/only_include_this_file_into_legacy_stack___ever.h"
#include "osi/include/future.h"

using bluetooth::shim::GetGabeldorscheStack;

future_t* bluetooth::shim::StartGabeldorscheStack() {
  GetGabeldorscheStack()->Start();
  return (future_t*)nullptr;
}

future_t* bluetooth::shim::StopGabeldorscheStack() {
  GetGabeldorscheStack()->Stop();
  return (future_t*)nullptr;
}

bluetooth::shim::IController* bluetooth::shim::GetController() {
  return GetGabeldorscheStack()->GetController();
}

bluetooth::shim::IConnectability* bluetooth::shim::GetConnectability() {
  return GetGabeldorscheStack()->GetConnectability();
}

bluetooth::shim::IDiscoverability* bluetooth::shim::GetDiscoverability() {
  return GetGabeldorscheStack()->GetDiscoverability();
}

bluetooth::shim::IInquiry* bluetooth::shim::GetInquiry() {
  return GetGabeldorscheStack()->GetInquiry();
}

bluetooth::shim::IHciLayer* bluetooth::shim::GetHciLayer() {
  return GetGabeldorscheStack()->GetHciLayer();
}

bluetooth::shim::IL2cap* bluetooth::shim::GetL2cap() {
  return GetGabeldorscheStack()->GetL2cap();
}

bluetooth::shim::IName* bluetooth::shim::GetName() {
  return GetGabeldorscheStack()->GetName();
}

bluetooth::shim::IPage* bluetooth::shim::GetPage() {
  return GetGabeldorscheStack()->GetPage();
}
