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

bluetooth::shim::IHciLayer* bluetooth::shim::GetHciLayer() {
  return GetGabeldorscheStack()->GetHciLayer();
}
