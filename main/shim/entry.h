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

#include "gd/shim/only_include_this_file_into_legacy_stack___ever.h"
#include "osi/include/future.h"

namespace bluetooth {
namespace shim {

future_t* StartGabeldorscheStack();
future_t* StopGabeldorscheStack();

bluetooth::shim::IController* GetController();
bluetooth::shim::IDiscoverability* GetDiscoverability();
bluetooth::shim::IConnectability* GetConnectability();
bluetooth::shim::IInquiry* GetInquiry();
bluetooth::shim::IHciLayer* GetHciLayer();
bluetooth::shim::IL2cap* GetL2cap();
bluetooth::shim::IName* GetName();
bluetooth::shim::IPage* GetPage();

}  // namespace shim
}  // namespace bluetooth
