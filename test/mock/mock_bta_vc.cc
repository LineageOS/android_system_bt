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

/*
 * Generated mock file from original source file
 *   Functions generated:7
 */

#include <map>
#include <string>

extern std::map<std::string, int> mock_function_count_map;

#include <base/bind.h>
#include <base/bind_helpers.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <hardware/bt_vc.h>
#include <string>
#include <vector>
#include "bta/vc/devices.h"
#include "bta_gatt_api.h"
#include "bta_gatt_queue.h"
#include "bta_vc_api.h"
#include "btif_storage.h"

#ifndef UNUSED_ATTR
#define UNUSED_ATTR
#endif

void VolumeControl::AddFromStorage(const RawAddress& address,
                                   bool auto_connect) {
  mock_function_count_map[__func__]++;
}
void VolumeControl::CleanUp() { mock_function_count_map[__func__]++; }
void VolumeControl::DebugDump(int fd) { mock_function_count_map[__func__]++; }
VolumeControl* VolumeControl::Get(void) {
  mock_function_count_map[__func__]++;
  return nullptr;
}
bool VolumeControl::IsVolumeControlRunning() {
  mock_function_count_map[__func__]++;
  return false;
}
void VolumeControl::Initialize(
    bluetooth::vc::VolumeControlCallbacks* callbacks) {
  mock_function_count_map[__func__]++;
}
