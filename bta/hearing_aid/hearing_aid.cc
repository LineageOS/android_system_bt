/******************************************************************************
 *
 *  Copyright 2018 The Android Open Source Project
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

#include "bta_hearing_aid_api.h"

#include <base/bind.h>
#include <base/logging.h>

using base::Closure;

void HearingAid::Initialize(
    bluetooth::hearing_aid::HearingAidCallbacks* callbacks, Closure initCb) {
  CHECK(false) << "unimplemented yet";
}

bool HearingAid::IsInitialized() {
  CHECK(false) << "unimplemented yet";
  return false;
}

HearingAid* HearingAid::Get() {
  CHECK(false) << "unimplemented yet";
  return nullptr;
};

void HearingAid::AddFromStorage(const RawAddress& address, uint16_t psm,
                                uint8_t capabilities, uint8_t codecs,
                                uint16_t audio_control_point_handle,
                                uint16_t volume_handle, uint64_t hiSyncId) {
  CHECK(false) << "unimplemented yet";
};

void HearingAid::CleanUp() { CHECK(false) << "unimplemented yet"; };
