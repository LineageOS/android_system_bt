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

#pragma once

#include "btaa/activity_attribution.h"
#include "hci/hci_packets.h"

namespace bluetooth {
namespace activity_attribution {

struct CmdEvtActivityClassification {
  Activity activity;
  uint16_t connection_handle_pos;
  uint16_t address_pos;
};

CmdEvtActivityClassification lookup_cmd(hci::OpCode opcode);
CmdEvtActivityClassification lookup_event(hci::EventCode event_code);
CmdEvtActivityClassification lookup_le_event(hci::SubeventCode subevent_code);

}  // namespace activity_attribution
}  // namespace bluetooth
