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
#define LOG_TAG "l2cap2"

#include <memory>

#include "common/address.h"
#include "common/bidi_queue.h"
#include "hci/acl_manager.h"
#include "hci/hci_packets.h"
#include "l2cap/l2cap_layer.h"
#include "module.h"
#include "os/handler.h"
#include "os/log.h"

namespace bluetooth {
namespace l2cap {

const ModuleFactory L2capLayer::Factory = ModuleFactory([]() { return new L2capLayer(); });

void L2capLayer::ListDependencies(ModuleList* list) {
  list->add<hci::AclManager>();
}

void L2capLayer::Start() {}

void L2capLayer::Stop() {}

}  // namespace l2cap
}  // namespace bluetooth