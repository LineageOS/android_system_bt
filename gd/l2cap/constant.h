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

#include <chrono>
#include <cstddef>

#include "l2cap/cid.h"
#include "l2cap/signal_id.h"

namespace bluetooth {
namespace l2cap {

constexpr size_t kChannelQueueCapacity = 10;
constexpr size_t kLinkQueueCapacity = 10;
constexpr std::chrono::milliseconds bogus_link_wakeup_time = std::chrono::milliseconds(15000);

constexpr SignalId kInitialSignalId = SignalId(0x80);

// Time after last channels closes before link is torn down
constexpr auto kLinkDisconnectTimeout = std::chrono::seconds(30);

// TODO(cmanton) Random numbers for now
constexpr auto kChannelConnectionTimeout = std::chrono::seconds(30);
constexpr auto kChannelConnectionPendingTimeout = std::chrono::seconds(30);
constexpr auto kChannelConfigurationTimeout = std::chrono::seconds(30);
constexpr auto kChannelDisconnectionTimeout = std::chrono::seconds(30);

// The depth of buffering that the signalling channel can handle.
constexpr auto kSignallingChannelSize = 20;

}  // namespace l2cap
}  // namespace bluetooth
