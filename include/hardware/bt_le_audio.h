/*
 * Copyright 2019 HIMSA II K/S - www.himsa.com. Represented by EHIMA -
 * www.ehima.com
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

#include <array>
#include <optional>

#include "raw_address.h"

namespace bluetooth {
namespace le_audio {

enum class ConnectionState {
  DISCONNECTED = 0,
  CONNECTING,
  CONNECTED,
  DISCONNECTING
};

enum class GroupStatus {
  IDLE = 0,
  STREAMING,
  SUSPENDED,
  RECONFIGURED,
  DESTROYED,
};

class LeAudioClientCallbacks {
 public:
  virtual ~LeAudioClientCallbacks() = default;

  /** Callback for profile connection state change */
  virtual void OnConnectionState(ConnectionState state,
                                 const RawAddress& address) = 0;

  /* Callback with group status update */
  virtual void OnGroupStatus(uint8_t group_id, GroupStatus group_status,
                             uint8_t group_flags) = 0;

  /* Callback for newly recognized or reconfigured existing le audio device */
  virtual void OnAudioConf(const RawAddress& addr, uint8_t direction,
                           uint8_t group_id, uint32_t snk_audio_location,
                           uint32_t src_audio_location) = 0;

  /* Callback for available set member  */
  virtual void OnSetMemberAvailable(const RawAddress& address,
                                    uint8_t group_id) = 0;
};

class LeAudioClientInterface {
 public:
  virtual ~LeAudioClientInterface() = default;

  /* Register the LeAudio callbacks */
  virtual void Initialize(LeAudioClientCallbacks* callbacks) = 0;

  /** Connect to LEAudio */
  virtual void Connect(const RawAddress& address) = 0;

  /** Disconnect from LEAudio */
  virtual void Disconnect(const RawAddress& address) = 0;

  /* Cleanup the LeAudio */
  virtual void Cleanup(void) = 0;

  /* Request to stream audio */
  virtual void GroupStream(uint8_t group_id, uint16_t content_type) = 0;

  /* Request to suspend audio */
  virtual void GroupSuspend(uint8_t group_id) = 0;

  /* Request to stop streaming audio */
  virtual void GroupStop(uint8_t group_id) = 0;
};

static constexpr uint8_t INSTANCE_ID_UNDEFINED = 0xFF;

} /* namespace le_audio */
} /* namespace bluetooth */
