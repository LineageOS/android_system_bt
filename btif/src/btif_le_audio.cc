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

#include <hardware/bluetooth.h>
#include <vector>

#include "btif_common.h"
#include "btif_storage.h"
#include "hardware/bt_le_audio.h"
#include "stack/include/btu.h"

#include <hardware/bt_le_audio.h>

using base::Bind;
using base::Unretained;
using bluetooth::le_audio::ConnectionState;

using bluetooth::le_audio::GroupStatus;
using bluetooth::le_audio::LeAudioClientCallbacks;
using bluetooth::le_audio::LeAudioClientInterface;

namespace {
class LeAudioClientInterfaceImpl;
std::unique_ptr<LeAudioClientInterface> lEAudioInstance;

class LeAudioClientInterfaceImpl : public LeAudioClientInterface,
                                   public LeAudioClientCallbacks {
  ~LeAudioClientInterfaceImpl() = default;

  void OnConnectionState(ConnectionState state,
                         const RawAddress& address) override {
    do_in_jni_thread(FROM_HERE, Bind(&LeAudioClientCallbacks::OnConnectionState,
                                     Unretained(callbacks), state, address));
  }

  void OnGroupStatus(uint8_t group_id, GroupStatus group_status,
                     uint8_t group_flags) override {
    do_in_jni_thread(FROM_HERE, Bind(&LeAudioClientCallbacks::OnGroupStatus,
                                     Unretained(callbacks), group_id,
                                     group_status, group_flags));
  }

  void OnSetMemberAvailable(const RawAddress& address,
                            uint8_t group_id) override {
    do_in_jni_thread(FROM_HERE,
                     Bind(&LeAudioClientCallbacks::OnSetMemberAvailable,
                          Unretained(callbacks), address, group_id));
  }

  void OnAudioConf(const RawAddress& addr, uint8_t direction, uint8_t group_id,
                   uint32_t snk_audio_location,
                   uint32_t src_audio_location) override {
    do_in_jni_thread(
        FROM_HERE,
        Bind(&LeAudioClientCallbacks::OnAudioConf, Unretained(callbacks), addr,
             direction, group_id, snk_audio_location, src_audio_location));
  }

  void Initialize(LeAudioClientCallbacks* callbacks) override {
    this->callbacks = callbacks;
  }

  void Cleanup(void) override {}

  void Connect(const RawAddress& address) override {}

  void Disconnect(const RawAddress& address) override {}

  void GroupStream(const uint8_t group_id,
                   const uint16_t content_type) override {}

  void GroupSuspend(const uint8_t group_id) override {}

  void GroupStop(const uint8_t group_id) override {}

 private:
  LeAudioClientCallbacks* callbacks;
};

} /* namespace */

LeAudioClientInterface* btif_le_audio_get_interface() {
  if (!lEAudioInstance) {
    lEAudioInstance.reset(new LeAudioClientInterfaceImpl());
  }

  return lEAudioInstance.get();
}
