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

#include "audio_hal_interface/a2dp_encoding.h"

namespace bluetooth {
namespace audio {
namespace a2dp {

bool update_codec_offloading_capabilities(
    const std::vector<btav_a2dp_codec_config_t>& framework_preference) {
  return false;
}

bool is_hal_2_0_enabled() { return false; }

bool is_hal_2_0_offloading() { return false; }

bool init(bluetooth::common::MessageLoopThread* message_loop) { return false; }

void cleanup() {}

// Set up the codec into BluetoothAudio HAL
bool setup_codec() { return false; }

void start_session() {}

void end_session() {}

void ack_stream_started(const tA2DP_CTRL_ACK& ack) {}

void ack_stream_suspended(const tA2DP_CTRL_ACK& ack) {}

size_t read(uint8_t* p_buf, uint32_t len) { return 0; }

void set_remote_delay(uint16_t delay_report) {}

}  // namespace a2dp
}  // namespace audio
}  // namespace bluetooth
