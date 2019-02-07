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

#include "a2dp_software_encoding.h"
#include "client_interface.h"

#include "btif_a2dp_source.h"
#include "btif_av.h"
#include "btif_av_co.h"
#include "btif_hf.h"
#include "osi/include/properties.h"

namespace {

using ::android::hardware::bluetooth::audio::V2_0::CodecType;
using ::bluetooth::audio::AudioConfiguration;
using ::bluetooth::audio::BitsPerSample;
using ::bluetooth::audio::BluetoothAudioCtrlAck;
using ::bluetooth::audio::ChannelMode;
using ::bluetooth::audio::PcmParameters;
using ::bluetooth::audio::SampleRate;
using ::bluetooth::audio::SessionType;

BluetoothAudioCtrlAck a2dp_ack_to_bt_audio_ctrl_ack(tA2DP_CTRL_ACK ack);
bool a2dp_get_selected_hal_pcm_config(PcmParameters* pcm_config);

// Provide call-in APIs for the Bluetooth Audio HAL
class A2dpTransport : public ::bluetooth::audio::IBluetoothTransportInstance {
 public:
  A2dpTransport(SessionType sessionType, AudioConfiguration audioConfig)
      : IBluetoothTransportInstance(sessionType, std::move(audioConfig)),
        a2dp_pending_cmd_(A2DP_CTRL_CMD_NONE),
        remote_delay_report_(0),
        total_bytes_read_(0),
        data_position_({}){};

  BluetoothAudioCtrlAck StartRequest() override {
    // Check if a previous request is not finished
    if (a2dp_pending_cmd_ == A2DP_CTRL_CMD_START) {
      LOG(INFO) << __func__ << ": A2DP_CTRL_CMD_START in progress";
      return a2dp_ack_to_bt_audio_ctrl_ack(A2DP_CTRL_ACK_PENDING);
    } else if (a2dp_pending_cmd_ != A2DP_CTRL_CMD_NONE) {
      LOG(WARNING) << __func__ << ": busy in pending_cmd=" << a2dp_pending_cmd_;
      return a2dp_ack_to_bt_audio_ctrl_ack(A2DP_CTRL_ACK_FAILURE);
    }

    // Don't send START request to stack while we are in a call
    if (!bluetooth::headset::IsCallIdle()) {
      LOG(ERROR) << __func__ << ": call state is busy";
      return a2dp_ack_to_bt_audio_ctrl_ack(A2DP_CTRL_ACK_INCALL_FAILURE);
    }

    if (btif_a2dp_source_is_streaming()) {
      LOG(ERROR) << __func__ << ": source is busy streaming";
      return a2dp_ack_to_bt_audio_ctrl_ack(A2DP_CTRL_ACK_FAILURE);
    }

    if (btif_av_stream_ready()) {
      /*
       * Post start event and wait for audio path to open.
       * If we are the source, the ACK will be sent after the start
       * procedure is completed, othewise send it now.
       */
      a2dp_pending_cmd_ = A2DP_CTRL_CMD_START;
      btif_av_stream_start();
      if (btif_av_get_peer_sep() != AVDT_TSEP_SRC) {
        LOG(INFO) << __func__ << ": accepted";
        return a2dp_ack_to_bt_audio_ctrl_ack(A2DP_CTRL_ACK_PENDING);
      }
      a2dp_pending_cmd_ = A2DP_CTRL_CMD_NONE;
      return a2dp_ack_to_bt_audio_ctrl_ack(A2DP_CTRL_ACK_SUCCESS);
    }

    if (btif_av_stream_started_ready()) {
      // Already started, ACK back immediately.
      return a2dp_ack_to_bt_audio_ctrl_ack(A2DP_CTRL_ACK_SUCCESS);
    }
    LOG(ERROR) << __func__ << ": AV stream is not ready to start";
    return a2dp_ack_to_bt_audio_ctrl_ack(A2DP_CTRL_ACK_FAILURE);
  }

  BluetoothAudioCtrlAck SuspendRequest() override {
    // Previous request is not finished
    if (a2dp_pending_cmd_ == A2DP_CTRL_CMD_SUSPEND) {
      LOG(INFO) << __func__ << ": A2DP_CTRL_CMD_SUSPEND in progress";
      return a2dp_ack_to_bt_audio_ctrl_ack(A2DP_CTRL_ACK_PENDING);
    } else if (a2dp_pending_cmd_ != A2DP_CTRL_CMD_NONE) {
      LOG(WARNING) << __func__ << ": busy in pending_cmd=" << a2dp_pending_cmd_;
      return a2dp_ack_to_bt_audio_ctrl_ack(A2DP_CTRL_ACK_FAILURE);
    }
    // Local suspend
    if (btif_av_stream_started_ready()) {
      LOG(INFO) << __func__ << ": accepted";
      a2dp_pending_cmd_ = A2DP_CTRL_CMD_SUSPEND;
      btif_av_stream_suspend();
      return BluetoothAudioCtrlAck::PENDING;
    }
    /* If we are not in started state, just ack back ok and let
     * audioflinger close the channel. This can happen if we are
     * remotely suspended, clear REMOTE SUSPEND flag.
     */
    btif_av_clear_remote_suspend_flag();
    return a2dp_ack_to_bt_audio_ctrl_ack(A2DP_CTRL_ACK_SUCCESS);
  }

  void StopRequest() override {
    if (btif_av_get_peer_sep() == AVDT_TSEP_SNK &&
        !btif_a2dp_source_is_streaming()) {
      return;
    }
    LOG(INFO) << __func__ << ": handling";
    a2dp_pending_cmd_ = A2DP_CTRL_CMD_STOP;
    btif_av_stream_stop(RawAddress::kEmpty);
  }

  bool GetPresentationPosition(uint64_t* remote_delay_report_ns,
                               uint64_t* total_bytes_read,
                               timespec* data_position) override {
    *remote_delay_report_ns = remote_delay_report_ * 100000u;
    *total_bytes_read = total_bytes_read_;
    *data_position = data_position_;
    VLOG(2) << __func__ << ": delay=" << remote_delay_report_
            << "/10ms, data=" << total_bytes_read_
            << " byte(s), timestamp=" << data_position_.tv_sec << "."
            << data_position_.tv_nsec << "s";
    return true;
  }

  void MetadataChanged(const source_metadata_t& source_metadata) override {
    auto track_count = source_metadata.track_count;
    auto tracks = source_metadata.tracks;
    VLOG(1) << __func__ << ": " << track_count << " track(s) received";
    while (track_count) {
      VLOG(2) << __func__ << ": usage=" << tracks->usage
              << ", content_type=" << tracks->content_type
              << ", gain=" << tracks->gain;
      --track_count;
      ++tracks;
    }
  }

  tA2DP_CTRL_CMD GetPendingCmd() const { return a2dp_pending_cmd_; }

  void ResetPendingCmd() { a2dp_pending_cmd_ = A2DP_CTRL_CMD_NONE; }

  void ResetPresentationPosition() override {
    remote_delay_report_ = 0;
    total_bytes_read_ = 0;
    data_position_ = {};
  }

  void LogBytesRead(size_t bytes_read) override {
    if (bytes_read != 0) {
      total_bytes_read_ += bytes_read;
      clock_gettime(CLOCK_MONOTONIC, &data_position_);
    }
  }

  // delay reports from AVDTP is based on 1/10 ms (100us)
  void SetRemoteDelay(uint16_t delay_report) {
    remote_delay_report_ = delay_report;
  }

 private:
  tA2DP_CTRL_CMD a2dp_pending_cmd_;
  uint16_t remote_delay_report_;
  uint64_t total_bytes_read_;
  timespec data_position_;
};

A2dpTransport* a2dp_sink = nullptr;

// Common interface to call-out into Bluetooth Audio HAL
bluetooth::audio::BluetoothAudioClientInterface* a2dp_hal_clientif = nullptr;

// Save the value if the remote reports its delay before a2dp_sink is
// initialized
uint16_t remote_delay = 0;

bool btaudio_a2dp_legacy_supported = false;
bool is_configured = false;

BluetoothAudioCtrlAck a2dp_ack_to_bt_audio_ctrl_ack(tA2DP_CTRL_ACK ack) {
  switch (ack) {
    case A2DP_CTRL_ACK_SUCCESS:
      return BluetoothAudioCtrlAck::SUCCESS_FINISHED;
    case A2DP_CTRL_ACK_PENDING:
      return BluetoothAudioCtrlAck::PENDING;
    case A2DP_CTRL_ACK_INCALL_FAILURE:
      return BluetoothAudioCtrlAck::FAILURE_BUSY;
    case A2DP_CTRL_ACK_DISCONNECT_IN_PROGRESS:
      return BluetoothAudioCtrlAck::FAILURE_DISCONNECTING;
    case A2DP_CTRL_ACK_UNSUPPORTED: /* Offloading but resource failure */
      return BluetoothAudioCtrlAck::FAILURE_UNSUPPORTED;
    case A2DP_CTRL_ACK_FAILURE:
      return BluetoothAudioCtrlAck::FAILURE;
    default:
      return BluetoothAudioCtrlAck::FAILURE;
  }
}

bool a2dp_get_selected_hal_pcm_config(PcmParameters* pcm_config) {
  if (pcm_config == nullptr) return false;
  A2dpCodecConfig* a2dp_codec_configs = bta_av_get_a2dp_current_codec();
  if (a2dp_codec_configs == nullptr) {
    LOG(WARNING) << __func__ << ": failure to get A2DP codec config";
    *pcm_config = ::bluetooth::audio::BluetoothAudioClientInterface::
        kInvalidPcmConfiguration;
    return false;
  }

  // include/hardware/bt_av.h
  btav_a2dp_codec_config_t current_codec = a2dp_codec_configs->getCodecConfig();
  switch (current_codec.sample_rate) {
    case BTAV_A2DP_CODEC_SAMPLE_RATE_44100:
      pcm_config->sampleRate = SampleRate::RATE_44100;
      break;
    case BTAV_A2DP_CODEC_SAMPLE_RATE_48000:
      pcm_config->sampleRate = SampleRate::RATE_48000;
      break;
    case BTAV_A2DP_CODEC_SAMPLE_RATE_88200:
      pcm_config->sampleRate = SampleRate::RATE_88200;
      break;
    case BTAV_A2DP_CODEC_SAMPLE_RATE_96000:
      pcm_config->sampleRate = SampleRate::RATE_96000;
      break;
    case BTAV_A2DP_CODEC_SAMPLE_RATE_176400:
      pcm_config->sampleRate = SampleRate::RATE_176400;
      break;
    case BTAV_A2DP_CODEC_SAMPLE_RATE_192000:
      pcm_config->sampleRate = SampleRate::RATE_192000;
      break;
    case BTAV_A2DP_CODEC_SAMPLE_RATE_16000:
      pcm_config->sampleRate = SampleRate::RATE_16000;
      break;
    case BTAV_A2DP_CODEC_SAMPLE_RATE_24000:
      pcm_config->sampleRate = SampleRate::RATE_24000;
      break;
    case BTAV_A2DP_CODEC_SAMPLE_RATE_NONE:
      pcm_config->sampleRate = SampleRate::RATE_UNKNOWN;
      break;
    default:
      pcm_config->sampleRate = SampleRate::RATE_UNKNOWN;
      break;
  }
  switch (current_codec.bits_per_sample) {
    case BTAV_A2DP_CODEC_BITS_PER_SAMPLE_16:
      pcm_config->bitsPerSample = BitsPerSample::BITS_16;
      break;
    case BTAV_A2DP_CODEC_BITS_PER_SAMPLE_24:
      pcm_config->bitsPerSample = BitsPerSample::BITS_24;
      break;
    case BTAV_A2DP_CODEC_BITS_PER_SAMPLE_32:
      pcm_config->bitsPerSample = BitsPerSample::BITS_32;
      break;
    case BTAV_A2DP_CODEC_BITS_PER_SAMPLE_NONE:
      pcm_config->bitsPerSample = BitsPerSample::BITS_UNKNOWN;
      break;
    default:
      pcm_config->bitsPerSample = BitsPerSample::BITS_UNKNOWN;
      break;
  }
  switch (current_codec.channel_mode) {
    case BTAV_A2DP_CODEC_CHANNEL_MODE_MONO:
      pcm_config->channelMode = ChannelMode::MONO;
      break;
    case BTAV_A2DP_CODEC_CHANNEL_MODE_STEREO:
      pcm_config->channelMode = ChannelMode::STEREO;
      break;
    case BTAV_A2DP_CODEC_CHANNEL_MODE_NONE:
      pcm_config->channelMode = ChannelMode::UNKNOWN;
      break;
    default:
      pcm_config->channelMode = ChannelMode::UNKNOWN;
      break;
  }
  return (pcm_config->sampleRate != SampleRate::RATE_UNKNOWN &&
          pcm_config->bitsPerSample != BitsPerSample::BITS_UNKNOWN &&
          pcm_config->channelMode != ChannelMode::UNKNOWN);
}

}  // namespace

namespace bluetooth {
namespace audio {
namespace a2dp {

// Checking if new bluetooth_audio is supported
bool is_hal_2_0_supported() {
  // we do not support offloading yet
  if (btif_av_is_a2dp_offload_enabled()) return false;
  if (!is_configured) {
    btaudio_a2dp_legacy_supported =
        osi_property_get_bool(BLUETOOTH_AUDIO_PROP_ENABLED, false);
    is_configured = true;
  }
  return btaudio_a2dp_legacy_supported;
}

// Checking if new bluetooth_audio is enabled
bool is_hal_2_0_enabled() { return a2dp_hal_clientif != nullptr; }

// Initialize BluetoothAudio HAL: openProvider
bool init(bluetooth::common::MessageLoopThread* message_loop) {
  LOG(INFO) << __func__;

  if (!is_hal_2_0_supported()) {
    LOG(ERROR) << __func__ << ": BluetoothAudio HAL is not supported";
    return false;
  }

  PcmParameters pcm_config{};
  a2dp_get_selected_hal_pcm_config(&pcm_config);
  AudioConfiguration audio_config{};
  audio_config.pcmConfig(pcm_config);
  a2dp_sink = new A2dpTransport(SessionType::A2DP_SOFTWARE_ENCODING_DATAPATH,
                                audio_config);
  a2dp_hal_clientif = new bluetooth::audio::BluetoothAudioClientInterface(
      a2dp_sink, message_loop);
  if (remote_delay != 0) {
    LOG(INFO) << __func__ << ": restore DELAY "
              << static_cast<float>(remote_delay / 10.0) << " ms";
    a2dp_sink->SetRemoteDelay(remote_delay);
    remote_delay = 0;
  }
  return true;
}

// Clean up BluetoothAudio HAL
void cleanup() {
  if (!is_hal_2_0_enabled()) return;
  end_session();
  delete a2dp_hal_clientif;
  a2dp_hal_clientif = nullptr;
  delete a2dp_sink;
  a2dp_sink = nullptr;
  remote_delay = 0;
}

// Set up the codec into BluetoothAudio HAL
bool setup_codec() {
  if (!is_hal_2_0_supported()) {
    LOG(ERROR) << __func__ << ": BluetoothAudio HAL is not supported";
    return false;
  }
  PcmParameters pcm_config{};
  AudioConfiguration audio_config{};
  if (a2dp_get_selected_hal_pcm_config(&pcm_config)) {
    audio_config.pcmConfig(pcm_config);
    return a2dp_hal_clientif->UpdateAudioConfig(audio_config);
  }
  return false;
}

void start_session() {
  if (!is_hal_2_0_supported()) {
    LOG(ERROR) << __func__ << ": BluetoothAudio HAL is not supported";
    return;
  }
  a2dp_hal_clientif->StartSession();
}

void end_session() {
  if (!is_hal_2_0_supported()) {
    LOG(ERROR) << __func__ << ": BluetoothAudio HAL is not supported";
    return;
  }
  a2dp_hal_clientif->EndSession();
}

void ack_stream_started(const tA2DP_CTRL_ACK& ack) {
  auto ctrl_ack = a2dp_ack_to_bt_audio_ctrl_ack(ack);
  LOG(INFO) << __func__ << ": result=" << ctrl_ack;
  auto pending_cmd = a2dp_sink->GetPendingCmd();
  if (pending_cmd == A2DP_CTRL_CMD_START) {
    a2dp_hal_clientif->StreamStarted(ctrl_ack);
  } else {
    LOG(WARNING) << __func__ << ": pending=" << pending_cmd
                 << " ignore result=" << ctrl_ack;
    return;
  }
  if (ctrl_ack != bluetooth::audio::BluetoothAudioCtrlAck::PENDING) {
    a2dp_sink->ResetPendingCmd();
  }
}

void ack_stream_suspended(const tA2DP_CTRL_ACK& ack) {
  auto ctrl_ack = a2dp_ack_to_bt_audio_ctrl_ack(ack);
  LOG(INFO) << __func__ << ": result=" << ctrl_ack;
  auto pending_cmd = a2dp_sink->GetPendingCmd();
  if (pending_cmd == A2DP_CTRL_CMD_SUSPEND) {
    a2dp_hal_clientif->StreamSuspended(ctrl_ack);
  } else if (pending_cmd == A2DP_CTRL_CMD_STOP) {
    LOG(INFO) << __func__ << ": A2DP_CTRL_CMD_STOP result=" << ctrl_ack;
  } else {
    LOG(WARNING) << __func__ << ": pending=" << pending_cmd
                 << " ignore result=" << ctrl_ack;
    return;
  }
  if (ctrl_ack != bluetooth::audio::BluetoothAudioCtrlAck::PENDING) {
    a2dp_sink->ResetPendingCmd();
  }
}

// Read from the FMQ of BluetoothAudio HAL
size_t read(uint8_t* p_buf, uint32_t len) {
  if (!is_hal_2_0_supported()) {
    LOG(ERROR) << __func__ << ": BluetoothAudio HAL is not supported";
    return 0;
  }
  return a2dp_hal_clientif->ReadAudioData(p_buf, len);
}

// Update A2DP delay report to BluetoothAudio HAL
void set_remote_delay(uint16_t delay_report) {
  if (!is_hal_2_0_enabled()) {
    LOG(INFO) << __func__ << ":  not ready for DelayReport "
              << static_cast<float>(delay_report / 10.0) << " ms";
    remote_delay = delay_report;
    return;
  }
  LOG(INFO) << __func__ << ": DELAY " << static_cast<float>(delay_report / 10.0)
            << " ms";
  a2dp_sink->SetRemoteDelay(delay_report);
}

}  // namespace a2dp
}  // namespace audio
}  // namespace bluetooth
