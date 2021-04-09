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

#include <functional>

#include "common/message_loop_thread.h"

namespace bluetooth {
namespace audio {
namespace le_audio {

struct StreamCallbacks {
  std::function<bool(bool start_media_task)> on_resume_;
  std::function<bool(void)> on_suspend_;
};

class LeAudioClientInterface {
 public:
  struct PcmParameters {
    uint32_t data_interval_us;
    uint32_t sample_rate;
    uint8_t bits_per_sample;
    uint8_t channels_count;
  };

 private:
  class IClientInterfaceEndpoint {
   public:
    virtual ~IClientInterfaceEndpoint() = default;
    virtual void Cleanup() = 0;
    virtual void SetPcmParameters(const PcmParameters& params) = 0;
    virtual void SetRemoteDelay(uint16_t delay_report_ms) = 0;
    virtual void StartSession() = 0;
    virtual void StopSession() = 0;
  };

 public:
  class Sink : public IClientInterfaceEndpoint {
   public:
    virtual ~Sink() = default;

    void Cleanup() override;
    void SetPcmParameters(const PcmParameters& params) override;
    void SetRemoteDelay(uint16_t delay_report_ms) override;
    void StartSession() override;
    void StopSession() override;

    // Read the stream of bytes sinked to us by the upper layers
    size_t Read(uint8_t* p_buf, uint32_t len);
  };
  class Source : public IClientInterfaceEndpoint {
   public:
    virtual ~Source() = default;

    void Cleanup() override;
    void SetPcmParameters(const PcmParameters& params) override;
    void SetRemoteDelay(uint16_t delay_report_ms) override;
    void StartSession() override;
    void StopSession() override;

    // Source the given stream of bytes to be sinked into the upper layers
    size_t Write(const uint8_t* p_buf, uint32_t len);
  };

  // Get LE Audio sink client interface if it's not previously acquired and not
  // yet released.
  Sink* GetSink(StreamCallbacks stream_cb,
                bluetooth::common::MessageLoopThread* message_loop);
  // This should be called before trying to get sink interface
  bool IsSinkAcquired();
  // Release sink interface if belongs to LE audio client interface
  bool ReleaseSink(Sink* sink);

  // Get LE Audio source client interface if it's not previously acquired and
  // not yet released.
  Source* GetSource(StreamCallbacks stream_cb,
                    bluetooth::common::MessageLoopThread* message_loop);
  // This should be called before trying to get source interface
  bool IsSourceAcquired();
  // Release source interface if belongs to LE audio client interface
  bool ReleaseSource(Source* source);

  // Get interface, if previously not initialized - it'll initialize singleton.
  static LeAudioClientInterface* Get();

 private:
  static LeAudioClientInterface* interface;
  Sink* sink_ = nullptr;
  Source* source_ = nullptr;
};

}  // namespace le_audio
}  // namespace audio
}  // namespace bluetooth
