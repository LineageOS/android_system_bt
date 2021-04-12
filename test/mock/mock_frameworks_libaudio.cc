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
 *   Functions generated:60
 */

#include <map>
#include <string>

extern std::map<std::string, int> mock_function_count_map;

#undef __INTRODUCED_IN
#define __INTRODUCED_IN(x)

#include <aaudio/AAudio.h>
#include <aaudio/AAudioTesting.h>

#ifndef UNUSED_ATTR
#define UNUSED_ATTR
#endif

aaudio_allowed_capture_policy_t AAudioStream_getAllowedCapturePolicy(
    AAudioStream* stream) {
  mock_function_count_map[__func__]++;
  return 0;
}
aaudio_content_type_t AAudioStream_getContentType(AAudioStream* stream) {
  mock_function_count_map[__func__]++;
  return 0;
}
aaudio_direction_t AAudioStream_getDirection(AAudioStream* stream) {
  mock_function_count_map[__func__]++;
  return 0;
}
aaudio_format_t AAudioStream_getFormat(AAudioStream* stream) {
  mock_function_count_map[__func__]++;
  return 0;
}
aaudio_input_preset_t AAudioStream_getInputPreset(AAudioStream* stream) {
  mock_function_count_map[__func__]++;
  return 0;
}
aaudio_performance_mode_t AAudioStream_getPerformanceMode(
    AAudioStream* stream) {
  mock_function_count_map[__func__]++;
  return 0;
}
aaudio_policy_t AAudio_getMMapPolicy() {
  mock_function_count_map[__func__]++;
  return 0;
}
aaudio_result_t AAudioStreamBuilder_delete(AAudioStreamBuilder* builder) {
  mock_function_count_map[__func__]++;
  return 0;
}
aaudio_result_t AAudioStreamBuilder_openStream(AAudioStreamBuilder* builder,
                                               AAudioStream** streamPtr) {
  mock_function_count_map[__func__]++;
  return 0;
}
aaudio_result_t AAudioStream_close(AAudioStream* stream) {
  mock_function_count_map[__func__]++;
  return 0;
}
aaudio_result_t AAudioStream_getTimestamp(AAudioStream* stream,
                                          clockid_t clockid,
                                          int64_t* framePosition,
                                          int64_t* timeNanoseconds) {
  mock_function_count_map[__func__]++;
  return 0;
}
aaudio_result_t AAudioStream_read(AAudioStream* stream, void* buffer,
                                  int32_t numFrames,
                                  int64_t timeoutNanoseconds) {
  mock_function_count_map[__func__]++;
  return 0;
}
aaudio_result_t AAudioStream_release(AAudioStream* stream) {
  mock_function_count_map[__func__]++;
  return 0;
}
aaudio_result_t AAudioStream_requestFlush(AAudioStream* stream) {
  mock_function_count_map[__func__]++;
  return 0;
}
aaudio_result_t AAudioStream_requestPause(AAudioStream* stream) {
  mock_function_count_map[__func__]++;
  return 0;
}
aaudio_result_t AAudioStream_requestStart(AAudioStream* stream) {
  mock_function_count_map[__func__]++;
  return 0;
}
aaudio_result_t AAudioStream_requestStop(AAudioStream* stream) {
  mock_function_count_map[__func__]++;
  return 0;
}
aaudio_result_t AAudioStream_setBufferSizeInFrames(AAudioStream* stream,
                                                   int32_t requestedFrames) {
  mock_function_count_map[__func__]++;
  return 0;
}
aaudio_result_t AAudioStream_waitForStateChange(
    AAudioStream* stream, aaudio_stream_state_t inputState,
    aaudio_stream_state_t* nextState, int64_t timeoutNanoseconds) {
  mock_function_count_map[__func__]++;
  return 0;
}
aaudio_result_t AAudioStream_write(AAudioStream* stream, const void* buffer,
                                   int32_t numFrames,
                                   int64_t timeoutNanoseconds) {
  mock_function_count_map[__func__]++;
  return 0;
}
aaudio_result_t AAudio_createStreamBuilder(AAudioStreamBuilder** builder) {
  mock_function_count_map[__func__]++;
  return 0;
}
aaudio_result_t AAudio_setMMapPolicy(aaudio_policy_t policy) {
  mock_function_count_map[__func__]++;
  return 0;
}
aaudio_sharing_mode_t AAudioStream_getSharingMode(AAudioStream* stream) {
  mock_function_count_map[__func__]++;
  return 0;
}
aaudio_stream_state_t AAudioStream_getState(AAudioStream* stream) {
  mock_function_count_map[__func__]++;
  return 0;
}
aaudio_usage_t AAudioStream_getUsage(AAudioStream* stream) {
  mock_function_count_map[__func__]++;
  return 0;
}
bool AAudioStream_isMMapUsed(AAudioStream* stream) {
  mock_function_count_map[__func__]++;
  return false;
}
bool AAudioStream_isPrivacySensitive(AAudioStream* stream) {
  mock_function_count_map[__func__]++;
  return false;
}
const char* AAudio_convertResultToText(aaudio_result_t returnCode) {
  mock_function_count_map[__func__]++;
  return nullptr;
}
const char* AAudio_convertStreamStateToText(aaudio_stream_state_t state) {
  mock_function_count_map[__func__]++;
  return nullptr;
}
int32_t AAudioStream_getBufferCapacityInFrames(AAudioStream* stream) {
  mock_function_count_map[__func__]++;
  return 0;
}
int32_t AAudioStream_getBufferSizeInFrames(AAudioStream* stream) {
  mock_function_count_map[__func__]++;
  return 0;
}
int32_t AAudioStream_getChannelCount(AAudioStream* stream) {
  mock_function_count_map[__func__]++;
  return 0;
}
int32_t AAudioStream_getDeviceId(AAudioStream* stream) {
  mock_function_count_map[__func__]++;
  return 0;
}
int32_t AAudioStream_getFramesPerBurst(AAudioStream* stream) {
  mock_function_count_map[__func__]++;
  return 0;
}
int32_t AAudioStream_getFramesPerDataCallback(AAudioStream* stream) {
  mock_function_count_map[__func__]++;
  return 0;
}
int32_t AAudioStream_getSampleRate(AAudioStream* stream) {
  mock_function_count_map[__func__]++;
  return 0;
}
int32_t AAudioStream_getSamplesPerFrame(AAudioStream* stream) {
  mock_function_count_map[__func__]++;
  return 0;
}
int32_t AAudioStream_getSessionId(AAudioStream* stream) {
  mock_function_count_map[__func__]++;
  return 0;
}
int32_t AAudioStream_getXRunCount(AAudioStream* stream) {
  mock_function_count_map[__func__]++;
  return 0;
}
int64_t AAudioStream_getFramesRead(AAudioStream* stream) {
  mock_function_count_map[__func__]++;
  return 0;
}
int64_t AAudioStream_getFramesWritten(AAudioStream* stream) {
  mock_function_count_map[__func__]++;
  return 0;
}
void AAudioStreamBuilder_setAllowedCapturePolicy(
    AAudioStreamBuilder* builder, aaudio_allowed_capture_policy_t policy) {
  mock_function_count_map[__func__]++;
  return;
}
void AAudioStreamBuilder_setBufferCapacityInFrames(AAudioStreamBuilder* builder,
                                                   int32_t frames) {
  mock_function_count_map[__func__]++;
  return;
}
void AAudioStreamBuilder_setChannelCount(AAudioStreamBuilder* builder,
                                         int32_t channelCount) {
  mock_function_count_map[__func__]++;
  return;
}
void AAudioStreamBuilder_setContentType(AAudioStreamBuilder* builder,
                                        aaudio_content_type_t contentType) {
  mock_function_count_map[__func__]++;
  return;
}
void AAudioStreamBuilder_setDataCallback(AAudioStreamBuilder* builder,
                                         AAudioStream_dataCallback callback,
                                         void* userData) {
  mock_function_count_map[__func__]++;
  return;
}
void AAudioStreamBuilder_setDeviceId(AAudioStreamBuilder* builder,
                                     int32_t deviceId) {
  mock_function_count_map[__func__]++;
  return;
}
void AAudioStreamBuilder_setDirection(AAudioStreamBuilder* builder,
                                      aaudio_direction_t direction) {
  mock_function_count_map[__func__]++;
  return;
}
void AAudioStreamBuilder_setErrorCallback(AAudioStreamBuilder* builder,
                                          AAudioStream_errorCallback callback,
                                          void* userData) {
  mock_function_count_map[__func__]++;
  return;
}
void AAudioStreamBuilder_setFormat(AAudioStreamBuilder* builder,
                                   aaudio_format_t format) {
  mock_function_count_map[__func__]++;
  return;
}
void AAudioStreamBuilder_setFramesPerDataCallback(AAudioStreamBuilder* builder,
                                                  int32_t frames) {
  mock_function_count_map[__func__]++;
  return;
}
void AAudioStreamBuilder_setInputPreset(AAudioStreamBuilder* builder,
                                        aaudio_input_preset_t inputPreset) {
  mock_function_count_map[__func__]++;
  return;
}
void AAudioStreamBuilder_setPerformanceMode(AAudioStreamBuilder* builder,
                                            aaudio_performance_mode_t mode) {
  mock_function_count_map[__func__]++;
  return;
}
void AAudioStreamBuilder_setPrivacySensitive(AAudioStreamBuilder* builder,
                                             bool privacySensitive) {
  mock_function_count_map[__func__]++;
  return;
}
void AAudioStreamBuilder_setSampleRate(AAudioStreamBuilder* builder,
                                       int32_t sampleRate) {
  mock_function_count_map[__func__]++;
  return;
}
void AAudioStreamBuilder_setSamplesPerFrame(AAudioStreamBuilder* builder,
                                            int32_t samplesPerFrame) {
  mock_function_count_map[__func__]++;
  return;
}
void AAudioStreamBuilder_setSessionId(AAudioStreamBuilder* builder,
                                      aaudio_session_id_t sessionId) {
  mock_function_count_map[__func__]++;
  return;
}
void AAudioStreamBuilder_setSharingMode(AAudioStreamBuilder* builder,
                                        aaudio_sharing_mode_t sharingMode) {
  mock_function_count_map[__func__]++;
  return;
}
void AAudioStreamBuilder_setUsage(AAudioStreamBuilder* builder,
                                  aaudio_usage_t usage) {
  mock_function_count_map[__func__]++;
  return;
}
