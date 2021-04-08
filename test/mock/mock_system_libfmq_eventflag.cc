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
 *   Functions generated:11
 */

#include <map>
#include <string>

extern std::map<std::string, int> mock_function_count_map;

#include <fmq/EventFlag.h>

using namespace android;
using namespace android::hardware;

namespace android {
namespace hardware {
namespace details {

void logError(const std::string& message) {}

}  // namespace details
}  // namespace hardware
}  // namespace android

#if 0
#include <linux/futex.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <utils/Log.h>
#include <utils/SystemClock.h>
#include <new>
#endif

#ifndef UNUSED_ATTR
#define UNUSED_ATTR
#endif

EventFlag::EventFlag(int fd, off_t offset, status_t* status) {
  mock_function_count_map[__func__]++;
}
EventFlag::EventFlag(std::atomic<uint32_t>* fwAddr, status_t* status) {
  mock_function_count_map[__func__]++;
}
EventFlag::~EventFlag() { mock_function_count_map[__func__]++; }
status_t EventFlag::createEventFlag(int fd, off_t offset, EventFlag** flag) {
  mock_function_count_map[__func__]++;
  return 0;
}
status_t EventFlag::createEventFlag(std::atomic<uint32_t>* fwAddr,
                                    EventFlag** flag) {
  mock_function_count_map[__func__]++;
  return 0;
}
status_t EventFlag::deleteEventFlag(EventFlag** evFlag) {
  mock_function_count_map[__func__]++;
  return 0;
}
status_t EventFlag::unmapEventFlagWord(std::atomic<uint32_t>* efWordPtr,
                                       bool* efWordNeedsUnmapping) {
  mock_function_count_map[__func__]++;
  return 0;
}
status_t EventFlag::wait(uint32_t bitmask, uint32_t* efState,
                         int64_t timeoutNanoSeconds, bool retry) {
  mock_function_count_map[__func__]++;
  return 0;
}
status_t EventFlag::waitHelper(uint32_t bitmask, uint32_t* efState,
                               int64_t timeoutNanoSeconds) {
  mock_function_count_map[__func__]++;
  return 0;
}
status_t EventFlag::wake(uint32_t bitmask) {
  mock_function_count_map[__func__]++;
  return 0;
}
void EventFlag::addNanosecondsToCurrentTime(int64_t nanoSeconds,
                                            struct timespec* waitTime) {
  mock_function_count_map[__func__]++;
}
