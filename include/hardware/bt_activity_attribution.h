/*
 * Copyright 2020 The Android Open Source Project
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

#ifndef ANDROID_INCLUDE_BT_ACTIVITY_ATTRIBUTION_H
#define ANDROID_INCLUDE_BT_ACTIVITY_ATTRIBUTION_H

#include "raw_address.h"

namespace bluetooth {
namespace activity_attribution {

class ActivityAttributionCallbacks {
 public:
  enum class Activity : uint8_t {
    UNKNOWN = 0,
    ADVERTISE,
    CONNECT,
    CONTROL,
    SCAN,
    HFP,
    VENDOR
  };

  virtual ~ActivityAttributionCallbacks() = default;

  /** Callback when Blutooth woke up the system */
  virtual void OnWakeup(const Activity activity, const RawAddress& address) = 0;
};

class ActivityAttributionInterface {
 public:
  virtual ~ActivityAttributionInterface() = default;

  /** Init the interface. */
  virtual void Init(void) = 0;

  /** Register JNI callbacks with the interface. */
  virtual void RegisterCallbacks(ActivityAttributionCallbacks* callbacks) = 0;

  /** Closes the interface. */
  virtual void Cleanup(void) = 0;
};

}  // namespace activity_attribution
}  // namespace bluetooth

#endif /* ANDROID_INCLUDE_BT_ACTIVITY_ATTRIBUTION_H */
