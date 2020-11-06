/******************************************************************************
 *
 *  Copyright 2020 The Android Open Source Project
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at:
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 ******************************************************************************/

#pragma once

#include <aidl/android/system/suspend/BnSuspendCallback.h>
#include <hardware/bt_activity_attribution.h>

using aidl::android::system::suspend::BnSuspendCallback;
using Status = ::ndk::ScopedAStatus;

namespace bluetooth {
namespace activity_attribution {
class ActivityAttribution {
 public:
  virtual ~ActivityAttribution() = default;

  static void CleanUp();
  static void Initialize(ActivityAttributionCallbacks* callbacks);
};

class WakeupCallback : public BnSuspendCallback {
 public:
  Status notifyWakeup(bool success,
                      const std::vector<std::string>& wakeupReasons) override;
};

}  // namespace activity_attribution
}  // namespace bluetooth
