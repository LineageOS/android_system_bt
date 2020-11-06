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

#include "activity_attribution.h"

#include <aidl/android/system/suspend/ISuspendControlService.h>
#include <android/binder_manager.h>
#include <base/logging.h>

using aidl::android::system::suspend::ISuspendCallback;
using aidl::android::system::suspend::ISuspendControlService;
using namespace ndk;

namespace bluetooth {
namespace activity_attribution {

class ActivityAttributionImpl;
static std::shared_ptr<ISuspendControlService> controlService;
static std::unique_ptr<ActivityAttributionImpl> instance;

class ActivityAttributionImpl : public ActivityAttribution {
 public:
  ~ActivityAttributionImpl() override = default;
  ActivityAttributionImpl(ActivityAttributionCallbacks* callbacks);

  void onWakeup(bool success, const std::vector<std::string>& wakeupReasons);

 private:
  [[maybe_unused]] ActivityAttributionCallbacks* mCallbacks;
};

ActivityAttributionImpl::ActivityAttributionImpl(
    ActivityAttributionCallbacks* callbacks)
    : mCallbacks(callbacks) {}

void ActivityAttributionImpl::onWakeup(
    bool success, const std::vector<std::string>& wakeupReasons) {}

Status WakeupCallback::notifyWakeup(
    bool success, const std::vector<std::string>& wakeupReasons) {
  instance->onWakeup(success, wakeupReasons);
  return Status::ok();
}

void ActivityAttribution::CleanUp() { instance.reset(); };

void ActivityAttribution::Initialize(ActivityAttributionCallbacks* callbacks) {
  bool is_registered = false;

  if (instance) {
    LOG(ERROR) << __func__ << " Already initialized!";
    return;
  }
  instance.reset(new ActivityAttributionImpl(callbacks));

  controlService = ISuspendControlService::fromBinder(
      SpAIBinder(AServiceManager_getService("suspend_control")));
  if (!controlService) {
    LOG(ERROR) << __func__ << " Fail to obtain suspend_control";
    return;
  }

  Status register_callback_status = controlService->registerCallback(
      SharedRefBase::make<WakeupCallback>(), &is_registered);
  if (!is_registered || !register_callback_status.isOk()) {
    LOG(ERROR) << __func__ << " Fail to register wakeup callback";
    return;
  }
}

}  // namespace activity_attribution
}  // namespace bluetooth
