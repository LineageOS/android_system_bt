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

#include "btsnoop_mem.h"

using aidl::android::system::suspend::ISuspendCallback;
using aidl::android::system::suspend::ISuspendControlService;
using namespace ndk;

namespace bluetooth {
namespace activity_attribution {

static const std::string kBtWakelockName("hal_bluetooth_lock");

class ActivityAttributionImpl;
static std::shared_ptr<ISuspendControlService> controlService;
static std::unique_ptr<ActivityAttributionImpl> instance;

class ActivityAttributionImpl : public ActivityAttribution {
 public:
  ~ActivityAttributionImpl() override = default;
  ActivityAttributionImpl(ActivityAttributionCallbacks* callbacks);

  static void onHciCaptured(const uint16_t type, const uint8_t* data,
                            const size_t length, const uint64_t timestamp_us);
  void onWakelockAcquired(void);
  void onWakelockReleased(void);
  void onWakeup(bool success, const std::vector<std::string>& wakeupReasons);

 private:
  [[maybe_unused]] ActivityAttributionCallbacks* mCallbacks;
};

ActivityAttributionImpl::ActivityAttributionImpl(
    ActivityAttributionCallbacks* callbacks)
    : mCallbacks(callbacks) {}

void ActivityAttributionImpl::onHciCaptured(const uint16_t type,
                                            const uint8_t* data,
                                            const size_t length,
                                            const uint64_t timestamp_us) {}

void ActivityAttributionImpl::onWakelockAcquired(void) {}

void ActivityAttributionImpl::onWakelockReleased(void) {}

void ActivityAttributionImpl::onWakeup(
    bool success, const std::vector<std::string>& wakeupReasons) {}

Status WakelockCallback::notifyAcquired(void) {
  if (instance) {
    instance->onWakelockAcquired();
  }
  return Status::ok();
}

Status WakelockCallback::notifyReleased(void) {
  if (instance) {
    instance->onWakelockReleased();
  }
  return Status::ok();
}

Status WakeupCallback::notifyWakeup(
    bool success, const std::vector<std::string>& wakeupReasons) {
  if (instance) {
    instance->onWakeup(success, wakeupReasons);
  }
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

  activity_attribution_set_callback(instance->onHciCaptured);

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

  register_callback_status = controlService->registerWakelockCallback(
      SharedRefBase::make<WakelockCallback>(), kBtWakelockName, &is_registered);
  if (!is_registered || !register_callback_status.isOk()) {
    LOG(ERROR) << __func__ << " Fail to register wakelock callback";
    return;
  }
}

}  // namespace activity_attribution
}  // namespace bluetooth
