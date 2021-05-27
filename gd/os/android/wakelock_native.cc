/******************************************************************************
 *
 *  Copyright 2021 Google, Inc.
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

#define LOG_TAG "BtGdWakelockNative"

#include "os/internal/wakelock_native.h"

#include <android/system/suspend/1.0/ISystemSuspend.h>
#include <fcntl.h>
#include <unistd.h>

#include <cerrno>
#include <string>

#include "os/log.h"

namespace bluetooth {
namespace os {
namespace internal {

using android::sp;
using android::system::suspend::V1_0::ISystemSuspend;
using android::system::suspend::V1_0::IWakeLock;
using android::system::suspend::V1_0::WakeLockType;

struct WakelockNative::Impl {
  sp<ISystemSuspend> suspend_service = nullptr;
  sp<IWakeLock> current_wakelock = nullptr;

  class SystemSuspendDeathRecipient : public ::android::hardware::hidl_death_recipient {
   public:
    explicit SystemSuspendDeathRecipient(WakelockNative::Impl* impl) : impl_(impl) {}
    void serviceDied(uint64_t /*cookie*/, const android::wp<::android::hidl::base::V1_0::IBase>& /*who*/) override {
      LOG_ERROR("ISystemSuspend HAL service died!");
      impl_->suspend_service = nullptr;
    }

   private:
    WakelockNative::Impl* impl_ = nullptr;
  };
  sp<SystemSuspendDeathRecipient> suspend_death_recipient;
};

void WakelockNative::Initialize() {
  LOG_INFO("Initializing native wake locks");
  pimpl_->suspend_service = ISystemSuspend::getService();
  ASSERT_LOG(pimpl_->suspend_service, "Cannot get ISystemSuspend service");
  pimpl_->suspend_death_recipient = new Impl::SystemSuspendDeathRecipient(pimpl_.get());
  pimpl_->suspend_service->linkToDeath(pimpl_->suspend_death_recipient, 0 /* cookie */);
}

WakelockNative::StatusCode WakelockNative::Acquire(const std::string& lock_name) {
  if (!pimpl_->suspend_service) {
    LOG_ERROR("lock not acquired, ISystemService is not available");
    return StatusCode::NATIVE_SERVICE_NOT_AVAILABLE;
  }

  if (pimpl_->current_wakelock) {
    LOG_INFO("wakelock is already acquired");
    return StatusCode::SUCCESS;
  }

  pimpl_->current_wakelock = pimpl_->suspend_service->acquireWakeLock(WakeLockType::PARTIAL, lock_name);
  if (!pimpl_->current_wakelock) {
    LOG_ERROR("wake lock not acquired: %s", strerror(errno));
    return StatusCode::NATIVE_API_ERROR;
  }

  return StatusCode::SUCCESS;
}

WakelockNative::StatusCode WakelockNative::Release(const std::string& lock_name) {
  if (!pimpl_->current_wakelock) {
    LOG_WARN("no lock is currently acquired");
    return StatusCode::SUCCESS;
  }
  pimpl_->current_wakelock->release();
  pimpl_->current_wakelock.clear();
  return StatusCode::SUCCESS;
}

void WakelockNative::CleanUp() {
  LOG_INFO("Cleaning up native wake locks");
  if (pimpl_->current_wakelock) {
    LOG_INFO("releasing current wakelock during clean up");
    pimpl_->current_wakelock->release();
    pimpl_->current_wakelock.clear();
  }
  if (pimpl_->suspend_service) {
    LOG_INFO("Unlink death recipient");
    pimpl_->suspend_service->unlinkToDeath(pimpl_->suspend_death_recipient);
    pimpl_->suspend_death_recipient.clear();
    pimpl_->suspend_service.clear();
  }
}

WakelockNative::WakelockNative() : pimpl_(std::make_unique<Impl>()) {}

WakelockNative::~WakelockNative() = default;

}  // namespace internal
}  // namespace os
}  // namespace bluetooth