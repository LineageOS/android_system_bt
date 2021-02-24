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

#define LOG_TAG "btaa"

#include "btaa/activity_attribution.h"

#include <aidl/android/system/suspend/BnSuspendCallback.h>
#include <aidl/android/system/suspend/BnWakelockCallback.h>
#include <aidl/android/system/suspend/ISuspendControlService.h>
#include <android/binder_manager.h>

#include "module.h"
#include "os/log.h"

using aidl::android::system::suspend::BnSuspendCallback;
using aidl::android::system::suspend::BnWakelockCallback;
using aidl::android::system::suspend::ISuspendCallback;
using aidl::android::system::suspend::ISuspendControlService;
using Status = ::ndk::ScopedAStatus;
using namespace ndk;

namespace bluetooth {
namespace activity_attribution {

const ModuleFactory ActivityAttribution::Factory = ModuleFactory([]() { return new ActivityAttribution(); });

static const std::string kBtWakelockName("hal_bluetooth_lock");

struct wakelock_callback : public BnWakelockCallback {
  wakelock_callback(ActivityAttribution* module) : module_(module) {}

  Status notifyAcquired() override {
    return Status::ok();
  }
  Status notifyReleased() override {
    return Status::ok();
  }

  ActivityAttribution* module_;
};

struct wakeup_callback : public BnSuspendCallback {
  wakeup_callback(ActivityAttribution* module) : module_(module) {}

  Status notifyWakeup(bool success, const std::vector<std::string>& wakeup_reasons) override {
    return Status::ok();
  }

  ActivityAttribution* module_;
};

struct ActivityAttribution::impl {
  impl(ActivityAttribution* module) {
    bool is_registered = false;

    auto control_service =
        ISuspendControlService::fromBinder(SpAIBinder(AServiceManager_getService("suspend_control")));
    if (!control_service) {
      LOG_ERROR("Fail to obtain suspend_control");
      return;
    }

    Status register_callback_status =
        control_service->registerCallback(SharedRefBase::make<wakeup_callback>(module), &is_registered);
    if (!is_registered || !register_callback_status.isOk()) {
      LOG_ERROR("Fail to register wakeup callback");
      return;
    }

    register_callback_status = control_service->registerWakelockCallback(
        SharedRefBase::make<wakelock_callback>(module), kBtWakelockName, &is_registered);
    if (!is_registered || !register_callback_status.isOk()) {
      LOG_ERROR("Fail to register wakelock callback");
      return;
    }
  }

  void on_hci_packet(hal::HciPacket packet, hal::SnoopLogger::PacketType type, uint16_t length) {}

  void register_callback(ActivityAttributionCallback* callback) {
    callback_ = callback;
  }

  ActivityAttributionCallback* callback_;
};

void ActivityAttribution::Capture(const hal::HciPacket& packet, hal::SnoopLogger::PacketType type) {
  uint16_t original_length = packet.size();
  uint16_t truncate_length;

  switch (type) {
    case hal::SnoopLogger::PacketType::CMD:
    case hal::SnoopLogger::PacketType::EVT:
      truncate_length = packet.size();
      break;
    case hal::SnoopLogger::PacketType::ACL:
    case hal::SnoopLogger::PacketType::SCO:
    case hal::SnoopLogger::PacketType::ISO:
      truncate_length = 0;
      break;
  }

  if (!truncate_length) {
    return;
  }

  hal::HciPacket truncate_packet(packet.begin(), packet.begin() + truncate_length);
  CallOn(pimpl_.get(), &impl::on_hci_packet, truncate_packet, type, original_length);
}

void ActivityAttribution::RegisterActivityAttributionCallback(ActivityAttributionCallback* callback) {
  CallOn(pimpl_.get(), &impl::register_callback, callback);
}

std::string ActivityAttribution::ToString() const {
  return "Btaa Module";
}

void ActivityAttribution::ListDependencies(ModuleList* list) {}

void ActivityAttribution::Start() {
  pimpl_ = std::make_unique<impl>(this);
}

void ActivityAttribution::Stop() {
  pimpl_.reset();
}

}  // namespace activity_attribution
}  // namespace bluetooth
