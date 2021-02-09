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

#include <android/hardware/bluetooth/audio/2.1/IBluetoothAudioProvidersFactory.h>
#include <android/hardware/bluetooth/audio/2.1/types.h>
#include <android/hidl/manager/1.2/IServiceManager.h>
#include <base/logging.h>
#include <hidl/ServiceManagement.h>

namespace bluetooth {
namespace audio {

using ::android::hardware::hidl_vec;

using IBluetoothAudioProvidersFactory_2_0 = ::android::hardware::bluetooth::
    audio::V2_0::IBluetoothAudioProvidersFactory;
using IBluetoothAudioProvidersFactory_2_1 = ::android::hardware::bluetooth::
    audio::V2_1::IBluetoothAudioProvidersFactory;

constexpr char kFullyQualifiedInterfaceName_2_0[] =
    "android.hardware.bluetooth.audio@2.0::IBluetoothAudioProvidersFactory";
constexpr char kFullyQualifiedInterfaceName_2_1[] =
    "android.hardware.bluetooth.audio@2.1::IBluetoothAudioProvidersFactory";

enum class BluetoothAudioHalVersion : uint8_t {
  VERSION_2_0 = 0,
  VERSION_2_1,
  VERSION_UNAVAILABLE,
};

class HalVersionManager {
 public:
  static BluetoothAudioHalVersion GetHalVersion() {
    std::lock_guard<std::mutex> guard(instance_ptr->mutex_);
    if (instance_ptr->providersFactory_2_1) {
      return BluetoothAudioHalVersion::VERSION_2_1;
    } else if (instance_ptr->providersFactory) {
      return BluetoothAudioHalVersion::VERSION_2_0;
    }
    return BluetoothAudioHalVersion::VERSION_UNAVAILABLE;
  }

  static android::sp<IBluetoothAudioProvidersFactory_2_1>
  GetProviderFactory_2_1() {
    std::lock_guard<std::mutex> guard(instance_ptr->mutex_);
    return instance_ptr->providersFactory_2_1;
  }

  static android::sp<IBluetoothAudioProvidersFactory_2_0>
  GetProviderFactory_2_0() {
    std::lock_guard<std::mutex> guard(instance_ptr->mutex_);
    if (instance_ptr->providersFactory_2_1)
      return instance_ptr->providersFactory_2_1;

    return instance_ptr->providersFactory;
  }

  HalVersionManager() {
    auto service_manager = android::hardware::defaultServiceManager1_2();
    CHECK(service_manager != nullptr);
    size_t instance_count = 0;
    auto listManifestByInterface_cb =
        [&instance_count](
            const hidl_vec<android::hardware::hidl_string>& instanceNames) {
          instance_count = instanceNames.size();
        };
    auto hidl_retval = service_manager->listManifestByInterface(
        kFullyQualifiedInterfaceName_2_1, listManifestByInterface_cb);
    if (!hidl_retval.isOk()) {
      LOG(FATAL) << __func__ << ": IServiceManager::listByInterface failure: "
                 << hidl_retval.description();
      return;
    }

    if (instance_count > 0) {
      providersFactory_2_1 = IBluetoothAudioProvidersFactory_2_1::getService();
      CHECK(providersFactory_2_1)
          << "V2_1::IBluetoothAudioProvidersFactory::getService() failed";

      LOG(INFO)
          << "V2_1::IBluetoothAudioProvidersFactory::getService() returned "
          << providersFactory_2_1.get()
          << (providersFactory_2_1->isRemote() ? " (remote)" : " (local)");
      return;
    }

    hidl_retval = service_manager->listManifestByInterface(
        kFullyQualifiedInterfaceName_2_0, listManifestByInterface_cb);
    if (!hidl_retval.isOk()) {
      LOG(FATAL) << __func__ << ": IServiceManager::listByInterface failure: "
                 << hidl_retval.description();
      return;
    }

    if (instance_count > 0) {
      providersFactory = IBluetoothAudioProvidersFactory_2_0::getService();
      CHECK(providersFactory)
          << "V2_0::IBluetoothAudioProvidersFactory::getService() failed";

      LOG(INFO)
          << "V2_0::IBluetoothAudioProvidersFactory::getService() returned "
          << providersFactory.get()
          << (providersFactory->isRemote() ? " (remote)" : " (local)");
      return;
    }

    LOG(FATAL) << __func__ << " No supported HAL version";
  }

 private:
  static std::unique_ptr<HalVersionManager> instance_ptr;
  std::mutex mutex_;

  android::sp<IBluetoothAudioProvidersFactory_2_0> providersFactory;
  android::sp<IBluetoothAudioProvidersFactory_2_1> providersFactory_2_1;
};

}  // namespace audio
}  // namespace bluetooth
