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

#include <cstdint>

#include <android/hardware/bluetooth/a2dp/1.0/IBluetoothAudioHost.h>

namespace android {
namespace hardware {
namespace bluetooth {

namespace a2dp {
namespace V1_0 {
class BluetoothAudioHost : public IBluetoothAudioHost {
  ::android::hardware::Return<void> setHALInstrumentation() { return Void(); }
  ::android::hardware::Return<bool> linkToDeath(
      android::sp<android::hardware::hidl_death_recipient> const&, uint64_t) {
    return false;
  }
  ::android::hardware::Return<void> ping() { return Void(); }
  ::android::hardware::Return<void> getDebugInfo(
      std::__1::function<void(android::hidl::base::V1_0::DebugInfo const&)>) {
    return Void();
  }
  ::android::hardware::Return<void> notifySyspropsChanged() { return Void(); }
  ::android::hardware::Return<bool> unlinkToDeath(
      android::sp<android::hardware::hidl_death_recipient> const&) {
    return false;
  }
};

}  // namespace V1_0
}  // namespace a2dp

namespace audio {

namespace V2_0 {

class AudioConfiguration {
  AudioConfiguration() {}
};

}  // namespace V2_0

}  // namespace audio
}  // namespace bluetooth
}  // namespace hardware
}  // namespace android
