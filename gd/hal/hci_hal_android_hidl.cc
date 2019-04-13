/*
 * Copyright 2019 The Android Open Source Project
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

#include "hal/hci_hal.h"

#include <stdlib.h>
#include <vector>

#include <android/hardware/bluetooth/1.0/IBluetoothHci.h>
#include <android/hardware/bluetooth/1.0/IBluetoothHciCallbacks.h>
#include <android/hardware/bluetooth/1.0/types.h>

#include "os/log.h"

using ::android::hardware::hidl_vec;
using ::android::hardware::Return;
using ::android::hardware::Void;
using ::android::hardware::bluetooth::V1_0::IBluetoothHci;
using ::android::hardware::bluetooth::V1_0::IBluetoothHciCallbacks;
using HidlStatus = ::android::hardware::bluetooth::V1_0::Status;

namespace bluetooth {
namespace hal {
namespace {
class BluetoothHciDeathRecipient : public ::android::hardware::hidl_death_recipient {
 public:
  virtual void serviceDied(uint64_t /*cookie*/, const android::wp<::android::hidl::base::V1_0::IBase>& /*who*/) {
    LOG_ERROR("Bluetooth HAL service died!");
    abort();
  }
};

android::sp<BluetoothHciDeathRecipient> bluetooth_hci_death_recipient_ = new BluetoothHciDeathRecipient();

class HciHalBluetoothHciCallbacks : public IBluetoothHciCallbacks {
 public:
  HciHalBluetoothHciCallbacks(BluetoothInitializationCompleteCallback* initialization_callback)
      : initialization_callback_(initialization_callback) {}

  void SetCallback(BluetoothHciHalCallbacks* callback) {
    ASSERT(callback_ == nullptr && callback != nullptr);
    callback_ = callback;
  }

  void ResetCallback() {
    callback_ = nullptr;
  }

  Return<void> initializationComplete(HidlStatus status) {
    ASSERT(status == HidlStatus::SUCCESS);
    initialization_callback_->initializationComplete(Status::SUCCESS);
    return Void();
  }

  Return<void> hciEventReceived(const hidl_vec<uint8_t>& event) {
    if (callback_ != nullptr) {
      callback_->hciEventReceived(std::vector<uint8_t>(event.begin(), event.end()));
    }
    return Void();
  }

  Return<void> aclDataReceived(const hidl_vec<uint8_t>& data) {
    if (callback_ != nullptr) {
      callback_->aclDataReceived(std::vector<uint8_t>(data.begin(), data.end()));
    }
    return Void();
  }

  Return<void> scoDataReceived(const hidl_vec<uint8_t>& data) {
    if (callback_ != nullptr) {
      callback_->scoDataReceived(std::vector<uint8_t>(data.begin(), data.end()));
    }
    return Void();
  }

 private:
  BluetoothInitializationCompleteCallback* initialization_callback_ = nullptr;
  BluetoothHciHalCallbacks* callback_ = nullptr;
};

}  // namespace

class BluetoothHciHalHidl : public BluetoothHciHal {
 public:
  void initialize(BluetoothInitializationCompleteCallback* callback) override {
    bt_hci_ = IBluetoothHci::getService();
    ASSERT(bt_hci_ != nullptr);
    auto death_link = bt_hci_->linkToDeath(bluetooth_hci_death_recipient_, 0);
    ASSERT_LOG(death_link.isOk(), "Unable to set the death recipient for the Bluetooth HAL");

    // Block allows allocation of a variable that might be bypassed by goto.
    {
      callbacks_ = new HciHalBluetoothHciCallbacks(callback);
      bt_hci_->initialize(callbacks_);
    }
  }

  void registerIncomingPacketCallback(BluetoothHciHalCallbacks* callback) override {
    callbacks_->SetCallback(callback);
  }

  void sendHciCommand(HciPacket command) override {
    bt_hci_->sendHciCommand(command);
  }

  void sendAclData(HciPacket packet) override {
    bt_hci_->sendAclData(packet);
  }

  void sendScoData(HciPacket packet) override {
    bt_hci_->sendScoData(packet);
  }

  void close() override {
    ASSERT(bt_hci_ != nullptr);
    auto death_unlink = bt_hci_->unlinkToDeath(bluetooth_hci_death_recipient_);
    if (!death_unlink.isOk()) {
      LOG_ERROR("Error unlinking death recipient from the Bluetooth HAL");
    }
    bt_hci_->close();
    callbacks_->ResetCallback();
    bt_hci_ = nullptr;
  }

 private:
  android::sp<HciHalBluetoothHciCallbacks> callbacks_;
  android::sp<IBluetoothHci> bt_hci_;
};

BluetoothHciHal* GetBluetoothHciHal() {
  static auto* instance = new BluetoothHciHalHidl;
  return instance;
}

}  // namespace hal
}  // namespace bluetooth
