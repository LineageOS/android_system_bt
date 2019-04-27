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
#include <future>

#include <android/hardware/bluetooth/1.0/IBluetoothHci.h>
#include <android/hardware/bluetooth/1.0/IBluetoothHciCallbacks.h>
#include <android/hardware/bluetooth/1.0/types.h>

#include "hal/bluetooth_snoop_logger.h"
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
constexpr char kDefaultBtsnoopPath[] = "/data/misc/bluetooth/logs/btsnoop_hci.log";

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
  HciHalBluetoothHciCallbacks(BluetoothSnoopLogger* btsnoop_logger)
      : btsnoop_logger_(btsnoop_logger) {
    init_promise_ = new std::promise<void>();
  }

  void SetCallback(BluetoothHciHalCallbacks* callback) {
    ASSERT(callback_ == nullptr && callback != nullptr);
    callback_ = callback;
  }

  void ResetCallback() {
    callback_ = nullptr;
  }

  std::promise<void>* GetInitPromise() {
    return init_promise_;
  }

  Return<void> initializationComplete(HidlStatus status) {
    ASSERT(status == HidlStatus::SUCCESS);
    init_promise_->set_value();
    return Void();
  }

  Return<void> hciEventReceived(const hidl_vec<uint8_t>& event) {
    std::vector<uint8_t> received_hci_packet(event.begin(), event.end());
    btsnoop_logger_->capture(received_hci_packet, BluetoothSnoopLogger::Direction::INCOMING,
                             BluetoothSnoopLogger::PacketType::EVT);
    if (callback_ != nullptr) {
      callback_->hciEventReceived(std::move(received_hci_packet));
    }
    return Void();
  }

  Return<void> aclDataReceived(const hidl_vec<uint8_t>& data) {
    std::vector<uint8_t> received_hci_packet(data.begin(), data.end());
    btsnoop_logger_->capture(received_hci_packet, BluetoothSnoopLogger::Direction::INCOMING,
                             BluetoothSnoopLogger::PacketType::ACL);
    if (callback_ != nullptr) {
      callback_->aclDataReceived(std::move(received_hci_packet));
    }
    return Void();
  }

  Return<void> scoDataReceived(const hidl_vec<uint8_t>& data) {
    std::vector<uint8_t> received_hci_packet(data.begin(), data.end());
    btsnoop_logger_->capture(received_hci_packet, BluetoothSnoopLogger::Direction::INCOMING,
                             BluetoothSnoopLogger::PacketType::SCO);
    if (callback_ != nullptr) {
      callback_->scoDataReceived(std::move(received_hci_packet));
    }
    return Void();
  }

 private:
  std::promise<void>* init_promise_ = nullptr;
  BluetoothHciHalCallbacks* callback_ = nullptr;
  BluetoothSnoopLogger* btsnoop_logger_ = nullptr;
};

}  // namespace

class BluetoothHciHalHidl : public BluetoothHciHal {
 public:
  void registerIncomingPacketCallback(BluetoothHciHalCallbacks* callback) override {
    callbacks_->SetCallback(callback);
  }

  void sendHciCommand(HciPacket command) override {
    btsnoop_logger_->capture(command, BluetoothSnoopLogger::Direction::OUTGOING, BluetoothSnoopLogger::PacketType::CMD);
    bt_hci_->sendHciCommand(command);
  }

  void sendAclData(HciPacket packet) override {
    btsnoop_logger_->capture(packet, BluetoothSnoopLogger::Direction::OUTGOING, BluetoothSnoopLogger::PacketType::ACL);
    bt_hci_->sendAclData(packet);
  }

  void sendScoData(HciPacket packet) override {
    btsnoop_logger_->capture(packet, BluetoothSnoopLogger::Direction::OUTGOING, BluetoothSnoopLogger::PacketType::SCO);
    bt_hci_->sendScoData(packet);
  }

 protected:
  void ListDependencies(ModuleList* list) override {
    // We have no dependencies
  }

  void Start(const ModuleRegistry* registry) override {
    btsnoop_logger_ = new BluetoothSnoopLogger(kDefaultBtsnoopPath);
    bt_hci_ = IBluetoothHci::getService();
    ASSERT(bt_hci_ != nullptr);
    auto death_link = bt_hci_->linkToDeath(bluetooth_hci_death_recipient_, 0);
    ASSERT_LOG(death_link.isOk(), "Unable to set the death recipient for the Bluetooth HAL");
    // Block allows allocation of a variable that might be bypassed by goto.
    {
      callbacks_ = new HciHalBluetoothHciCallbacks(btsnoop_logger_);
      bt_hci_->initialize(callbacks_);
      // Don't timeout here, time out at a higher layer
      callbacks_->GetInitPromise()->get_future().wait();
    }
  }

  void Stop(const ModuleRegistry* registry) override {
    ASSERT(bt_hci_ != nullptr);
    auto death_unlink = bt_hci_->unlinkToDeath(bluetooth_hci_death_recipient_);
    if (!death_unlink.isOk()) {
      LOG_ERROR("Error unlinking death recipient from the Bluetooth HAL");
    }
    bt_hci_->close();
    callbacks_->ResetCallback();
    bt_hci_ = nullptr;
    delete btsnoop_logger_;
    btsnoop_logger_ = nullptr;
  }

 private:
  android::sp<HciHalBluetoothHciCallbacks> callbacks_;
  android::sp<IBluetoothHci> bt_hci_;
  BluetoothSnoopLogger* btsnoop_logger_;
};

const ModuleFactory BluetoothHciHal::Factory = ModuleFactory([]() {
  return new BluetoothHciHalHidl();
});

}  // namespace hal
}  // namespace bluetooth
