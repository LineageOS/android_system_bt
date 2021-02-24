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

#include <android/hardware/bluetooth/1.0/types.h>
#include <android/hardware/bluetooth/1.1/IBluetoothHci.h>
#include <android/hardware/bluetooth/1.1/IBluetoothHciCallbacks.h>
#include <stdlib.h>

#include <future>
#include <vector>

#include "common/stop_watch.h"
#include "common/strings.h"
#include "hal/hci_hal.h"
#include "hal/snoop_logger.h"
#include "os/log.h"

using ::android::hardware::hidl_vec;
using ::android::hardware::Return;
using ::android::hardware::Void;
using ::android::hardware::bluetooth::V1_1::IBluetoothHci;
using ::android::hardware::bluetooth::V1_1::IBluetoothHciCallbacks;
using HidlStatus = ::android::hardware::bluetooth::V1_0::Status;
using IBluetoothHci_1_0 = ::android::hardware::bluetooth::V1_0::IBluetoothHci;

namespace bluetooth {
namespace hal {
namespace {

class HciDeathRecipient : public ::android::hardware::hidl_death_recipient {
 public:
  virtual void serviceDied(uint64_t /*cookie*/, const android::wp<::android::hidl::base::V1_0::IBase>& /*who*/) {
    LOG_ERROR("Bluetooth HAL service died!");
    abort();
  }
};

android::sp<HciDeathRecipient> hci_death_recipient_ = new HciDeathRecipient();

template <class VecType>
std::string GetTimerText(const char* func_name, VecType vec) {
  return common::StringFormat(
      "%s: len %zu, 1st 5 bytes '%s'",
      func_name,
      vec.size(),
      common::ToHexString(vec.begin(), std::min(vec.end(), vec.begin() + 5)).c_str());
}

class InternalHciCallbacks : public IBluetoothHciCallbacks {
 public:
  InternalHciCallbacks(SnoopLogger* btsnoop_logger) : btsnoop_logger_(btsnoop_logger) {
    init_promise_ = new std::promise<void>();
  }

  void SetCallback(HciHalCallbacks* callback) {
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

  Return<void> hciEventReceived(const hidl_vec<uint8_t>& event) override {
    common::StopWatch(GetTimerText(__func__, event));
    std::vector<uint8_t> received_hci_packet(event.begin(), event.end());
    btsnoop_logger_->Capture(received_hci_packet, SnoopLogger::Direction::INCOMING, SnoopLogger::PacketType::EVT);
    if (callback_ != nullptr) {
      callback_->hciEventReceived(std::move(received_hci_packet));
    }
    return Void();
  }

  Return<void> aclDataReceived(const hidl_vec<uint8_t>& data) override {
    common::StopWatch(GetTimerText(__func__, data));
    std::vector<uint8_t> received_hci_packet(data.begin(), data.end());
    btsnoop_logger_->Capture(received_hci_packet, SnoopLogger::Direction::INCOMING, SnoopLogger::PacketType::ACL);
    if (callback_ != nullptr) {
      callback_->aclDataReceived(std::move(received_hci_packet));
    }
    return Void();
  }

  Return<void> scoDataReceived(const hidl_vec<uint8_t>& data) override {
    common::StopWatch(GetTimerText(__func__, data));
    std::vector<uint8_t> received_hci_packet(data.begin(), data.end());
    btsnoop_logger_->Capture(received_hci_packet, SnoopLogger::Direction::INCOMING, SnoopLogger::PacketType::SCO);
    if (callback_ != nullptr) {
      callback_->scoDataReceived(std::move(received_hci_packet));
    }
    return Void();
  }

  Return<void> isoDataReceived(const hidl_vec<uint8_t>& data) override {
    common::StopWatch(GetTimerText(__func__, data));
    std::vector<uint8_t> received_hci_packet(data.begin(), data.end());
    btsnoop_logger_->Capture(received_hci_packet, SnoopLogger::Direction::INCOMING, SnoopLogger::PacketType::ISO);
    if (callback_ != nullptr) {
      callback_->isoDataReceived(std::move(received_hci_packet));
    }
    return Void();
  }

 private:
  std::promise<void>* init_promise_ = nullptr;
  HciHalCallbacks* callback_ = nullptr;
  SnoopLogger* btsnoop_logger_ = nullptr;
};

}  // namespace

class HciHalHidl : public HciHal {
 public:
  void registerIncomingPacketCallback(HciHalCallbacks* callback) override {
    callbacks_->SetCallback(callback);
  }

  void unregisterIncomingPacketCallback() override {
    callbacks_->ResetCallback();
  }

  void sendHciCommand(HciPacket command) override {
    common::StopWatch(GetTimerText(__func__, command));
    btsnoop_logger_->Capture(command, SnoopLogger::Direction::OUTGOING, SnoopLogger::PacketType::CMD);
    bt_hci_->sendHciCommand(command);
  }

  void sendAclData(HciPacket packet) override {
    common::StopWatch(GetTimerText(__func__, packet));
    btsnoop_logger_->Capture(packet, SnoopLogger::Direction::OUTGOING, SnoopLogger::PacketType::ACL);
    bt_hci_->sendAclData(packet);
  }

  void sendScoData(HciPacket packet) override {
    common::StopWatch(GetTimerText(__func__, packet));
    btsnoop_logger_->Capture(packet, SnoopLogger::Direction::OUTGOING, SnoopLogger::PacketType::SCO);
    bt_hci_->sendScoData(packet);
  }

  void sendIsoData(HciPacket packet) override {
    if (bt_hci_1_1_ == nullptr) {
      LOG_ERROR("ISO is not supported in HAL v1.0");
      return;
    }

    common::StopWatch(GetTimerText(__func__, packet));
    btsnoop_logger_->Capture(packet, SnoopLogger::Direction::OUTGOING, SnoopLogger::PacketType::ISO);
    bt_hci_1_1_->sendIsoData(packet);
  }

 protected:
  void ListDependencies(ModuleList* list) override {
    list->add<SnoopLogger>();
  }

  void Start() override {
    btsnoop_logger_ = GetDependency<SnoopLogger>();

    bt_hci_1_1_ = IBluetoothHci::getService();

    if (bt_hci_1_1_ != nullptr) {
      bt_hci_ = bt_hci_1_1_;
    } else {
      bt_hci_ = IBluetoothHci_1_0::getService();
    }

    ASSERT(bt_hci_ != nullptr);
    auto death_link = bt_hci_->linkToDeath(hci_death_recipient_, 0);
    ASSERT_LOG(death_link.isOk(), "Unable to set the death recipient for the Bluetooth HAL");
    // Block allows allocation of a variable that might be bypassed by goto.
    {
      callbacks_ = new InternalHciCallbacks(btsnoop_logger_);
      if (bt_hci_1_1_ != nullptr) {
        bt_hci_1_1_->initialize_1_1(callbacks_);
      } else {
        bt_hci_->initialize(callbacks_);
      }

      // Don't timeout here, time out at a higher layer
      callbacks_->GetInitPromise()->get_future().wait();
    }
  }

  void Stop() override {
    ASSERT(bt_hci_ != nullptr);
    auto death_unlink = bt_hci_->unlinkToDeath(hci_death_recipient_);
    if (!death_unlink.isOk()) {
      LOG_ERROR("Error unlinking death recipient from the Bluetooth HAL");
    }
    bt_hci_->close();
    callbacks_->ResetCallback();
    bt_hci_ = nullptr;
    bt_hci_1_1_ = nullptr;
  }

 private:
  android::sp<InternalHciCallbacks> callbacks_;
  android::sp<IBluetoothHci_1_0> bt_hci_;
  android::sp<IBluetoothHci> bt_hci_1_1_;
  SnoopLogger* btsnoop_logger_;
};

const ModuleFactory HciHal::Factory = ModuleFactory([]() { return new HciHalHidl(); });

}  // namespace hal
}  // namespace bluetooth
