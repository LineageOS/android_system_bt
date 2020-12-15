#include <android/hardware/bluetooth/1.0/IBluetoothHci.h>
#include <android/hardware/bluetooth/1.0/IBluetoothHciCallbacks.h>
#include <android/hardware/bluetooth/1.0/types.h>
#include <stdlib.h>

#include "../../os/log.h"
#include "src/ffi/hidl.h"

using ::android::hardware::hidl_vec;
using ::android::hardware::Return;
using ::android::hardware::Void;
using ::android::hardware::bluetooth::V1_0::IBluetoothHci;
using ::android::hardware::bluetooth::V1_0::IBluetoothHciCallbacks;
using HidlStatus = ::android::hardware::bluetooth::V1_0::Status;

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

class HciCallbackTrampoline : public IBluetoothHciCallbacks {
 public:
  HciCallbackTrampoline() {}

  Return<void> initializationComplete(HidlStatus status) {
    ASSERT(status == HidlStatus::SUCCESS);
    on_init_complete();
    return Void();
  }

  Return<void> hciEventReceived(const hidl_vec<uint8_t>& event) {
    on_event(rust::Slice(&event[0], event.size()));
    return Void();
  }

  Return<void> aclDataReceived(const hidl_vec<uint8_t>& data) {
    on_acl(rust::Slice(&data[0], data.size()));
    return Void();
  }

  Return<void> scoDataReceived(const hidl_vec<uint8_t>& data) {
    on_sco(rust::Slice(&data[0], data.size()));
    return Void();
  }
};

android::sp<HciDeathRecipient> hci_death_recipient_ = new HciDeathRecipient();
android::sp<IBluetoothHci> bt_hci_;
android::sp<HciCallbackTrampoline> trampoline_;

}  // namespace

void start_hal() {
  ASSERT(bt_hci_ == nullptr);

  bt_hci_ = IBluetoothHci::getService();
  ASSERT(bt_hci_ != nullptr);
  auto death_link = bt_hci_->linkToDeath(hci_death_recipient_, 0);
  ASSERT_LOG(death_link.isOk(), "Unable to set the death recipient for the Bluetooth HAL");

  trampoline_ = new HciCallbackTrampoline();
  bt_hci_->initialize(trampoline_);
}

void stop_hal() {
  ASSERT(bt_hci_ != nullptr);

  auto death_unlink = bt_hci_->unlinkToDeath(hci_death_recipient_);
  if (!death_unlink.isOk()) {
    LOG_ERROR("Error unlinking death recipient from the Bluetooth HAL");
  }
  bt_hci_->close();
  bt_hci_ = nullptr;
  trampoline_ = nullptr;
}

void send_command(rust::Slice<uint8_t> data) {
  ASSERT(bt_hci_ != nullptr);
  bt_hci_->sendHciCommand(hidl_vec<uint8_t>(data.data(), data.data() + data.length()));
}

void send_acl(rust::Slice<uint8_t> data) {
  ASSERT(bt_hci_ != nullptr);
  bt_hci_->sendAclData(hidl_vec<uint8_t>(data.data(), data.data() + data.length()));
}

void send_sco(rust::Slice<uint8_t> data) {
  ASSERT(bt_hci_ != nullptr);
  bt_hci_->sendScoData(hidl_vec<uint8_t>(data.data(), data.data() + data.length()));
}

}  // namespace hal
}  // namespace bluetooth
