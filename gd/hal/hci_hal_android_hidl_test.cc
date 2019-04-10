#include "hal/hci_hal.h"

#include <chrono>
#include <future>

#include <gtest/gtest.h>

namespace bluetooth {
namespace hal {
namespace {

std::promise<void>* g_promise;

class TestBluetoothHciHalCallbacks : public BluetoothHciHalCallbacks {
 public:
  void initializationComplete(Status status) override {
    EXPECT_EQ(status, Status::SUCCESS);
    g_promise->set_value();
  }

  void hciEventReceived(HciPacket) override {}

  void aclDataReceived(HciPacket) override {}

  void scoDataReceived(HciPacket) override {}
};

class HciHalHidlTest : public ::testing::Test {
 protected:
  void SetUp() override {
    g_promise = new std::promise<void>;
    hal_ = GetBluetoothHciHal();
    hal_->initialize(&callbacks_);
  }

  void TearDown() override {
    hal_->close();
    hal_ = nullptr;
    delete g_promise;
  }

  BluetoothHciHal* hal_ = nullptr;
  TestBluetoothHciHalCallbacks callbacks_;
};

TEST_F(HciHalHidlTest, init_and_close) {
  // Give a long timeout because this only checks HAL is initialized, not performance
  auto wait_status = g_promise->get_future().wait_for(std::chrono::seconds(30));
  EXPECT_EQ(wait_status, std::future_status::ready);
}
}  // namespace
}  // namespace hal
}  // namespace bluetooth
