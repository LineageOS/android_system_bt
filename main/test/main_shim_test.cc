/*
 *  Copyright 2021 The Android Open Source Project
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
 */

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <map>

#include "gd/btaa/activity_attribution.h"
#include "gd/hal/hci_hal.h"
#include "gd/hci/acl_manager_mock.h"
#include "gd/hci/controller_mock.h"
#include "gd/module.h"
#include "gd/os/mock_queue.h"
#include "hci/include/hci_layer.h"
#include "hci/include/hci_packet_factory.h"
#include "hci/include/hci_packet_parser.h"
#include "hci/include/packet_fragmenter.h"
#include "include/hardware/bt_activity_attribution.h"
#include "main/shim/acl.h"
#include "os/handler.h"
#include "os/thread.h"
#include "stack/btm/btm_int_types.h"
#include "stack/include/btu.h"
#include "stack/l2cap/l2c_int.h"

using namespace bluetooth;
using namespace testing;

std::map<std::string, int> mock_function_count_map;

tL2C_CB l2cb;
tBTM_CB btm_cb;

const hci_packet_factory_t* hci_packet_factory_get_interface() {
  return nullptr;
}
const hci_packet_parser_t* hci_packet_parser_get_interface() { return nullptr; }
const hci_t* hci_layer_get_interface() { return nullptr; }
const packet_fragmenter_t* packet_fragmenter_get_interface() { return nullptr; }
void LogMsg(uint32_t trace_set_mask, const char* fmt_str, ...) {}

namespace bluetooth {
namespace shim {
void init_activity_attribution() {}

namespace testing {
extern os::Handler* mock_handler_;
}  // namespace testing

}  // namespace shim

namespace hci {
namespace testing {

extern MockController* mock_controller_;
extern MockAclManager* mock_acl_manager_;

}  // namespace testing
}  // namespace hci

namespace activity_attribution {
ActivityAttributionInterface* get_activity_attribution_instance() {
  return nullptr;
}

const ModuleFactory ActivityAttribution::Factory =
    ModuleFactory([]() { return nullptr; });
}  // namespace activity_attribution

namespace hal {
const ModuleFactory HciHal::Factory = ModuleFactory([]() { return nullptr; });
}  // namespace hal

}  // namespace bluetooth

class MainShimTest : public testing::Test {
 public:
 protected:
  void SetUp() override {
    thread_ = new os::Thread("thread", os::Thread::Priority::NORMAL);
    handler_ = new os::Handler(thread_);

    hci::testing::mock_acl_manager_ = new hci::testing::MockAclManager();
    hci::testing::mock_controller_ = new hci::testing::MockController();
  }
  void TearDown() override {
    delete hci::testing::mock_controller_;
    delete hci::testing::mock_acl_manager_;

    handler_->Clear();
    delete handler_;
    delete thread_;
  }
  os::Thread* thread_{nullptr};
  os::Handler* handler_{nullptr};
};

TEST_F(MainShimTest, Nop) {}

TEST_F(MainShimTest, Acl_Lifecycle) {
  EXPECT_CALL(*hci::testing::mock_acl_manager_, RegisterCallbacks(_, _))
      .Times(1);
  EXPECT_CALL(*hci::testing::mock_acl_manager_, RegisterLeCallbacks(_, _))
      .Times(1);
  EXPECT_CALL(*hci::testing::mock_controller_,
              RegisterCompletedMonitorAclPacketsCallback(_))
      .Times(1);
  EXPECT_CALL(*hci::testing::mock_acl_manager_,
              HACK_SetScoDisconnectCallback(_))
      .Times(1);
  EXPECT_CALL(*hci::testing::mock_controller_,
              UnregisterCompletedMonitorAclPacketsCallback)
      .Times(1);

  auto acl = std::make_unique<shim::legacy::Acl>(
      handler_, shim::legacy::GetAclInterface(), 16);
}
