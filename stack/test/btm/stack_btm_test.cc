/*
 *
 *  Copyright 2020 The Android Open Source Project
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
 */

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <map>

#include "hci/include/hci_layer.h"
#include "hci/include/hci_packet_factory.h"
#include "internal_include/stack_config.h"
#include "osi/include/osi.h"
#include "stack/btm/btm_int_types.h"
#include "stack/include/acl_hci_link_interface.h"
#include "types/raw_address.h"

base::MessageLoop* get_main_message_loop() { return nullptr; }

const hci_packet_factory_t* hci_packet_factory_get_interface() {
  return nullptr;
}
const hci_t* hci_layer_get_interface() { return nullptr; }

bt_status_t do_in_main_thread(const base::Location& from_here,
                              base::OnceClosure task) {
  return BT_STATUS_SUCCESS;
}
void LogMsg(uint32_t trace_set_mask, const char* fmt_str, ...) {}

const std::string kSmpOptions("mock smp options");

bool get_trace_config_enabled(void) { return false; }
bool get_pts_avrcp_test(void) { return false; }
bool get_pts_secure_only_mode(void) { return false; }
bool get_pts_conn_updates_disabled(void) { return false; }
bool get_pts_crosskey_sdp_disable(void) { return false; }
const std::string* get_pts_smp_options(void) { return &kSmpOptions; }
int get_pts_smp_failure_case(void) { return 123; }
config_t* get_all(void) { return nullptr; }

stack_config_t mock_stack_config{
    .get_trace_config_enabled = get_trace_config_enabled,
    .get_pts_avrcp_test = get_pts_avrcp_test,
    .get_pts_secure_only_mode = get_pts_secure_only_mode,
    .get_pts_conn_updates_disabled = get_pts_conn_updates_disabled,
    .get_pts_crosskey_sdp_disable = get_pts_crosskey_sdp_disable,
    .get_pts_smp_options = get_pts_smp_options,
    .get_pts_smp_failure_case = get_pts_smp_failure_case,
    .get_all = get_all,
};
const stack_config_t* stack_config_get_interface(void) {
  return &mock_stack_config;
}

std::map<std::string, int> mock_function_count_map;

bool MOCK_bluetooth_shim_is_gd_acl_enabled_;

namespace {

using testing::_;
using testing::DoAll;
using testing::NotNull;
using testing::Pointee;
using testing::Return;
using testing::SaveArg;
using testing::SaveArgPointee;
using testing::StrEq;
using testing::StrictMock;
using testing::Test;

class StackBtmTest : public Test {
 public:
 protected:
  void SetUp() override {}
  void TearDown() override {}
};

TEST_F(StackBtmTest, GlobalLifecycle) {
  btm_init();
  btm_free();
}

TEST_F(StackBtmTest, DynamicLifecycle) {
  auto* btm = new tBTM_CB();
  delete btm;
}

TEST_F(StackBtmTest, InformBtmOnConnection) {
  MOCK_bluetooth_shim_is_gd_acl_enabled_ = true;

  btm_init();

  RawAddress bda({0x11, 0x22, 0x33, 0x44, 0x55, 0x66});

  btm_acl_connected(bda, 2, HCI_SUCCESS, false);
  ASSERT_EQ(static_cast<size_t>(1),
            mock_function_count_map.count("BTA_dm_acl_up"));

  btm_free();
}

}  // namespace
