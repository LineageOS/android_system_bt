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

#include <base/bind.h>
#include <base/location.h>
#include <gtest/gtest.h>

#include "bta/dm/bta_dm_int.h"
#include "bta/hf_client/bta_hf_client_int.h"
#include "bta/include/bta_hf_client_api.h"
#include "bta/test/common/fake_osi.h"
#include "common/message_loop_thread.h"

std::map<std::string, int> mock_function_count_map;

void LogMsg(uint32_t trace_set_mask, const char* fmt_str, ...) {}

namespace base {
class MessageLoop;
}  // namespace base

namespace {
constexpr uint8_t kUnusedTimer = BTA_ID_MAX;
}  // namespace

class BtaDmTest : public testing::Test {
 protected:
  void SetUp() override {
    mock_function_count_map.clear();

    bta_dm_init_cb();

    for (int i = 0; i < BTA_DM_NUM_PM_TIMER; i++) {
      for (int j = 0; j < BTA_DM_PM_MODE_TIMER_MAX; j++) {
        bta_dm_cb.pm_timer[i].srvc_id[j] = kUnusedTimer;
      }
    }
  }
  void TearDown() override { bta_dm_deinit_cb(); }
};

TEST_F(BtaDmTest, nop) {
  bool status = true;
  ASSERT_EQ(true, status);
}

extern struct fake_osi_alarm_set_on_mloop fake_osi_alarm_set_on_mloop_;

TEST_F(BtaDmTest, disable_no_acl_links) {
  bta_dm_cb.disabling = true;

  bta_dm_disable();  // Waiting for all ACL connections to drain
  ASSERT_EQ(0, mock_function_count_map["btm_remove_acl"]);
  ASSERT_EQ(1, mock_function_count_map["alarm_set_on_mloop"]);

  // Execute timer callback
  fake_osi_alarm_set_on_mloop_.cb(fake_osi_alarm_set_on_mloop_.data);
  ASSERT_EQ(1, mock_function_count_map["alarm_set_on_mloop"]);
  ASSERT_EQ(0, mock_function_count_map["BTIF_dm_disable"]);
  ASSERT_EQ(1, mock_function_count_map["future_ready"]);
  ASSERT_TRUE(!bta_dm_cb.disabling);
}

extern uint16_t mock_stack_acl_num_links;
TEST_F(BtaDmTest, disable_first_pass_with_acl_links) {
  bta_dm_cb.disabling = true;
  // ACL link is open
  mock_stack_acl_num_links = bta_dm_cb.device_list.count = 1;

  bta_dm_disable();              // Waiting for all ACL connections to drain
  mock_stack_acl_num_links = 0;  // ACL link has closed
  ASSERT_EQ(1, mock_function_count_map["alarm_set_on_mloop"]);
  ASSERT_EQ(0, mock_function_count_map["BTIF_dm_disable"]);

  // First disable pass
  fake_osi_alarm_set_on_mloop_.cb(fake_osi_alarm_set_on_mloop_.data);
  ASSERT_EQ(1, mock_function_count_map["alarm_set_on_mloop"]);
  ASSERT_EQ(1, mock_function_count_map["BTIF_dm_disable"]);
  ASSERT_TRUE(!bta_dm_cb.disabling);
}

TEST_F(BtaDmTest, disable_second_pass_with_acl_links) {
  bta_dm_cb.disabling = true;
  // ACL link is open
  mock_stack_acl_num_links = bta_dm_cb.device_list.count = 1;

  bta_dm_disable();  // Waiting for all ACL connections to drain
  ASSERT_EQ(1, mock_function_count_map["alarm_set_on_mloop"]);
  ASSERT_EQ(0, mock_function_count_map["BTIF_dm_disable"]);

  // First disable pass
  fake_osi_alarm_set_on_mloop_.cb(fake_osi_alarm_set_on_mloop_.data);
  ASSERT_EQ(2, mock_function_count_map["alarm_set_on_mloop"]);
  ASSERT_EQ(0, mock_function_count_map["BTIF_dm_disable"]);
  ASSERT_EQ(1, mock_function_count_map["btm_remove_acl"]);

  // Second disable pass
  fake_osi_alarm_set_on_mloop_.cb(fake_osi_alarm_set_on_mloop_.data);
  ASSERT_EQ(1, mock_function_count_map["BTIF_dm_disable"]);
  ASSERT_TRUE(!bta_dm_cb.disabling);
}
