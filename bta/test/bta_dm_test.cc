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
#include "common/message_loop_thread.h"

std::map<std::string, int> mock_function_count_map;

bt_status_t do_in_main_thread_delayed(const base::Location& from_here,
                                      base::OnceClosure task,
                                      const base::TimeDelta& delay) {
  return BT_STATUS_SUCCESS;
}

bt_status_t do_in_main_thread(const base::Location& from_here,
                              base::OnceClosure task) {
  return BT_STATUS_SUCCESS;
}

void LogMsg(uint32_t trace_set_mask, const char* fmt_str, ...) {}

namespace base {
class MessageLoop;
}  // namespace base
bluetooth::common::MessageLoopThread* get_main_thread() { return nullptr; }

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
