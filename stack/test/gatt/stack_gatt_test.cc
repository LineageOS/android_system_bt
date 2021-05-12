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

#include <gtest/gtest.h>
#include <string.h>

#include <cstdint>
#include <map>
#include <memory>
#include <string>

#include "common/message_loop_thread.h"
#include "stack/gatt/gatt_int.h"

std::map<std::string, int> mock_function_count_map;

void LogMsg(uint32_t trace_set_mask, const char* fmt_str, ...) {}

bluetooth::common::MessageLoopThread* get_main_thread() { return nullptr; }

class StackGattTest : public ::testing::Test {};

// Actual size of structure without compiler padding
size_t actual_sizeof_tGATT_REG() {
  return sizeof(bluetooth::Uuid) + sizeof(tGATT_CBACK) + sizeof(tGATT_IF) +
         sizeof(bool) + sizeof(uint8_t) + sizeof(bool);
}

TEST_F(StackGattTest, lifecycle_tGATT_REG) {
  {
    std::unique_ptr<tGATT_REG> reg0 = std::make_unique<tGATT_REG>();
    std::unique_ptr<tGATT_REG> reg1 = std::make_unique<tGATT_REG>();
    memset(reg0.get(), 0xff, sizeof(tGATT_REG));
    memset(reg1.get(), 0xff, sizeof(tGATT_REG));
    ASSERT_EQ(0, memcmp(reg0.get(), reg1.get(), sizeof(tGATT_REG)));
  }

  {
    std::unique_ptr<tGATT_REG> reg0 = std::make_unique<tGATT_REG>();
    memset(reg0.get(), 0xff, sizeof(tGATT_REG));

    tGATT_REG reg1;
    memset(&reg1, 0xff, sizeof(tGATT_REG));

    // Clear the structures
    memset(reg0.get(), 0, sizeof(tGATT_REG));
    reg1 = {};
    ASSERT_EQ(0, memcmp(reg0.get(), &reg1, actual_sizeof_tGATT_REG()));
  }

  {
    tGATT_REG* reg0 = new tGATT_REG();
    tGATT_REG* reg1 = new tGATT_REG();
    memset(reg0, 0, sizeof(tGATT_REG));
    *reg1 = {};
    reg0->in_use = true;
    ASSERT_NE(0, memcmp(reg0, reg1, sizeof(tGATT_REG)));
    delete reg1;
    delete reg0;
  }
}
