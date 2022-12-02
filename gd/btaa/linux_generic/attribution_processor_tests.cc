/*
 * Copyright 2022 The Android Open Source Project
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

#include <base/strings/stringprintf.h>
#include <gtest/gtest.h>
#include <unistd.h>

#include <chrono>
#include <functional>
#include <memory>
#include <vector>

#include "btaa/activity_attribution.h"
#include "btaa/attribution_processor.h"

using bluetooth::hci::Address;
using namespace bluetooth::activity_attribution;
using namespace std::chrono;

// mock for std::chrono::system_clock::now
static AttributionProcessor::ClockType now_ret_val;
static AttributionProcessor::ClockType fake_now() {
  return now_ret_val;
}

class AttributionProcessorTest : public ::testing::Test {
 protected:
  void SetUp() override {
    pAttProc = std::make_unique<AttributionProcessor>(fake_now);
  }
  void TearDown() override {
    pAttProc.reset();
  }

  std::unique_ptr<AttributionProcessor> pAttProc;
};

static void fake_now_set_current() {
  now_ret_val = system_clock::now();
}

static void fake_now_advance_1000sec() {
  now_ret_val += seconds(1000s);
}

TEST_F(AttributionProcessorTest, UAFInOnWakelockReleasedRegressionTest) {
  std::vector<BtaaHciPacket> btaaPackets;
  Address addr;

  fake_now_set_current();

  // setup the condition 1 for triggering erase operation
  // add 220 entries in app_activity_aggregator_
  // and btaa_aggregator_
  for (int i = 0; i < 220; i++) {
    std::string addrStr = base::StringPrintf("21:43:65:87:a9:%02x", i + 10);
    ASSERT_TRUE(Address::FromString(addrStr, addr));
    BtaaHciPacket packet(Activity::ACL, addr, 30 * i);
    btaaPackets.push_back(packet);
  }

  pAttProc->OnBtaaPackets(btaaPackets);
  pAttProc->OnWakelockReleased(100);

  // setup the condition 2 for triggering erase operation
  // make elapsed_time_sec > 900s
  fake_now_advance_1000sec();

  pAttProc->OnBtaaPackets(btaaPackets);
  pAttProc->OnWakelockReleased(100);
}
