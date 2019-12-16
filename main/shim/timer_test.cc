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

#include <gtest/gtest.h>
#include <cstdint>
#include <future>

#define LOG_TAG "bt_shim_test"

#include <base/logging.h>
#include "osi/include/log.h"
#include "shim/timer.h"
#include "stub/osi.h"

#include <stdlib.h>

namespace bluetooth {
namespace legacy {

constexpr uint64_t kDurationMs = 3;

static const char* kTimer0 = "TestTimer00";
static const char* kTimer1 = "TestTimer01";

namespace {

class TimerTest : public testing::Test {
 public:
  void SetUp() override {
    // Ensure expected global state default initial conditions
    bluetooth::shim::stub::name_to_alarm_map_.clear();
  }

  void TearDown() override {
    // Reset global state to defaults
    bluetooth::shim::stub::name_to_alarm_map_.clear();
  }
};

TEST_F(TimerTest, Set) {
  std::promise<void> promise;
  auto future = promise.get_future();

  shim::Timer* timer = new shim::Timer(kTimer0);

  timer->Set(kDurationMs, [&promise]() { promise.set_value(); });

  CHECK(bluetooth::shim::stub::alarm_is_set(kTimer0) == true);
  CHECK(bluetooth::shim::stub::alarm_interval_ms(kTimer0) == kDurationMs);
  CHECK(bluetooth::shim::stub::alarm_data(kTimer0));

  {
    shim::Timer* timer =
        static_cast<shim::Timer*>(bluetooth::shim::stub::alarm_data(kTimer0));
    bluetooth::shim::Timer::Pop(timer);
  }
  future.wait();

  delete timer;
  CHECK(bluetooth::shim::stub::name_to_alarm_map_.empty());
}

TEST_F(TimerTest, Set2) {
  std::promise<void> promise0;
  std::promise<void> promise1;
  auto future0 = promise0.get_future();
  auto future1 = promise1.get_future();

  shim::Timer* timer0 = new shim::Timer(kTimer0);
  CHECK(bluetooth::shim::stub::name_to_alarm_map_.size() == 1);

  shim::Timer* timer1 = new shim::Timer(kTimer1);
  CHECK(bluetooth::shim::stub::name_to_alarm_map_.size() == 2);

  timer0->Set(kDurationMs, [&promise0]() { promise0.set_value(); });

  timer1->Set(kDurationMs * 2, [&promise1]() { promise1.set_value(); });

  CHECK(bluetooth::shim::stub::alarm_is_set(kTimer0) == true);
  CHECK(bluetooth::shim::stub::alarm_interval_ms(kTimer0) == kDurationMs);
  CHECK(bluetooth::shim::stub::alarm_data(kTimer0));

  CHECK(bluetooth::shim::stub::alarm_is_set(kTimer1) == true);
  CHECK(bluetooth::shim::stub::alarm_interval_ms(kTimer1) == kDurationMs * 2);
  CHECK(bluetooth::shim::stub::alarm_data(kTimer1));

  {
    shim::Timer* timer =
        static_cast<shim::Timer*>(bluetooth::shim::stub::alarm_data(kTimer0));
    bluetooth::shim::Timer::Pop(timer);
  }

  {
    shim::Timer* timer =
        static_cast<shim::Timer*>(bluetooth::shim::stub::alarm_data(kTimer1));
    bluetooth::shim::Timer::Pop(timer);
  }

  future0.wait();
  future1.wait();

  delete timer0;
  delete timer1;

  CHECK(bluetooth::shim::stub::name_to_alarm_map_.empty());
}

TEST_F(TimerTest, Cancel) {
  std::promise<void> promise;
  auto future = promise.get_future();

  shim::Timer* timer = new shim::Timer(kTimer0);

  timer->Set(kDurationMs, [&promise]() { promise.set_value(); });

  CHECK(bluetooth::shim::stub::alarm_is_set(kTimer0) == true);
  CHECK(bluetooth::shim::stub::alarm_interval_ms(kTimer0) == kDurationMs);
  CHECK(bluetooth::shim::stub::alarm_data(kTimer0));

  timer->Cancel();

  CHECK(bluetooth::shim::stub::alarm_is_set(kTimer0) == false);
  CHECK(bluetooth::shim::stub::alarm_interval_ms(kTimer0) == 0);
  CHECK(bluetooth::shim::stub::alarm_data(kTimer0) == nullptr);

  delete timer;
  CHECK(bluetooth::shim::stub::name_to_alarm_map_.empty());
}

}  // namespace
}  // namespace legacy
}  // namespace bluetooth
