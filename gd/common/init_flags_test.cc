/******************************************************************************
 *
 *  Copyright 2019 The Android Open Source Project
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
 ******************************************************************************/

#include "common/init_flags.h"

#include <gtest/gtest.h>

using bluetooth::common::InitFlags;

TEST(InitFlagsTest, test_load_nullptr) {
  InitFlags::Load(nullptr);
  ASSERT_EQ(false, InitFlags::GdCoreEnabled());
}

TEST(InitFlagsTest, test_load_empty) {
  const char* input[] = {nullptr};
  InitFlags::Load(input);
  ASSERT_EQ(false, InitFlags::GdCoreEnabled());
}

TEST(InitFlagsTest, test_load_garbage) {
  const char* input[] = {"some random non-existent flag", nullptr};
  InitFlags::Load(input);
  ASSERT_EQ(false, InitFlags::GdCoreEnabled());
}

TEST(InitFlagsTest, test_load_core) {
  const char* input[] = {"INIT_gd_core", nullptr};
  InitFlags::Load(input);
  ASSERT_EQ(true, InitFlags::GdCoreEnabled());
  ASSERT_EQ(true, InitFlags::GdControllerEnabled());
  ASSERT_EQ(true, InitFlags::GdHciEnabled());
}

TEST(InitFlagsTest, test_load_controller) {
  const char* input[] = {"INIT_gd_controller", nullptr};
  InitFlags::Load(input);
  ASSERT_EQ(false, InitFlags::GdCoreEnabled());
  ASSERT_EQ(true, InitFlags::GdControllerEnabled());
  ASSERT_EQ(true, InitFlags::GdHciEnabled());
}

TEST(InitFlagsTest, test_load_hci) {
  const char* input[] = {"INIT_gd_hci", nullptr};
  InitFlags::Load(input);
  ASSERT_EQ(false, InitFlags::GdCoreEnabled());
  ASSERT_EQ(false, InitFlags::GdControllerEnabled());
  ASSERT_EQ(true, InitFlags::GdHciEnabled());
}

TEST(InitFlagsTest, test_load_gatt_robust_caching) {
  const char* input[] = {"INIT_gatt_robust_caching", nullptr};
  InitFlags::Load(input);
  ASSERT_EQ(true, InitFlags::GattRobustCachingEnabled());
}
