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

#include <string>

#include <gtest/gtest.h>

#include "os/system_properties.h"

namespace testing {

using bluetooth::os::ClearSystemPropertiesForHost;
using bluetooth::os::GetSystemProperty;
using bluetooth::os::SetSystemProperty;

TEST(SystemPropertiesTest, set_and_get_test) {
  ASSERT_TRUE(SetSystemProperty("persist.bluetooth.factoryreset", "true"));
  auto ret = GetSystemProperty("persist.bluetooth.factoryreset");
  ASSERT_TRUE(ret);
  ASSERT_EQ(ret, "true");
  ASSERT_TRUE(SetSystemProperty("persist.bluetooth.factoryreset", "false"));
  ret = GetSystemProperty("persist.bluetooth.factoryreset");
  ASSERT_TRUE(ret);
  ASSERT_EQ(ret, "false");
  ret = GetSystemProperty("persist.bluetooth.factoryreset_do_not_exist");
  ASSERT_FALSE(ret);
  ClearSystemPropertiesForHost();
  ASSERT_FALSE(GetSystemProperty("persist.bluetooth.factoryreset"));
}

}  // namespace testing