/*
 * Copyright 2020 The Android Open Source Project
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

#include "storage/mutation.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "storage/config_cache.h"

namespace testing {

using bluetooth::storage::ConfigCache;
using bluetooth::storage::Mutation;
using bluetooth::storage::MutationEntry;

TEST(MutationTest, simple_sequence_test) {
  ConfigCache config(100);
  config.SetProperty("A", "B", "C");
  config.SetProperty("AA:BB:CC:DD:EE:FF", "B", "C");
  config.SetProperty("AA:BB:CC:DD:EE:FF", "C", "D");
  config.SetProperty("CC:DD:EE:FF:00:11", "LinkKey", "AABBAABBCCDDEE");
  Mutation mutation(config);
  mutation.Add(MutationEntry::Set("AA:BB:CC:DD:EE:FF", "LinkKey", "CCDDEEFFGG"));
  mutation.Add(MutationEntry::Remove("AA:BB:CC:DD:EE:FF", "LinkKey"));
  mutation.Commit();
  EXPECT_THAT(config.GetPersistentDevices(), ElementsAre("CC:DD:EE:FF:00:11"));
  Mutation mutation2(config);
  mutation2.Add(MutationEntry::Set("AA:BB:CC:DD:EE:FF", "LinkKey", "CCDDEEFFGG"));
  mutation2.Commit();
  EXPECT_THAT(config.GetPersistentDevices(), ElementsAre("CC:DD:EE:FF:00:11", "AA:BB:CC:DD:EE:FF"));
}

}  // namespace testing