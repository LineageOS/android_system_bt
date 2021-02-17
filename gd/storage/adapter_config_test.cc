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

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "storage/adapter_config.h"
#include "storage/mutation.h"

using bluetooth::common::ByteArray;
using bluetooth::hci::Address;
using bluetooth::hci::DeviceType;
using bluetooth::storage::AdapterConfig;
using bluetooth::storage::ConfigCache;
using bluetooth::storage::Device;
using bluetooth::storage::Mutation;
using ::testing::Eq;
using ::testing::Optional;

TEST(AdapterConfigTest, create_new_adapter_config) {
  ConfigCache config(10, Device::kLinkKeyProperties);
  ConfigCache memory_only_config(10, {});
  AdapterConfig adapter_config(&config, &memory_only_config, "Adapter");
  ASSERT_FALSE(adapter_config.GetAddress());
}

TEST(AdapterConfigTest, set_property) {
  ConfigCache config(10, Device::kLinkKeyProperties);
  ConfigCache memory_only_config(10, {});
  Address address = {{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}};
  AdapterConfig adapter_config(&config, &memory_only_config, "Adapter");
  ASSERT_FALSE(adapter_config.GetAddress());
  Mutation mutation(&config, &memory_only_config);
  mutation.Add(adapter_config.SetAddress(address));
  mutation.Commit();
  ASSERT_THAT(adapter_config.GetAddress(), Optional(Eq(address)));
}

TEST(AdapterConfigTest, equality_test) {
  ConfigCache config(10, Device::kLinkKeyProperties);
  ConfigCache memory_only_config(10, {});
  bluetooth::hci::Address address = {{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}};
  AdapterConfig adapter_config_1(&config, &memory_only_config, "Adapter");
  AdapterConfig adapter_config_2(&config, &memory_only_config, "Adapter");
  ASSERT_EQ(adapter_config_1, adapter_config_2);
  ConfigCache memory_only_config_2(10, {});
  AdapterConfig adapter_config_3(&config, &memory_only_config_2, "Adapter");
  ASSERT_NE(adapter_config_1, adapter_config_3);
}

