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

#include "common/byte_array.h"
#include "hci/link_key.h"
#include "storage/classic_device.h"
#include "storage/mutation.h"

using bluetooth::common::ByteArray;
using bluetooth::hci::Address;
using bluetooth::hci::DeviceType;
using bluetooth::hci::kExampleLinkKey;
using bluetooth::storage::ClassicDevice;
using bluetooth::storage::ConfigCache;
using bluetooth::storage::Device;
using bluetooth::storage::Mutation;
using ::testing::Eq;
using ::testing::Optional;

TEST(ClassicDeviceTest, create_new_le_device) {
  ConfigCache config(10, Device::kLinkKeyProperties);
  ConfigCache memory_only_config(10, {});
  bluetooth::hci::Address address = {{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}};
  ClassicDevice device(&config, &memory_only_config, address.ToString());
  ASSERT_FALSE(device.GetLinkKey());
}

TEST(ClassicDeviceTest, set_property) {
  ConfigCache config(10, Device::kLinkKeyProperties);
  ConfigCache memory_only_config(10, {});
  Address address = {{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}};
  ClassicDevice device(&config, &memory_only_config, address.ToString());
  ASSERT_FALSE(device.GetLinkKey());
  Mutation mutation(&config, &memory_only_config);
  mutation.Add(device.SetLinkKey(kExampleLinkKey));
  mutation.Commit();
  ASSERT_THAT(device.GetLinkKey(), Optional(Eq(kExampleLinkKey)));
}

TEST(ClassicDeviceTest, equality_test) {
  ConfigCache config(10, Device::kLinkKeyProperties);
  ConfigCache memory_only_config(10, {});
  bluetooth::hci::Address address = {{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}};
  ClassicDevice device1(&config, &memory_only_config, address.ToString());
  ClassicDevice device2(&config, &memory_only_config, address.ToString());
  ASSERT_EQ(device1, device2);
  bluetooth::hci::Address address3 = {{0x01, 0x02, 0x03, 0x04, 0x05, 0x07}};
  ClassicDevice device3(&config, &memory_only_config, address3.ToString());
  ASSERT_NE(device1, device3);
}

