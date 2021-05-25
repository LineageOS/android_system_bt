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

#include "storage/device.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "storage/classic_device.h"
#include "storage/device.h"
#include "storage/le_device.h"
#include "storage/mutation.h"

using bluetooth::hci::Address;
using bluetooth::hci::DeviceType;
using bluetooth::storage::ConfigCache;
using bluetooth::storage::Device;
using bluetooth::storage::Mutation;
using ::testing::Eq;
using ::testing::MatchesRegex;
using ::testing::Optional;
using ::testing::StrEq;

TEST(DeviceTest, create_new_device_using_legacy_key_address) {
  ConfigCache config(10, Device::kLinkKeyProperties);
  ConfigCache memory_only_config(10, {});

  // A new device
  Address address = {{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}};
  Device device(&config, &memory_only_config, address, Device::ConfigKeyAddressType::LEGACY_KEY_ADDRESS);
  ASSERT_FALSE(device.Exists());
  ASSERT_FALSE(device.GetClassOfDevice());

  // An existing device
  Address address2 = {{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}};
  config.SetProperty(address2.ToString(), "Name", "hello");
  Device device2(&config, &memory_only_config, address2, Device::ConfigKeyAddressType::LEGACY_KEY_ADDRESS);
  ASSERT_TRUE(device2.Exists());
  ASSERT_THAT(device2.GetName(), Optional(StrEq("hello")));

  // devices with the same key address and config pointer are the same
  Address address3 = {{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}};
  Device device3(&config, &memory_only_config, address3, Device::ConfigKeyAddressType::LEGACY_KEY_ADDRESS);
  ASSERT_EQ(device2, device3);
  ASSERT_TRUE(device3.Exists());
  ASSERT_THAT(device3.GetName(), Optional(StrEq("hello")));
}

TEST(DeviceTest, create_new_device_using_classic_address) {
  ConfigCache config(10, Device::kLinkKeyProperties);
  ConfigCache memory_only_config(10, {});

  // A new device
  Address address = {{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}};
  Device device(&config, &memory_only_config, address, Device::ConfigKeyAddressType::CLASSIC_ADDRESS);
  ASSERT_FALSE(device.Exists());
  ASSERT_FALSE(device.GetClassOfDevice());

  // An existing device
  Address address2 = {{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}};
  config.SetProperty(address2.ToString(), "Name", "hello");
  Device device2(&config, &memory_only_config, address2, Device::ConfigKeyAddressType::CLASSIC_ADDRESS);
  ASSERT_TRUE(device2.Exists());
  ASSERT_THAT(device2.GetName(), Optional(StrEq("hello")));

  // devices with the same key address and config pointer are the same
  Address address3 = {{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}};
  Device device3(&config, &memory_only_config, address3, Device::ConfigKeyAddressType::CLASSIC_ADDRESS);
  ASSERT_EQ(device2, device3);
  ASSERT_TRUE(device3.Exists());
  ASSERT_THAT(device3.GetName(), Optional(StrEq("hello")));
}

TEST(DeviceTest, create_new_device_using_le_identity_address) {
  ConfigCache config(10, Device::kLinkKeyProperties);
  ConfigCache memory_only_config(10, {});

  // A new device
  Address address = {{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}};
  Device device(&config, &memory_only_config, address, Device::ConfigKeyAddressType::LE_IDENTITY_ADDRESS);
  ASSERT_FALSE(device.Exists());
  ASSERT_FALSE(device.GetClassOfDevice());

  // An existing device
  Address pseudo_first_seen_address = {{0xab, 0xcd, 0xef, 0x12, 0x34, 0x56}};
  Address le_identity_address = {{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}};
  // first seen address used as key
  config.SetProperty(pseudo_first_seen_address.ToString(), "Name", "hello");
  config.SetProperty(pseudo_first_seen_address.ToString(), "LeIdentityAddr", le_identity_address.ToString());
  config.SetProperty(address.ToString(), "Name", "world");
  Device device2(&config, &memory_only_config, le_identity_address, Device::ConfigKeyAddressType::LE_IDENTITY_ADDRESS);
  ASSERT_TRUE(device2.Exists());
  ASSERT_THAT(device2.GetName(), Optional(StrEq("hello")));
}

TEST(DeviceTest, set_property) {
  ConfigCache config(10, Device::kLinkKeyProperties);
  ConfigCache memory_only_config(10, {});
  Address address = {{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}};
  Device device(&config, &memory_only_config, address, Device::ConfigKeyAddressType::LEGACY_KEY_ADDRESS);
  ASSERT_FALSE(device.Exists());
  ASSERT_FALSE(device.GetName());
  Mutation mutation(&config, &memory_only_config);
  mutation.Add(device.SetName("hello world!"));
  mutation.Commit();
  ASSERT_TRUE(device.Exists());
  ASSERT_THAT(device.GetName(), Optional(StrEq("hello world!")));
}

TEST(DeviceTest, set_device_type) {
  ConfigCache config(10, Device::kLinkKeyProperties);
  ConfigCache memory_only_config(10, {});
  Address address = {{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}};
  Device device(&config, &memory_only_config, address, Device::ConfigKeyAddressType::LEGACY_KEY_ADDRESS);
  ASSERT_FALSE(device.Exists());
  ASSERT_FALSE(device.GetName());
  {
    Mutation mutation(&config, &memory_only_config);
    mutation.Add(device.SetDeviceType(DeviceType::BR_EDR));
    mutation.Commit();
  }
  ASSERT_THAT(device.GetDeviceType(), Optional(Eq(DeviceType::BR_EDR)));
  {
    Mutation mutation(&config, &memory_only_config);
    mutation.Add(device.SetDeviceType(DeviceType::LE));
    mutation.Commit();
  }
  ASSERT_THAT(device.GetDeviceType(), Optional(Eq(DeviceType::DUAL)));
}

TEST(DeviceTest, get_le_and_bredr) {
  ConfigCache config(10, Device::kLinkKeyProperties);
  ConfigCache memory_only_config(10, {});
  Address address = {{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}};
  Device device(&config, &memory_only_config, address, Device::ConfigKeyAddressType::LEGACY_KEY_ADDRESS);
  ASSERT_FALSE(device.GetDeviceType());
  ASSERT_DEATH({ device.Le(); }, MatchesRegex(".*"));
  ASSERT_DEATH({ device.Classic(); }, MatchesRegex(".*"));

  // classic
  {
    Mutation mutation(&config, &memory_only_config);
    mutation.Add(device.SetDeviceType(DeviceType::BR_EDR));
    mutation.Commit();
  }
  ASSERT_THAT(device.GetDeviceType(), Optional(Eq(DeviceType::BR_EDR)));
  auto classic_device = device.Classic();
  ASSERT_THAT(classic_device.Parent(), Eq(device));

  // le
  {
    Mutation mutation(&config, &memory_only_config);
    mutation.Add(device.RemoveDeviceType());
    mutation.Commit();
  }
  ASSERT_FALSE(device.GetDeviceType());
  {
    Mutation mutation(&config, &memory_only_config);
    mutation.Add(device.SetDeviceType(DeviceType::LE));
    mutation.Commit();
  }
  ASSERT_THAT(device.GetDeviceType(), Optional(Eq(DeviceType::LE)));
  auto le_device = device.Le();
  ASSERT_THAT(le_device.Parent(), Eq(device));

  // dual
  {
    Mutation mutation(&config, &memory_only_config);
    mutation.Add(device.RemoveDeviceType());
    mutation.Commit();
  }
  ASSERT_FALSE(device.GetDeviceType());
  {
    Mutation mutation(&config, &memory_only_config);
    mutation.Add(device.SetDeviceType(DeviceType::DUAL));
    mutation.Commit();
  }
  ASSERT_THAT(device.GetDeviceType(), Optional(Eq(DeviceType::DUAL)));
  classic_device = device.Classic();
  ASSERT_THAT(classic_device.Parent(), Eq(device));
  le_device = device.Le();
  ASSERT_THAT(le_device.Parent(), Eq(device));
}

TEST(DeviceTest, equality_test) {
  ConfigCache config(10, Device::kLinkKeyProperties);
  ConfigCache memory_only_config(10, {});
  Address address = {{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}};
  Device device1(&config, &memory_only_config, address, Device::ConfigKeyAddressType::LEGACY_KEY_ADDRESS);
  Device device2(&config, &memory_only_config, address, Device::ConfigKeyAddressType::LEGACY_KEY_ADDRESS);
  ASSERT_EQ(device1, device2);

  // different config cache
  ConfigCache config_alt(10, Device::kLinkKeyProperties);
  ConfigCache memory_only_config_alt(10, {});
  Device device3(&config_alt, &memory_only_config_alt, address, Device::ConfigKeyAddressType::LEGACY_KEY_ADDRESS);
  ASSERT_NE(device1, device3);

  // different address
  Address address_alt = {{0x01, 0x02, 0x03, 0x04, 0x05, 0x07}};
  Device device4(&config, &memory_only_config, address_alt, Device::ConfigKeyAddressType::LEGACY_KEY_ADDRESS);
  ASSERT_NE(device1, device4);

  Device device5 = std::move(device2);
  ASSERT_EQ(device1, device5);

  config.SetProperty(address.ToString(), "Name", "hello");
  ASSERT_THAT(device5.GetName(), Optional(StrEq("hello")));
  ASSERT_THAT(device1.GetName(), Optional(StrEq("hello")));
}

TEST(DeviceTest, remove_config_test) {
  ConfigCache config(10, Device::kLinkKeyProperties);
  ConfigCache memory_only_config(10, {});
  Address address = {{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}};
  config.SetProperty(address.ToString(), "Name", "hello");
  Device device(&config, &memory_only_config, address, Device::ConfigKeyAddressType::LEGACY_KEY_ADDRESS);
  ASSERT_TRUE(device.Exists());
  ASSERT_THAT(device.GetName(), Optional(StrEq("hello")));
  Mutation mutation(&config, &memory_only_config);
  mutation.Add(device.RemoveFromConfig());
  mutation.Commit();
  ASSERT_FALSE(device.Exists());
  ASSERT_FALSE(config.GetProperty(address.ToString(), "Name"));
}

