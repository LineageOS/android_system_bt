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
#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <list>
#include <memory>
#include <mutex>
#include <string>

#include "hci/address.h"
#include "module.h"
#include "storage/adapter_config.h"
#include "storage/config_cache.h"
#include "storage/device.h"
#include "storage/mutation.h"

namespace bluetooth {

namespace shim {
class BtifConfigInterface;
}

namespace storage {

class StorageModule : public bluetooth::Module {
 public:
  static const std::string kInfoSection;
  static const std::string kFileSourceProperty;
  static const std::string kTimeCreatedProperty;
  static const std::string kTimeCreatedFormat;

  static const std::string kAdapterSection;

  ~StorageModule();
  static const ModuleFactory Factory;

  // Methods to access the storage layer via Device abstraction
  // - Devices will be lazily created when methods below are called. Hence, no std::optional<> nor nullptr is used in
  //   the return type. User of the API can use the Device object's API to find out if the device has existed before
  // - Devices with no config values will not be saved to config cache
  // - Devices that are not paired will also be discarded when stack shutdown

  // Concept:
  //
  // BR/EDR Address:
  //  -> Public static address only, begin with 3 byte IEEE assigned OUI number
  //
  // BLE Addresses
  //  -> Public Address: begin with IEEE assigned OUI number
  //     -> Static: static public address do not change
  //     -> Private/Variable: We haven't seen private/variable public address yet
  //  -> Random Address: randomly generated, does not begin with IEEE assigned OUI number
  //     -> Static: static random address do not change
  //     -> Private/Variable: private random address changes once so often
  //        -> Resolvable: this address can be resolved into a static address using identity resolving key (IRK)
  //        -> Non-resolvable: this address is for temporary use only, do not save this address
  //
  // MAC addresses are six bytes only and hence are only regionally unique

  // Get a device object using the |legacy_key_address|. In legacy config, each device's config is stored in a config
  // section keyed by a single MAC address. For BR/EDR device, this is straightforward as a BR/EDR device has only a
  // single public static MAC address. However, for LE devices using private addresses, we only learn its real static
  // address after pairing. Since we still need to store that device's information prior to pairing, we use the
  // first-seen address of that device, no matter random private or static public, as a "key" to store that device's
  // config. This method gives you a device object using this legacy key. If the key does not exist, the device will
  // be lazily created in the config
  Device GetDeviceByLegacyKey(hci::Address legacy_key_address);

  // A classic (BR/EDR) or dual mode device can be uniquely located by its classic (BR/EDR) MAC address
  Device GetDeviceByClassicMacAddress(hci::Address classic_address);

  // A LE or dual mode device can be uniquely located by its identity address that is either:
  //   -> Public static address
  //   -> Random static address
  // If remote device uses LE random private resolvable address, user of this API must resolve its identity address
  // before calling this method to get the device object
  //
  // Note: A dual mode device's identity address is normally the same as its BR/EDR address, but they can also be
  // different. Hence, please don't make such assumption and don't use GetDeviceByBrEdrMacAddress() interchangeably
  Device GetDeviceByLeIdentityAddress(hci::Address le_identity_address);

  // A think copyable, movable, comparable object that is used to access adapter level information
  AdapterConfig GetAdapterConfig();

  // Get a list of bonded devices from config
  std::vector<Device> GetBondedDevices();

  // Modify the underlying config by starting a mutation. All entries in the mutation will be applied atomically when
  // Commit() is called. User should never touch ConfigCache() directly.
  Mutation Modify();

 protected:
  void ListDependencies(ModuleList* list) override;
  void Start() override;
  void Stop() override;
  std::string ToString() const override;

  friend shim::BtifConfigInterface;
  // For shim layer only
  ConfigCache* GetConfigCache();
  // For unit test only
  ConfigCache* GetMemoryOnlyConfigCache();
  // Normally, underlying config will be saved at most 3 seconds after the first config change in a series of changes
  // This method triggers the delayed saving automatically, the delay is equal to |config_save_delay_|
  void SaveDelayed();
  // In some cases, one may want to save the config immediately to disk. Call this method with caution as it runs
  // immediately on the calling thread
  void SaveImmediately();

  // Create the storage module where:
  // - config_file_path is the path to the config file on disk, a .bak file will be created with the original
  // - config_save_delay is the duration after which to dump config to disk after SaveDelayed() is called
  // - temp_devices_capacity is the number of temporary, typically unpaired devices to hold in a memory based LRU
  // - is_restricted_mode and is_single_user_mode are flags from upper layer
  StorageModule(
      std::string config_file_path,
      std::chrono::milliseconds config_save_delay,
      size_t temp_devices_capacity,
      bool is_restricted_mode,
      bool is_single_user_mode);

 private:
  struct impl;
  mutable std::recursive_mutex mutex_;
  std::unique_ptr<impl> pimpl_;
  std::string config_file_path_;
  std::string config_backup_path_;
  std::chrono::milliseconds config_save_delay_;
  size_t temp_devices_capacity_;
  bool is_restricted_mode_;
  bool is_single_user_mode_;

  DISALLOW_COPY_AND_ASSIGN(StorageModule);
};

}  // namespace storage
}  // namespace bluetooth
