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
#include "storage/config_cache.h"
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
  ~StorageModule() override;
  static const ModuleFactory Factory;

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
  // Normally, underlying config will be saved at most 3 seconds after the first config change in a series of changes
  // This method triggers the delayed saving automatically, the delay is equal to |config_save_delay_|
  void SaveDelayed();
  // In some cases, one may want to save the config immediately to disk. Call this method with caution as it runs
  // immediately on the calling thread
  void SaveImmediately();

 private:
  struct impl;
  mutable std::mutex mutex_;
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
