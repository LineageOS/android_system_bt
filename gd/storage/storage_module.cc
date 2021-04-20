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

#include "storage/storage_module.h"

#include <chrono>
#include <ctime>
#include <iomanip>
#include <memory>
#include <utility>

#include "common/bind.h"
#include "os/alarm.h"
#include "os/files.h"
#include "os/handler.h"
#include "os/parameter_provider.h"
#include "os/system_properties.h"
#include "storage/config_cache.h"
#include "storage/legacy_config_file.h"
#include "storage/mutation.h"

namespace bluetooth {
namespace storage {

using common::ListMap;
using common::LruCache;
using os::Alarm;
using os::Handler;

static const std::string kFactoryResetProperty = "persist.bluetooth.factoryreset";

static const size_t kDefaultTempDeviceCapacity = 10000;
// Save config whenever there is a change, but delay it by this value so that burst config change won't overwhelm disk
static const std::chrono::milliseconds kDefaultConfigSaveDelay = std::chrono::milliseconds(3000);
// Writing a config to disk takes a minimum 10 ms on a decent x86_64 machine, and 20 ms if including backup file
// The config saving delay must be bigger than this value to avoid overwhelming the disk
static const std::chrono::milliseconds kMinConfigSaveDelay = std::chrono::milliseconds(20);

const std::string StorageModule::kInfoSection = "Info";
const std::string StorageModule::kFileSourceProperty = "FileSource";
const std::string StorageModule::kTimeCreatedProperty = "TimeCreated";
const std::string StorageModule::kTimeCreatedFormat = "%Y-%m-%d %H:%M:%S";

const std::string StorageModule::kAdapterSection = "Adapter";

StorageModule::StorageModule(
    std::string config_file_path,
    std::chrono::milliseconds config_save_delay,
    size_t temp_devices_capacity,
    bool is_restricted_mode,
    bool is_single_user_mode)
    : config_file_path_(std::move(config_file_path)),
      config_save_delay_(config_save_delay),
      temp_devices_capacity_(temp_devices_capacity),
      is_restricted_mode_(is_restricted_mode),
      is_single_user_mode_(is_single_user_mode) {
  // e.g. "/data/misc/bluedroid/bt_config.conf" to "/data/misc/bluedroid/bt_config.bak"
  config_backup_path_ = config_file_path_.substr(0, config_file_path_.find_last_of('.')) + ".bak";
  ASSERT_LOG(
      config_save_delay > kMinConfigSaveDelay,
      "Config save delay of %lld ms is not enough, must be at least %lld ms to avoid overwhelming the disk",
      config_save_delay_.count(),
      kMinConfigSaveDelay.count());
};

StorageModule::~StorageModule() {
  std::lock_guard<std::recursive_mutex> lock(mutex_);
  pimpl_.reset();
}

const ModuleFactory StorageModule::Factory = ModuleFactory([]() {
  return new StorageModule(
      os::ParameterProvider::ConfigFilePath(), kDefaultConfigSaveDelay, kDefaultTempDeviceCapacity, false, false);
});

struct StorageModule::impl {
  explicit impl(Handler* handler, ConfigCache cache, size_t in_memory_cache_size_limit)
      : config_save_alarm_(handler), cache_(std::move(cache)), memory_only_cache_(in_memory_cache_size_limit, {}) {}
  Alarm config_save_alarm_;
  ConfigCache cache_;
  ConfigCache memory_only_cache_;
  bool has_pending_config_save_ = false;
};

Mutation StorageModule::Modify() {
  std::lock_guard<std::recursive_mutex> lock(mutex_);
  return Mutation(&pimpl_->cache_, &pimpl_->memory_only_cache_);
}

ConfigCache* StorageModule::GetConfigCache() {
  std::lock_guard<std::recursive_mutex> lock(mutex_);
  return &pimpl_->cache_;
}

ConfigCache* StorageModule::GetMemoryOnlyConfigCache() {
  std::lock_guard<std::recursive_mutex> lock(mutex_);
  return &pimpl_->memory_only_cache_;
}

void StorageModule::SaveDelayed() {
  std::lock_guard<std::recursive_mutex> lock(mutex_);
  if (pimpl_->has_pending_config_save_) {
    return;
  }
  pimpl_->config_save_alarm_.Schedule(
      common::BindOnce(&StorageModule::SaveImmediately, common::Unretained(this)), config_save_delay_);
  pimpl_->has_pending_config_save_ = true;
}

void StorageModule::SaveImmediately() {
  std::lock_guard<std::recursive_mutex> lock(mutex_);
  if (pimpl_->has_pending_config_save_) {
    pimpl_->config_save_alarm_.Cancel();
    pimpl_->has_pending_config_save_ = false;
  }
  // 1. rename old config to backup name
  if (os::FileExists(config_file_path_)) {
    ASSERT(os::RenameFile(config_file_path_, config_backup_path_));
  }
  // 2. write in-memory config to disk, if failed, backup can still be used
  ASSERT(LegacyConfigFile::FromPath(config_file_path_).Write(pimpl_->cache_));
  // 3. now write back up to disk as well
  ASSERT(LegacyConfigFile::FromPath(config_backup_path_).Write(pimpl_->cache_));
}

void StorageModule::ListDependencies(ModuleList* list) {
  // No dependencies
}

void StorageModule::Start() {
  std::lock_guard<std::recursive_mutex> lock(mutex_);
  std::string file_source;
  if (os::GetSystemProperty(kFactoryResetProperty) == "true") {
    LegacyConfigFile::FromPath(config_file_path_).Delete();
    LegacyConfigFile::FromPath(config_backup_path_).Delete();
  }
  auto config = LegacyConfigFile::FromPath(config_file_path_).Read(temp_devices_capacity_);
  if (!config || !config->HasSection(kAdapterSection)) {
    LOG_WARN("cannot load config at %s, using backup at %s.", config_file_path_.c_str(), config_backup_path_.c_str());
    config = LegacyConfigFile::FromPath(config_backup_path_).Read(temp_devices_capacity_);
    file_source = "Backup";
  }
  if (!config || !config->HasSection(kAdapterSection)) {
    LOG_WARN("cannot load backup config at %s; creating new empty ones", config_backup_path_.c_str());
    config.emplace(temp_devices_capacity_, Device::kLinkKeyProperties);
    file_source = "Empty";
  }
  if (!file_source.empty()) {
    config->SetProperty(kInfoSection, kFileSourceProperty, std::move(file_source));
  }
  // Cleanup temporary pairings if we have left guest mode
  if (!is_restricted_mode_) {
    config->RemoveSectionWithProperty("Restricted");
  }
  // Read or set config file creation timestamp
  auto time_str = config->GetProperty(kInfoSection, kTimeCreatedProperty);
  if (!time_str) {
    std::stringstream ss;
    auto now = std::chrono::system_clock::now();
    auto now_time_t = std::chrono::system_clock::to_time_t(now);
    ss << std::put_time(std::localtime(&now_time_t), kTimeCreatedFormat.c_str());
    config->SetProperty(kInfoSection, kTimeCreatedProperty, ss.str());
  }
  config->FixDeviceTypeInconsistencies();
  config->SetPersistentConfigChangedCallback([this] { this->CallOn(this, &StorageModule::SaveDelayed); });
  // TODO (b/158035889) Migrate metrics module to GD
  pimpl_ = std::make_unique<impl>(GetHandler(), std::move(config.value()), temp_devices_capacity_);
  SaveDelayed();
}

void StorageModule::Stop() {
  std::lock_guard<std::recursive_mutex> lock(mutex_);
  SaveImmediately();
  pimpl_.reset();
}

std::string StorageModule::ToString() const {
  return "Storage Module";
}

Device StorageModule::GetDeviceByLegacyKey(hci::Address legacy_key_address) {
  std::lock_guard<std::recursive_mutex> lock(mutex_);
  return Device(
      &pimpl_->cache_,
      &pimpl_->memory_only_cache_,
      std::move(legacy_key_address),
      Device::ConfigKeyAddressType::LEGACY_KEY_ADDRESS);
}

Device StorageModule::GetDeviceByClassicMacAddress(hci::Address classic_address) {
  std::lock_guard<std::recursive_mutex> lock(mutex_);
  return Device(
      &pimpl_->cache_,
      &pimpl_->memory_only_cache_,
      std::move(classic_address),
      Device::ConfigKeyAddressType::CLASSIC_ADDRESS);
}

Device StorageModule::GetDeviceByLeIdentityAddress(hci::Address le_identity_address) {
  std::lock_guard<std::recursive_mutex> lock(mutex_);
  return Device(
      &pimpl_->cache_,
      &pimpl_->memory_only_cache_,
      std::move(le_identity_address),
      Device::ConfigKeyAddressType::LE_IDENTITY_ADDRESS);
}

AdapterConfig StorageModule::GetAdapterConfig() {
  std::lock_guard<std::recursive_mutex> lock(mutex_);
  return AdapterConfig(&pimpl_->cache_, &pimpl_->memory_only_cache_, kAdapterSection);
}

std::vector<Device> StorageModule::GetBondedDevices() {
  std::lock_guard<std::recursive_mutex> lock(mutex_);
  auto persistent_sections = GetConfigCache()->GetPersistentSections();
  std::vector<Device> result;
  result.reserve(persistent_sections.size());
  for (const auto& section : persistent_sections) {
    result.emplace_back(&pimpl_->cache_, &pimpl_->memory_only_cache_, section);
  }
  return result;
}

}  // namespace storage
}  // namespace bluetooth