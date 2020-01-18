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
#define LOG_TAG "bt_gd_shim"

#include "shim/storage.h"

#include <functional>
#include <memory>

#include "common/bind.h"
#include "module.h"
#include "os/handler.h"
#include "os/log.h"
#include "storage/legacy.h"

namespace bluetooth {
namespace shim {

namespace {
constexpr char kModuleName[] = "shim::Storage";
}

struct Storage::impl {
  impl(bluetooth::storage::LegacyModule* storage_manager, os::Handler* handler);
  ~impl() = default;

  void config_read(const std::string filename, ConfigReadCallback callback);
  void config_write(const std::string filename, const config_t* config, ConfigWriteCallback callback);
  void checksum_read(const std::string filename, ChecksumReadCallback callback);
  void checksum_write(const std::string filename, const std::string& checksum, ChecksumWriteCallback callback);

 private:
  void OnConfigRead(const std::string filename, std::unique_ptr<config_t> config) {
    ASSERT(config_read_to_callback_map_.find(filename) != config_read_to_callback_map_.end());
    config_read_to_callback_map_[filename](std::move(config));
    config_read_to_callback_map_.erase(filename);
  }
  void OnConfigWrite(const std::string filename, bool success) {
    ASSERT(config_write_to_callback_map_.find(filename) != config_write_to_callback_map_.end());
    config_write_to_callback_map_[filename](success);
    config_write_to_callback_map_.erase(filename);
  }
  void OnChecksumRead(const std::string filename, std::string hash_value) {
    ASSERT(checksum_read_to_callback_map_.find(filename) != checksum_read_to_callback_map_.end());
    checksum_read_to_callback_map_[filename](hash_value);
    checksum_read_to_callback_map_.erase(filename);
  }
  void OnChecksumWrite(const std::string filename, bool success) {
    ASSERT(checksum_write_to_callback_map_.find(filename) != checksum_write_to_callback_map_.end());
    checksum_write_to_callback_map_[filename](success);
    checksum_write_to_callback_map_.erase(filename);
  }
  std::map<const std::string, ConfigReadCallback> config_read_to_callback_map_;
  std::map<const std::string, ConfigWriteCallback> config_write_to_callback_map_;
  std::map<const std::string, ChecksumReadCallback> checksum_read_to_callback_map_;
  std::map<const std::string, ChecksumWriteCallback> checksum_write_to_callback_map_;

  bluetooth::storage::LegacyModule* legacy_module_{nullptr};
  os::Handler* handler_;
};

const ModuleFactory Storage::Factory = ModuleFactory([]() { return new Storage(); });

Storage::impl::impl(bluetooth::storage::LegacyModule* storage_manager, os::Handler* handler)
    : legacy_module_(storage_manager), handler_(handler) {}

void Storage::impl::config_read(const std::string filename, ConfigReadCallback callback) {
  ASSERT(config_read_to_callback_map_.find(filename) == config_read_to_callback_map_.end());
  config_read_to_callback_map_[filename] = callback;
  legacy_module_->ConfigRead(filename, common::BindOnce(&Storage::impl::OnConfigRead, common::Unretained(this)),
                             handler_);
}

void Storage::impl::config_write(const std::string filename, const config_t* config, ConfigWriteCallback callback) {
  ASSERT(config_write_to_callback_map_.find(filename) == config_write_to_callback_map_.end());
  config_write_to_callback_map_[filename] = callback;
  legacy_module_->ConfigWrite(filename, *config,
                              common::BindOnce(&Storage::impl::OnConfigWrite, common::Unretained(this)), handler_);
}

void Storage::impl::checksum_read(const std::string filename, ChecksumReadCallback callback) {
  ASSERT(checksum_read_to_callback_map_.find(filename) == checksum_read_to_callback_map_.end());
  checksum_read_to_callback_map_[filename] = callback;
  legacy_module_->ChecksumRead(filename, common::BindOnce(&Storage::impl::OnChecksumRead, common::Unretained(this)),
                               handler_);
}

void Storage::impl::checksum_write(const std::string filename, const std::string& checksum,
                                   ChecksumWriteCallback callback) {
  ASSERT(checksum_write_to_callback_map_.find(filename) == checksum_write_to_callback_map_.end());
  checksum_write_to_callback_map_[filename] = callback;
  legacy_module_->ChecksumWrite(filename, checksum,
                                common::BindOnce(&Storage::impl::OnChecksumWrite, common::Unretained(this)), handler_);
}

void Storage::ConfigRead(const std::string filename, ConfigReadCallback callback) {
  GetHandler()->Post(
      common::BindOnce(&Storage::impl::config_read, common::Unretained(pimpl_.get()), filename, std::move(callback)));
}

void Storage::ConfigWrite(const std::string filename, const config_t* config, ConfigWriteCallback callback) {
  GetHandler()->Post(common::BindOnce(&Storage::impl::config_write, common::Unretained(pimpl_.get()), filename, config,
                                      std::move(callback)));
}

void Storage::ChecksumRead(const std::string filename, ChecksumReadCallback callback) {
  GetHandler()->Post(
      common::BindOnce(&Storage::impl::checksum_read, common::Unretained(pimpl_.get()), filename, std::move(callback)));
}

void Storage::ChecksumWrite(const std::string filename, const std::string& checksum, ChecksumWriteCallback callback) {
  GetHandler()->Post(common::BindOnce(&Storage::impl::checksum_write, common::Unretained(pimpl_.get()), filename,
                                      checksum, std::move(callback)));
}

/**
 * Module methods
 */
void Storage::ListDependencies(ModuleList* list) {
  list->add<bluetooth::storage::LegacyModule>();
}

void Storage::Start() {
  pimpl_ = std::make_unique<impl>(GetDependency<bluetooth::storage::LegacyModule>(), GetHandler());
}

void Storage::Stop() {
  pimpl_.reset();
}

std::string Storage::ToString() const {
  return kModuleName;
}

}  // namespace shim
}  // namespace bluetooth
