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

#include "storage/config_cache.h"

namespace bluetooth {
namespace storage {

// A thin wrapper around ConfigCache and implement more type supports other than std::string
//
// - all SetX methods accept value as copy and std::move() in encouraged
// - all GetX methods return std::optional<X> and std::nullopt if not exist. std::optional<> can be treated as bool
class ConfigCacheHelper {
 public:
  static ConfigCacheHelper FromConfigCache(ConfigCache& config_cache) {
    return ConfigCacheHelper(config_cache);
  }
  explicit ConfigCacheHelper(ConfigCache& config_cache) : config_cache_(config_cache) {}
  virtual ~ConfigCacheHelper() = default;
  virtual void SetBool(const std::string& section, const std::string& property, bool value);
  virtual std::optional<bool> GetBool(const std::string& section, const std::string& property) const;
  virtual void SetUint64(const std::string& section, const std::string& property, uint64_t value);
  virtual std::optional<uint64_t> GetUint64(const std::string& section, const std::string& property) const;
  virtual void SetInt(const std::string& section, const std::string& property, int value);
  virtual std::optional<int> GetInt(const std::string& section, const std::string& property) const;
  virtual void SetBin(const std::string& section, const std::string& property, const std::vector<uint8_t>& value);
  virtual std::optional<std::vector<uint8_t>> GetBin(const std::string& section, const std::string& property) const;

 private:
  ConfigCache& config_cache_;
};

}  // namespace storage
}  // namespace bluetooth
