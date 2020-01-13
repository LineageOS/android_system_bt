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

#include <functional>
#include <memory>
#include <string>

struct config_t;

/**
 * The gd API exported to the legacy api
 */
namespace bluetooth {
namespace shim {

using ConfigReadCallback = std::function<void(std::unique_ptr<config_t>)>;
using ConfigWriteCallback = std::function<void(bool)>;
using ChecksumReadCallback = std::function<void(std::string)>;
using ChecksumWriteCallback = std::function<void(bool)>;

struct IStorage {
  virtual void ConfigRead(const std::string filename, ConfigReadCallback callback) = 0;
  virtual void ConfigWrite(const std::string filename, const config_t* config, ConfigWriteCallback callback) = 0;
  virtual void ChecksumRead(const std::string filename, ChecksumReadCallback callback) = 0;
  virtual void ChecksumWrite(const std::string filename, const std::string& checksum, ChecksumWriteCallback) = 0;

  virtual ~IStorage() {}
};

}  // namespace shim
}  // namespace bluetooth
