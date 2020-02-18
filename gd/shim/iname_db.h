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
#include <cstdint>
#include <functional>
#include <string>

/**
 * The gd API exported to the legacy api
 */
using ReadRemoteNameDbCallback = std::function<void(std::string string_address, bool success)>;

namespace bluetooth {
namespace shim {

struct INameDb {
  virtual void ReadRemoteNameDbRequest(std::string string_address, ReadRemoteNameDbCallback callback) = 0;

  virtual bool IsNameCached(std::string string_address) const = 0;
  virtual std::array<uint8_t, 248> ReadCachedRemoteName(std::string string_address) const = 0;

  virtual ~INameDb() {}
};

}  // namespace shim
}  // namespace bluetooth
