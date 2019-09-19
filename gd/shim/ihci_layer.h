/*
 * Copyright 2019 The Android Open Source Project
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

#include <cstdint>
#include <vector>

/**
 * Legacy interface and API into the Gd shim hci layer module.
 */
using CommandCompleteCallback =
    std::function<void(uint16_t command_op_code, std::vector<const uint8_t> data, const void* token)>;
using CommandStatusCallback =
    std::function<void(uint16_t command_op_code, std::vector<const uint8_t> data, const void* token, uint8_t status)>;

namespace bluetooth {
namespace shim {

struct IHciLayer {
  virtual void TransmitCommand(uint16_t op_code, const uint8_t* data, size_t len, const void* token) = 0;

  virtual void RegisterCommandComplete(CommandCompleteCallback callback) = 0;
  virtual void UnregisterCommandComplete() = 0;

  virtual void RegisterCommandStatus(CommandStatusCallback callback) = 0;
  virtual void UnregisterCommandStatus() = 0;

  virtual ~IHciLayer() {}
};

}  // namespace shim
}  // namespace bluetooth
