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
#include <functional>
#include <string>

/**
 * The gd API exported to the legacy api
 */
using ReadRemoteNameCallback =
    std::function<void(std::string address_string, uint8_t hci_status, std::array<uint8_t, 248> remote_name)>;
using CancelRemoteNameCallback = std::function<void(std::string address_string, uint8_t hci_status)>;

namespace bluetooth {
namespace shim {

struct IName {
  virtual void ReadRemoteNameRequest(std::string remote_address, ReadRemoteNameCallback callback) = 0;
  virtual void CancelRemoteNameRequest(std::string remote_address, CancelRemoteNameCallback callback) = 0;

  virtual ~IName() {}
};

}  // namespace shim
}  // namespace bluetooth
