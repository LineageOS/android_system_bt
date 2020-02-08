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
namespace bluetooth {
namespace shim {

using SimplePairingCallback = std::function<bool(std::string address, uint32_t value, bool just_works)>;

struct ISecurity {
  virtual void CreateBond(std::string address) = 0;
  virtual void CreateBondLe(std::string address, uint8_t address_type) = 0;
  virtual void CancelBond(std::string address) = 0;
  virtual void RemoveBond(std::string address) = 0;

  virtual void SetSimplePairingCallback(SimplePairingCallback callback) = 0;

  virtual ~ISecurity() {}
};

}  // namespace shim
}  // namespace bluetooth
