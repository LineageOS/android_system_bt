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
#include <memory>
#include <string>

#include "module.h"

/**
 * The hci layer shim module that depends on the Gd hci layer module.
 */
namespace bluetooth {
namespace shim {

/**
 * Legacy interface and API into the Gd shim hci layer module.
 */
using CommandCompleteCallback =
    std::function<void(uint16_t command_op_code, std::vector<const uint8_t> data, const void* token)>;
using CommandStatusCallback =
    std::function<void(uint16_t command_op_code, std::vector<const uint8_t> data, const void* token, uint8_t status)>;

class HciLayer : public ::bluetooth::Module {
 public:
  HciLayer() = default;
  ~HciLayer() = default;

  void TransmitCommand(uint16_t op_code, const uint8_t* data, size_t len, const void* token);

  void RegisterCommandComplete(CommandCompleteCallback callback);
  void UnregisterCommandComplete();

  void RegisterCommandStatus(CommandStatusCallback callback);
  void UnregisterCommandStatus();

  static const ModuleFactory Factory;

 protected:
  void ListDependencies(ModuleList* list) override;  // Module
  void Start() override;                             // Module
  void Stop() override;                              // Module
  std::string ToString() const override;             // Module

 private:
  struct impl;
  std::unique_ptr<impl> pimpl_;
  DISALLOW_COPY_AND_ASSIGN(HciLayer);
};

}  // namespace shim
}  // namespace bluetooth
