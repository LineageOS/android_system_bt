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
#include "shim/ihci_layer.h"

/**
 * The hci layer shim module that depends on the Gd hci layer module.
 */
namespace bluetooth {
namespace shim {

class HciLayer : public ::bluetooth::Module, public ::bluetooth::shim::IHciLayer {
 public:
  HciLayer() = default;
  ~HciLayer() = default;

  void TransmitCommand(uint16_t op_code, const uint8_t* data, size_t len,
                       const void* token);  // IHciLayer

  void RegisterCommandComplete(CommandCompleteCallback callback);  // IHciLayer
  void UnregisterCommandComplete();                                // IHciLayer

  void RegisterCommandStatus(CommandStatusCallback callback);  // IHciLayer
  void UnregisterCommandStatus();                              // IHciLayer

  static const ModuleFactory Factory;

 protected:
  void ListDependencies(ModuleList* list) override;  // Module
  void Start() override;                             // Module
  void Stop() override;                              // Module

 private:
  struct impl;
  std::unique_ptr<impl> pimpl_;
  DISALLOW_COPY_AND_ASSIGN(HciLayer);
};

}  // namespace shim
}  // namespace bluetooth
