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

#include <memory>
#include <string>

#include "module.h"
#include "shim/icontroller.h"

/**
 * Gd shim controller module that depends upon the Gd controller module.
 *
 * Wraps the Gd controller module to expose a sufficient API to allow
 * proper operation of the legacy shim controller interface.
 *
 */
namespace bluetooth {
namespace shim {

class Controller : public bluetooth::Module, public bluetooth::shim::IController {
 public:
  Controller() = default;
  ~Controller() = default;

  static const ModuleFactory Factory;

  // Exported controller methods from IController for shim layer
  bool IsCommandSupported(int op_code) const override;
  LeBufferSize GetControllerLeBufferSize() const override;
  LeMaximumDataLength GetControllerLeMaximumDataLength() const override;
  std::string GetControllerMacAddress() const override;
  uint16_t GetControllerAclPacketLength() const override;
  uint16_t GetControllerNumAclPacketBuffers() const override;
  uint64_t GetControllerLeLocalSupportedFeatures() const override;
  uint64_t GetControllerLeSupportedStates() const override;
  uint64_t GetControllerLocalExtendedFeatures(uint8_t page_number) const override;
  uint8_t GetControllerLeNumberOfSupportedAdverisingSets() const override;
  uint8_t GetControllerLocalExtendedFeaturesMaxPageNumber() const override;

 protected:
  void ListDependencies(ModuleList* list) override;  // Module
  void Start() override;                             // Module
  void Stop() override;                              // Module

 private:
  struct impl;
  std::unique_ptr<impl> pimpl_;
  DISALLOW_COPY_AND_ASSIGN(Controller);
};

}  // namespace shim
}  // namespace bluetooth
