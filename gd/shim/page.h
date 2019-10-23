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

#include "module.h"
#include "shim/ipage.h"

namespace bluetooth {
namespace shim {

class Page : public bluetooth::Module, public bluetooth::shim::IPage {
 public:
  void SetScanActivity(uint16_t interval, uint16_t window) override;
  void GetScanActivity(uint16_t& interval, uint16_t& window) const override;

  void SetInterlacedScan() override;
  void SetStandardScan() override;

  Page() = default;
  ~Page() = default;

  static const ModuleFactory Factory;

 protected:
  void ListDependencies(ModuleList* list) override;  // Module
  void Start() override;                             // Module
  void Stop() override;                              // Module

 private:
  struct impl;
  std::unique_ptr<impl> pimpl_;
  DISALLOW_COPY_AND_ASSIGN(Page);
};

}  // namespace shim
}  // namespace bluetooth
