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
#include <memory>
#include <string>

#include "module.h"

namespace bluetooth {
namespace shim {

using ReadRemoteNameDbCallback = std::function<void(std::string string_address, bool success)>;

class NameDb : public bluetooth::Module {
 public:
  void ReadRemoteNameDbRequest(std::string string_address, ReadRemoteNameDbCallback callback);

  bool IsNameCached(std::string string_address) const;
  std::array<uint8_t, 248> ReadCachedRemoteName(std::string string_address) const;

  NameDb() = default;
  ~NameDb() = default;

  static const ModuleFactory Factory;

 protected:
  void ListDependencies(ModuleList* list) override;  // Module
  void Start() override;                             // Module
  void Stop() override;                              // Module
  std::string ToString() const override;             // Module

 private:
  struct impl;
  std::unique_ptr<impl> pimpl_;
  DISALLOW_COPY_AND_ASSIGN(NameDb);
};

}  // namespace shim
}  // namespace bluetooth
