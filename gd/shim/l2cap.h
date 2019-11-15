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
#include <future>
#include <memory>
#include <string>

#include "module.h"
#include "shim/il2cap.h"

namespace bluetooth {
namespace shim {

class L2cap : public bluetooth::Module, public bluetooth::shim::IL2cap {
 public:
  void RegisterService(uint16_t psm, ConnectionOpenCallback on_open, std::promise<void> completed) override;
  void UnregisterService(uint16_t psm) override;

  void CreateConnection(uint16_t psm, const std::string address_string, ConnectionOpenCallback on_open,
                        std::promise<uint16_t> completed) override;
  void CloseConnection(uint16_t cid) override;

  void SetReadDataReadyCallback(uint16_t cid, ReadDataReadyCallback on_data_ready) override;
  void SetConnectionClosedCallback(uint16_t cid, ConnectionClosedCallback on_closed) override;

  void Write(uint16_t cid, const uint8_t* data, size_t len) override;
  void WriteFlushable(uint16_t cid, const uint8_t* data, size_t len) override;
  void WriteNonFlushable(uint16_t cid, const uint8_t* data, size_t len) override;

  void SendLoopbackResponse(std::function<void()>) override;

  L2cap() = default;
  ~L2cap() = default;

  static const ModuleFactory Factory;

 protected:
  void ListDependencies(ModuleList* list) override;  // Module
  void Start() override;                             // Module
  void Stop() override;                              // Module

 private:
  struct impl;
  std::unique_ptr<impl> pimpl_;
  DISALLOW_COPY_AND_ASSIGN(L2cap);
};

}  // namespace shim
}  // namespace bluetooth
