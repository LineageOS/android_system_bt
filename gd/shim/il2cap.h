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
#include <future>
#include <string>
#include <vector>

/**
 * The gd API exported to the legacy api
 */
namespace bluetooth {
namespace shim {

using OnReadDataReady = std::function<void(uint16_t cid, std::vector<const uint8_t> data)>;
using OnClose = std::function<void(int error_code)>;

struct IL2cap {
  virtual void RegisterService(uint16_t psm, bool snoop_enabled, std::promise<void> completed) = 0;
  virtual void Connect(uint16_t psm, const std::string address, std::promise<uint16_t> completed) = 0;

  virtual void SetOnReadDataReady(uint16_t cid, OnReadDataReady on_data_ready) = 0;
  virtual bool Write(uint16_t cid, const uint8_t* data, size_t len) = 0;
  virtual bool WriteFlushable(uint16_t cid, const uint8_t* data, size_t len) = 0;
  virtual bool WriteNonFlushable(uint16_t cid, const uint8_t* data, size_t len) = 0;

  virtual void SetOnClose(uint16_t cid, OnClose on_close) = 0;

  virtual bool IsCongested(uint16_t cid) = 0;
  virtual ~IL2cap() {}
};

}  // namespace shim
}  // namespace bluetooth
