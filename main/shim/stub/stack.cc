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
#include <cstdint>
#include <future>

#include "gd/shim/only_include_this_file_into_legacy_stack___ever.h"
#include "main/shim/entry.h"
#include "main/shim/stub/stack.h"
#include "osi/include/log.h"

#define ASSERT(condition)                                    \
  do {                                                       \
    if (!(condition)) {                                      \
      LOG_ALWAYS_FATAL("assertion '" #condition "' failed"); \
    }                                                        \
  } while (false)

TestStack test_stack_;

bluetooth::shim::IStack* bluetooth::shim::GetGabeldorscheStack() {
  return (bluetooth::shim::IStack*)&test_stack_;
}

void TestGdShimL2cap::RegisterService(
    uint16_t psm, bool use_ertm, uint16_t mtu,
    bluetooth::shim::ConnectionOpenCallback on_open,
    std::promise<void> completed) {
  completed.set_value();
  registered_service_.insert(psm);
}

void TestGdShimL2cap::UnregisterService(uint16_t psm) {
  registered_service_.erase(psm);
}

void TestGdShimL2cap::CreateConnection(
    uint16_t psm, const std::string address,
    bluetooth::shim::ConnectionOpenCallback on_open,
    std::promise<uint16_t> completed) {
  completed.set_value(cid_);
}

void TestGdShimL2cap::CloseConnection(uint16_t cid) {}

void TestGdShimL2cap::SetReadDataReadyCallback(
    uint16_t cid, bluetooth::shim::ReadDataReadyCallback on_data_ready) {}

void TestGdShimL2cap::SetConnectionClosedCallback(
    uint16_t cid, bluetooth::shim::ConnectionClosedCallback on_closed) {}

void TestGdShimL2cap::Write(uint16_t cid, const uint8_t* data, size_t len) {
  ASSERT(data_buffer_ != nullptr);
  ASSERT(data_buffer_size_ > len);
  memcpy(data_buffer_, data, len);
}

void TestGdShimL2cap::WriteFlushable(uint16_t cid, const uint8_t* data,
                                     size_t len) {}

void TestGdShimL2cap::WriteNonFlushable(uint16_t cid, const uint8_t* data,
                                        size_t len) {}

void TestGdShimL2cap::SendLoopbackResponse(std::function<void()> function) {
  function();
}

void TestStack::Start() {}

void TestStack::Stop() {}

bluetooth::shim::IAdvertising* TestStack::GetAdvertising() { return nullptr; }

bluetooth::shim::IController* TestStack::GetController() { return nullptr; }

bluetooth::shim::IConnectability* TestStack::GetConnectability() {
  return nullptr;
}

bluetooth::shim::IDiscoverability* TestStack::GetDiscoverability() {
  return nullptr;
}

bluetooth::shim::IHciLayer* TestStack::GetHciLayer() { return nullptr; }

bluetooth::shim::IInquiry* TestStack::GetInquiry() { return nullptr; }

bluetooth::shim::IL2cap* TestStack::GetL2cap() { return &test_l2cap_; }

bluetooth::shim::IName* TestStack::GetName() { return nullptr; }

bluetooth::shim::IPage* TestStack::GetPage() { return nullptr; }

bluetooth::shim::IScanning* TestStack::GetScanning() { return nullptr; }
