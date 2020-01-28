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
#include <set>

#include "gd/shim/only_include_this_file_into_legacy_stack___ever.h"
#include "main/shim/entry.h"

class TestGdShimL2cap : public bluetooth::shim::IL2cap {
 public:
  uint16_t cid_{0};
  bool write_success_{false};
  bool is_congested_{false};
  uint8_t* data_buffer_{nullptr};
  size_t data_buffer_size_{0};
  std::set<uint16_t /* psm */> registered_service_;

  void RegisterService(
      uint16_t psm, bool use_ertm, uint16_t mtu,
      bluetooth::shim::ConnectionCompleteCallback on_complete,
      bluetooth::shim::RegisterServicePending register_pending) override;
  void UnregisterService(
      uint16_t psm,
      bluetooth::shim::UnregisterServicePending unregister_pending) override;

  void CreateConnection(
      uint16_t psm, const std::string address_string,
      bluetooth::shim::ConnectionCompleteCallback on_complete,
      bluetooth::shim::CreateConnectionPending create_pending) override;

  void CloseConnection(uint16_t cid);
  void SetReadDataReadyCallback(
      uint16_t cid,
      bluetooth::shim::ReadDataReadyCallback on_data_ready) override;
  void SetConnectionClosedCallback(
      uint16_t cid,
      bluetooth::shim::ConnectionClosedCallback on_closed) override;
  void Write(uint16_t cid, const uint8_t* data, size_t len) override;
  void SendLoopbackResponse(std::function<void()>) override;
};

class TestStack : public bluetooth::shim::IStack {
 public:
  TestStack() = default;

  bluetooth::shim::IAdvertising* GetAdvertising();
  bluetooth::shim::IController* GetController();
  bluetooth::shim::IConnectability* GetConnectability();
  bluetooth::shim::IDiscoverability* GetDiscoverability();
  bluetooth::shim::IDumpsys* GetDumpsys();
  bluetooth::shim::IHciLayer* GetHciLayer();
  bluetooth::shim::IInquiry* GetInquiry();
  bluetooth::shim::IL2cap* GetL2cap();
  bluetooth::shim::IName* GetName();
  bluetooth::shim::IPage* GetPage();
  bluetooth::shim::IScanning* GetScanning();
  bluetooth::shim::ISecurity* GetSecurity();
  bluetooth::shim::IStorage* GetStorage();

  TestGdShimL2cap test_l2cap_;

  void Start();
  void Stop();
};

extern TestStack test_stack_;
