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
// Authors: corbin.souffrant@leviathansecurity.com
//          dylan.katz@leviathansecurity.com

#pragma once

#include <fuzzer/FuzzedDataProvider.h>
#include <gd/l2cap/classic/internal/dynamic_channel_service_manager_impl.h>
#include <gd/l2cap/classic/internal/fixed_channel_service_manager_impl.h>
#include <gd/l2cap/classic/internal/link_manager.h>
#include <gd/l2cap/internal/parameter_provider.h>
#include <gd/shim/l2cap.h>
#include <future>
#include <memory>

#include "hci/fuzz/fuzz_hci_layer.h"
#include "l2cap/classic/l2cap_classic_module.h"
#include "os/handler.h"

#include "fuzz_l2cap_classic_module.h"

namespace bluetooth {

namespace shim {
namespace {
class ShimL2capFuzz {
 public:
  void OnConnectionComplete(std::string string_address, uint16_t psm, uint16_t cid, bool connected) {
    connection_string_address_ = string_address;
    connection_psm_ = psm;
    connection_cid_ = cid;
    connection_connected_ = connected;
    connection_complete_promise_.set_value();
  }

  uint16_t CreateConnection(uint16_t psm, std::string device_address) {
    std::promise<uint16_t> promise;
    auto future = promise.get_future();

    shim_l2cap_->CreateClassicConnection(
        psm,
        device_address,
        std::bind(
            &shim::ShimL2capFuzz::OnConnectionComplete,
            this,
            std::placeholders::_1,
            std::placeholders::_2,
            std::placeholders::_3,
            std::placeholders::_4),
        std::move(promise));
    return future.get();
  }

  ShimL2capFuzz(FuzzedDataProvider* fdp) {
    hci::fuzz::FuzzHciLayer* fuzzHci = fake_registry_.Inject<hci::fuzz::FuzzHciLayer>(&hci::HciLayer::Factory);
    fuzz_l2cap_classic_module_ = new FuzzL2capClassicModule();
    fake_registry_.InjectTestModule(&l2cap::classic::L2capClassicModule::Factory, fuzz_l2cap_classic_module_);
    fake_registry_.Start<shim::L2cap>();

    // The autoreply is needed to prevent it from hanging.
    fuzzHci->TurnOnAutoReply(fdp);
    acl_manager_ = fake_registry_.Start<hci::AclManager>();
    fuzzHci->TurnOffAutoReply();
    shim_l2cap_ = static_cast<shim::L2cap*>(fake_registry_.GetModuleUnderTest(&shim::L2cap::Factory));

    // Create the LinkManager
    handler_ = std::unique_ptr<os::Handler>(new os::Handler(&thread_));
    dynamic_channel_impl = std::unique_ptr<l2cap::classic::internal::DynamicChannelServiceManagerImpl>(
        new l2cap::classic::internal::DynamicChannelServiceManagerImpl(handler_.get()));
    fixed_channel_impl = std::unique_ptr<l2cap::classic::internal::FixedChannelServiceManagerImpl>(
        new l2cap::classic::internal::FixedChannelServiceManagerImpl(handler_.get()));
    parameter_provider = std::unique_ptr<l2cap::internal::ParameterProvider>(new l2cap::internal::ParameterProvider());
    link_manager = std::unique_ptr<l2cap::classic::internal::LinkManager>(new l2cap::classic::internal::LinkManager(
        handler_.get(), acl_manager_, fixed_channel_impl.get(), dynamic_channel_impl.get(), parameter_provider.get()));
  }

  ~ShimL2capFuzz() {
    handler_->Clear();
  }

  void stopRegistry() {
    fake_registry_.WaitForIdleAndStopAll();
  }

  std::string connection_string_address_;
  uint16_t connection_psm_{0};
  uint16_t connection_cid_{1000};
  bool connection_connected_{false};
  std::promise<void> connection_complete_promise_;

  shim::L2cap* shim_l2cap_{nullptr};
  FuzzL2capClassicModule* fuzz_l2cap_classic_module_{nullptr};
  hci::AclManager* acl_manager_{nullptr};

  std::unique_ptr<os::Handler> handler_;
  std::unique_ptr<l2cap::classic::internal::FixedChannelServiceManagerImpl> fixed_channel_impl;
  std::unique_ptr<l2cap::classic::internal::DynamicChannelServiceManagerImpl> dynamic_channel_impl;
  std::unique_ptr<l2cap::classic::internal::LinkManager> link_manager;
  std::unique_ptr<l2cap::internal::ParameterProvider> parameter_provider;

 private:
  FuzzTestModuleRegistry fake_registry_;
  os::Thread& thread_ = fake_registry_.GetTestThread();
};
}  // namespace
}  // namespace shim
}  // namespace bluetooth
