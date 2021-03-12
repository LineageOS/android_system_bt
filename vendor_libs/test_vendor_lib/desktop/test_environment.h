//
// Copyright 2017 The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

#pragma once

#include <future>

#include "model/controller/dual_mode_controller.h"
#include "model/setup/async_manager.h"
#include "model/setup/test_channel_transport.h"
#include "model/setup/test_command_handler.h"
#include "model/setup/test_model.h"

namespace android {
namespace bluetooth {
namespace root_canal {

class TestEnvironment {
 public:
  TestEnvironment(uint16_t test_port, uint16_t hci_server_port,
                  uint16_t link_server_port,
                  const std::string& controller_properties_file = "",
                  const std::string& default_commands_file = "")
      : test_port_(test_port),
        hci_server_port_(hci_server_port),
        link_server_port_(link_server_port),
        default_commands_file_(default_commands_file),
        controller_(std::make_shared<test_vendor_lib::DualModeController>(
            controller_properties_file)) {}

  void initialize(std::promise<void> barrier);

  void close();

 private:
  uint16_t test_port_;
  uint16_t hci_server_port_;
  uint16_t link_server_port_;
  std::string default_commands_file_;
  std::promise<void> barrier_;

  test_vendor_lib::AsyncManager async_manager_;

  void SetUpTestChannel();
  void SetUpHciServer(const std::function<void(int)>& on_connect);
  void SetUpLinkLayerServer(const std::function<void(int)>& on_connect);
  int ConnectToRemoteServer(const std::string& server, int port);

  std::shared_ptr<test_vendor_lib::DualModeController> controller_;

  test_vendor_lib::TestChannelTransport test_channel_transport_;
  test_vendor_lib::TestChannelTransport remote_hci_transport_;
  test_vendor_lib::TestChannelTransport remote_link_layer_transport_;

  test_vendor_lib::TestModel test_model_{
      [this]() { return async_manager_.GetNextUserId(); },
      [this](test_vendor_lib::AsyncUserId user_id,
             std::chrono::milliseconds delay,
             const test_vendor_lib::TaskCallback& task) {
        return async_manager_.ExecAsync(user_id, delay, task);
      },

      [this](test_vendor_lib::AsyncUserId user_id,
             std::chrono::milliseconds delay, std::chrono::milliseconds period,
             const test_vendor_lib::TaskCallback& task) {
        return async_manager_.ExecAsyncPeriodically(user_id, delay, period,
                                                    task);
      },

      [this](test_vendor_lib::AsyncUserId user) {
        async_manager_.CancelAsyncTasksFromUser(user);
      },

      [this](test_vendor_lib::AsyncTaskId task) {
        async_manager_.CancelAsyncTask(task);
      },

      [this](const std::string& server, int port) {
        return ConnectToRemoteServer(server, port);
      }};

  test_vendor_lib::TestCommandHandler test_channel_{test_model_};
};

}  // namespace root_canal
}  // namespace bluetooth
}  // namespace android
