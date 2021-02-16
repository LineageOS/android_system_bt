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

#define LOG_TAG "bt_headless_mode"

#include <inttypes.h>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <future>
#include <map>
#include <string>

#include "base/logging.h"  // LOG() stdout and android log
#include "btif/include/stack_manager.h"
#include "osi/include/log.h"  // android log only
#include "stack/include/btm_api.h"
#include "stack/include/btm_api_types.h"
#include "stack/include/hci_error_code.h"
#include "stack/include/l2cap_acl_interface.h"
#include "test/headless/connect/connect.h"
#include "test/headless/get_options.h"
#include "test/headless/headless.h"
#include "test/headless/interface.h"
#include "types/raw_address.h"

const stack_manager_t* stack_manager_get_interface();
extern bt_interface_t bluetoothInterface;

void power_mode_callback(const RawAddress& p_bda, tBTM_PM_STATUS status,
                         uint16_t value, tHCI_STATUS hci_status) {
  fprintf(stdout, "Got callback\n");
};

std::promise<acl_state_changed_params_t> acl_state_changed_promise;

void callback_interface(interface_data_t data) {
  if (data.name == "acl_state_changed") {
    LOG(INFO) << "Received acl state changed";
    acl_state_changed_params_t p{
        .status = BT_STATUS_SUCCESS,
        .remote_bd_addr = nullptr,
        .state = BT_ACL_STATE_CONNECTED,
    };
    acl_state_changed_promise.set_value(p);
    return;
  }
  LOG(ERROR) << "Received unexpected interface callback";
}

namespace {

int do_connect(unsigned int num_loops, const RawAddress& bd_addr,
               std::list<std::string> options) {
  int disconnect_wait_time{0};

  if (options.size() != 0) {
    std::string opt = options.front();
    options.pop_front();
    auto v = bluetooth::test::headless::GetOpt::Split(opt);
    if (v.size() == 2) {
      if (v[0] == "wait") disconnect_wait_time = std::stoi(v[1]);
    }
  }
  ASSERT_LOG(disconnect_wait_time >= 0, "Time cannot go backwards");

  headless_add_callback("acl_state_changed", callback_interface);

  acl_state_changed_promise = std::promise<acl_state_changed_params_t>();
  auto future = acl_state_changed_promise.get_future();

  fprintf(stdout, "Creating connection to:%s\n", bd_addr.ToString().c_str());
  LOG(INFO) << "Creating classic connection to " << bd_addr.ToString();
  acl_create_classic_connection(bd_addr, false, false);

  acl_state_changed_params_t result = future.get();
  fprintf(stdout, "Connected created to:%s result:%s[%u]\n",
          bd_addr.ToString().c_str(), bt_status_text(result.status).c_str(),
          result.status);
  acl_state_changed_promise = std::promise<acl_state_changed_params_t>();
  future = acl_state_changed_promise.get_future();

  uint64_t connect = std::chrono::duration_cast<std::chrono::milliseconds>(
                         std::chrono::system_clock::now().time_since_epoch())
                         .count();

  fprintf(stdout, "Just crushing stack\n");
  LOG(INFO) << "Just crushing stack";
  stack_manager_get_interface()->clean_up_stack();

  if (disconnect_wait_time == 0) {
    fprintf(stdout, "Waiting to disconnect from supervision timeout\n");
    result = future.get();
    uint64_t disconnect =
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch())
            .count();

    fprintf(stdout, "Disconnected after:%" PRId64 "ms from:%s result:%s[%u]\n",
            disconnect - connect, bd_addr.ToString().c_str(),
            bt_status_text(result.status).c_str(), result.status);

    headless_remove_callback("acl_state_changed", callback_interface);
  } else {
    fprintf(stdout, "Waiting %d seconds to just shutdown\n",
            disconnect_wait_time);
    sleep(disconnect_wait_time);
    bluetoothInterface.dump(1, nullptr);
    bluetoothInterface.cleanup();
  }
  return 0;
}

}  // namespace

int bluetooth::test::headless::Connect::Run() {
  return RunOnHeadlessStack<int>([this]() {
    return do_connect(options_.loop_, options_.device_.front(),
                      options_.non_options_);
  });
}
