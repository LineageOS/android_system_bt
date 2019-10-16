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

#define LOG_TAG "bt_gd"

#include "shim/stack.h"
#include "hal/hci_hal.h"
#include "hci/acl_manager.h"
#include "hci/classic_security_manager.h"
#include "l2cap/classic/l2cap_classic_module.h"
#include "l2cap/le/l2cap_le_module.h"
#include "os/log.h"
#include "os/thread.h"
#include "security/security_module.h"
#include "shim/controller.h"
#include "shim/hci_layer.h"
#include "stack_manager.h"

using ::bluetooth::os::Thread;

struct bluetooth::shim::Stack::impl {
  void Start() {
    if (is_running_) {
      LOG_ERROR("%s Gd stack already running", __func__);
      return;
    }

    LOG_INFO("%s Starting Gd stack", __func__);
    ModuleList modules;
    modules.add<::bluetooth::hal::HciHal>();
    modules.add<::bluetooth::hci::AclManager>();
    modules.add<::bluetooth::hci::ClassicSecurityManager>();
    modules.add<::bluetooth::l2cap::classic::L2capClassicModule>();
    modules.add<::bluetooth::l2cap::le::L2capLeModule>();
    modules.add<::bluetooth::shim::Controller>();
    modules.add<::bluetooth::shim::HciLayer>();
    modules.add<::bluetooth::security::SecurityModule>();

    stack_thread_ = new Thread("gd_stack_thread", Thread::Priority::NORMAL);
    stack_manager_.StartUp(&modules, stack_thread_);
    // TODO(cmanton) Gd stack has spun up another thread with no
    // ability to ascertain the completion
    is_running_ = true;
    LOG_INFO("%s Successfully toggled Gd stack", __func__);
  }

  void Stop() {
    if (!is_running_) {
      LOG_ERROR("%s Gd stack not running", __func__);
      return;
    }

    stack_manager_.ShutDown();
    delete stack_thread_;
    is_running_ = false;
    LOG_INFO("%s Successfully shut down Gd stack", __func__);
  }

  IController* GetController() {
    return stack_manager_.GetInstance<bluetooth::shim::Controller>();
  }

  IHciLayer* GetHciLayer() {
    return stack_manager_.GetInstance<bluetooth::shim::HciLayer>();
  }

 private:
  os::Thread* stack_thread_ = nullptr;
  bool is_running_ = false;
  StackManager stack_manager_;
};

bluetooth::shim::Stack::Stack() {
  pimpl_ = std::make_unique<impl>();
  LOG_INFO("%s Created gd stack", __func__);
}

void bluetooth::shim::Stack::Start() {
  pimpl_->Start();
}

void bluetooth::shim::Stack::Stop() {
  pimpl_->Stop();
}

bluetooth::shim::IController* bluetooth::shim::Stack::GetController() {
  return pimpl_->GetController();
}

bluetooth::shim::IHciLayer* bluetooth::shim::Stack::GetHciLayer() {
  return pimpl_->GetHciLayer();
}

bluetooth::shim::IStack* bluetooth::shim::GetGabeldorscheStack() {
  static IStack* instance = new Stack();
  return instance;
}
