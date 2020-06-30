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

#define LOG_TAG "bt_gd_shim"

#include "gd/att/att_module.h"
#include "gd/hal/hci_hal.h"
#include "gd/hci/acl_manager.h"
#include "gd/hci/hci_layer.h"
#include "gd/hci/le_advertising_manager.h"
#include "gd/hci/le_scanning_manager.h"
#include "gd/l2cap/classic/l2cap_classic_module.h"
#include "gd/l2cap/le/l2cap_le_module.h"
#include "gd/neighbor/connectability.h"
#include "gd/neighbor/discoverability.h"
#include "gd/neighbor/inquiry.h"
#include "gd/neighbor/name.h"
#include "gd/neighbor/name_db.h"
#include "gd/neighbor/page.h"
#include "gd/neighbor/scan.h"
#include "gd/os/log.h"
#include "gd/os/thread.h"
#include "gd/security/security_module.h"
#include "gd/shim/dumpsys.h"
#include "gd/shim/l2cap.h"
#include "gd/stack_manager.h"
#include "gd/storage/storage_module.h"

#include "main/shim/stack.h"

namespace bluetooth {
namespace shim {

Stack* Stack::GetInstance() {
  static Stack instance;
  return &instance;
}

void Stack::Start() {
  if (is_running_) {
    LOG_ERROR("%s Gd stack already running", __func__);
    return;
  }

  LOG_INFO("%s Starting Gd stack", __func__);
  ModuleList modules;
  modules.add<att::AttModule>();
  modules.add<hal::HciHal>();
  modules.add<hci::AclManager>();
  modules.add<hci::HciLayer>();
  modules.add<hci::LeAdvertisingManager>();
  modules.add<hci::LeScanningManager>();
  modules.add<l2cap::classic::L2capClassicModule>();
  modules.add<l2cap::le::L2capLeModule>();
  modules.add<neighbor::ConnectabilityModule>();
  modules.add<neighbor::DiscoverabilityModule>();
  modules.add<neighbor::InquiryModule>();
  modules.add<neighbor::NameModule>();
  modules.add<neighbor::NameDbModule>();
  modules.add<neighbor::PageModule>();
  modules.add<neighbor::ScanModule>();
  modules.add<security::SecurityModule>();
  modules.add<storage::StorageModule>();
  modules.add<shim::Dumpsys>();
  modules.add<shim::L2cap>();

  stack_thread_ =
      new os::Thread("gd_stack_thread", os::Thread::Priority::NORMAL);
  stack_manager_.StartUp(&modules, stack_thread_);
  // Make sure the leaf modules are started
  ASSERT(stack_manager_.GetInstance<shim::L2cap>() != nullptr);
  ASSERT(stack_manager_.GetInstance<shim::Dumpsys>() != nullptr);

  stack_handler_ = new os::Handler(stack_thread_);

  btm_ = new Btm(stack_handler_,
                 stack_manager_.GetInstance<neighbor::InquiryModule>());

  is_running_ = true;

  LOG_INFO("%s Successfully toggled Gd stack", __func__);
}

void Stack::Stop() {
  if (!is_running_) {
    LOG_ERROR("%s Gd stack not running", __func__);
    return;
  }

  delete btm_;
  btm_ = nullptr;

  stack_handler_->Clear();
  delete stack_handler_;
  stack_handler_ = nullptr;

  stack_manager_.ShutDown();
  stack_thread_->Stop();
  delete stack_thread_;
  stack_thread_ = nullptr;

  is_running_ = false;
  LOG_INFO("%s Successfully shut down Gd stack", __func__);
}

bool Stack::IsRunning() { return is_running_; }

StackManager* Stack::GetStackManager() {
  ASSERT(is_running_);
  return &stack_manager_;
}

Btm* Stack::GetBtm() {
  ASSERT(is_running_);
  return btm_;
}

os::Handler* Stack::GetHandler() {
  ASSERT(is_running_);
  return stack_handler_;
}

}  // namespace shim
}  // namespace bluetooth
