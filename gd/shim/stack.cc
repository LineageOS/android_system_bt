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

#include "shim/stack.h"
#include "hal/hci_hal.h"
#include "hci/acl_manager.h"
#include "hci/classic_security_manager.h"
#include "hci/le_advertising_manager.h"
#include "hci/le_scanning_manager.h"
#include "l2cap/classic/l2cap_classic_module.h"
#include "l2cap/le/l2cap_le_module.h"
#include "neighbor/connectability.h"
#include "neighbor/discoverability.h"
#include "neighbor/inquiry.h"
#include "neighbor/name.h"
#include "neighbor/page.h"
#include "neighbor/scan.h"
#include "os/log.h"
#include "os/thread.h"
#include "security/security_module.h"
#include "shim/advertising.h"
#include "shim/connectability.h"
#include "shim/controller.h"
#include "shim/discoverability.h"
#include "shim/hci_layer.h"
#include "shim/inquiry.h"
#include "shim/l2cap.h"
#include "shim/name.h"
#include "shim/page.h"
#include "shim/scanning.h"
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
    modules.add<::bluetooth::hci::LeAdvertisingManager>();
    modules.add<::bluetooth::hci::LeScanningManager>();
    modules.add<::bluetooth::l2cap::classic::L2capClassicModule>();
    modules.add<::bluetooth::l2cap::le::L2capLeModule>();
    modules.add<::bluetooth::neighbor::ConnectabilityModule>();
    modules.add<::bluetooth::neighbor::DiscoverabilityModule>();
    modules.add<::bluetooth::neighbor::InquiryModule>();
    modules.add<::bluetooth::neighbor::NameModule>();
    modules.add<::bluetooth::neighbor::PageModule>();
    modules.add<::bluetooth::neighbor::ScanModule>();
    modules.add<::bluetooth::shim::Controller>();
    modules.add<::bluetooth::shim::HciLayer>();
    modules.add<::bluetooth::security::SecurityModule>();
    modules.add<::bluetooth::shim::Advertising>();
    modules.add<::bluetooth::shim::Connectability>();
    modules.add<::bluetooth::shim::Discoverability>();
    modules.add<::bluetooth::shim::Inquiry>();
    modules.add<::bluetooth::shim::Name>();
    modules.add<::bluetooth::shim::L2cap>();
    modules.add<::bluetooth::shim::Page>();
    modules.add<::bluetooth::shim::Scanning>();

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

  IAdvertising* GetAdvertising() {
    return stack_manager_.GetInstance<bluetooth::shim::Advertising>();
  }

  IController* GetController() {
    return stack_manager_.GetInstance<bluetooth::shim::Controller>();
  }

  IConnectability* GetConnectability() {
    return stack_manager_.GetInstance<bluetooth::shim::Connectability>();
  }

  IDiscoverability* GetDiscoverability() {
    return stack_manager_.GetInstance<bluetooth::shim::Discoverability>();
  }

  IHciLayer* GetHciLayer() {
    return stack_manager_.GetInstance<bluetooth::shim::HciLayer>();
  }

  IInquiry* GetInquiry() {
    return stack_manager_.GetInstance<bluetooth::shim::Inquiry>();
  }

  IL2cap* GetL2cap() {
    return stack_manager_.GetInstance<bluetooth::shim::L2cap>();
  }

  IName* GetName() {
    return stack_manager_.GetInstance<bluetooth::shim::Name>();
  }

  IPage* GetPage() {
    return stack_manager_.GetInstance<bluetooth::shim::Page>();
  }

  IScanning* GetScanning() {
    return stack_manager_.GetInstance<bluetooth::shim::Scanning>();
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

bluetooth::shim::IAdvertising* bluetooth::shim::Stack::GetAdvertising() {
  return pimpl_->GetAdvertising();
}

bluetooth::shim::IConnectability* bluetooth::shim::Stack::GetConnectability() {
  return pimpl_->GetConnectability();
}

bluetooth::shim::IController* bluetooth::shim::Stack::GetController() {
  return pimpl_->GetController();
}

bluetooth::shim::IDiscoverability* bluetooth::shim::Stack::GetDiscoverability() {
  return pimpl_->GetDiscoverability();
}

bluetooth::shim::IHciLayer* bluetooth::shim::Stack::GetHciLayer() {
  return pimpl_->GetHciLayer();
}

bluetooth::shim::IInquiry* bluetooth::shim::Stack::GetInquiry() {
  return pimpl_->GetInquiry();
}

bluetooth::shim::IL2cap* bluetooth::shim::Stack::GetL2cap() {
  return pimpl_->GetL2cap();
}

bluetooth::shim::IName* bluetooth::shim::Stack::GetName() {
  return pimpl_->GetName();
}

bluetooth::shim::IPage* bluetooth::shim::Stack::GetPage() {
  return pimpl_->GetPage();
}

bluetooth::shim::IScanning* bluetooth::shim::Stack::GetScanning() {
  return pimpl_->GetScanning();
}

bluetooth::shim::IStack* bluetooth::shim::GetGabeldorscheStack() {
  static IStack* instance = new Stack();
  return instance;
}
