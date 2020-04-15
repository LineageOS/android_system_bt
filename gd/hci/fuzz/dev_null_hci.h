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

#include <stddef.h>
#include <stdint.h>
#include "hci/fuzz/status_vs_complete_commands.h"
#include "hci/hci_layer.h"
#include "hci/hci_packets.h"
#include "module.h"
#include "os/fuzz/dev_null_queue.h"
#include "os/fuzz/fuzz_inject_queue.h"

namespace bluetooth {
namespace hci {
namespace fuzz {

class DevNullHci : public Module {
 public:
  DevNullHci() : Module() {}

  void Start() override;
  void Stop() override;

  void injectAclData(std::vector<uint8_t> data);

  void injectHciCommand(std::vector<uint8_t> data);

  void ListDependencies(ModuleList* list) override {
    list->add<hci::HciLayer>();
  }

  static const ModuleFactory Factory;

  std::string ToString() const override {
    return "DevNullHci";
  }

 private:
  template <typename TVIEW, typename TBUILDER>
  void inject_command(std::vector<uint8_t> data, CommandInterface<TBUILDER>* interface) {
    auto packet = packet::PacketView<packet::kLittleEndian>(std::make_shared<std::vector<uint8_t>>(data));
    TVIEW commandPacket = TVIEW::Create(packet);
    if (!commandPacket.IsValid()) {
      return;
    }

    if (uses_command_status(commandPacket.GetOpCode())) {
      interface->EnqueueCommand(TBUILDER::FromView(commandPacket), common::BindOnce([](CommandStatusView status) {}),
                                GetHandler());
    } else {
      interface->EnqueueCommand(TBUILDER::FromView(commandPacket), common::BindOnce([](CommandCompleteView status) {}),
                                GetHandler());
    }
  }

  hci::HciLayer* hci_ = nullptr;
  os::fuzz::DevNullQueue<AclPacketView>* aclDevNull_;
  os::fuzz::FuzzInjectQueue<AclPacketBuilder>* aclInject_;
};

}  // namespace fuzz
}  // namespace hci
}  // namespace bluetooth
