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

#include <stddef.h>
#include <stdint.h>
#include "hci/hci_layer.h"
#include "hci/hci_packets.h"
#include "module.h"
#include "os/fuzz/dev_null_queue.h"
#include "os/fuzz/fuzz_inject_queue.h"

using bluetooth::hci::AclPacketView;
using bluetooth::hci::HciLayer;
using bluetooth::os::fuzz::DevNullQueue;
using bluetooth::os::fuzz::FuzzInjectQueue;

namespace bluetooth {
namespace hci {
namespace fuzz {

class DevNullHci : public Module {
 public:
  DevNullHci() : Module() {}

  void Start() override {
    hci_ = GetDependency<HciLayer>();
    aclDevNull_ = new DevNullQueue<AclPacketView>(hci_->GetAclQueueEnd(), GetHandler());
    aclDevNull_->Start();
    aclInject_ = new FuzzInjectQueue<AclPacketBuilder>(hci_->GetAclQueueEnd(), GetHandler());
  }

  void Stop() override {
    aclDevNull_->Stop();
    delete aclDevNull_;
    delete aclInject_;
  }

  void injectAclData(std::vector<uint8_t> data) {
    auto packet = packet::PacketView<packet::kLittleEndian>(std::make_shared<std::vector<uint8_t>>(data));
    hci::AclPacketView aclPacket = hci::AclPacketView::Create(packet);
    if (!aclPacket.IsValid()) {
      return;
    }

    aclInject_->Inject(AclPacketBuilder::FromView(aclPacket));
  }

  void ListDependencies(ModuleList* list) override {
    list->add<HciLayer>();
  }

  static const ModuleFactory Factory;

  std::string ToString() const override {
    return "DevNullHci";
  }

 private:
  HciLayer* hci_ = nullptr;
  DevNullQueue<AclPacketView>* aclDevNull_;
  FuzzInjectQueue<AclPacketBuilder>* aclInject_;
};

const ModuleFactory DevNullHci::Factory = ModuleFactory([]() { return new DevNullHci(); });

}  // namespace fuzz
}  // namespace hci
}  // namespace bluetooth
