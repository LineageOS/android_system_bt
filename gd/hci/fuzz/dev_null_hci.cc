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

#include "hci/fuzz/dev_null_hci.h"

using bluetooth::hci::AclPacketView;

namespace bluetooth {
namespace hci {
namespace fuzz {

const ModuleFactory DevNullHci::Factory = ModuleFactory([]() { return new DevNullHci(); });

void DevNullHci::Start() {
  hci_ = GetDependency<hci::HciLayer>();
  aclDevNull_ = new os::fuzz::DevNullQueue<AclPacketView>(hci_->GetAclQueueEnd(), GetHandler());
  aclDevNull_->Start();
  aclInject_ = new os::fuzz::FuzzInjectQueue<AclPacketBuilder>(hci_->GetAclQueueEnd(), GetHandler());
}

void DevNullHci::Stop() {
  aclDevNull_->Stop();
  delete aclDevNull_;
  delete aclInject_;
}

void DevNullHci::injectAclData(std::vector<uint8_t> data) {
  auto packet = packet::PacketView<packet::kLittleEndian>(std::make_shared<std::vector<uint8_t>>(data));
  hci::AclPacketView aclPacket = hci::AclPacketView::Create(packet);
  if (!aclPacket.IsValid()) {
    return;
  }

  aclInject_->Inject(AclPacketBuilder::FromView(aclPacket));
}

void DevNullHci::injectHciCommand(std::vector<uint8_t> data) {
  inject_command<CommandPacketView, CommandPacketBuilder>(data, hci_);
}

}  // namespace fuzz
}  // namespace hci
}  // namespace bluetooth
