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
#include "os/fuzzing/dev_null_queue.h"

using bluetooth::hci::AclPacketView;
using bluetooth::hci::HciLayer;
using bluetooth::os::fuzzing::DevNullQueue;

namespace bluetooth {
namespace hci {
namespace fuzzing {

class DevNullHci : public Module {
 public:
  DevNullHci() : Module() {}

  void Start() override {
    hci_ = GetDependency<HciLayer>();
    aclDevNull_ = new DevNullQueue<AclPacketView>(hci_->GetAclQueueEnd(), GetHandler());
    aclDevNull_->Start();
  }

  void Stop() override {
    aclDevNull_->Stop();
    delete aclDevNull_;
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
};

const ModuleFactory DevNullHci::Factory = ModuleFactory([]() { return new DevNullHci(); });

}  // namespace fuzzing
}  // namespace hci
}  // namespace bluetooth
