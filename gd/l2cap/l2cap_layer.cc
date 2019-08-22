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
#define LOG_TAG "l2cap2"

#include <memory>

#include "common/bidi_queue.h"
#include "hci/acl_manager.h"
#include "hci/address.h"
#include "hci/hci_packets.h"
#include "l2cap/internal/classic_fixed_channel_service_manager_impl.h"
#include "l2cap/internal/classic_link_manager.h"
#include "module.h"
#include "os/handler.h"
#include "os/log.h"

#include "l2cap/l2cap_layer.h"

namespace bluetooth {
namespace l2cap {

const ModuleFactory L2capLayer::Factory = ModuleFactory([]() { return new L2capLayer(); });

struct L2capLayer::impl {
  impl(os::Handler* handler, hci::AclManager* acl_manager) : handler_(handler), acl_manager_(acl_manager) {}
  os::Handler* handler_;
  hci::AclManager* acl_manager_;
  internal::ClassicFixedChannelServiceManagerImpl classic_fixed_channel_service_manager_impl_{handler_};
  internal::ClassicLinkManager classic_link_manager_{handler_, acl_manager_,
                                                     &classic_fixed_channel_service_manager_impl_};
};

void L2capLayer::ListDependencies(ModuleList* list) {
  list->add<hci::AclManager>();
}

void L2capLayer::Start() {
  pimpl_ = std::make_unique<impl>(GetHandler(), GetDependency<hci::AclManager>());
}

void L2capLayer::Stop() {
  pimpl_.reset();
}

std::unique_ptr<ClassicFixedChannelManager> L2capLayer::GetClassicFixedChannelManager() {
  return std::unique_ptr<ClassicFixedChannelManager>(new ClassicFixedChannelManager(
      &pimpl_->classic_fixed_channel_service_manager_impl_, &pimpl_->classic_link_manager_, pimpl_->handler_));
}

}  // namespace l2cap
}  // namespace bluetooth