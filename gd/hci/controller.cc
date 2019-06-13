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

#include "hci/controller.h"

#include <future>
#include <memory>
#include <utility>

#include "common/bind.h"
#include "common/callback.h"
#include "hci/hci_layer.h"

namespace bluetooth {
namespace hci {

using common::Bind;
using common::BindOnce;
using common::Callback;
using common::Closure;
using common::OnceCallback;
using common::OnceClosure;
using os::Handler;

struct Controller::impl {
  impl(Controller& module) : module_(module) {}

  void Start(hci::HciLayer* hci) {
    hci_ = hci;
    std::promise<void> promise;
    auto future = promise.get_future();
    hci_->RegisterEventHandler(EventCode::NUMBER_OF_COMPLETED_PACKETS,
                               Bind(&Controller::impl::NumberOfCompletedPackets, common::Unretained(this)),
                               module_.GetHandler());
    hci_->EnqueueCommand(
        ReadBufferSizeBuilder::Create(),
        BindOnce(&Controller::impl::read_buffer_size_complete_handler, common::Unretained(this), std::move(promise)),
        module_.GetHandler());
    future.wait();
  }

  void Stop() {
    hci_->UnregisterEventHandler(EventCode::NUMBER_OF_COMPLETED_PACKETS);
    hci_ = nullptr;
  }

  void NumberOfCompletedPackets(EventPacketView event) {
    ASSERT(acl_credits_handler_ != nullptr);
    auto complete_view = NumberOfCompletedPacketsView::Create(event);
    ASSERT(complete_view.IsValid());
    for (auto completed_packets : complete_view.GetHandlesAndCompletedPackets()) {
      uint16_t handle = completed_packets & 0x0fff;
      uint16_t credits = (completed_packets & 0xffff0000) >> 16;
      acl_credits_handler_->Post(Bind(acl_credits_callback_, handle, credits));
    }
  }

  void RegisterCompletedAclPacketsCallback(Callback<void(uint16_t /* handle */, uint16_t /* packets */)> cb,
                                           Handler* handler) {
    ASSERT(acl_credits_handler_ == nullptr);
    acl_credits_callback_ = cb;
    acl_credits_handler_ = handler;
  }

  void read_buffer_size_complete_handler(std::promise<void> promise, CommandCompleteView view) {
    auto complete_view = ReadBufferSizeCompleteView::Create(view);
    ASSERT(complete_view.IsValid());
    ErrorCode status = complete_view.GetStatus();
    ASSERT_LOG(status == ErrorCode::SUCCESS, "Status 0x%02hhx, %s", status, ErrorCodeText(status).c_str());
    acl_buffer_length_ = complete_view.GetAclDataPacketLength();
    acl_buffers_ = complete_view.GetTotalNumAclDataPackets();

    sco_buffer_length_ = complete_view.GetSynchronousDataPacketLength();
    sco_buffers_ = complete_view.GetTotalNumSynchronousDataPackets();
    promise.set_value();
  }

  uint16_t ReadControllerAclPacketLength() {
    return acl_buffer_length_;
  }

  uint16_t ReadControllerNumAclPacketBuffers() {
    return acl_buffers_;
  }

  uint8_t ReadControllerScoPacketLength() {
    return sco_buffer_length_;
  }

  uint16_t ReadControllerNumScoPacketBuffers() {
    return sco_buffers_;
  }

  Controller& module_;

  HciLayer* hci_;

  Callback<void(uint16_t, uint16_t)> acl_credits_callback_;
  Handler* acl_credits_handler_ = nullptr;

  uint16_t acl_buffer_length_ = 0;
  uint16_t acl_buffers_;
  uint8_t sco_buffer_length_;
  uint16_t sco_buffers_;
};  // namespace hci

Controller::Controller() : impl_(std::make_unique<impl>(*this)) {}

Controller::~Controller() = default;

void Controller::RegisterCompletedAclPacketsCallback(Callback<void(uint16_t /* handle */, uint16_t /* packets */)> cb,
                                                     Handler* handler) {
  impl_->RegisterCompletedAclPacketsCallback(cb, handler);
}

uint16_t Controller::ReadControllerAclPacketLength() {
  return impl_->ReadControllerAclPacketLength();
}

uint16_t Controller::ReadControllerNumAclPacketBuffers() {
  return impl_->ReadControllerNumAclPacketBuffers();
}

uint8_t Controller::ReadControllerScoPacketLength() {
  return impl_->ReadControllerScoPacketLength();
}

uint16_t Controller::ReadControllerNumScoPacketBuffers() {
  return impl_->ReadControllerNumScoPacketBuffers();
}

const ModuleFactory Controller::Factory = ModuleFactory([]() { return new Controller(); });

void Controller::ListDependencies(ModuleList* list) {
  list->add<hci::HciLayer>();
}

void Controller::Start() {
  impl_->Start(GetDependency<hci::HciLayer>());
}

void Controller::Stop() {
  impl_->Stop();
}
}  // namespace hci
}  // namespace bluetooth
