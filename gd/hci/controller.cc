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
    hci_->RegisterEventHandler(EventCode::NUMBER_OF_COMPLETED_PACKETS,
                               Bind(&Controller::impl::NumberOfCompletedPackets, common::Unretained(this)),
                               module_.GetHandler());
    hci_->EnqueueCommand(ReadBufferSizeBuilder::Create(),
                         BindOnce(&Controller::impl::read_buffer_size_complete_handler, common::Unretained(this)),
                         module_.GetHandler());

    // We only need to synchronize the last read. Make BD_ADDR to be the last one.
    std::promise<void> promise;
    auto future = promise.get_future();
    hci_->EnqueueCommand(
        ReadBdAddrBuilder::Create(),
        BindOnce(&Controller::impl::read_controller_mac_address_handler, common::Unretained(this), std::move(promise)),
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

  void read_buffer_size_complete_handler(CommandCompleteView view) {
    auto complete_view = ReadBufferSizeCompleteView::Create(view);
    ASSERT(complete_view.IsValid());
    ErrorCode status = complete_view.GetStatus();
    ASSERT_LOG(status == ErrorCode::SUCCESS, "Status 0x%02hhx, %s", status, ErrorCodeText(status).c_str());
    acl_buffer_length_ = complete_view.GetAclDataPacketLength();
    acl_buffers_ = complete_view.GetTotalNumAclDataPackets();

    sco_buffer_length_ = complete_view.GetSynchronousDataPacketLength();
    sco_buffers_ = complete_view.GetTotalNumSynchronousDataPackets();
  }

  void read_controller_mac_address_handler(std::promise<void> promise, CommandCompleteView view) {
    auto complete_view = ReadBdAddrCompleteView::Create(view);
    ASSERT(complete_view.IsValid());
    ErrorCode status = complete_view.GetStatus();
    ASSERT_LOG(status == ErrorCode::SUCCESS, "Status 0x%02hhx, %s", status, ErrorCodeText(status).c_str());
    mac_address_ = complete_view.GetBdAddr();
    promise.set_value();
  }

  Controller& module_;

  HciLayer* hci_;

  Callback<void(uint16_t, uint16_t)> acl_credits_callback_;
  Handler* acl_credits_handler_ = nullptr;

  uint16_t acl_buffer_length_ = 0;
  uint16_t acl_buffers_ = 0;
  uint8_t sco_buffer_length_ = 0;
  uint16_t sco_buffers_ = 0;
  common::Address mac_address_;
};  // namespace hci

Controller::Controller() : impl_(std::make_unique<impl>(*this)) {}

Controller::~Controller() = default;

void Controller::RegisterCompletedAclPacketsCallback(Callback<void(uint16_t /* handle */, uint16_t /* packets */)> cb,
                                                     Handler* handler) {
  impl_->RegisterCompletedAclPacketsCallback(cb, handler);
}

uint16_t Controller::GetControllerAclPacketLength() {
  return impl_->acl_buffer_length_;
}

uint16_t Controller::GetControllerNumAclPacketBuffers() {
  return impl_->acl_buffers_;
}

uint8_t Controller::GetControllerScoPacketLength() {
  return impl_->sco_buffer_length_;
}

uint16_t Controller::GetControllerNumScoPacketBuffers() {
  return impl_->sco_buffers_;
}

common::Address Controller::GetControllerMacAddress() {
  return impl_->mac_address_;
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
