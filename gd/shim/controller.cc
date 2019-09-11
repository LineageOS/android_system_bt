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
#define LOG_TAG "gd_shim"

#include <memory>

#include "common/bidi_queue.h"
#include "hci/address.h"
#include "hci/controller.h"
#include "hci/hci_packets.h"
#include "module.h"
#include "os/handler.h"
#include "os/log.h"
#include "shim/controller.h"

namespace bluetooth {
namespace shim {

const ModuleFactory Controller::Factory = ModuleFactory([]() { return new Controller(); });

struct Controller::impl {
  impl(hci::Controller* hci_controller) : hci_controller_(hci_controller) {}

  hci::Controller* hci_controller_{nullptr};
};

bool Controller::IsCommandSupported(int op_code) const {
  return pimpl_->hci_controller_->IsSupported((bluetooth::hci::OpCode)op_code);
}

uint16_t Controller::GetControllerAclPacketLength() const {
  return pimpl_->hci_controller_->GetControllerAclPacketLength();
}

LeBufferSize Controller::GetControllerLeBufferSize() const {
  LeBufferSize le_buffer_size;
  hci::LeBufferSize hci_le_buffer_size = pimpl_->hci_controller_->GetControllerLeBufferSize();

  le_buffer_size.le_data_packet_length = hci_le_buffer_size.le_data_packet_length_;
  le_buffer_size.total_num_le_packets = hci_le_buffer_size.total_num_le_packets_;
  return le_buffer_size;
}

LeMaximumDataLength Controller::GetControllerLeMaximumDataLength() const {
  LeMaximumDataLength maximum_data_length;
  hci::LeMaximumDataLength hci_maximum_data_length = pimpl_->hci_controller_->GetControllerLeMaximumDataLength();

  maximum_data_length.supported_max_tx_octets = hci_maximum_data_length.supported_max_tx_octets_;
  maximum_data_length.supported_max_tx_time = hci_maximum_data_length.supported_max_tx_time_;
  maximum_data_length.supported_max_rx_octets = hci_maximum_data_length.supported_max_rx_octets_;
  maximum_data_length.supported_max_rx_time = hci_maximum_data_length.supported_max_rx_time_;
  return maximum_data_length;
}

uint16_t Controller::GetControllerNumAclPacketBuffers() const {
  return pimpl_->hci_controller_->GetControllerNumAclPacketBuffers();
}

uint64_t Controller::GetControllerLeLocalSupportedFeatures() const {
  return pimpl_->hci_controller_->GetControllerLeLocalSupportedFeatures();
}

uint64_t Controller::GetControllerLocalExtendedFeatures(uint8_t page_number) const {
  return pimpl_->hci_controller_->GetControllerLocalExtendedFeatures(page_number);
}

std::string Controller::GetControllerMacAddress() const {
  return pimpl_->hci_controller_->GetControllerMacAddress().ToString();
}

uint64_t Controller::GetControllerLeSupportedStates() const {
  return pimpl_->hci_controller_->GetControllerLeSupportedStates();
}

uint8_t Controller::GetControllerLocalExtendedFeaturesMaxPageNumber() const {
  return pimpl_->hci_controller_->GetControllerLocalExtendedFeaturesMaxPageNumber();
}

/**
 * Module methods
 */
void Controller::ListDependencies(ModuleList* list) {
  list->add<hci::Controller>();
}

void Controller::Start() {
  LOG_INFO("%s Starting controller shim layer", __func__);
  pimpl_ = std::make_unique<impl>(GetDependency<hci::Controller>());
}

void Controller::Stop() {
  pimpl_.reset();
}

}  // namespace shim
}  // namespace bluetooth
