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

#include <cstdint>
#include <memory>
#include <queue>
#include <unordered_map>
#include <vector>

#include "hci/hci_layer.h"
#include "hci/hci_packets.h"
#include "module.h"
#include "os/handler.h"
#include "os/log.h"
#include "packet/raw_builder.h"
#include "shim/hci_layer.h"

namespace bluetooth {
namespace shim {

using TokenQueue = std::queue<const void*>;
using OpCodeTokenQueueMap = std::unordered_map<hci::OpCode, TokenQueue>;

const ModuleFactory HciLayer::Factory = ModuleFactory([]() { return new HciLayer(); });

struct HciLayer::impl {
  impl(os::Handler* handler, hci::HciLayer* hci_layer) : handler_(handler), hci_layer_(hci_layer) {}

  void OnTransmitPacketCommandComplete(hci::CommandCompleteView view) {
    if (command_complete_callback_ == nullptr) {
      LOG_WARN("%s Received packet complete with no complete callback registered", __func__);
      return;
    }

    uint16_t command_op_code = static_cast<uint16_t>(view.GetCommandOpCode());
    std::vector<const uint8_t> data(view.begin(), view.end());

    if (op_code_token_queue_map_.count(view.GetCommandOpCode()) == 0) {
      LOG_WARN("%s Received unexpected command complete for opcode:0x%04x", __func__, command_op_code);
      return;
    }
    const void* token = op_code_token_queue_map_[view.GetCommandOpCode()].front();
    if (token == nullptr) {
      LOG_WARN("%s Received expected command status but no token for opcode:0x%04x", __func__, command_op_code);
      return;
    }

    op_code_token_queue_map_[view.GetCommandOpCode()].pop();
    command_complete_callback_(command_op_code, data, token);
  }

  void OnTransmitPacketStatus(hci::CommandStatusView view) {
    if (command_status_callback_ == nullptr) {
      LOG_WARN("%s Received packet complete with no status callback registered", __func__);
      return;
    }

    uint16_t command_op_code = static_cast<uint16_t>(view.GetCommandOpCode());
    std::vector<const uint8_t> data(view.begin(), view.end());

    if (op_code_token_queue_map_.count(view.GetCommandOpCode()) == 0) {
      LOG_WARN("%s Received unexpected command status for opcode:0x%04x", __func__, command_op_code);
      return;
    }
    const void* token = op_code_token_queue_map_[view.GetCommandOpCode()].front();
    if (token == nullptr) {
      LOG_WARN("%s Received expected command status but no token for opcode:0x%04x", __func__, command_op_code);
      return;
    }

    op_code_token_queue_map_[view.GetCommandOpCode()].pop();
    uint8_t status = static_cast<uint8_t>(view.GetStatus());
    command_status_callback_(command_op_code, data, token, status);
  }

  void TransmitCommand(uint16_t command, const uint8_t* data, size_t len, const void* token) {
    ASSERT(data != nullptr);
    ASSERT(token != nullptr);

    const hci::OpCode op_code = static_cast<const hci::OpCode>(command);

    auto payload = MakeUniquePacket(data, len);
    auto packet = hci::CommandPacketBuilder::Create(op_code, std::move(payload));

    op_code_token_queue_map_[op_code].push(token);
    if (IsCommandStatusOpcode(op_code)) {
      hci_layer_->EnqueueCommand(std::move(packet),
                                 common::BindOnce(&impl::OnTransmitPacketStatus, common::Unretained(this)), handler_);
    } else {
      hci_layer_->EnqueueCommand(std::move(packet),
                                 common::BindOnce(&impl::OnTransmitPacketCommandComplete, common::Unretained(this)),
                                 handler_);
    }
  }

  void RegisterCommandComplete(CommandCompleteCallback callback) {
    ASSERT(command_complete_callback_ == nullptr);
    command_complete_callback_ = callback;
  }

  void UnregisterCommandComplete() {
    ASSERT(command_complete_callback_ != nullptr);
    command_complete_callback_ = nullptr;
  }

  void RegisterCommandStatus(CommandStatusCallback callback) {
    ASSERT(command_status_callback_ == nullptr);
    command_status_callback_ = callback;
  }

  void UnregisterCommandStatus() {
    ASSERT(command_status_callback_ != nullptr);
    command_status_callback_ = nullptr;
  }

 private:
  os::Handler* handler_{nullptr};
  hci::HciLayer* hci_layer_{nullptr};

  CommandCompleteCallback command_complete_callback_;
  CommandStatusCallback command_status_callback_;

  OpCodeTokenQueueMap op_code_token_queue_map_;

  /**
   * Returns true if expecting command complete, false otherwise
   */
  bool IsCommandStatusOpcode(hci::OpCode op_code) {
    switch (op_code) {
      case hci::OpCode::INQUIRY:
      case hci::OpCode::CREATE_CONNECTION:
      case hci::OpCode::DISCONNECT:
      case hci::OpCode::ACCEPT_CONNECTION_REQUEST:
      case hci::OpCode::REJECT_CONNECTION_REQUEST:
      case hci::OpCode::CHANGE_CONNECTION_PACKET_TYPE:
      case hci::OpCode::AUTHENTICATION_REQUESTED:
      case hci::OpCode::SET_CONNECTION_ENCRYPTION:
      case hci::OpCode::CHANGE_CONNECTION_LINK_KEY:
      case hci::OpCode::MASTER_LINK_KEY:
      case hci::OpCode::REMOTE_NAME_REQUEST:
      case hci::OpCode::READ_REMOTE_SUPPORTED_FEATURES:
      case hci::OpCode::READ_REMOTE_EXTENDED_FEATURES:
      case hci::OpCode::READ_REMOTE_VERSION_INFORMATION:
      case hci::OpCode::READ_CLOCK_OFFSET:
      case hci::OpCode::SETUP_SYNCHRONOUS_CONNECTION:
      case hci::OpCode::ACCEPT_SYNCHRONOUS_CONNECTION:
      case hci::OpCode::REJECT_SYNCHRONOUS_CONNECTION:
      case hci::OpCode::ENHANCED_SETUP_SYNCHRONOUS_CONNECTION:
      case hci::OpCode::ENHANCED_ACCEPT_SYNCHRONOUS_CONNECTION:
      case hci::OpCode::HOLD_MODE:
      case hci::OpCode::SNIFF_MODE:
      case hci::OpCode::EXIT_SNIFF_MODE:
      case hci::OpCode::QOS_SETUP:
      case hci::OpCode::SWITCH_ROLE:
      case hci::OpCode::FLOW_SPECIFICATION:
      case hci::OpCode::REFRESH_ENCRYPTION_KEY:
      case hci::OpCode::LE_CREATE_CONNECTION:
      case hci::OpCode::LE_CONNECTION_UPDATE:
      case hci::OpCode::LE_READ_REMOTE_FEATURES:
      case hci::OpCode::LE_READ_LOCAL_P_256_PUBLIC_KEY_COMMAND:
      case hci::OpCode::LE_GENERATE_DHKEY_COMMAND:
      case hci::OpCode::LE_SET_PHY:
      case hci::OpCode::LE_EXTENDED_CREATE_CONNECTION:
      case hci::OpCode::LE_PERIODIC_ADVERTISING_CREATE_SYNC:
        return true;
      default:
        return false;
    }
  }

  std::unique_ptr<packet::RawBuilder> MakeUniquePacket(const uint8_t* data, size_t len) {
    packet::RawBuilder builder;
    std::vector<uint8_t> bytes(data, data + len);

    auto payload = std::make_unique<packet::RawBuilder>();
    payload->AddOctets(bytes);

    return payload;
  }
};

void HciLayer::TransmitCommand(uint16_t op_code, const uint8_t* data, size_t len, const void* token) {
  pimpl_->TransmitCommand(op_code, data, len, std::move(token));
}

void HciLayer::RegisterCommandComplete(CommandCompleteCallback callback) {
  pimpl_->RegisterCommandComplete(callback);
}

void HciLayer::UnregisterCommandComplete() {
  pimpl_->UnregisterCommandComplete();
}

void HciLayer::RegisterCommandStatus(CommandStatusCallback callback) {
  pimpl_->RegisterCommandStatus(callback);
}

void HciLayer::UnregisterCommandStatus() {
  pimpl_->UnregisterCommandStatus();
}

/**
 * Module methods
 */
void HciLayer::ListDependencies(ModuleList* list) {
  list->add<hci::HciLayer>();
}

void HciLayer::Start() {
  LOG_INFO("%s Starting controller shim layer", __func__);
  pimpl_ = std::make_unique<impl>(GetHandler(), GetDependency<hci::HciLayer>());
}

void HciLayer::Stop() {
  pimpl_.reset();
}

}  // namespace shim
}  // namespace bluetooth
