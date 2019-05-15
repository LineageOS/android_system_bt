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

#include "hci/hci_layer.h"

#include "packet/packet_builder.h"

namespace {
using bluetooth::hci::CommandCompleteView;
using bluetooth::hci::CommandPacketBuilder;
using bluetooth::hci::CommandStatusView;
using bluetooth::hci::EventPacketView;
using bluetooth::os::Handler;

class EventHandler {
 public:
  EventHandler() : event_handler(), handler(nullptr) {}
  EventHandler(std::function<void(EventPacketView)> on_event, Handler* on_event_handler)
      : event_handler(on_event), handler(on_event_handler) {}
  std::function<void(EventPacketView)> event_handler;
  Handler* handler;
};

class CommandQueueEntry {
 public:
  CommandQueueEntry(std::unique_ptr<CommandPacketBuilder> command_packet,
                    std::function<void(CommandStatusView)> on_status_function,
                    std::function<void(CommandCompleteView)> on_complete_function, Handler* handler)
      : command(std::move(command_packet)), on_status(on_status_function), on_complete(on_complete_function),
        caller_handler(handler) {}

  std::unique_ptr<CommandPacketBuilder> command;
  std::function<void(CommandStatusView)> on_status;
  std::function<void(CommandCompleteView)> on_complete;
  Handler* caller_handler;
};
}  // namespace

namespace bluetooth {
namespace hci {

using common::Address;
using common::BidiQueue;
using common::BidiQueueEnd;
using os::Handler;

struct HciLayer::impl : public hal::HciHalCallbacks {
  impl(HciLayer& module) : hal_(nullptr), module_(module) {
    RegisterEventHandler(EventCode::COMMAND_COMPLETE, [this](EventPacketView event) { CommandCompleteCallback(event); },
                         module_.GetHandler());
    RegisterEventHandler(EventCode::COMMAND_STATUS, [this](EventPacketView event) { CommandStatusCallback(event); },
                         module_.GetHandler());
  }

  void Start(hal::HciHal* hal) {
    hal_ = hal;
    hal_->registerIncomingPacketCallback(this);

    send_acl_ = [this](std::unique_ptr<hci::BasePacketBuilder> packet) {
      std::vector<uint8_t> bytes;
      BitInserter bi(bytes);
      packet->Serialize(bi);
      hal_->sendAclData(bytes);
    };
    send_sco_ = [this](std::unique_ptr<hci::BasePacketBuilder> packet) {
      std::vector<uint8_t> bytes;
      BitInserter bi(bytes);
      packet->Serialize(bi);
      hal_->sendScoData(bytes);
    };
    auto queue_end = acl_queue_.GetDownEnd();
    Handler* handler = module_.GetHandler();
    queue_end->RegisterDequeue(handler, [queue_end, this]() { send_acl_(queue_end->TryDequeue()); });
  }

  void Stop() {
    acl_queue_.GetDownEnd()->UnregisterDequeue();
    hal_ = nullptr;
  }

  void CommandStatusCallback(EventPacketView event) {
    CommandStatusView status_view = CommandStatusView::Create(event);
    ASSERT(status_view.IsValid());
    if (command_queue_.size() == 0) {
      ASSERT_LOG(status_view.GetCommandOpCode() == OpCode::NONE, "Unexpected status event with OpCode 0x%02hx",
                 status_view.GetCommandOpCode());
      return;
    }
    // TODO: Check whether this is the CommandOpCode we're looking for.
    auto caller_handler = command_queue_.front().caller_handler;
    auto on_status = command_queue_.front().on_status;
    caller_handler->Post([on_status, status_view]() { on_status(status_view); });
    command_queue_.pop();
  }

  void CommandCompleteCallback(EventPacketView event) {
    CommandCompleteView complete_view = CommandCompleteView::Create(event);
    ASSERT(complete_view.IsValid());
    if (command_queue_.size() == 0) {
      ASSERT_LOG(complete_view.GetCommandOpCode() == OpCode::NONE,
                 "Unexpected command complete event with OpCode 0x%02hx", complete_view.GetCommandOpCode());
      return;
    }
    // TODO: Check whether this is the CommandOpCode we're looking for.
    auto caller_handler = command_queue_.front().caller_handler;
    auto on_complete = command_queue_.front().on_complete;
    caller_handler->Post([on_complete, complete_view]() { on_complete(complete_view); });
    command_queue_.pop();
  }

  void hciEventReceived(hal::HciPacket event_bytes) override {
    auto packet = packet::PacketView<packet::kLittleEndian>(std::make_shared<std::vector<uint8_t>>(event_bytes));
    EventPacketView event = EventPacketView::Create(packet);
    ASSERT(event.IsValid());
    EventCode event_code = event.GetEventCode();

    Handler* hci_handler = module_.GetHandler();
    hci_handler->Post([this, event, event_code]() {
      ASSERT_LOG(event_handlers_.find(event_code) != event_handlers_.end(), "Unhandled event of type 0x%02hhx",
                 event.GetEventCode());
      auto& registered_handler = event_handlers_[event_code].event_handler;
      event_handlers_[event_code].handler->Post([event, registered_handler]() { registered_handler(event); });
    });
    // TODO: Credits
  }

  void aclDataReceived(hal::HciPacket data_bytes) override {
    module_.GetHandler()->Post([this, data_bytes]() {
      auto queue_end = acl_queue_.GetDownEnd();
      Handler* hci_handler = module_.GetHandler();
      queue_end->RegisterEnqueue(hci_handler, [queue_end, data_bytes]() {
        auto packet = packet::PacketView<packet::kLittleEndian>(std::make_shared<std::vector<uint8_t>>(data_bytes));
        AclPacketView acl2 = AclPacketView::Create(packet);
        queue_end->UnregisterEnqueue();
        return std::make_unique<AclPacketView>(acl2);
      });
    });
  }

  void scoDataReceived(hal::HciPacket data_bytes) override {
    auto packet = packet::PacketView<packet::kLittleEndian>(std::make_shared<std::vector<uint8_t>>(data_bytes));
    ScoPacketView sco = ScoPacketView::Create(packet);
  }

  void EnqueueCommand(std::unique_ptr<CommandPacketBuilder> command, std::function<void(CommandStatusView)> on_status,
                      std::function<void(CommandCompleteView)> on_complete, Handler* handler) {
    command_queue_.emplace(std::move(command), on_status, on_complete, handler);

    if (command_queue_.size() == 1) {
      std::vector<uint8_t> bytes;
      BitInserter bi(bytes);
      command_queue_.front().command->Serialize(bi);
      hal_->sendHciCommand(bytes);
    }
  }

  BidiQueueEnd<AclPacketBuilder, AclPacketView>* GetAclQueueEnd() {
    return acl_queue_.GetUpEnd();
  }

  void RegisterEventHandler(EventCode event_code, std::function<void(EventPacketView)> event_handler,
                            Handler* handler) {
    ASSERT_LOG(event_handlers_.count(event_code) == 0, "Can not register a second handler for event_code %02hhx",
               event_code);
    EventHandler to_save(event_handler, handler);
    event_handlers_[event_code] = to_save;
  }

  void UnregisterEventHandler(EventCode event_code) {
    event_handlers_.erase(event_code);
  }

  // The HAL
  hal::HciHal* hal_;

  // A reference to the HciLayer module
  HciLayer& module_;

  // Conversion functions for sending bytes from Builders
  std::function<void(std::unique_ptr<hci::BasePacketBuilder>)> send_acl_;
  std::function<void(std::unique_ptr<hci::BasePacketBuilder>)> send_sco_;

  // Command Handling
  std::queue<CommandQueueEntry> command_queue_;

  std::map<EventCode, EventHandler> event_handlers_;
  OpCode waiting_command_;

  // Acl packets
  BidiQueue<AclPacketView, AclPacketBuilder> acl_queue_{3 /* TODO: Set queue depth */};
};

HciLayer::HciLayer() : impl_(std::make_unique<impl>(*this)) {}

HciLayer::~HciLayer() {
  impl_.reset();
}

void HciLayer::EnqueueCommand(std::unique_ptr<CommandPacketBuilder> command,
                              std::function<void(CommandStatusView)> on_status,
                              std::function<void(CommandCompleteView)> on_complete, Handler* handler) {
  impl_->EnqueueCommand(std::move(command), on_status, on_complete, handler);
}

common::BidiQueueEnd<AclPacketBuilder, AclPacketView>* HciLayer::GetAclQueueEnd() {
  return impl_->GetAclQueueEnd();
}

void HciLayer::RegisterEventHandler(EventCode event_code, std::function<void(EventPacketView)> event_handler,
                                    Handler* handler) {
  impl_->RegisterEventHandler(event_code, event_handler, handler);
}

void HciLayer::UnregisterEventHandler(EventCode event_code) {
  impl_->UnregisterEventHandler(event_code);
}

const ModuleFactory HciLayer::Factory = ModuleFactory([]() { return new HciLayer(); });

void HciLayer::ListDependencies(ModuleList* list) {
  list->add<hal::HciHal>();
}

void HciLayer::Start() {
  impl_->Start(GetDependency<hal::HciHal>());
}

void HciLayer::Stop() {
  impl_->Stop();
}
}  // namespace hci
}  // namespace bluetooth
