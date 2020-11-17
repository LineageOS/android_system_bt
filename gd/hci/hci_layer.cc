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

#include "common/bind.h"
#include "common/init_flags.h"
#include "os/alarm.h"
#include "os/queue.h"
#include "packet/packet_builder.h"

namespace bluetooth {
namespace hci {
using bluetooth::common::BindOn;
using bluetooth::common::BindOnce;
using bluetooth::common::ContextualCallback;
using bluetooth::common::ContextualOnceCallback;
using bluetooth::hci::CommandCompleteView;
using bluetooth::hci::CommandPacketBuilder;
using bluetooth::hci::CommandStatusView;
using bluetooth::hci::EventPacketView;
using bluetooth::hci::LeMetaEventView;
using bluetooth::os::Handler;
using common::BidiQueue;
using common::BidiQueueEnd;
using hci::OpCode;
using hci::ResetCompleteView;
using os::Alarm;
using os::Handler;
using std::move;
using std::unique_ptr;

static void fail_if_reset_complete_not_success(CommandCompleteView complete) {
  auto reset_complete = ResetCompleteView::Create(complete);
  ASSERT(reset_complete.IsValid());
  ASSERT(reset_complete.GetStatus() == ErrorCode::SUCCESS);
}

static void on_hci_timeout(OpCode op_code) {
  ASSERT_LOG(false, "Timed out waiting for 0x%02hx (%s)", op_code, OpCodeText(op_code).c_str());
}

class CommandQueueEntry {
 public:
  CommandQueueEntry(unique_ptr<CommandPacketBuilder> command_packet,
                    ContextualOnceCallback<void(CommandCompleteView)> on_complete_function)
      : command(move(command_packet)), waiting_for_status_(false), on_complete(move(on_complete_function)) {}

  CommandQueueEntry(unique_ptr<CommandPacketBuilder> command_packet,
                    ContextualOnceCallback<void(CommandStatusView)> on_status_function)
      : command(move(command_packet)), waiting_for_status_(true), on_status(move(on_status_function)) {}

  unique_ptr<CommandPacketBuilder> command;
  bool waiting_for_status_;
  ContextualOnceCallback<void(CommandStatusView)> on_status;
  ContextualOnceCallback<void(CommandCompleteView)> on_complete;

  template <typename TView>
  ContextualOnceCallback<void(TView)>* GetCallback() {
    return nullptr;
  }

  template <>
  ContextualOnceCallback<void(CommandStatusView)>* GetCallback<CommandStatusView>() {
    return &on_status;
  }

  template <>
  ContextualOnceCallback<void(CommandCompleteView)>* GetCallback<CommandCompleteView>() {
    return &on_complete;
  }
};

struct HciLayer::impl {
  impl(hal::HciHal* hal, HciLayer& module) : hal_(hal), module_(module) {
    hci_timeout_alarm_ = new Alarm(module.GetHandler());
  }

  ~impl() {
    incoming_acl_buffer_.Clear();
    delete hci_timeout_alarm_;
    command_queue_.clear();
  }

  void drop(EventPacketView event) {
    LOG_INFO("Dropping event %s", EventCodeText(event.GetEventCode()).c_str());
  }

  void on_outbound_acl_ready() {
    auto packet = acl_queue_.GetDownEnd()->TryDequeue();
    std::vector<uint8_t> bytes;
    BitInserter bi(bytes);
    packet->Serialize(bi);
    hal_->sendAclData(bytes);
  }

  template <typename TResponse>
  void enqueue_command(unique_ptr<CommandPacketBuilder> command, ContextualOnceCallback<void(TResponse)> on_response) {
    command_queue_.emplace_back(move(command), move(on_response));
    send_next_command();
  }

  void on_command_status(EventPacketView event) {
    handle_command_response<CommandStatusView>(event, "status");
  }

  void on_command_complete(EventPacketView event) {
    handle_command_response<CommandCompleteView>(event, "complete");
  }

  template <typename TResponse>
  void handle_command_response(EventPacketView event, std::string logging_id) {
    TResponse response_view = TResponse::Create(event);
    ASSERT(response_view.IsValid());
    command_credits_ = response_view.GetNumHciCommandPackets();
    OpCode op_code = response_view.GetCommandOpCode();
    if (op_code == OpCode::NONE) {
      send_next_command();
      return;
    }
    bool is_status = logging_id == "status";

    ASSERT_LOG(!command_queue_.empty(), "Unexpected %s event with OpCode 0x%02hx (%s)", logging_id.c_str(), op_code,
               OpCodeText(op_code).c_str());
    ASSERT_LOG(waiting_command_ == op_code, "Waiting for 0x%02hx (%s), got 0x%02hx (%s)", waiting_command_,
               OpCodeText(waiting_command_).c_str(), op_code, OpCodeText(op_code).c_str());
    ASSERT_LOG(command_queue_.front().waiting_for_status_ == is_status, "0x%02hx (%s) was not expecting %s event",
               op_code, OpCodeText(op_code).c_str(), logging_id.c_str());

    command_queue_.front().GetCallback<TResponse>()->Invoke(move(response_view));
    command_queue_.pop_front();
    waiting_command_ = OpCode::NONE;
    hci_timeout_alarm_->Cancel();
    send_next_command();
  }

  void send_next_command() {
    if (command_credits_ == 0) {
      return;
    }
    if (waiting_command_ != OpCode::NONE) {
      return;
    }
    if (command_queue_.size() == 0) {
      return;
    }
    std::shared_ptr<std::vector<uint8_t>> bytes = std::make_shared<std::vector<uint8_t>>();
    BitInserter bi(*bytes);
    command_queue_.front().command->Serialize(bi);
    hal_->sendHciCommand(*bytes);

    auto cmd_view = CommandPacketView::Create(PacketView<kLittleEndian>(bytes));
    ASSERT(cmd_view.IsValid());
    OpCode op_code = cmd_view.GetOpCode();
    waiting_command_ = op_code;
    command_credits_ = 0;  // Only allow one outstanding command
    hci_timeout_alarm_->Schedule(BindOnce(&on_hci_timeout, op_code), kHciTimeoutMs);
  }

  void register_event(EventCode event, ContextualCallback<void(EventPacketView)> handler) {
    ASSERT_LOG(
        event != EventCode::LE_META_EVENT,
        "Can not register handler for %02hhx (%s)",
        EventCode::LE_META_EVENT,
        EventCodeText(EventCode::LE_META_EVENT).c_str());
    ASSERT_LOG(event_handlers_.count(event) == 0, "Can not register a second handler for %02hhx (%s)", event,
               EventCodeText(event).c_str());
    event_handlers_[event] = handler;
  }

  void unregister_event(EventCode event) {
    event_handlers_.erase(event_handlers_.find(event));
  }

  void register_le_meta_event(ContextualCallback<void(EventPacketView)> handler) {
    ASSERT_LOG(
        event_handlers_.count(EventCode::LE_META_EVENT) == 0,
        "Can not register a second handler for %02hhx (%s)",
        EventCode::LE_META_EVENT,
        EventCodeText(EventCode::LE_META_EVENT).c_str());
    event_handlers_[EventCode::LE_META_EVENT] = handler;
  }

  void unregister_le_meta_event() {
    unregister_event(EventCode::LE_META_EVENT);
  }

  void register_le_event(SubeventCode event, ContextualCallback<void(LeMetaEventView)> handler) {
    ASSERT_LOG(subevent_handlers_.count(event) == 0, "Can not register a second handler for %02hhx (%s)", event,
               SubeventCodeText(event).c_str());
    subevent_handlers_[event] = handler;
  }

  void unregister_le_event(SubeventCode event) {
    subevent_handlers_.erase(subevent_handlers_.find(event));
  }

  void on_hci_event(EventPacketView event) {
    ASSERT(event.IsValid());
    EventCode event_code = event.GetEventCode();
    ASSERT_LOG(
        event_handlers_.find(event_code) != event_handlers_.end(),
        "Unhandled event of type 0x%02hhx (%s)",
        event_code,
        EventCodeText(event_code).c_str());
    event_handlers_[event_code].Invoke(event);
  }

  void on_le_meta_event(EventPacketView event) {
    LeMetaEventView meta_event_view = LeMetaEventView::Create(event);
    ASSERT(meta_event_view.IsValid());
    SubeventCode subevent_code = meta_event_view.GetSubeventCode();
    ASSERT_LOG(
        subevent_handlers_.find(subevent_code) != subevent_handlers_.end(),
        "Unhandled le subevent of type 0x%02hhx (%s)",
        subevent_code,
        SubeventCodeText(subevent_code).c_str());
    subevent_handlers_[subevent_code].Invoke(meta_event_view);
  }

  hal::HciHal* hal_;
  HciLayer& module_;

  // Command Handling
  std::list<CommandQueueEntry> command_queue_;

  std::map<EventCode, ContextualCallback<void(EventPacketView)>> event_handlers_;
  std::map<SubeventCode, ContextualCallback<void(LeMetaEventView)>> subevent_handlers_;
  OpCode waiting_command_{OpCode::NONE};
  uint8_t command_credits_{1};  // Send reset first
  Alarm* hci_timeout_alarm_{nullptr};

  // Acl packets
  BidiQueue<AclPacketView, AclPacketBuilder> acl_queue_{3 /* TODO: Set queue depth */};
  os::EnqueueBuffer<AclPacketView> incoming_acl_buffer_{acl_queue_.GetDownEnd()};
};

// All functions here are running on the HAL thread
struct HciLayer::hal_callbacks : public hal::HciHalCallbacks {
  hal_callbacks(HciLayer& module) : module_(module) {}

  void hciEventReceived(hal::HciPacket event_bytes) override {
    auto packet = packet::PacketView<packet::kLittleEndian>(std::make_shared<std::vector<uint8_t>>(event_bytes));
    EventPacketView event = EventPacketView::Create(packet);
    module_.CallOn(module_.impl_, &impl::on_hci_event, move(event));
  }

  void aclDataReceived(hal::HciPacket data_bytes) override {
    auto packet = packet::PacketView<packet::kLittleEndian>(std::make_shared<std::vector<uint8_t>>(move(data_bytes)));
    auto acl = std::make_unique<AclPacketView>(AclPacketView::Create(packet));
    module_.impl_->incoming_acl_buffer_.Enqueue(move(acl), module_.GetHandler());
  }

  void scoDataReceived(hal::HciPacket data_bytes) override {
    // Not implemented yet
  }

  void isoDataReceived(hal::HciPacket data_bytes) override {
    // Not implemented yet
  }

  HciLayer& module_;
};

HciLayer::HciLayer() : impl_(nullptr), hal_callbacks_(nullptr) {}

HciLayer::~HciLayer() {
}

common::BidiQueueEnd<AclPacketBuilder, AclPacketView>* HciLayer::GetAclQueueEnd() {
  return impl_->acl_queue_.GetUpEnd();
}

void HciLayer::EnqueueCommand(unique_ptr<CommandPacketBuilder> command,
                              ContextualOnceCallback<void(CommandCompleteView)> on_complete) {
  CallOn(impl_, &impl::enqueue_command<CommandCompleteView>, move(command), move(on_complete));
}

void HciLayer::EnqueueCommand(unique_ptr<CommandPacketBuilder> command,
                              ContextualOnceCallback<void(CommandStatusView)> on_status) {
  CallOn(impl_, &impl::enqueue_command<CommandStatusView>, move(command), move(on_status));
}

void HciLayer::RegisterEventHandler(EventCode event, ContextualCallback<void(EventPacketView)> handler) {
  CallOn(impl_, &impl::register_event, event, handler);
}

void HciLayer::RegisterLeMetaEventHandler(ContextualCallback<void(EventPacketView)> handler) {
  CallOn(impl_, &impl::register_le_meta_event, handler);
}

void HciLayer::UnregisterEventHandler(EventCode event) {
  CallOn(impl_, &impl::unregister_event, event);
}

void HciLayer::RegisterLeEventHandler(SubeventCode event, ContextualCallback<void(LeMetaEventView)> handler) {
  CallOn(impl_, &impl::register_le_event, event, handler);
}

void HciLayer::UnregisterLeEventHandler(SubeventCode event) {
  CallOn(impl_, &impl::unregister_le_event, event);
}

void HciLayer::on_disconnection_complete(EventPacketView event_view) {
  auto disconnection_view = DisconnectionCompleteView::Create(event_view);
  if (!disconnection_view.IsValid()) {
    LOG_INFO("Dropping invalid disconnection packet");
    return;
  }

  uint16_t handle = disconnection_view.GetConnectionHandle();
  ErrorCode reason = disconnection_view.GetReason();
  Disconnect(handle, reason);
}

void HciLayer::Disconnect(uint16_t handle, ErrorCode reason) {
  for (auto callback : disconnect_handlers_) {
    callback.Invoke(handle, reason);
  }
}

void HciLayer::on_read_remote_version_complete(EventPacketView event_view) {
  auto view = ReadRemoteVersionInformationCompleteView::Create(event_view);
  ASSERT_LOG(view.IsValid(), "Read remote version information packet invalid");
  if (view.GetStatus() != ErrorCode::SUCCESS) {
    auto status = view.GetStatus();
    std::string error_code = ErrorCodeText(status);
    LOG_ERROR("Received with error code %s", error_code.c_str());
    return;
  }
  uint16_t handle = view.GetConnectionHandle();
  ReadRemoteVersion(handle, view.GetVersion(), view.GetManufacturerName(), view.GetSubVersion());
}

void HciLayer::ReadRemoteVersion(uint16_t handle, uint8_t version, uint16_t manufacturer_name, uint16_t sub_version) {
  for (auto callback : read_remote_version_handlers_) {
    callback.Invoke(handle, version, manufacturer_name, sub_version);
  }
}

AclConnectionInterface* HciLayer::GetAclConnectionInterface(
    ContextualCallback<void(EventPacketView)> event_handler,
    ContextualCallback<void(uint16_t, ErrorCode)> on_disconnect,
    ContextualCallback<void(uint16_t, uint8_t version, uint16_t manufacturer_name, uint16_t sub_version)>
        on_read_remote_version) {
  for (const auto event : AclConnectionEvents) {
    RegisterEventHandler(event, event_handler);
  }
  disconnect_handlers_.push_back(on_disconnect);
  read_remote_version_handlers_.push_back(on_read_remote_version);
  return &acl_connection_manager_interface_;
}

LeAclConnectionInterface* HciLayer::GetLeAclConnectionInterface(
    ContextualCallback<void(LeMetaEventView)> event_handler,
    ContextualCallback<void(uint16_t, ErrorCode)> on_disconnect,
    ContextualCallback<void(uint16_t, uint8_t version, uint16_t manufacturer_name, uint16_t sub_version)>
        on_read_remote_version) {
  for (const auto event : LeConnectionManagementEvents) {
    RegisterLeEventHandler(event, event_handler);
  }
  disconnect_handlers_.push_back(on_disconnect);
  read_remote_version_handlers_.push_back(on_read_remote_version);
  return &le_acl_connection_manager_interface_;
}

SecurityInterface* HciLayer::GetSecurityInterface(ContextualCallback<void(EventPacketView)> event_handler) {
  for (const auto event : SecurityEvents) {
    RegisterEventHandler(event, event_handler);
  }
  return &security_interface;
}

LeSecurityInterface* HciLayer::GetLeSecurityInterface(ContextualCallback<void(LeMetaEventView)> event_handler) {
  for (const auto subevent : LeSecurityEvents) {
    RegisterLeEventHandler(subevent, event_handler);
  }
  return &le_security_interface;
}

LeAdvertisingInterface* HciLayer::GetLeAdvertisingInterface(ContextualCallback<void(LeMetaEventView)> event_handler) {
  for (const auto subevent : LeAdvertisingEvents) {
    RegisterLeEventHandler(subevent, event_handler);
  }
  return &le_advertising_interface;
}

LeScanningInterface* HciLayer::GetLeScanningInterface(ContextualCallback<void(LeMetaEventView)> event_handler) {
  for (const auto subevent : LeScanningEvents) {
    RegisterLeEventHandler(subevent, event_handler);
  }
  return &le_scanning_interface;
}

const ModuleFactory HciLayer::Factory = ModuleFactory([]() { return new HciLayer(); });

void HciLayer::ListDependencies(ModuleList* list) {
  list->add<hal::HciHal>();
}

void HciLayer::Start() {
  auto hal = GetDependency<hal::HciHal>();
  impl_ = new impl(hal, *this);
  hal_callbacks_ = new hal_callbacks(*this);

  Handler* handler = GetHandler();
  impl_->acl_queue_.GetDownEnd()->RegisterDequeue(handler, BindOn(impl_, &impl::on_outbound_acl_ready));
  RegisterEventHandler(EventCode::COMMAND_COMPLETE, handler->BindOn(impl_, &impl::on_command_complete));
  RegisterEventHandler(EventCode::COMMAND_STATUS, handler->BindOn(impl_, &impl::on_command_status));
  RegisterLeMetaEventHandler(handler->BindOn(impl_, &impl::on_le_meta_event));
  if (bluetooth::common::InitFlags::GdAclEnabled()) {
    RegisterEventHandler(
        EventCode::DISCONNECTION_COMPLETE, handler->BindOn(this, &HciLayer::on_disconnection_complete));
    RegisterEventHandler(
        EventCode::READ_REMOTE_VERSION_INFORMATION_COMPLETE,
        handler->BindOn(this, &HciLayer::on_read_remote_version_complete));
  }
  auto drop_packet = handler->BindOn(impl_, &impl::drop);
  RegisterEventHandler(EventCode::PAGE_SCAN_REPETITION_MODE_CHANGE, drop_packet);
  RegisterEventHandler(EventCode::MAX_SLOTS_CHANGE, drop_packet);
  RegisterEventHandler(EventCode::VENDOR_SPECIFIC, drop_packet);

  EnqueueCommand(ResetBuilder::Create(), handler->BindOnce(&fail_if_reset_complete_not_success));
  hal->registerIncomingPacketCallback(hal_callbacks_);
}

void HciLayer::Stop() {
  auto hal = GetDependency<hal::HciHal>();
  hal->unregisterIncomingPacketCallback();
  delete hal_callbacks_;

  impl_->acl_queue_.GetDownEnd()->UnregisterDequeue();
  delete impl_;
}

}  // namespace hci
}  // namespace bluetooth
