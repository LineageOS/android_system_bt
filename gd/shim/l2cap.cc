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
#include <functional>
#include <future>
#include <memory>
#include <queue>
#include <unordered_map>
#include <vector>

#include "common/bind.h"
#include "hci/address.h"
#include "hci/hci_packets.h"
#include "l2cap/classic/dynamic_channel_manager.h"
#include "l2cap/classic/l2cap_classic_module.h"
#include "l2cap/psm.h"
#include "l2cap/security_policy.h"
#include "module.h"
#include "os/handler.h"
#include "os/log.h"
#include "packet/packet_view.h"
#include "packet/raw_builder.h"
#include "shim/l2cap.h"

namespace bluetooth {
namespace shim {

const ModuleFactory L2cap::Factory = ModuleFactory([]() { return new L2cap(); });

using ChannelInterfaceId = uint16_t;
static const ChannelInterfaceId kInvalidChannelInterfaceId = 0;
static const ChannelInterfaceId kStartChannelInterfaceId = 64;
static const ChannelInterfaceId kMaxChannels = UINT16_MAX - 1;

std::unique_ptr<packet::RawBuilder> MakeUniquePacket(const uint8_t* data, size_t len) {
  packet::RawBuilder builder;
  std::vector<uint8_t> bytes(data, data + len);
  auto payload = std::make_unique<packet::RawBuilder>();
  payload->AddOctets(bytes);
  return payload;
}

class ChannelInterface {
 public:
  ChannelInterface(ChannelInterfaceId id, std::unique_ptr<l2cap::classic::DynamicChannel> channel, os::Handler* handler)
      : channel_interface_id_(id), channel_(std::move(channel)), handler_(handler), on_data_ready_callback_{nullptr} {
    channel_->RegisterOnCloseCallback(handler_, common::BindOnce(&ChannelInterface::OnClose, common::Unretained(this)));
    channel_->GetQueueUpEnd()->RegisterDequeue(handler_,
                                               common::Bind(&ChannelInterface::OnReadReady, common::Unretained(this)));
    dequeue_registered_ = true;
  }

  ~ChannelInterface() {
    if (dequeue_registered_) {
      channel_->GetQueueUpEnd()->UnregisterDequeue();
      dequeue_registered_ = false;
    }
  }

  void OnReadReady() {
    std::unique_ptr<packet::PacketView<packet::kLittleEndian>> packet = channel_->GetQueueUpEnd()->TryDequeue();
    if (packet == nullptr) {
      LOG_WARN("Got read ready from gd l2cap but no packet is ready");
      return;
    }
    std::vector<const uint8_t> data(packet->begin(), packet->end());
    ASSERT(on_data_ready_callback_ != nullptr);
    on_data_ready_callback_(channel_interface_id_, data);
  }

  void OnClose(hci::ErrorCode error_code) {
    LOG_DEBUG("Channel interface closed reason:%s id:%hd device:%s", hci::ErrorCodeText(error_code).c_str(),
              channel_interface_id_, channel_->GetDevice().ToString().c_str());
    ASSERT(on_close_callback_ != nullptr);
    on_close_callback_(static_cast<int>(error_code));
  }

  std::unique_ptr<packet::BasePacketBuilder> WriteReady() {
    auto data = std::move(write_queue_.front());
    write_queue_.pop();
    if (write_queue_.empty()) {
      channel_->GetQueueUpEnd()->UnregisterEnqueue();
      enqueue_registered_ = false;
    }
    return data;
  }

  void SetOnReadDataReady(OnReadDataReady on_data_ready) {
    ASSERT(on_data_ready_callback_ == nullptr);
    on_data_ready_callback_ = on_data_ready;
  }

  void SetOnClose(::bluetooth::shim::OnClose on_close) {
    ASSERT(on_close == nullptr);
    on_close_callback_ = on_close;
  }

  void Write(std::unique_ptr<packet::RawBuilder> packet) {
    write_queue_.push(std::move(packet));
    if (!enqueue_registered_) {
      enqueue_registered_ = true;
      channel_->GetQueueUpEnd()->RegisterEnqueue(handler_,
                                                 common::Bind(&ChannelInterface::WriteReady, common::Unretained(this)));
    }
  }

  void Close() {
    ASSERT(write_queue_.empty());
    channel_->GetQueueUpEnd()->UnregisterDequeue();
    channel_->Close();
  }

 private:
  ChannelInterfaceId channel_interface_id_;
  std::unique_ptr<l2cap::classic::DynamicChannel> channel_;
  os::Handler* handler_;

  OnReadDataReady on_data_ready_callback_;
  ::bluetooth::shim::OnClose on_close_callback_;

  std::queue<std::unique_ptr<packet::PacketBuilder<hci::kLittleEndian>>> write_queue_;

  bool enqueue_registered_{false};
  bool dequeue_registered_{false};
};

struct ChannelInterfaceManager {
 public:
  ChannelInterfaceId AddChannel(std::unique_ptr<l2cap::classic::DynamicChannel> channel);
  void RemoveChannel(ChannelInterfaceId id);

  void SetOnReadDataReady(ChannelInterfaceId id, OnReadDataReady on_data_ready);
  bool Write(ChannelInterfaceId id, std::unique_ptr<packet::RawBuilder> packet);

  void SetOnClose(ChannelInterfaceId id, OnClose on_close);

  bool HasResources() const;
  void SetHandler(os::Handler* handler) {
    handler_ = handler;
  }

  ChannelInterfaceManager();

 private:
  std::unordered_map<ChannelInterfaceId, std::unique_ptr<ChannelInterface>> channel_id_to_interface_map_;
  ChannelInterfaceId current_channel_interface_id_;
  os::Handler* handler_;

  bool Exists(ChannelInterfaceId id) const;
};

ChannelInterfaceManager::ChannelInterfaceManager() : current_channel_interface_id_(kStartChannelInterfaceId) {}

ChannelInterfaceId ChannelInterfaceManager::AddChannel(std::unique_ptr<l2cap::classic::DynamicChannel> channel) {
  while (!Exists(++current_channel_interface_id_)) {
  }
  auto channel_interface =
      std::make_unique<ChannelInterface>(current_channel_interface_id_, std::move(channel), handler_);
  channel_id_to_interface_map_[current_channel_interface_id_] = std::move(channel_interface);
  return current_channel_interface_id_;
}

void ChannelInterfaceManager::RemoveChannel(ChannelInterfaceId id) {
  ASSERT(channel_id_to_interface_map_.erase(id) == 1);
}

bool ChannelInterfaceManager::HasResources() const {
  return channel_id_to_interface_map_.size() < kMaxChannels;
}

bool ChannelInterfaceManager::Exists(ChannelInterfaceId id) const {
  return channel_id_to_interface_map_.find(id) != channel_id_to_interface_map_.end();
}

void ChannelInterfaceManager::SetOnReadDataReady(ChannelInterfaceId id, OnReadDataReady on_data_ready) {
  ASSERT(Exists(id));
  return channel_id_to_interface_map_[id]->SetOnReadDataReady(on_data_ready);
}

void ChannelInterfaceManager::SetOnClose(ChannelInterfaceId id, OnClose on_close) {
  ASSERT(Exists(id));
  return channel_id_to_interface_map_[id]->SetOnClose(on_close);
}

bool ChannelInterfaceManager::Write(ChannelInterfaceId id, std::unique_ptr<packet::RawBuilder> packet) {
  if (!Exists(id)) {
    return false;
  }
  channel_id_to_interface_map_[id]->Write(std::move(packet));
  return true;
}

struct L2cap::impl {
  void RegisterService(l2cap::Psm psm, std::promise<void> completed);
  void Connect(l2cap::Psm psm, hci::Address address, std::promise<uint16_t> completed);

  void RegistrationComplete(l2cap::classic::DynamicChannelManager::RegistrationResult result,
                            std::unique_ptr<l2cap::classic::DynamicChannelService> service);
  void LocalConnectionOpen(std::unique_ptr<l2cap::classic::DynamicChannel> channel);
  void RemoteConnectionOpen(std::unique_ptr<l2cap::classic::DynamicChannel> channel);
  void ConnectionFailure(l2cap::classic::DynamicChannelManager::ConnectionResult result);

  bool Write(ChannelInterfaceId cid, std::unique_ptr<packet::RawBuilder> packet);

  impl(L2cap& module, l2cap::classic::L2capClassicModule* l2cap_module);
  ChannelInterfaceManager channel_interface_manager_;

 private:
  L2cap& module_;
  l2cap::classic::L2capClassicModule* l2cap_module_{nullptr};

  std::unique_ptr<l2cap::classic::DynamicChannelManager> dynamic_channel_manager_;

  std::queue<std::promise<void>> register_completed_queue_;
  std::queue<std::promise<uint16_t>> connect_completed_queue_;

  os::Handler* handler_;
};

L2cap::impl::impl(L2cap& module, l2cap::classic::L2capClassicModule* l2cap_module)
    : module_(module), l2cap_module_(l2cap_module) {
  handler_ = module_.GetHandler();
  dynamic_channel_manager_ = l2cap_module_->GetDynamicChannelManager();
  channel_interface_manager_.SetHandler(handler_);
}

void L2cap::impl::RegistrationComplete(l2cap::classic::DynamicChannelManager::RegistrationResult result,
                                       std::unique_ptr<l2cap::classic::DynamicChannelService> service) {
  LOG_DEBUG("Registration is complete");
  auto completed = std::move(register_completed_queue_.front());
  register_completed_queue_.pop();
  completed.set_value();
}

void L2cap::impl::LocalConnectionOpen(std::unique_ptr<l2cap::classic::DynamicChannel> channel) {
  LOG_DEBUG("Local initiated connection is open to connect_queue_size:%zd device:%s", connect_completed_queue_.size(),
            channel->GetDevice().ToString().c_str());
  auto completed = std::move(connect_completed_queue_.front());
  connect_completed_queue_.pop();
  if (!channel_interface_manager_.HasResources()) {
    completed.set_value(kInvalidChannelInterfaceId);
  }
  completed.set_value(channel_interface_manager_.AddChannel(std::move(channel)));
}

void L2cap::impl::RemoteConnectionOpen(std::unique_ptr<l2cap::classic::DynamicChannel> channel) {
  LOG_DEBUG("Remote initiated connection is open to connect_queue_size:%zd device:%s", connect_completed_queue_.size(),
            channel->GetDevice().ToString().c_str());
  // TODO(cmanton) plumb back to legacy somehow
}

void L2cap::impl::ConnectionFailure(l2cap::classic::DynamicChannelManager::ConnectionResult result) {
  switch (result.connection_result_code) {
    case l2cap::classic::DynamicChannelManager::ConnectionResultCode::SUCCESS:
      LOG_WARN("Connection failed result:success hci:%s", hci::ErrorCodeText(result.hci_error).c_str());
      break;
    case l2cap::classic::DynamicChannelManager::ConnectionResultCode::FAIL_NO_SERVICE_REGISTERED:
      LOG_DEBUG("Connection failed result:no service registered hci:%s", hci::ErrorCodeText(result.hci_error).c_str());
      break;
    case l2cap::classic::DynamicChannelManager::ConnectionResultCode::FAIL_HCI_ERROR:
      LOG_DEBUG("Connection failed result:hci error hci:%s", hci::ErrorCodeText(result.hci_error).c_str());
      break;
    case l2cap::classic::DynamicChannelManager::ConnectionResultCode::FAIL_L2CAP_ERROR:
      LOG_DEBUG("Connection failed result:l2cap error hci:%s l2cap:%s", hci::ErrorCodeText(result.hci_error).c_str(),
                l2cap::ConnectionResponseResultText(result.l2cap_connection_response_result).c_str());
      break;
  }
  auto completed = std::move(connect_completed_queue_.front());
  connect_completed_queue_.pop();
  completed.set_value(kInvalidChannelInterfaceId);
}

void L2cap::impl::RegisterService(l2cap::Psm psm, std::promise<void> register_completed) {
  l2cap::SecurityPolicy security_policy;
  register_completed_queue_.push(std::move(register_completed));
  bool rc = dynamic_channel_manager_->RegisterService(
      psm, security_policy, common::BindOnce(&L2cap::impl::RegistrationComplete, common::Unretained(this)),
      common::Bind(&L2cap::impl::RemoteConnectionOpen, common::Unretained(this)), handler_);
  ASSERT_LOG(rc == true, "Failed to request register classic service");
}

void L2cap::impl::Connect(l2cap::Psm psm, hci::Address address, std::promise<uint16_t> connect_completed) {
  connect_completed_queue_.push(std::move(connect_completed));
  bool rc = dynamic_channel_manager_->ConnectChannel(
      address, psm, common::Bind(&L2cap::impl::LocalConnectionOpen, common::Unretained(this)),
      common::Bind(&L2cap::impl::ConnectionFailure, common::Unretained(this)), handler_);
  ASSERT_LOG(rc == true, "Failed to request connect classic channel");
}

bool L2cap::impl::Write(ChannelInterfaceId cid, std::unique_ptr<packet::RawBuilder> packet) {
  return channel_interface_manager_.Write(cid, std::move(packet));
}

void L2cap::RegisterService(uint16_t raw_psm, bool snoop_enabled, std::promise<void> register_completed) {
  if (!snoop_enabled) {
    LOG_WARN("UNIMPLEMENTED Cannot disable snooping on psm:%d", raw_psm);
  }

  l2cap::Psm psm = raw_psm;
  pimpl_->RegisterService(psm, std::move(register_completed));
}

void L2cap::Connect(uint16_t raw_psm, const std::string address_string, std::promise<uint16_t> connect_completed) {
  l2cap::Psm psm = raw_psm;
  hci::Address address;
  hci::Address::FromString(address_string, address);

  return pimpl_->Connect(psm, address, std::move(connect_completed));
}

void L2cap::SetOnReadDataReady(uint16_t cid, OnReadDataReady on_data_ready) {
  pimpl_->channel_interface_manager_.SetOnReadDataReady(static_cast<ChannelInterfaceId>(cid), on_data_ready);
}

void L2cap::SetOnClose(uint16_t cid, OnClose on_close) {
  pimpl_->channel_interface_manager_.SetOnClose(static_cast<ChannelInterfaceId>(cid), on_close);
}

bool L2cap::Write(uint16_t cid, const uint8_t* data, size_t len) {
  auto packet = MakeUniquePacket(data, len);
  return pimpl_->Write(static_cast<ChannelInterfaceId>(cid), std::move(packet));
}

bool L2cap::WriteFlushable(uint16_t cid, const uint8_t* data, size_t len) {
  LOG_WARN("UNIMPLEMENTED Write flushable");
  return false;
}

bool L2cap::WriteNonFlushable(uint16_t cid, const uint8_t* data, size_t len) {
  LOG_WARN("UNIMPLEMENTED Write non flushable");
  return false;
}

bool L2cap::IsCongested(ChannelInterfaceId cid) {
  LOG_WARN("UNIMPLEMENTED Congestion check on channels or links");
  return false;
}

/**
 * Module methods
 */
void L2cap::ListDependencies(ModuleList* list) {
  list->add<l2cap::classic::L2capClassicModule>();
}

void L2cap::Start() {
  pimpl_ = std::make_unique<impl>(*this, GetDependency<l2cap::classic::L2capClassicModule>());
}

void L2cap::Stop() {
  pimpl_.reset();
}

}  // namespace shim
}  // namespace bluetooth
