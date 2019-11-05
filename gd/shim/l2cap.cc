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

using ConnectionInterfaceDescriptor = uint16_t;
static const ConnectionInterfaceDescriptor kInvalidConnectionInterfaceDescriptor = 0;
static const ConnectionInterfaceDescriptor kStartConnectionInterfaceDescriptor = 64;
static const ConnectionInterfaceDescriptor kMaxConnections = UINT16_MAX - kStartConnectionInterfaceDescriptor - 1;

std::unique_ptr<packet::RawBuilder> MakeUniquePacket(const uint8_t* data, size_t len) {
  packet::RawBuilder builder;
  std::vector<uint8_t> bytes(data, data + len);
  auto payload = std::make_unique<packet::RawBuilder>();
  payload->AddOctets(bytes);
  return payload;
}

class ConnectionInterface {
 public:
  ConnectionInterface(ConnectionInterfaceDescriptor cid, std::unique_ptr<l2cap::classic::DynamicChannel> channel,
                      os::Handler* handler)
      : cid_(cid), channel_(std::move(channel)), handler_(handler), on_data_ready_callback_(nullptr),
        on_connection_closed_callback_(nullptr) {
    channel_->RegisterOnCloseCallback(
        handler_, common::BindOnce(&ConnectionInterface::OnConnectionClosed, common::Unretained(this)));
    channel_->GetQueueUpEnd()->RegisterDequeue(
        handler_, common::Bind(&ConnectionInterface::OnReadReady, common::Unretained(this)));
    dequeue_registered_ = true;
  }

  ~ConnectionInterface() {
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
    on_data_ready_callback_(cid_, data);
  }

  void OnConnectionClosed(hci::ErrorCode error_code) {
    LOG_DEBUG("Channel interface closed reason:%s cid:%hd device:%s", hci::ErrorCodeText(error_code).c_str(), cid_,
              channel_->GetDevice().ToString().c_str());
    ASSERT(on_connection_closed_callback_ != nullptr);
    on_connection_closed_callback_(cid_, static_cast<int>(error_code));
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

  void SetReadDataReadyCallback(ReadDataReadyCallback on_data_ready) {
    ASSERT(on_data_ready_callback_ == nullptr);
    on_data_ready_callback_ = on_data_ready;
  }

  void SetConnectionClosedCallback(::bluetooth::shim::ConnectionClosedCallback on_connection_closed) {
    ASSERT(on_connection_closed_callback_ == nullptr);
    on_connection_closed_callback_ = on_connection_closed;
  }

  void Write(std::unique_ptr<packet::RawBuilder> packet) {
    write_queue_.push(std::move(packet));
    if (!enqueue_registered_) {
      enqueue_registered_ = true;
      channel_->GetQueueUpEnd()->RegisterEnqueue(
          handler_, common::Bind(&ConnectionInterface::WriteReady, common::Unretained(this)));
    }
  }

  void Close() {
    ASSERT(write_queue_.empty());
    channel_->GetQueueUpEnd()->UnregisterDequeue();
    channel_->Close();
  }

 private:
  ConnectionInterfaceDescriptor cid_;
  std::unique_ptr<l2cap::classic::DynamicChannel> channel_;
  os::Handler* handler_;

  ReadDataReadyCallback on_data_ready_callback_;
  ::bluetooth::shim::ConnectionClosedCallback on_connection_closed_callback_;

  std::queue<std::unique_ptr<packet::PacketBuilder<hci::kLittleEndian>>> write_queue_;

  bool enqueue_registered_{false};
  bool dequeue_registered_{false};
};

struct ConnectionInterfaceManager {
 public:
  ConnectionInterfaceDescriptor AddChannel(std::unique_ptr<l2cap::classic::DynamicChannel> channel);
  void RemoveConnection(ConnectionInterfaceDescriptor cid);

  void SetReadDataReadyCallback(ConnectionInterfaceDescriptor cid, ReadDataReadyCallback on_data_ready);
  void SetConnectionClosedCallback(ConnectionInterfaceDescriptor cid, ConnectionClosedCallback on_closed);

  bool Write(ConnectionInterfaceDescriptor cid, std::unique_ptr<packet::RawBuilder> packet);

  bool HasResources() const;
  void SetHandler(os::Handler* handler) {
    handler_ = handler;
  }

  size_t NumberOfActiveConnections() const {
    return cid_to_interface_map_.size();
  }

  ConnectionInterfaceManager();

 private:
  std::unordered_map<ConnectionInterfaceDescriptor, std::unique_ptr<ConnectionInterface>> cid_to_interface_map_;
  ConnectionInterfaceDescriptor current_connection_interface_descriptor_;
  os::Handler* handler_;

  bool Exists(ConnectionInterfaceDescriptor id) const;
};

ConnectionInterfaceManager::ConnectionInterfaceManager()
    : current_connection_interface_descriptor_(kStartConnectionInterfaceDescriptor) {}

ConnectionInterfaceDescriptor ConnectionInterfaceManager::AddChannel(
    std::unique_ptr<l2cap::classic::DynamicChannel> channel) {
  ASSERT(HasResources());
  while (Exists(current_connection_interface_descriptor_)) {
    if (++current_connection_interface_descriptor_ == kInvalidConnectionInterfaceDescriptor) {
      current_connection_interface_descriptor_ = kStartConnectionInterfaceDescriptor;
    }
  }
  auto channel_interface =
      std::make_unique<ConnectionInterface>(current_connection_interface_descriptor_, std::move(channel), handler_);
  cid_to_interface_map_[current_connection_interface_descriptor_] = std::move(channel_interface);
  return current_connection_interface_descriptor_;
}

void ConnectionInterfaceManager::RemoveConnection(ConnectionInterfaceDescriptor cid) {
  ASSERT(cid_to_interface_map_.erase(cid) == 1);
}

bool ConnectionInterfaceManager::HasResources() const {
  return cid_to_interface_map_.size() < kMaxConnections;
}

bool ConnectionInterfaceManager::Exists(ConnectionInterfaceDescriptor cid) const {
  return cid_to_interface_map_.find(cid) != cid_to_interface_map_.end();
}

void ConnectionInterfaceManager::SetReadDataReadyCallback(ConnectionInterfaceDescriptor cid,
                                                          ReadDataReadyCallback on_data_ready) {
  ASSERT(Exists(cid));
  return cid_to_interface_map_[cid]->SetReadDataReadyCallback(on_data_ready);
}

void ConnectionInterfaceManager::SetConnectionClosedCallback(ConnectionInterfaceDescriptor cid,
                                                             ConnectionClosedCallback on_closed) {
  ASSERT(Exists(cid));
  return cid_to_interface_map_[cid]->SetConnectionClosedCallback(on_closed);
}

bool ConnectionInterfaceManager::Write(ConnectionInterfaceDescriptor cid, std::unique_ptr<packet::RawBuilder> packet) {
  if (!Exists(cid)) {
    return false;
  }
  cid_to_interface_map_[cid]->Write(std::move(packet));
  return true;
}

struct ServiceManager {
 public:
  void AddService(l2cap::Psm psm, std::unique_ptr<l2cap::classic::DynamicChannelService> service);
  void RemoveService(l2cap::Psm psm);

  ServiceManager() = default;

 private:
  std::unordered_map<l2cap::Psm, std::unique_ptr<l2cap::classic::DynamicChannelService>> psm_to_service_map_;

  bool Exists(l2cap::Psm psm) const;
};

void ServiceManager::AddService(l2cap::Psm psm, std::unique_ptr<l2cap::classic::DynamicChannelService> service) {
  ASSERT(psm_to_service_map_.find(psm) == psm_to_service_map_.end());
  psm_to_service_map_[psm] = std::move(service);
}

void ServiceManager::RemoveService(l2cap::Psm psm) {
  ASSERT(psm_to_service_map_.erase(psm) == 1);
}

bool ServiceManager::Exists(l2cap::Psm psm) const {
  return psm_to_service_map_.find(psm) != psm_to_service_map_.end();
}

struct L2cap::impl {
  void RegisterService(l2cap::Psm psm, ConnectionOpenCallback on_open, std::promise<void> completed);
  void CreateConnection(l2cap::Psm psm, hci::Address address, std::promise<uint16_t> completed);

  void OnRegistrationComplete(l2cap::classic::DynamicChannelManager::RegistrationResult result,
                              std::unique_ptr<l2cap::classic::DynamicChannelService> service);
  void OnConnectionOpen(std::unique_ptr<l2cap::classic::DynamicChannel> channel);
  void OnConnectionFailure(l2cap::classic::DynamicChannelManager::ConnectionResult result);

  bool Write(ConnectionInterfaceDescriptor cid, std::unique_ptr<packet::RawBuilder> packet);

  impl(L2cap& module, l2cap::classic::L2capClassicModule* l2cap_module);
  ConnectionInterfaceManager connection_interface_manager_;
  ServiceManager service_manager_;

 private:
  void SyncConnectionOpen(ConnectionInterfaceDescriptor cid);

  L2cap& module_;
  l2cap::classic::L2capClassicModule* l2cap_module_{nullptr};

  std::unordered_map<l2cap::Psm, ConnectionOpenCallback> psm_to_connection_open_map_;

  std::unique_ptr<l2cap::classic::DynamicChannelManager> dynamic_channel_manager_;

  std::queue<std::promise<void>> register_completed_queue_;
  std::queue<std::promise<uint16_t>> connect_completed_queue_;

  os::Handler* handler_;
};

L2cap::impl::impl(L2cap& module, l2cap::classic::L2capClassicModule* l2cap_module)
    : module_(module), l2cap_module_(l2cap_module) {
  handler_ = module_.GetHandler();
  dynamic_channel_manager_ = l2cap_module_->GetDynamicChannelManager();
  connection_interface_manager_.SetHandler(handler_);
}

void L2cap::impl::OnRegistrationComplete(l2cap::classic::DynamicChannelManager::RegistrationResult result,
                                         std::unique_ptr<l2cap::classic::DynamicChannelService> service) {
  LOG_DEBUG("Registration is complete");
  ASSERT(!register_completed_queue_.empty());
  auto completed = std::move(register_completed_queue_.front());
  register_completed_queue_.pop();
  completed.set_value();

  service_manager_.AddService(service->GetPsm(), std::move(service));
}

void L2cap::impl::SyncConnectionOpen(ConnectionInterfaceDescriptor cid) {
  ASSERT(!connect_completed_queue_.empty());
  auto completed = std::move(connect_completed_queue_.front());
  connect_completed_queue_.pop();
  completed.set_value(cid);
}

void L2cap::impl::OnConnectionOpen(std::unique_ptr<l2cap::classic::DynamicChannel> channel) {
  LOG_DEBUG("Connection is open to connect_queue_size:%zd device:%s", connect_completed_queue_.size(),
            channel->GetDevice().ToString().c_str());

  ConnectionInterfaceDescriptor cid = kInvalidConnectionInterfaceDescriptor;
  if (connection_interface_manager_.HasResources()) {
    cid = connection_interface_manager_.AddChannel(std::move(channel));
  }
  if (!connect_completed_queue_.empty()) {
    SyncConnectionOpen(cid);
  }
  // TODO(cmanton) Inform legacy psm service that a new connection is
  // available
}

void L2cap::impl::OnConnectionFailure(l2cap::classic::DynamicChannelManager::ConnectionResult result) {
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
  completed.set_value(kInvalidConnectionInterfaceDescriptor);
}

void L2cap::impl::RegisterService(l2cap::Psm psm, ConnectionOpenCallback on_open, std::promise<void> completed) {
  l2cap::SecurityPolicy security_policy;
  register_completed_queue_.push(std::move(completed));

  psm_to_connection_open_map_[psm] = std::move(on_open);

  bool rc = dynamic_channel_manager_->RegisterService(
      psm, security_policy, common::BindOnce(&L2cap::impl::OnRegistrationComplete, common::Unretained(this)),
      common::Bind(&L2cap::impl::OnConnectionOpen, common::Unretained(this)), handler_);
  ASSERT_LOG(rc == true, "Failed to register classic service");
}

void L2cap::impl::CreateConnection(l2cap::Psm psm, hci::Address address, std::promise<uint16_t> completed) {
  LOG_INFO("Creating connection to psm:%hd device:%s", psm, address.ToString().c_str());
  connect_completed_queue_.push(std::move(completed));
  bool rc = dynamic_channel_manager_->ConnectChannel(
      address, psm, common::Bind(&L2cap::impl::OnConnectionOpen, common::Unretained(this)),
      common::Bind(&L2cap::impl::OnConnectionFailure, common::Unretained(this)), handler_);
  ASSERT_LOG(rc == true, "Failed to create classic connection channel");
}

bool L2cap::impl::Write(ConnectionInterfaceDescriptor cid, std::unique_ptr<packet::RawBuilder> packet) {
  return connection_interface_manager_.Write(cid, std::move(packet));
}

void L2cap::RegisterService(uint16_t raw_psm, ConnectionOpenCallback on_open, std::promise<void> completed) {
  l2cap::Psm psm{raw_psm};
  pimpl_->RegisterService(psm, on_open, std::move(completed));
}

void L2cap::CreateConnection(uint16_t raw_psm, const std::string address_string, std::promise<uint16_t> completed) {
  l2cap::Psm psm{raw_psm};
  hci::Address address;
  hci::Address::FromString(address_string, address);

  return pimpl_->CreateConnection(psm, address, std::move(completed));
}

void L2cap::SetReadDataReadyCallback(uint16_t cid, ReadDataReadyCallback on_data_ready) {
  pimpl_->connection_interface_manager_.SetReadDataReadyCallback(static_cast<ConnectionInterfaceDescriptor>(cid),
                                                                 on_data_ready);
}

void L2cap::SetConnectionClosedCallback(uint16_t cid, ConnectionClosedCallback on_closed) {
  pimpl_->connection_interface_manager_.SetConnectionClosedCallback(static_cast<ConnectionInterfaceDescriptor>(cid),
                                                                    on_closed);
}

bool L2cap::Write(uint16_t cid, const uint8_t* data, size_t len) {
  auto packet = MakeUniquePacket(data, len);
  return pimpl_->Write(static_cast<ConnectionInterfaceDescriptor>(cid), std::move(packet));
}

bool L2cap::WriteFlushable(uint16_t cid, const uint8_t* data, size_t len) {
  LOG_WARN("UNIMPLEMENTED Write flushable");
  return false;
}

bool L2cap::WriteNonFlushable(uint16_t cid, const uint8_t* data, size_t len) {
  LOG_WARN("UNIMPLEMENTED Write non flushable");
  return false;
}

bool L2cap::IsCongested(ConnectionInterfaceDescriptor cid) {
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
