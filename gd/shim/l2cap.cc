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
#include <mutex>
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

using ServiceInterfaceCallback =
    std::function<void(l2cap::Psm psm, l2cap::classic::DynamicChannelManager::RegistrationResult result)>;
using ConnectionInterfaceCallback =
    std::function<void(l2cap::Psm psm, std::unique_ptr<l2cap::classic::DynamicChannel>)>;

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
        on_connection_closed_callback_(nullptr), address_(channel_->GetDevice()) {
    channel_->RegisterOnCloseCallback(
        handler_, common::BindOnce(&ConnectionInterface::OnConnectionClosed, common::Unretained(this)));
    channel_->GetQueueUpEnd()->RegisterDequeue(
        handler_, common::Bind(&ConnectionInterface::OnReadReady, common::Unretained(this)));
    dequeue_registered_ = true;
  }

  ~ConnectionInterface() {
    ASSERT(!dequeue_registered_);
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

  void SetReadDataReadyCallback(ReadDataReadyCallback on_data_ready) {
    ASSERT(on_data_ready != nullptr);
    ASSERT(on_data_ready_callback_ == nullptr);
    on_data_ready_callback_ = on_data_ready;
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

  void Write(std::unique_ptr<packet::RawBuilder> packet) {
    LOG_DEBUG("Writing packet cid:%hd size:%zd", cid_, packet->size());
    write_queue_.push(std::move(packet));
    if (!enqueue_registered_) {
      enqueue_registered_ = true;
      channel_->GetQueueUpEnd()->RegisterEnqueue(
          handler_, common::Bind(&ConnectionInterface::WriteReady, common::Unretained(this)));
    }
  }

  void Close() {
    if (dequeue_registered_) {
      channel_->GetQueueUpEnd()->UnregisterDequeue();
      dequeue_registered_ = false;
    }
    ASSERT(write_queue_.empty());
    channel_->Close();
  }

  void OnConnectionClosed(hci::ErrorCode error_code) {
    LOG_DEBUG("Channel interface closed reason:%s cid:%hd device:%s", hci::ErrorCodeText(error_code).c_str(), cid_,
              address_.ToString().c_str());
    ASSERT(on_connection_closed_callback_ != nullptr);
    on_connection_closed_callback_(cid_, static_cast<int>(error_code));
  }

  void SetConnectionClosedCallback(::bluetooth::shim::ConnectionClosedCallback on_connection_closed) {
    ASSERT(on_connection_closed != nullptr);
    ASSERT(on_connection_closed_callback_ == nullptr);
    on_connection_closed_callback_ = std::move(on_connection_closed);
  }

 private:
  const ConnectionInterfaceDescriptor cid_;
  const std::unique_ptr<l2cap::classic::DynamicChannel> channel_;
  os::Handler* handler_;

  ReadDataReadyCallback on_data_ready_callback_;
  ConnectionClosedCallback on_connection_closed_callback_;

  const hci::Address address_;

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

  size_t NumberOfActiveConnections() const {
    return cid_to_interface_map_.size();
  }

  void GeneralCallback(ConnectionOpenCallback on_open, hci::Address address, l2cap::Psm psm,
                       ConnectionInterfaceDescriptor cid) {
    on_open(address.ToString(), static_cast<uint16_t>(psm), static_cast<uint16_t>(cid));
  }

  void ConnectionOpened(ConnectionOpenCallback on_open, hci::Address address, l2cap::Psm psm,
                        ConnectionInterfaceDescriptor cid) {
    LOG_DEBUG("address:%s psm:%hd cid:%hd", address.ToString().c_str(), psm, cid);
    handler_->Post(common::BindOnce(&ConnectionInterfaceManager::GeneralCallback, common::Unretained(this), on_open,
                                    address, psm, cid));
    // TODO(cmanton) queue this pending connection address/psm tuple up for deletion
    // There may be multiple, so only remove one
  }

  void ConnectionFailed(hci::Address address, l2cap::Psm psm) {
    LOG_DEBUG("Connection Failed");
    // TODO(cmanton) queue this pending connection address/psm tuple up for deletion
    // There may be multiple, so only remove one
  }

  ConnectionInterfaceManager(os::Handler* handler);

 private:
  os::Handler* handler_;
  ConnectionInterfaceDescriptor current_connection_interface_descriptor_;

  bool HasResources() const;
  bool Exists(ConnectionInterfaceDescriptor id) const;

  std::unordered_map<ConnectionInterfaceDescriptor, std::unique_ptr<ConnectionInterface>> cid_to_interface_map_;
  ConnectionInterfaceDescriptor AllocateConnectionInterfaceDescriptor();
  ConnectionInterfaceManager() = delete;
};

ConnectionInterfaceManager::ConnectionInterfaceManager(os::Handler* handler)
    : handler_(handler), current_connection_interface_descriptor_(kStartConnectionInterfaceDescriptor) {}

bool ConnectionInterfaceManager::Exists(ConnectionInterfaceDescriptor cid) const {
  return cid_to_interface_map_.find(cid) != cid_to_interface_map_.end();
}

ConnectionInterfaceDescriptor ConnectionInterfaceManager::AllocateConnectionInterfaceDescriptor() {
  ASSERT(HasResources());
  while (Exists(current_connection_interface_descriptor_)) {
    if (++current_connection_interface_descriptor_ == kInvalidConnectionInterfaceDescriptor) {
      current_connection_interface_descriptor_ = kStartConnectionInterfaceDescriptor;
    }
  }
  return current_connection_interface_descriptor_++;
}

ConnectionInterfaceDescriptor ConnectionInterfaceManager::AddChannel(
    std::unique_ptr<l2cap::classic::DynamicChannel> channel) {
  if (!HasResources()) {
    return kInvalidConnectionInterfaceDescriptor;
  }
  ConnectionInterfaceDescriptor cid = AllocateConnectionInterfaceDescriptor();

  auto channel_interface = std::make_unique<ConnectionInterface>(cid, std::move(channel), handler_);
  cid_to_interface_map_[cid] = std::move(channel_interface);
  return cid;
}

void ConnectionInterfaceManager::RemoveConnection(ConnectionInterfaceDescriptor cid) {
  ASSERT(cid_to_interface_map_.count(cid) == 1);
  cid_to_interface_map_.find(cid)->second->Close();
  cid_to_interface_map_.erase(cid);
}

bool ConnectionInterfaceManager::HasResources() const {
  return cid_to_interface_map_.size() < kMaxConnections;
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

class PendingConnection {
 public:
  PendingConnection(ConnectionInterfaceManager* connection_interface_manager, l2cap::Psm psm, hci::Address address,
                    ConnectionOpenCallback on_open, std::promise<uint16_t> completed)
      : connection_interface_manager_(connection_interface_manager), psm_(psm), address_(address),
        on_open_(std::move(on_open)), completed_(std::move(completed)) {}

  void OnConnectionOpen(std::unique_ptr<l2cap::classic::DynamicChannel> channel) {
    LOG_DEBUG("Local initiated connection is open to device:%s for psm:%hd", address_.ToString().c_str(), psm_);
    ConnectionInterfaceDescriptor cid = connection_interface_manager_->AddChannel(std::move(channel));
    completed_.set_value(cid);
    // Attempt to avoid async race condition with upper stack
    std::this_thread::yield();
    connection_interface_manager_->ConnectionOpened(std::move(on_open_), address_, psm_, cid);
  }

  void OnConnectionFailure(l2cap::classic::DynamicChannelManager::ConnectionResult result) {
    LOG_DEBUG("Connection failed to device:%s for psm:%hd", address_.ToString().c_str(), psm_);
    switch (result.connection_result_code) {
      case l2cap::classic::DynamicChannelManager::ConnectionResultCode::SUCCESS:
        LOG_WARN("Connection failed result:success hci:%s", hci::ErrorCodeText(result.hci_error).c_str());
        break;
      case l2cap::classic::DynamicChannelManager::ConnectionResultCode::FAIL_NO_SERVICE_REGISTERED:
        LOG_DEBUG("Connection failed result:no service registered hci:%s",
                  hci::ErrorCodeText(result.hci_error).c_str());
        break;
      case l2cap::classic::DynamicChannelManager::ConnectionResultCode::FAIL_HCI_ERROR:
        LOG_DEBUG("Connection failed result:hci error hci:%s", hci::ErrorCodeText(result.hci_error).c_str());
        break;
      case l2cap::classic::DynamicChannelManager::ConnectionResultCode::FAIL_L2CAP_ERROR:
        LOG_DEBUG("Connection failed result:l2cap error hci:%s l2cap:%s", hci::ErrorCodeText(result.hci_error).c_str(),
                  l2cap::ConnectionResponseResultText(result.l2cap_connection_response_result).c_str());
        break;
    }
    completed_.set_value(kInvalidConnectionInterfaceDescriptor);
    connection_interface_manager_->ConnectionFailed(address_, psm_);
  }

 private:
  ConnectionInterfaceManager* connection_interface_manager_;
  const l2cap::Psm psm_;
  const hci::Address address_;
  ConnectionOpenCallback on_open_;
  std::promise<uint16_t> completed_;
};

class ServiceInterface {
 public:
  ServiceInterface(ConnectionInterfaceManager* connection_interface_manager, l2cap::Psm psm,
                   ConnectionOpenCallback on_open, std::promise<void> completed)
      : connection_interface_manager_(connection_interface_manager), psm_(psm), on_open_(on_open),
        completed_(std::move(completed)) {}

  void OnRegistrationComplete(l2cap::classic::DynamicChannelManager::RegistrationResult result,
                              std::unique_ptr<l2cap::classic::DynamicChannelService> service) {
    ASSERT(service_ == nullptr);
    ASSERT(psm_ == service->GetPsm());
    LOG_DEBUG("Registration is complete for psm:%hd", psm_);
    service_ = std::move(service);
    completed_.set_value();
  }

  void OnConnectionOpen(std::unique_ptr<l2cap::classic::DynamicChannel> channel) {
    LOG_DEBUG("Remote initiated connection is open from device:%s for psm:%hd", channel->GetDevice().ToString().c_str(),
              psm_);
    hci::Address address = channel->GetDevice();
    ConnectionInterfaceDescriptor cid = connection_interface_manager_->AddChannel(std::move(channel));
    connection_interface_manager_->ConnectionOpened(on_open_, address, psm_, cid);
  }

  l2cap::SecurityPolicy GetSecurityPolicy() const {
    return security_policy_;
  }

  void RegisterService(
      std::function<void(l2cap::Psm, l2cap::SecurityPolicy security_policy,
                         l2cap::classic::DynamicChannelManager::OnRegistrationCompleteCallback on_registration_complete,
                         l2cap::classic::DynamicChannelManager::OnConnectionOpenCallback on_connection_open)>
          func) {
    func(psm_, security_policy_, common::BindOnce(&ServiceInterface::OnRegistrationComplete, common::Unretained(this)),
         common::Bind(&ServiceInterface::OnConnectionOpen, common::Unretained(this)));
  }

 private:
  ConnectionInterfaceManager* connection_interface_manager_;
  const l2cap::Psm psm_;
  ConnectionOpenCallback on_open_;
  std::promise<void> completed_;

  std::unique_ptr<l2cap::classic::DynamicChannelService> service_;

  const l2cap::SecurityPolicy security_policy_;
};

struct L2cap::impl {
  void RegisterService(l2cap::Psm psm, l2cap::classic::DynamicChannelConfigurationOption option,
                       ConnectionOpenCallback on_open, std::promise<void> completed);
  void UnregisterService(l2cap::Psm psm);

  void CreateConnection(l2cap::Psm psm, hci::Address address, ConnectionOpenCallback on_open,
                        std::promise<uint16_t> completed);
  void CloseConnection(ConnectionInterfaceDescriptor cid);

  void SetReadDataReadyCallback(ConnectionInterfaceDescriptor cid, ReadDataReadyCallback on_data_ready);
  void SetConnectionClosedCallback(ConnectionInterfaceDescriptor cid, ConnectionClosedCallback on_closed);

  void Write(ConnectionInterfaceDescriptor cid, std::unique_ptr<packet::RawBuilder> packet);

  void SendLoopbackResponse(std::function<void()> function);

  impl(L2cap& module, l2cap::classic::L2capClassicModule* l2cap_module);

 private:
  L2cap& module_;
  l2cap::classic::L2capClassicModule* l2cap_module_;
  os::Handler* handler_;
  ConnectionInterfaceManager connection_interface_manager_;

  std::unique_ptr<l2cap::classic::DynamicChannelManager> dynamic_channel_manager_;

  std::unordered_map<l2cap::Psm, std::shared_ptr<ServiceInterface>> psm_to_service_interface_map_;
  std::unordered_map<l2cap::Psm, std::shared_ptr<PendingConnection>> psm_to_pending_connection_map_;
};

L2cap::impl::impl(L2cap& module, l2cap::classic::L2capClassicModule* l2cap_module)
    : module_(module), l2cap_module_(l2cap_module), handler_(module_.GetHandler()),
      connection_interface_manager_(handler_) {
  dynamic_channel_manager_ = l2cap_module_->GetDynamicChannelManager();
}

void L2cap::impl::RegisterService(l2cap::Psm psm, l2cap::classic::DynamicChannelConfigurationOption option,
                                  ConnectionOpenCallback on_open, std::promise<void> completed) {
  ASSERT(psm_to_service_interface_map_.find(psm) == psm_to_service_interface_map_.end());

  auto service_interface =
      std::make_shared<ServiceInterface>(&connection_interface_manager_, psm, on_open, std::move(completed));
  psm_to_service_interface_map_.emplace(psm, service_interface);

  service_interface->RegisterService(
      [this, option](l2cap::Psm psm, l2cap::SecurityPolicy security_policy,
                     l2cap::classic::DynamicChannelManager::OnRegistrationCompleteCallback on_registration_complete,
                     l2cap::classic::DynamicChannelManager::OnConnectionOpenCallback on_connection_open) {
        bool rc = dynamic_channel_manager_->RegisterService(
            psm, option, security_policy, std::move(on_registration_complete), on_connection_open, handler_);
        ASSERT_LOG(rc == true, "Failed to register classic service");
      });
}

void L2cap::impl::UnregisterService(l2cap::Psm psm) {
  psm_to_service_interface_map_.erase(psm);
}

void L2cap::impl::CreateConnection(l2cap::Psm psm, hci::Address address, ConnectionOpenCallback on_open,
                                   std::promise<uint16_t> completed) {
  LOG_DEBUG("Initiating classic connection to psm:%hd device:%s", psm, address.ToString().c_str());
  auto pending_connection = std::make_shared<PendingConnection>(&connection_interface_manager_, psm, address,
                                                                std::move(on_open), std::move(completed));
  // TODO(cmanton) hash psm/address pair into unordered map for pending_connection
  // This is ok for now
  psm_to_pending_connection_map_[psm] = pending_connection;
  // TODO(cmanton): Add ERTM mode support by changing configuratio_option in ConnectChannel()
  bool rc = dynamic_channel_manager_->ConnectChannel(
      address, l2cap::classic::DynamicChannelConfigurationOption(), psm,
      common::Bind(&PendingConnection::OnConnectionOpen, common::Unretained(pending_connection.get())),
      common::BindOnce(&PendingConnection::OnConnectionFailure, common::Unretained(pending_connection.get())),
      handler_);
  ASSERT_LOG(rc == true, "Failed to create classic connection");
}

void L2cap::impl::CloseConnection(ConnectionInterfaceDescriptor cid) {
  connection_interface_manager_.RemoveConnection(cid);
}

void L2cap::impl::SetReadDataReadyCallback(ConnectionInterfaceDescriptor cid, ReadDataReadyCallback on_data_ready) {
  connection_interface_manager_.SetReadDataReadyCallback(cid, on_data_ready);
}

void L2cap::impl::SetConnectionClosedCallback(ConnectionInterfaceDescriptor cid, ConnectionClosedCallback on_closed) {
  connection_interface_manager_.SetConnectionClosedCallback(cid, std::move(on_closed));
}

void L2cap::impl::Write(ConnectionInterfaceDescriptor cid, std::unique_ptr<packet::RawBuilder> packet) {
  connection_interface_manager_.Write(cid, std::move(packet));
}

void L2cap::impl::SendLoopbackResponse(std::function<void()> function) {
  function();
}

void L2cap::RegisterService(uint16_t raw_psm, bool use_ertm, uint16_t mtu, ConnectionOpenCallback on_open,
                            std::promise<void> completed) {
  l2cap::Psm psm{raw_psm};
  l2cap::classic::DynamicChannelConfigurationOption option;
  if (use_ertm) {
    option.channel_mode =
        l2cap::classic::DynamicChannelConfigurationOption::RetransmissionAndFlowControlMode::ENHANCED_RETRANSMISSION;
  }
  option.incoming_mtu = mtu;
  GetHandler()->Post(common::BindOnce(&L2cap::impl::RegisterService, common::Unretained(pimpl_.get()), psm, option,
                                      on_open, std::move(completed)));
}

void L2cap::UnregisterService(uint16_t raw_psm) {
  l2cap::Psm psm{raw_psm};
  GetHandler()->Post(common::Bind(&L2cap::impl::UnregisterService, common::Unretained(pimpl_.get()), psm));
}

void L2cap::CreateConnection(uint16_t raw_psm, const std::string address_string, ConnectionOpenCallback on_open,
                             std::promise<uint16_t> completed) {
  l2cap::Psm psm{raw_psm};
  hci::Address address;
  hci::Address::FromString(address_string, address);

  GetHandler()->Post(common::BindOnce(&L2cap::impl::CreateConnection, common::Unretained(pimpl_.get()), psm, address,
                                      on_open, std::move(completed)));
}

void L2cap::CloseConnection(uint16_t raw_cid) {
  ConnectionInterfaceDescriptor cid(raw_cid);
  GetHandler()->Post(common::Bind(&L2cap::impl::CloseConnection, common::Unretained(pimpl_.get()), cid));
}

void L2cap::SetReadDataReadyCallback(uint16_t raw_cid, ReadDataReadyCallback on_data_ready) {
  ConnectionInterfaceDescriptor cid(raw_cid);
  GetHandler()->Post(
      common::Bind(&L2cap::impl::SetReadDataReadyCallback, common::Unretained(pimpl_.get()), cid, on_data_ready));
}

void L2cap::SetConnectionClosedCallback(uint16_t raw_cid, ConnectionClosedCallback on_closed) {
  ConnectionInterfaceDescriptor cid(raw_cid);
  GetHandler()->Post(common::Bind(&L2cap::impl::SetConnectionClosedCallback, common::Unretained(pimpl_.get()), cid,
                                  std::move(on_closed)));
}

void L2cap::Write(uint16_t raw_cid, const uint8_t* data, size_t len) {
  ConnectionInterfaceDescriptor cid(raw_cid);
  auto packet = MakeUniquePacket(data, len);
  GetHandler()->Post(common::BindOnce(&L2cap::impl::Write, common::Unretained(pimpl_.get()), cid, std::move(packet)));
}

void L2cap::WriteFlushable(uint16_t raw_cid, const uint8_t* data, size_t len) {
  LOG_WARN("UNIMPLEMENTED Write flushable");
  return Write(raw_cid, data, len);
}

void L2cap::WriteNonFlushable(uint16_t raw_cid, const uint8_t* data, size_t len) {
  LOG_WARN("UNIMPLEMENTED Write non flushable");
  return Write(raw_cid, data, len);
}

void L2cap::SendLoopbackResponse(std::function<void()> function) {
  GetHandler()->Post(common::BindOnce(&L2cap::impl::SendLoopbackResponse, common::Unretained(pimpl_.get()), function));
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
