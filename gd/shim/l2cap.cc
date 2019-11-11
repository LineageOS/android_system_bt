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

  bool HasResources() const;
  bool Exists(ConnectionInterfaceDescriptor id) const;
  ConnectionInterfaceDescriptor AllocateConnectionInterfaceDescriptor();
};

ConnectionInterfaceManager::ConnectionInterfaceManager()
    : current_connection_interface_descriptor_(kStartConnectionInterfaceDescriptor) {}

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

class ServiceInterface {
 public:
  ServiceInterface(uint16_t psm, ServiceInterfaceCallback register_callback,
                   ConnectionInterfaceCallback connection_callback)
      : psm_(psm), register_callback_(register_callback), connection_callback_(connection_callback) {}

  void OnRegistrationComplete(l2cap::classic::DynamicChannelManager::RegistrationResult result,
                              std::unique_ptr<l2cap::classic::DynamicChannelService> service) {
    ASSERT(service_ == nullptr);
    ASSERT(psm_ == service->GetPsm());
    LOG_DEBUG("Registration is complete for psm:%hd", psm_);
    service_ = std::move(service);
    register_callback_(psm_, result);
  }

  void OnConnectionOpen(std::unique_ptr<l2cap::classic::DynamicChannel> channel) {
    LOG_DEBUG("Connection is open to device:%s for psm:%hd", channel->GetDevice().ToString().c_str(), psm_);
    connection_callback_(psm_, std::move(channel));
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
  const l2cap::Psm psm_;
  std::unique_ptr<l2cap::classic::DynamicChannelService> service_;
  const l2cap::SecurityPolicy security_policy_;
  ServiceInterfaceCallback register_callback_;
  ConnectionInterfaceCallback connection_callback_;
};

struct L2cap::impl {
  void RegisterService(l2cap::Psm psm, ConnectionOpenCallback on_open, std::promise<void> completed);
  void UnregisterService(l2cap::Psm psm);

  void CreateConnection(l2cap::Psm psm, hci::Address address, std::promise<uint16_t> completed);
  void CloseConnection(ConnectionInterfaceDescriptor cid);

  void OnConnectionOpenNever(std::unique_ptr<l2cap::classic::DynamicChannel> channel);
  void OnConnectionFailureNever(l2cap::classic::DynamicChannelManager::ConnectionResult result);

  bool Write(ConnectionInterfaceDescriptor cid, std::unique_ptr<packet::RawBuilder> packet);

  impl(L2cap& module, l2cap::classic::L2capClassicModule* l2cap_module);
  ConnectionInterfaceManager connection_interface_manager_;

  void OpenConnection(l2cap::Psm psm, ConnectionInterfaceDescriptor cid);

 private:
  L2cap& module_;
  l2cap::classic::L2capClassicModule* l2cap_module_{nullptr};
  std::unique_ptr<l2cap::classic::DynamicChannelManager> dynamic_channel_manager_;

  std::unordered_map<l2cap::Psm, std::shared_ptr<ServiceInterface>> psm_to_service_interface_map_;
  std::unordered_map<l2cap::Psm, ConnectionOpenCallback> psm_to_on_open_map_;

  std::mutex mutex_;
  std::unordered_map<l2cap::Psm, std::promise<void>> psm_to_register_complete_map_;
  std::unordered_map<l2cap::Psm, std::queue<std::promise<uint16_t>>> psm_to_connect_completed_queue_;

  os::Handler* handler_;
};

L2cap::impl::impl(L2cap& module, l2cap::classic::L2capClassicModule* l2cap_module)
    : module_(module), l2cap_module_(l2cap_module) {
  handler_ = module_.GetHandler();
  dynamic_channel_manager_ = l2cap_module_->GetDynamicChannelManager();
  connection_interface_manager_.SetHandler(handler_);
}

void L2cap::impl::OnConnectionOpenNever(std::unique_ptr<l2cap::classic::DynamicChannel> channel) {
  ASSERT(false);
}

void L2cap::impl::OnConnectionFailureNever(l2cap::classic::DynamicChannelManager::ConnectionResult result) {
  ASSERT(false);
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
}

void L2cap::impl::OpenConnection(l2cap::Psm psm, ConnectionInterfaceDescriptor cid) {
  LOG_INFO("About to call back to client indicating open connection psm:%hd cid:%hd", psm, cid);
  psm_to_on_open_map_[psm](psm, cid, [cid](std::function<void(uint16_t cid)> func) {
    LOG_DEBUG("About to run postable on this thread and inform sdp that connection is open");
    func(cid);
  });
}

void L2cap::impl::RegisterService(l2cap::Psm psm, ConnectionOpenCallback on_open, std::promise<void> completed) {
  ASSERT(psm_to_service_interface_map_.find(psm) == psm_to_service_interface_map_.end());
  ASSERT(psm_to_register_complete_map_.find(psm) == psm_to_register_complete_map_.end());
  ASSERT(psm_to_on_open_map_.find(psm) == psm_to_on_open_map_.end());

  psm_to_on_open_map_[psm] = on_open;

  psm_to_service_interface_map_.emplace(
      psm, std::make_shared<ServiceInterface>(
               psm,
               [this](l2cap::Psm psm, l2cap::classic::DynamicChannelManager::RegistrationResult result) {
                 LOG_DEBUG("Service has been registered");
                 ASSERT(psm_to_register_complete_map_.find(psm) != psm_to_register_complete_map_.end());
                 {
                   std::unique_lock<std::mutex> lock(mutex_);
                   auto completed = std::move(psm_to_register_complete_map_[psm]);
                   psm_to_register_complete_map_.erase(psm);
                   completed.set_value();
                 }
               },

               [this](l2cap::Psm psm, std::unique_ptr<l2cap::classic::DynamicChannel> channel) {
                 ConnectionInterfaceDescriptor cid = connection_interface_manager_.AddChannel(std::move(channel));
                 LOG_DEBUG("Connection has been opened cid:%hd psm:%hd", cid, psm);
                 {
                   // If initiated locally unblock requestor that
                   // we now have a connection by providing the
                   // cid.
                   std::unique_lock<std::mutex> lock(mutex_);
                   if (psm_to_connect_completed_queue_.find(psm) != psm_to_connect_completed_queue_.end()) {
                     if (!psm_to_connect_completed_queue_[psm].empty()) {
                       LOG_DEBUG("Locally initiated, so inform waiting client of the cid %hd", cid);
                       auto completed = std::move(psm_to_connect_completed_queue_[psm].front());
                       psm_to_connect_completed_queue_[psm].pop();
                       completed.set_value(cid);
                     }
                   }
                   std::this_thread::yield();
                 }
                 if (cid != kInvalidConnectionInterfaceDescriptor) {
                   handler_->Post(common::BindOnce(&L2cap::impl::OpenConnection, common::Unretained(this), psm, cid));
                 }
                 usleep(10);
               }));

  psm_to_service_interface_map_.find(psm)->second->RegisterService(
      [this](l2cap::Psm psm, l2cap::SecurityPolicy security_policy,
             l2cap::classic::DynamicChannelManager::OnRegistrationCompleteCallback on_registration_complete,
             l2cap::classic::DynamicChannelManager::OnConnectionOpenCallback on_connection_open) {
        bool rc = dynamic_channel_manager_->RegisterService(psm, security_policy, std::move(on_registration_complete),
                                                            on_connection_open, handler_);
        ASSERT_LOG(rc == true, "Failed to register classic service");
      });
}

void L2cap::impl::UnregisterService(l2cap::Psm psm) {
  psm_to_service_interface_map_.erase(psm);
}

void L2cap::impl::CreateConnection(l2cap::Psm psm, hci::Address address, std::promise<uint16_t> completed) {
  LOG_INFO("Creating connection to psm:%hd device:%s", psm, address.ToString().c_str());
  {
    std::unique_lock<std::mutex> lock(mutex_);
    psm_to_connect_completed_queue_[psm].push(std::move(completed));
  }
  bool rc = dynamic_channel_manager_->ConnectChannel(
      address, psm, common::Bind(&L2cap::impl::OnConnectionOpenNever, common::Unretained(this)),
      common::Bind(&L2cap::impl::OnConnectionFailureNever, common::Unretained(this)), handler_);
  ASSERT_LOG(rc == true, "Failed to create classic connection channel");
}

void L2cap::impl::CloseConnection(ConnectionInterfaceDescriptor cid) {
  connection_interface_manager_.RemoveConnection(cid);
}

bool L2cap::impl::Write(ConnectionInterfaceDescriptor cid, std::unique_ptr<packet::RawBuilder> packet) {
  return connection_interface_manager_.Write(cid, std::move(packet));
}

void L2cap::RegisterService(uint16_t raw_psm, ConnectionOpenCallback on_open, std::promise<void> completed) {
  l2cap::Psm psm{raw_psm};
  pimpl_->RegisterService(psm, on_open, std::move(completed));
}

void L2cap::UnregisterService(uint16_t raw_psm) {
  l2cap::Psm psm{raw_psm};
  pimpl_->UnregisterService(psm);
}

void L2cap::CreateConnection(uint16_t raw_psm, const std::string address_string, std::promise<uint16_t> completed) {
  l2cap::Psm psm{raw_psm};
  hci::Address address;
  hci::Address::FromString(address_string, address);

  return pimpl_->CreateConnection(psm, address, std::move(completed));
}

void L2cap::CloseConnection(uint16_t raw_cid) {
  ConnectionInterfaceDescriptor cid(raw_cid);
  return pimpl_->CloseConnection(cid);
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
