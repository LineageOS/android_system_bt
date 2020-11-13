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

#include "hci/facade/le_acl_manager_facade.h"

#include <condition_variable>
#include <memory>
#include <mutex>

#include "common/bind.h"
#include "grpc/grpc_event_queue.h"
#include "hci/acl_manager.h"
#include "hci/facade/le_acl_manager_facade.grpc.pb.h"
#include "hci/facade/le_acl_manager_facade.pb.h"
#include "hci/hci_packets.h"
#include "packet/raw_builder.h"

using ::grpc::ServerAsyncResponseWriter;
using ::grpc::ServerAsyncWriter;
using ::grpc::ServerContext;

using ::bluetooth::packet::RawBuilder;

namespace bluetooth {
namespace hci {
namespace facade {

using acl_manager::LeAclConnection;
using acl_manager::LeConnectionCallbacks;
using acl_manager::LeConnectionManagementCallbacks;

class LeAclManagerFacadeService : public LeAclManagerFacade::Service, public LeConnectionCallbacks {
 public:
  LeAclManagerFacadeService(AclManager* acl_manager, ::bluetooth::os::Handler* facade_handler)
      : acl_manager_(acl_manager), facade_handler_(facade_handler) {
    acl_manager_->RegisterLeCallbacks(this, facade_handler_);
  }

  ~LeAclManagerFacadeService() override {
    std::unique_lock<std::mutex> lock(acl_connections_mutex_);
    for (auto& conn : acl_connections_) {
      if (conn.second.connection_ != nullptr) {
        conn.second.connection_->GetAclQueueEnd()->UnregisterDequeue();
        conn.second.connection_.reset();
      }
    }
  }

  ::grpc::Status CreateConnection(
      ::grpc::ServerContext* context,
      const ::bluetooth::facade::BluetoothAddressWithType* request,
      ::grpc::ServerWriter<LeConnectionEvent>* writer) override {
    Address peer_address;
    ASSERT(Address::FromString(request->address().address(), peer_address));
    AddressWithType peer(peer_address, static_cast<AddressType>(request->type()));
    acl_manager_->CreateLeConnection(peer);
    if (per_connection_events_.size() > current_connection_request_) {
      return ::grpc::Status(::grpc::StatusCode::RESOURCE_EXHAUSTED, "Only one outstanding request is supported");
    }
    per_connection_events_.emplace_back(std::make_unique<::bluetooth::grpc::GrpcEventQueue<LeConnectionEvent>>(
        std::string("connection attempt ") + std::to_string(current_connection_request_)));
    return per_connection_events_[current_connection_request_]->RunLoop(context, writer);
  }

  ::grpc::Status CancelConnection(
      ::grpc::ServerContext* context,
      const ::bluetooth::facade::BluetoothAddressWithType* request,
      google::protobuf::Empty* response) override {
    Address peer_address;
    ASSERT(Address::FromString(request->address().address(), peer_address));
    AddressWithType peer(peer_address, static_cast<AddressType>(request->type()));
    if (per_connection_events_.size() == current_connection_request_) {
      // Todo: Check that the address matches an outstanding connection request
      return ::grpc::Status(::grpc::StatusCode::INVALID_ARGUMENT, "No matching outstanding connection");
    }
    acl_manager_->CancelLeConnect(peer);
    return ::grpc::Status::OK;
  }

  ::grpc::Status Disconnect(::grpc::ServerContext* context, const LeHandleMsg* request,
                            ::google::protobuf::Empty* response) override {
    std::unique_lock<std::mutex> lock(acl_connections_mutex_);
    auto connection = acl_connections_.find(request->handle());
    if (connection == acl_connections_.end()) {
      LOG_ERROR("Invalid handle");
      return ::grpc::Status(::grpc::StatusCode::INVALID_ARGUMENT, "Invalid handle");
    } else {
      connection->second.connection_->Disconnect(DisconnectReason::REMOTE_USER_TERMINATED_CONNECTION);
      return ::grpc::Status::OK;
    }
  }

#define GET_CONNECTION(view)                                                         \
  std::map<uint16_t, Connection>::iterator connection;                               \
  do {                                                                               \
    if (!view.IsValid()) {                                                           \
      return ::grpc::Status(::grpc::StatusCode::INVALID_ARGUMENT, "Invalid handle"); \
    }                                                                                \
    std::unique_lock<std::mutex> lock(acl_connections_mutex_);                       \
    connection = acl_connections_.find(view.GetConnectionHandle());                  \
    if (connection == acl_connections_.end()) {                                      \
      return ::grpc::Status(::grpc::StatusCode::INVALID_ARGUMENT, "Invalid handle"); \
    }                                                                                \
  } while (0)

  ::grpc::Status ConnectionCommand(
      ::grpc::ServerContext* context,
      const LeConnectionCommandMsg* request,
      ::google::protobuf::Empty* response) override {
    auto command_view = ConnectionManagementCommandView::Create(CommandPacketView::Create(PacketView<kLittleEndian>(
        std::make_shared<std::vector<uint8_t>>(request->packet().begin(), request->packet().end()))));
    if (!command_view.IsValid()) {
      return ::grpc::Status(::grpc::StatusCode::INVALID_ARGUMENT, "Invalid command packet");
    }
    switch (command_view.GetOpCode()) {
      case OpCode::DISCONNECT: {
        auto view = DisconnectView::Create(command_view);
        GET_CONNECTION(view);
        connection->second.connection_->Disconnect(view.GetReason());
        return ::grpc::Status::OK;
      }
      default:
        return ::grpc::Status(::grpc::StatusCode::INVALID_ARGUMENT, "Invalid command packet");
    }
  }
#undef GET_CONNECTION

  ::grpc::Status FetchIncomingConnection(
      ::grpc::ServerContext* context,
      const google::protobuf::Empty* request,
      ::grpc::ServerWriter<LeConnectionEvent>* writer) override {
    if (per_connection_events_.size() > current_connection_request_) {
      return ::grpc::Status(::grpc::StatusCode::RESOURCE_EXHAUSTED, "Only one outstanding connection is supported");
    }
    per_connection_events_.emplace_back(std::make_unique<::bluetooth::grpc::GrpcEventQueue<LeConnectionEvent>>(
        std::string("incoming connection ") + std::to_string(current_connection_request_)));
    return per_connection_events_[current_connection_request_]->RunLoop(context, writer);
  }

  ::grpc::Status SendAclData(
      ::grpc::ServerContext* context, const LeAclData* request, ::google::protobuf::Empty* response) override {
    std::promise<void> promise;
    auto future = promise.get_future();
    {
      std::unique_lock<std::mutex> lock(acl_connections_mutex_);
      auto connection = acl_connections_.find(request->handle());
      if (connection == acl_connections_.end()) {
        return ::grpc::Status(::grpc::StatusCode::INVALID_ARGUMENT, "Invalid handle");
      }
      connection->second.connection_->GetAclQueueEnd()->RegisterEnqueue(
          facade_handler_,
          common::Bind(
              &LeAclManagerFacadeService::enqueue_packet,
              common::Unretained(this),
              common::Unretained(request),
              common::Passed(std::move(promise))));
      auto status = future.wait_for(std::chrono::milliseconds(1000));
      if (status != std::future_status::ready) {
        return ::grpc::Status(::grpc::StatusCode::RESOURCE_EXHAUSTED, "Can't send packet");
      }
    }
    return ::grpc::Status::OK;
  }

  std::unique_ptr<BasePacketBuilder> enqueue_packet(const LeAclData* request, std::promise<void> promise) {
    auto connection = acl_connections_.find(request->handle());
    ASSERT_LOG(connection != acl_connections_.end(), "handle %d", request->handle());
    connection->second.connection_->GetAclQueueEnd()->UnregisterEnqueue();
    std::unique_ptr<RawBuilder> packet =
        std::make_unique<RawBuilder>(std::vector<uint8_t>(request->payload().begin(), request->payload().end()));
    promise.set_value();
    return packet;
  }

  ::grpc::Status FetchAclData(
      ::grpc::ServerContext* context, const LeHandleMsg* request, ::grpc::ServerWriter<LeAclData>* writer) override {
    auto connection = acl_connections_.find(request->handle());
    if (connection == acl_connections_.end()) {
      return ::grpc::Status(::grpc::StatusCode::INVALID_ARGUMENT, "Invalid handle");
    }
    return connection->second.pending_acl_data_.RunLoop(context, writer);
  }

  static inline uint16_t to_handle(uint32_t current_request) {
    return (current_request + 0x10) % 0xe00;
  }

  static inline std::string builder_to_string(std::unique_ptr<BasePacketBuilder> builder) {
    std::vector<uint8_t> bytes;
    BitInserter bit_inserter(bytes);
    builder->Serialize(bit_inserter);
    return std::string(bytes.begin(), bytes.end());
  }

  void on_incoming_acl(std::shared_ptr<LeAclConnection> connection, uint16_t handle) {
    auto packet = connection->GetAclQueueEnd()->TryDequeue();
    auto connection_tracker = acl_connections_.find(handle);
    ASSERT_LOG(connection_tracker != acl_connections_.end(), "handle %d", handle);
    LeAclData acl_data;
    acl_data.set_handle(handle);
    acl_data.set_payload(std::string(packet->begin(), packet->end()));
    connection_tracker->second.pending_acl_data_.OnIncomingEvent(acl_data);
  }

  void OnLeConnectSuccess(AddressWithType address_with_type, std::unique_ptr<LeAclConnection> connection) override {
    LOG_INFO("%s", address_with_type.ToString().c_str());

    std::unique_lock<std::mutex> lock(acl_connections_mutex_);
    auto addr = address_with_type.GetAddress();
    std::shared_ptr<LeAclConnection> shared_connection = std::move(connection);
    uint16_t handle = to_handle(current_connection_request_);
    acl_connections_.emplace(
        std::piecewise_construct,
        std::forward_as_tuple(handle),
        std::forward_as_tuple(handle, shared_connection, per_connection_events_[current_connection_request_]));
    shared_connection->GetAclQueueEnd()->RegisterDequeue(
        facade_handler_,
        common::Bind(&LeAclManagerFacadeService::on_incoming_acl, common::Unretained(this), shared_connection, handle));
    auto callbacks = acl_connections_.find(handle)->second.GetCallbacks();
    shared_connection->RegisterCallbacks(callbacks, facade_handler_);
    {
      std::unique_ptr<BasePacketBuilder> builder = LeConnectionCompleteBuilder::Create(
          ErrorCode::SUCCESS,
          handle,
          Role::CENTRAL,
          address_with_type.GetAddressType(),
          addr,
          1,
          2,
          3,
          ClockAccuracy::PPM_20);
      LeConnectionEvent success;
      success.set_payload(builder_to_string(std::move(builder)));
      per_connection_events_[current_connection_request_]->OnIncomingEvent(success);
    }
    current_connection_request_++;
  }

  void OnLeConnectFail(AddressWithType address, ErrorCode reason) override {
    std::unique_ptr<BasePacketBuilder> builder = LeConnectionCompleteBuilder::Create(
        reason, 0, Role::CENTRAL, address.GetAddressType(), address.GetAddress(), 0, 0, 0, ClockAccuracy::PPM_20);
    LeConnectionEvent fail;
    fail.set_payload(builder_to_string(std::move(builder)));
    per_connection_events_[current_connection_request_]->OnIncomingEvent(fail);
    current_connection_request_++;
  }

  class Connection : public LeConnectionManagementCallbacks {
   public:
    Connection(
        uint16_t handle,
        std::shared_ptr<LeAclConnection> connection,
        std::shared_ptr<::bluetooth::grpc::GrpcEventQueue<LeConnectionEvent>> event_stream)
        : handle_(handle), connection_(std::move(connection)), event_stream_(std::move(event_stream)) {}
    void OnConnectionUpdate(
        uint16_t connection_interval, uint16_t connection_latency, uint16_t supervision_timeout) override {
      LOG_INFO(
          "interval: 0x%hx, latency: 0x%hx, timeout 0x%hx",
          connection_interval,
          connection_latency,
          supervision_timeout);
    }

    void OnDataLengthChange(uint16_t tx_octets, uint16_t tx_time, uint16_t rx_octets, uint16_t rx_time) override {
      LOG_INFO(
          "tx_octets: 0x%hx, tx_time: 0x%hx, rx_octets 0x%hx, rx_time 0x%hx", tx_octets, tx_time, rx_octets, rx_time);
    }
    void OnDisconnection(ErrorCode reason) override {
      std::unique_ptr<BasePacketBuilder> builder =
          DisconnectionCompleteBuilder::Create(ErrorCode::SUCCESS, handle_, reason);
      LeConnectionEvent disconnection;
      disconnection.set_payload(builder_to_string(std::move(builder)));
      event_stream_->OnIncomingEvent(disconnection);
    }

    void OnReadRemoteVersionInformationComplete(
        uint8_t lmp_version, uint16_t manufacturer_name, uint16_t sub_version) override {}

    LeConnectionManagementCallbacks* GetCallbacks() {
      return this;
    }

    uint16_t handle_;
    std::shared_ptr<LeAclConnection> connection_;
    std::shared_ptr<::bluetooth::grpc::GrpcEventQueue<LeConnectionEvent>> event_stream_;
    ::bluetooth::grpc::GrpcEventQueue<LeAclData> pending_acl_data_{std::string("PendingAclData") +
                                                                   std::to_string(handle_)};
  };

 private:
  AclManager* acl_manager_;
  ::bluetooth::os::Handler* facade_handler_;
  mutable std::mutex acl_connections_mutex_;
  std::vector<std::shared_ptr<::bluetooth::grpc::GrpcEventQueue<LeConnectionEvent>>> per_connection_events_;
  std::map<uint16_t, Connection> acl_connections_;
  uint32_t current_connection_request_{0};
};

void LeAclManagerFacadeModule::ListDependencies(ModuleList* list) {
  ::bluetooth::grpc::GrpcFacadeModule::ListDependencies(list);
  list->add<AclManager>();
}

void LeAclManagerFacadeModule::Start() {
  ::bluetooth::grpc::GrpcFacadeModule::Start();
  service_ = new LeAclManagerFacadeService(GetDependency<AclManager>(), GetHandler());
}

void LeAclManagerFacadeModule::Stop() {
  delete service_;
  ::bluetooth::grpc::GrpcFacadeModule::Stop();
}

::grpc::Service* LeAclManagerFacadeModule::GetService() const {
  return service_;
}

const ModuleFactory LeAclManagerFacadeModule::Factory =
    ::bluetooth::ModuleFactory([]() { return new LeAclManagerFacadeModule(); });

}  // namespace facade
}  // namespace hci
}  // namespace bluetooth
