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

#include "hci/facade.h"

#include <condition_variable>
#include <memory>
#include <mutex>

#include "common/bind.h"
#include "common/blocking_queue.h"
#include "grpc/grpc_event_stream.h"
#include "hci/acl_manager.h"
#include "hci/controller.h"
#include "hci/facade.grpc.pb.h"
#include "hci/hci_layer.h"
#include "hci/hci_packets.h"
#include "packet/raw_builder.h"

using ::grpc::ServerAsyncResponseWriter;
using ::grpc::ServerAsyncWriter;
using ::grpc::ServerContext;

using ::bluetooth::facade::EventStreamRequest;
using ::bluetooth::packet::RawBuilder;

namespace bluetooth {
namespace hci {

class AclManagerFacadeService : public AclManagerFacade::Service, public ::bluetooth::hci::ConnectionCallbacks {
 public:
  AclManagerFacadeService(AclManager* acl_manager, Controller* controller, HciLayer* hci_layer,
                          ::bluetooth::os::Handler* facade_handler)
      : acl_manager_(acl_manager), controller_(controller), hci_layer_(hci_layer), facade_handler_(facade_handler) {
    acl_manager_->RegisterCallbacks(this, facade_handler_);
  }

  using EventStream = ::bluetooth::grpc::GrpcEventStream<AclData, AclPacketView>;

  ::grpc::Status ReadLocalAddress(::grpc::ServerContext* context, const ::google::protobuf::Empty* request,
                                  ::bluetooth::facade::BluetoothAddress* response) override {
    auto address = controller_->GetControllerMacAddress().ToString();
    response->set_address(address);
    return ::grpc::Status::OK;
  }

  ::grpc::Status SetPageScanMode(::grpc::ServerContext* context, const ::bluetooth::hci::PageScanMode* request,
                                 ::google::protobuf::Empty* response) override {
    ScanEnable scan_enable = request->enabled() ? ScanEnable::PAGE_SCAN_ONLY : ScanEnable::NO_SCANS;
    std::promise<void> promise;
    auto future = promise.get_future();
    hci_layer_->EnqueueCommand(
        WriteScanEnableBuilder::Create(scan_enable),
        common::BindOnce([](std::promise<void> promise, CommandCompleteView) { promise.set_value(); },
                         std::move(promise)),
        facade_handler_);
    future.wait();
    return ::grpc::Status::OK;
  }

  ::grpc::Status Connect(::grpc::ServerContext* context, const facade::BluetoothAddress* remote,
                         ::google::protobuf::Empty* response) override {
    std::unique_lock<std::mutex> lock(mutex_);
    common::Address peer;
    ASSERT(common::Address::FromString(remote->address(), peer));
    acl_manager_->CreateConnection(peer);
    return ::grpc::Status::OK;
  }

  ::grpc::Status Disconnect(::grpc::ServerContext* context, const facade::BluetoothAddress* request,
                            ::google::protobuf::Empty* response) override {
    std::unique_lock<std::mutex> lock(mutex_);
    common::Address peer;
    common::Address::FromString(request->address(), peer);
    auto connection = acl_connections_.find(request->address());
    if (connection == acl_connections_.end()) {
      LOG_ERROR("Invalid address");
      return ::grpc::Status(::grpc::StatusCode::INVALID_ARGUMENT, "Invalid address");
    } else {
      connection->second.Disconnect(DisconnectReason::REMOTE_USER_TERMINATED_CONNECTION);
      return ::grpc::Status::OK;
    }
  }

  ::grpc::Status SendAclData(::grpc::ServerContext* context, const AclData* request,
                             ::google::protobuf::Empty* response) override {
    std::unique_lock<std::mutex> lock(mutex_);
    std::promise<void> promise;
    auto future = promise.get_future();
    acl_connections_[request->remote().address()].GetAclQueueEnd()->RegisterEnqueue(
        facade_handler_, common::Bind(&AclManagerFacadeService::enqueue_packet, common::Unretained(this),
                                      common::Unretained(request), common::Passed(std::move(promise))));
    future.wait();
    return ::grpc::Status::OK;
  }

  std::unique_ptr<BasePacketBuilder> enqueue_packet(const AclData* request, std::promise<void> promise) {
    acl_connections_[request->remote().address()].GetAclQueueEnd()->UnregisterEnqueue();
    std::string req_string = request->payload();
    std::unique_ptr<RawBuilder> packet = std::make_unique<RawBuilder>();
    packet->AddOctets(std::vector<uint8_t>(req_string.begin(), req_string.end()));
    promise.set_value();
    return packet;
  }

  ::grpc::Status FetchAclData(::grpc::ServerContext* context, const facade::EventStreamRequest* request,
                              ::grpc::ServerWriter<AclData>* writer) override {
    std::unique_lock<std::mutex> lock(mutex_);
    return acl_stream_.HandleRequest(context, request, writer);
  }

  void on_incoming_acl(std::string address) {
    auto connection = acl_connections_.find(address);
    if (connection == acl_connections_.end()) {
      LOG_ERROR("Invalid address");
      return;
    }

    auto packet = connection->second.GetAclQueueEnd()->TryDequeue();
    auto acl_packet = AclPacketView::Create(*packet);
    AclData acl_data;
    acl_data.mutable_remote()->set_address(address);
    std::string data = std::string(acl_packet.begin(), acl_packet.end());
    acl_data.set_payload(data);
    acl_stream_.OnIncomingEvent(acl_data);
  }

  void OnConnectSuccess(::bluetooth::hci::AclConnection connection) override {
    std::unique_lock<std::mutex> lock(mutex_);
    auto addr = connection.GetAddress();
    acl_connections_.emplace(addr.ToString(), connection);
    connection.RegisterDisconnectCallback(
        common::BindOnce(&AclManagerFacadeService::on_disconnect, common::Unretained(this), addr.ToString()),
        facade_handler_);
    connection_complete_stream_.OnIncomingEvent(connection);
  }

  void on_disconnect(std::string address, ErrorCode code) {
    acl_connections_.erase(address);
    DisconnectionEvent event;
    event.mutable_remote()->set_address(address);
    event.set_reason(static_cast<uint32_t>(code));
    disconnection_stream_.OnIncomingEvent(event);
  }

  ::grpc::Status FetchConnectionComplete(::grpc::ServerContext* context, const EventStreamRequest* request,
                                         ::grpc::ServerWriter<ConnectionEvent>* writer) override {
    return connection_complete_stream_.HandleRequest(context, request, writer);
  };

  void OnConnectFail(::bluetooth::common::Address address, ::bluetooth::hci::ErrorCode reason) override {
    std::unique_lock<std::mutex> lock(mutex_);
    ConnectionFailedEvent event;
    event.mutable_remote()->set_address(address.ToString());
    event.set_reason(static_cast<uint32_t>(reason));
    connection_failed_stream_.OnIncomingEvent(event);
  }

  ::grpc::Status FetchConnectionFailed(::grpc::ServerContext* context, const EventStreamRequest* request,
                                       ::grpc::ServerWriter<ConnectionFailedEvent>* writer) override {
    return connection_failed_stream_.HandleRequest(context, request, writer);
  };

  ::grpc::Status FetchDisconnection(::grpc::ServerContext* context,
                                    const ::bluetooth::facade::EventStreamRequest* request,
                                    ::grpc::ServerWriter<DisconnectionEvent>* writer) override {
    return disconnection_stream_.HandleRequest(context, request, writer);
  }

 private:
  AclManager* acl_manager_;
  Controller* controller_;
  HciLayer* hci_layer_;
  mutable std::mutex mutex_;
  ::bluetooth::os::Handler* facade_handler_;

  class ConnectionCompleteStreamCallback
      : public ::bluetooth::grpc::GrpcEventStreamCallback<ConnectionEvent, AclConnection> {
   public:
    void OnWriteResponse(ConnectionEvent* response, AclConnection const& connection) override {
      response->mutable_remote()->set_address(connection.GetAddress().ToString());
    }
  } connection_complete_stream_callback_;
  ::bluetooth::grpc::GrpcEventStream<ConnectionEvent, AclConnection> connection_complete_stream_{
      &connection_complete_stream_callback_};

  class ConnectionFailedStreamCallback
      : public ::bluetooth::grpc::GrpcEventStreamCallback<ConnectionFailedEvent, ConnectionFailedEvent> {
   public:
    void OnWriteResponse(ConnectionFailedEvent* response, const ConnectionFailedEvent& event) override {
      response->CopyFrom(event);
    }
  } connection_failed_stream_callback_;
  ::bluetooth::grpc::GrpcEventStream<ConnectionFailedEvent, ConnectionFailedEvent> connection_failed_stream_{
      &connection_failed_stream_callback_};

  class DisconnectionStreamCallback
      : public ::bluetooth::grpc::GrpcEventStreamCallback<DisconnectionEvent, DisconnectionEvent> {
   public:
    void OnWriteResponse(DisconnectionEvent* response, const DisconnectionEvent& event) override {
      response->CopyFrom(event);
    }
  } disconnection_stream_callback_;
  ::bluetooth::grpc::GrpcEventStream<DisconnectionEvent, DisconnectionEvent> disconnection_stream_{
      &disconnection_stream_callback_};

  class AclStreamCallback : public ::bluetooth::grpc::GrpcEventStreamCallback<AclData, AclData> {
   public:
    AclStreamCallback(AclManagerFacadeService* service) : service_(service) {}

    ~AclStreamCallback() {
      if (subscribed_) {
        for (const auto& connection : service_->acl_connections_) {
          connection.second.GetAclQueueEnd()->UnregisterDequeue();
        }
        subscribed_ = false;
      }
    }

    void OnSubscribe() override {
      if (subscribed_) {
        LOG_WARN("Already subscribed");
        return;
      }
      for (const auto& connection : service_->acl_connections_) {
        auto remote_address = connection.second.GetAddress().ToString();
        connection.second.GetAclQueueEnd()->RegisterDequeue(
            service_->facade_handler_,
            common::Bind(&AclManagerFacadeService::on_incoming_acl, common::Unretained(service_), remote_address));
      }
      subscribed_ = true;
    }

    void OnUnsubscribe() override {
      if (!subscribed_) {
        LOG_WARN("Not subscribed");
        return;
      }
      for (const auto& connection : service_->acl_connections_) {
        connection.second.GetAclQueueEnd()->UnregisterDequeue();
      }
      subscribed_ = false;
    }

    void OnWriteResponse(AclData* response, const AclData& event) override {
      response->CopyFrom(event);
    }

   private:
    AclManagerFacadeService* service_;
    bool subscribed_ = false;
  } acl_stream_callback_{this};
  ::bluetooth::grpc::GrpcEventStream<AclData, AclData> acl_stream_{&acl_stream_callback_};

  std::map<std::string, AclConnection> acl_connections_;
};

void AclManagerFacadeModule::ListDependencies(ModuleList* list) {
  ::bluetooth::grpc::GrpcFacadeModule::ListDependencies(list);
  list->add<AclManager>();
  list->add<Controller>();
  list->add<HciLayer>();
}

void AclManagerFacadeModule::Start() {
  ::bluetooth::grpc::GrpcFacadeModule::Start();
  service_ = new AclManagerFacadeService(GetDependency<AclManager>(), GetDependency<Controller>(),
                                         GetDependency<HciLayer>(), GetHandler());
}

void AclManagerFacadeModule::Stop() {
  delete service_;
  ::bluetooth::grpc::GrpcFacadeModule::Stop();
}

::grpc::Service* AclManagerFacadeModule::GetService() const {
  return service_;
}

const ModuleFactory AclManagerFacadeModule::Factory =
    ::bluetooth::ModuleFactory([]() { return new AclManagerFacadeModule(); });

}  // namespace hci
}  // namespace bluetooth
