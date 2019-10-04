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

#include "l2cap/classic/cert/cert.h"

#include <cstdint>
#include <memory>
#include <mutex>
#include <queue>
#include <unordered_map>

#include "common/blocking_queue.h"
#include "grpc/grpc_event_stream.h"
#include "hci/acl_manager.h"
#include "hci/cert/cert.h"
#include "l2cap/classic/cert/api.grpc.pb.h"
#include "l2cap/classic/l2cap_classic_module.h"
#include "l2cap/l2cap_packets.h"
#include "os/log.h"
#include "packet/raw_builder.h"

using ::grpc::ServerAsyncResponseWriter;
using ::grpc::ServerAsyncWriter;
using ::grpc::ServerContext;

using ::bluetooth::facade::EventStreamRequest;
using ::bluetooth::packet::RawBuilder;

using ::bluetooth::l2cap::classic::cert::ConnectionCompleteEvent;
using ::bluetooth::l2cap::classic::cert::L2capPacket;

namespace bluetooth {
namespace l2cap {
namespace classic {
namespace cert {

using namespace facade;

class L2capModuleCertService : public L2capModuleCert::Service {
 public:
  L2capModuleCertService(hci::AclManager* acl_manager, os::Handler* facade_handler)
      : handler_(facade_handler), acl_manager_(acl_manager) {
    ASSERT(handler_ != nullptr);
    acl_manager_->RegisterCallbacks(&acl_callbacks, handler_);
  }

  class ConnectionCompleteCallback
      : public grpc::GrpcEventStreamCallback<ConnectionCompleteEvent, ConnectionCompleteEvent> {
   public:
    void OnWriteResponse(ConnectionCompleteEvent* response, const ConnectionCompleteEvent& event) override {
      response->CopyFrom(event);
    }

  } connection_complete_callback_;
  ::bluetooth::grpc::GrpcEventStream<ConnectionCompleteEvent, ConnectionCompleteEvent> connection_complete_stream_{
      &connection_complete_callback_};

  ::grpc::Status FetchConnectionComplete(::grpc::ServerContext* context,
                                         const ::bluetooth::facade::EventStreamRequest* request,
                                         ::grpc::ServerWriter<ConnectionCompleteEvent>* writer) override {
    return connection_complete_stream_.HandleRequest(context, request, writer);
  }

  ::grpc::Status SendL2capPacket(::grpc::ServerContext* context, const L2capPacket* request,
                                 ::google::protobuf::Empty* response) override {
    std::unique_ptr<RawBuilder> packet = std::make_unique<RawBuilder>();
    auto req_string = request->payload();
    packet->AddOctets(std::vector<uint8_t>(req_string.begin(), req_string.end()));
    std::unique_ptr<BasicFrameBuilder> l2cap_builder = BasicFrameBuilder::Create(request->channel(), std::move(packet));
    outgoing_packet_queue_.push(std::move(l2cap_builder));
    if (outgoing_packet_queue_.size() == 1) {
      acl_connection_->GetAclQueueEnd()->RegisterEnqueue(
          handler_, common::Bind(&L2capModuleCertService::enqueue_packet_to_acl, common::Unretained(this)));
    }
    return ::grpc::Status::OK;
  }

  std::unique_ptr<packet::BasePacketBuilder> enqueue_packet_to_acl() {
    auto basic_frame_builder = std::move(outgoing_packet_queue_.front());
    outgoing_packet_queue_.pop();
    if (outgoing_packet_queue_.size() == 0) {
      acl_connection_->GetAclQueueEnd()->UnregisterEnqueue();
    }
    return basic_frame_builder;
  }

  ::grpc::Status FetchL2capData(::grpc::ServerContext* context, const ::bluetooth::facade::EventStreamRequest* request,
                                ::grpc::ServerWriter<L2capPacket>* writer) override {
    return l2cap_stream_.HandleRequest(context, request, writer);
  }

  class L2capStreamCallback : public ::bluetooth::grpc::GrpcEventStreamCallback<L2capPacket, L2capPacket> {
   public:
    void OnWriteResponse(L2capPacket* response, const L2capPacket& event) override {
      response->CopyFrom(event);
    }

  } l2cap_stream_callback_;
  ::bluetooth::grpc::GrpcEventStream<L2capPacket, L2capPacket> l2cap_stream_{&l2cap_stream_callback_};

  void on_incoming_packet() {
    auto packet = acl_connection_->GetAclQueueEnd()->TryDequeue();
    BasicFrameView basic_frame_view = BasicFrameView::Create(*packet);
    ASSERT(basic_frame_view.IsValid());
    L2capPacket l2cap_packet;
    std::string data = std::string(packet->begin(), packet->end());
    l2cap_packet.set_payload(data);
    l2cap_packet.set_channel(basic_frame_view.GetChannelId());
    l2cap_stream_.OnIncomingEvent(l2cap_packet);
  }

  std::queue<std::unique_ptr<BasicFrameBuilder>> outgoing_packet_queue_;
  ::bluetooth::os::Handler* handler_;
  hci::AclManager* acl_manager_;
  std::unique_ptr<hci::AclConnection> acl_connection_;

  class AclCallbacks : public hci::ConnectionCallbacks {
   public:
    AclCallbacks(L2capModuleCertService* module) : module_(module) {}
    void OnConnectSuccess(std::unique_ptr<hci::AclConnection> connection) override {
      ConnectionCompleteEvent event;
      event.mutable_remote()->set_address(connection->GetAddress().ToString());
      module_->connection_complete_stream_.OnIncomingEvent(event);
      module_->acl_connection_ = std::move(connection);
      module_->acl_connection_->RegisterDisconnectCallback(common::BindOnce([](hci::ErrorCode) {}), module_->handler_);
      module_->acl_connection_->GetAclQueueEnd()->RegisterDequeue(
          module_->handler_, common::Bind(&L2capModuleCertService::on_incoming_packet, common::Unretained(module_)));
    }
    void OnConnectFail(hci::Address address, hci::ErrorCode reason) override {}

    ~AclCallbacks() {
      module_->acl_connection_->GetAclQueueEnd()->UnregisterDequeue();
    }

    L2capModuleCertService* module_;
  } acl_callbacks{this};

  std::mutex mutex_;
};

void L2capModuleCertModule::ListDependencies(ModuleList* list) {
  ::bluetooth::grpc::GrpcFacadeModule::ListDependencies(list);
  list->add<hci::AclManager>();
  list->add<hci::HciLayer>();
}

void L2capModuleCertModule::Start() {
  ::bluetooth::grpc::GrpcFacadeModule::Start();
  GetDependency<hci::HciLayer>()->EnqueueCommand(hci::WriteScanEnableBuilder::Create(hci::ScanEnable::PAGE_SCAN_ONLY),
                                                 common::BindOnce([](hci::CommandCompleteView) {}), GetHandler());
  service_ = new L2capModuleCertService(GetDependency<hci::AclManager>(), GetHandler());
}

void L2capModuleCertModule::Stop() {
  delete service_;
  ::bluetooth::grpc::GrpcFacadeModule::Stop();
}

::grpc::Service* L2capModuleCertModule::GetService() const {
  return service_;
}

const ModuleFactory L2capModuleCertModule::Factory =
    ::bluetooth::ModuleFactory([]() { return new L2capModuleCertModule(); });

}  // namespace cert
}  // namespace classic
}  // namespace l2cap
}  // namespace bluetooth
