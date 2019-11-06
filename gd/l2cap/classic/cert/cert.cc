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
#include "hci/hci_packets.h"
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

  ::grpc::Status SetOnIncomingConnectionRequest(
      ::grpc::ServerContext* context,
      const ::bluetooth::l2cap::classic::cert::SetOnIncomingConnectionRequestRequest* request,
      ::bluetooth::l2cap::classic::cert::SetOnIncomingConnectionRequestResponse* response) override {
    accept_incoming_connection_ = request->accept();
    return ::grpc::Status::OK;
  }

  bool accept_incoming_connection_ = true;

  ::grpc::Status SendL2capPacket(::grpc::ServerContext* context, const L2capPacket* request,
                                 ::google::protobuf::Empty* response) override {
    std::unique_ptr<RawBuilder> packet = std::make_unique<RawBuilder>();
    auto req_string = request->payload();
    packet->AddOctets(std::vector<uint8_t>(req_string.begin(), req_string.end()));
    std::unique_ptr<BasicFrameBuilder> l2cap_builder = BasicFrameBuilder::Create(request->channel(), std::move(packet));
    outgoing_packet_queue_.push(std::move(l2cap_builder));
    send_packet_from_queue();
    return ::grpc::Status::OK;
  }

  static constexpr Cid kFirstDynamicChannelForIncomingRequest = kFirstDynamicChannel + 0x100;

  ::grpc::Status SendConnectionRequest(::grpc::ServerContext* context, const cert::ConnectionRequest* request,
                                       ::google::protobuf::Empty* response) override {
    auto scid = request->scid();
    if (last_connection_request_scid_ != kInvalidCid) {
      return ::grpc::Status(::grpc::StatusCode::INVALID_ARGUMENT, "Another connection request is pending");
    }
    if (scid >= kFirstDynamicChannelForIncomingRequest) {
      return ::grpc::Status(::grpc::StatusCode::INVALID_ARGUMENT, "Use scid < kFirstDynamicChannelForIncomingRequest");
    }
    for (const auto& cid_pair : open_channels_scid_dcid_) {
      if (cid_pair.first == scid) {
        return ::grpc::Status(::grpc::StatusCode::INVALID_ARGUMENT, "SCID already taken");
      }
    }
    auto builder = ConnectionRequestBuilder::Create(1, request->psm(), scid);
    auto l2cap_builder = BasicFrameBuilder::Create(1, std::move(builder));
    outgoing_packet_queue_.push(std::move(l2cap_builder));
    send_packet_from_queue();
    last_connection_request_scid_ = scid;
    return ::grpc::Status::OK;
  }
  Cid last_connection_request_scid_ = kInvalidCid;
  Cid next_incoming_request_cid_ = kFirstDynamicChannelForIncomingRequest;

  ::grpc::Status SendConfigurationRequest(
      ::grpc::ServerContext* context, const ::bluetooth::l2cap::classic::cert::ConfigurationRequest* request,
      ::bluetooth::l2cap::classic::cert::SendConfigurationRequestResult* response) override {
    auto builder = ConfigurationRequestBuilder::Create(1, request->scid(), Continuation::END, {});
    auto l2cap_builder = BasicFrameBuilder::Create(kClassicSignallingCid, std::move(builder));
    outgoing_packet_queue_.push(std::move(l2cap_builder));
    send_packet_from_queue();
    return ::grpc::Status::OK;
  }

  ::grpc::Status SendDisconnectionRequest(::grpc::ServerContext* context, const cert::DisconnectionRequest* request,
                                          ::google::protobuf::Empty* response) override {
    auto builder = DisconnectionRequestBuilder::Create(3, request->dcid(), request->scid());
    auto l2cap_builder = BasicFrameBuilder::Create(kClassicSignallingCid, std::move(builder));
    outgoing_packet_queue_.push(std::move(l2cap_builder));
    send_packet_from_queue();

    return ::grpc::Status::OK;
  }

  ::grpc::Status FetchOpenedChannels(
      ::grpc::ServerContext* context, const ::bluetooth::l2cap::classic::cert::FetchOpenedChannelsRequest* request,
      ::bluetooth::l2cap::classic::cert::FetchOpenedChannelsResponse* response) override {
    for (const auto& cid_pair : open_channels_scid_dcid_) {
      response->mutable_scid()->Add(cid_pair.first);
      response->mutable_dcid()->Add(cid_pair.second);
    }
    return ::grpc::Status::OK;
  }
  std::vector<std::pair<uint16_t, uint16_t>> open_channels_scid_dcid_;

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

    if (basic_frame_view.GetChannelId() == kClassicSignallingCid) {
      ControlView control_view = ControlView::Create(basic_frame_view.GetPayload());
      ASSERT(control_view.IsValid());
      handle_signalling_packet(control_view);
    }
  }

  void send_packet_from_queue() {
    if (outgoing_packet_queue_.size() == 1) {
      acl_connection_->GetAclQueueEnd()->RegisterEnqueue(
          handler_, common::Bind(&L2capModuleCertService::enqueue_packet_to_acl, common::Unretained(this)));
    }
  }

  void handle_signalling_packet(ControlView control_view) {
    auto code = control_view.GetCode();
    switch (code) {
      case CommandCode::CONNECTION_REQUEST: {
        ConnectionRequestView view = ConnectionRequestView::Create(control_view);
        ASSERT(view.IsValid());
        auto builder = ConnectionResponseBuilder::Create(
            view.GetIdentifier(), next_incoming_request_cid_, view.GetSourceCid(),
            accept_incoming_connection_ ? ConnectionResponseResult::SUCCESS : ConnectionResponseResult::INVALID_CID,
            ConnectionResponseStatus::NO_FURTHER_INFORMATION_AVAILABLE);
        auto l2cap_builder = BasicFrameBuilder::Create(kClassicSignallingCid, std::move(builder));
        outgoing_packet_queue_.push(std::move(l2cap_builder));
        send_packet_from_queue();
        open_channels_scid_dcid_.emplace_back(next_incoming_request_cid_, view.GetSourceCid());
        next_incoming_request_cid_++;
        break;
      }
      case CommandCode::CONNECTION_RESPONSE: {
        ConnectionResponseView view = ConnectionResponseView::Create(control_view);
        ASSERT(view.IsValid());
        open_channels_scid_dcid_.emplace_back(last_connection_request_scid_, view.GetSourceCid());
        last_connection_request_scid_ = kInvalidCid;
        break;
      }

      case CommandCode::CONFIGURATION_REQUEST: {
        ConfigurationRequestView view = ConfigurationRequestView::Create(control_view);
        ASSERT(view.IsValid());
        auto builder =
            ConfigurationResponseBuilder::Create(view.GetIdentifier(), view.GetDestinationCid(), Continuation::END,
                                                 ConfigurationResponseResult::SUCCESS, {});
        auto l2cap_builder = BasicFrameBuilder::Create(kClassicSignallingCid, std::move(builder));
        outgoing_packet_queue_.push(std::move(l2cap_builder));
        send_packet_from_queue();
        break;
      }
      case CommandCode::INFORMATION_REQUEST: {
        InformationRequestView information_request_view = InformationRequestView::Create(control_view);
        if (!information_request_view.IsValid()) {
          return;
        }
        auto type = information_request_view.GetInfoType();
        switch (type) {
          case InformationRequestInfoType::CONNECTIONLESS_MTU: {
            auto response = InformationResponseConnectionlessMtuBuilder::Create(
                information_request_view.GetIdentifier(), InformationRequestResult::NOT_SUPPORTED, 0);
            auto l2cap_builder = BasicFrameBuilder::Create(kClassicSignallingCid, std::move(response));
            outgoing_packet_queue_.push(std::move(l2cap_builder));
            send_packet_from_queue();
            break;
          }
          case InformationRequestInfoType::EXTENDED_FEATURES_SUPPORTED: {
            // TODO: implement this response
            auto response = InformationResponseExtendedFeaturesBuilder::Create(information_request_view.GetIdentifier(),
                                                                               InformationRequestResult::NOT_SUPPORTED,
                                                                               0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
            auto l2cap_builder = BasicFrameBuilder::Create(kClassicSignallingCid, std::move(response));
            outgoing_packet_queue_.push(std::move(l2cap_builder));
            send_packet_from_queue();
            break;
          }
          case InformationRequestInfoType::FIXED_CHANNELS_SUPPORTED: {
            constexpr uint64_t kSignallingChannelMask = 0x02;
            auto response = InformationResponseFixedChannelsBuilder::Create(
                information_request_view.GetIdentifier(), InformationRequestResult::SUCCESS, kSignallingChannelMask);
            auto l2cap_builder = BasicFrameBuilder::Create(kClassicSignallingCid, std::move(response));
            outgoing_packet_queue_.push(std::move(l2cap_builder));
            send_packet_from_queue();
            break;
          }
        }
        break;
      }
      default:
        return;
    }
  }

  std::queue<std::unique_ptr<BasePacketBuilder>> outgoing_packet_queue_;
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
      dequeue_registered_ = true;
    }
    void OnConnectFail(hci::Address address, hci::ErrorCode reason) override {}

    ~AclCallbacks() {
      if (dequeue_registered_) {
        module_->acl_connection_->GetAclQueueEnd()->UnregisterDequeue();
      }
    }

    bool dequeue_registered_ = false;

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
