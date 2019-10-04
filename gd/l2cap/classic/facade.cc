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
#include <cstdint>
#include <unordered_map>

#include "common/bidi_queue.h"
#include "common/bind.h"
#include "grpc/grpc_event_stream.h"
#include "hci/address.h"
#include "hci/facade.h"
#include "l2cap/classic/facade.grpc.pb.h"
#include "l2cap/classic/facade.h"
#include "l2cap/classic/l2cap_classic_module.h"
#include "l2cap/l2cap_packets.h"
#include "os/log.h"
#include "packet/raw_builder.h"

using ::grpc::ServerAsyncResponseWriter;
using ::grpc::ServerAsyncWriter;
using ::grpc::ServerContext;

using ::bluetooth::facade::EventStreamRequest;
using ::bluetooth::packet::RawBuilder;

namespace bluetooth {
namespace l2cap {
namespace classic {

class L2capModuleFacadeService : public L2capModuleFacade::Service {
 public:
  L2capModuleFacadeService(L2capClassicModule* l2cap_layer, os::Handler* facade_handler)
      : l2cap_layer_(l2cap_layer), facade_handler_(facade_handler) {
    ASSERT(l2cap_layer_ != nullptr);
    ASSERT(facade_handler_ != nullptr);
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

  ::grpc::Status FetchConnectionComplete(
      ::grpc::ServerContext* context, const ::bluetooth::facade::EventStreamRequest* request,
      ::grpc::ServerWriter<::bluetooth::l2cap::classic::ConnectionCompleteEvent>* writer) override {
    return connection_complete_stream_.HandleRequest(context, request, writer);
  }

  ::grpc::Status Connect(::grpc::ServerContext* context, const facade::BluetoothAddress* request,
                         ::google::protobuf::Empty* response) override {
    auto fixed_channel_manager = l2cap_layer_->GetFixedChannelManager();
    hci::Address peer;
    ASSERT(hci::Address::FromString(request->address(), peer));
    fixed_channel_manager->ConnectServices(peer, common::BindOnce([](FixedChannelManager::ConnectionResult) {}),
                                           facade_handler_);
    return ::grpc::Status::OK;
  }

  ::grpc::Status SendL2capPacket(::grpc::ServerContext* context,
                                 const ::bluetooth::l2cap::classic::L2capPacket* request,
                                 ::bluetooth::l2cap::classic::SendL2capPacketResult* response) override {
    if (connection_less_channel_helper_map_.find(request->channel()) == connection_less_channel_helper_map_.end()) {
      return ::grpc::Status(::grpc::StatusCode::FAILED_PRECONDITION, "Channel not registered");
    }
    std::vector<uint8_t> packet(request->payload().begin(), request->payload().end());
    connection_less_channel_helper_map_[request->channel()]->SendPacket(packet);
    response->set_result_type(::bluetooth::l2cap::classic::SendL2capPacketResultType::OK);
    return ::grpc::Status::OK;
  }

  ::grpc::Status FetchL2capData(::grpc::ServerContext* context, const ::bluetooth::facade::EventStreamRequest* request,
                                ::grpc::ServerWriter<::bluetooth::l2cap::classic::L2capPacket>* writer) override {
    return l2cap_stream_.HandleRequest(context, request, writer);
  }

  ::grpc::Status RegisterChannel(::grpc::ServerContext* context,
                                 const ::bluetooth::l2cap::classic::RegisterChannelRequest* request,
                                 ::google::protobuf::Empty* response) override {
    if (connection_less_channel_helper_map_.find(request->channel()) != connection_less_channel_helper_map_.end()) {
      return ::grpc::Status(::grpc::StatusCode::FAILED_PRECONDITION, "Already registered");
    }
    connection_less_channel_helper_map_.emplace(
        request->channel(),
        std::make_unique<L2capFixedChannelHelper>(this, l2cap_layer_, facade_handler_, request->channel()));

    return ::grpc::Status::OK;
  }

  class L2capFixedChannelHelper {
   public:
    L2capFixedChannelHelper(L2capModuleFacadeService* service, L2capClassicModule* l2cap_layer, os::Handler* handler,
                            Cid cid)
        : facade_service_(service), l2cap_layer_(l2cap_layer), handler_(handler), cid_(cid) {
      fixed_channel_manager_ = l2cap_layer_->GetFixedChannelManager();
      fixed_channel_manager_->RegisterService(
          cid, {},
          common::BindOnce(&L2capFixedChannelHelper::on_l2cap_service_registration_complete, common::Unretained(this)),
          common::Bind(&L2capFixedChannelHelper::on_connection_open, common::Unretained(this)), handler_);
    }

    void on_l2cap_service_registration_complete(FixedChannelManager::RegistrationResult registration_result,
                                                std::unique_ptr<FixedChannelService> service) {
      service_ = std::move(service);
    }

    void on_connection_open(std::unique_ptr<FixedChannel> channel) {
      ConnectionCompleteEvent event;
      event.mutable_remote()->set_address(channel->GetDevice().ToString());
      facade_service_->connection_complete_stream_.OnIncomingEvent(event);
      channel_ = std::move(channel);
    }

    void SendPacket(std::vector<uint8_t> packet) {
      if (channel_ == nullptr) {
        LOG_WARN("Channel is not open");
        return;
      }
      channel_->GetQueueUpEnd()->RegisterEnqueue(
          handler_, common::Bind(&L2capFixedChannelHelper::enqueue_callback, common::Unretained(this), packet));
    }

    void on_incoming_packet() {
      auto packet = channel_->GetQueueUpEnd()->TryDequeue();
      std::string data = std::string(packet->begin(), packet->end());
      L2capPacket l2cap_data;
      l2cap_data.set_channel(cid_);
      l2cap_data.set_payload(data);
      facade_service_->l2cap_stream_.OnIncomingEvent(l2cap_data);
    }

    std::unique_ptr<packet::BasePacketBuilder> enqueue_callback(std::vector<uint8_t> packet) {
      auto packet_one = std::make_unique<packet::RawBuilder>();
      packet_one->AddOctets(packet);
      channel_->GetQueueUpEnd()->UnregisterEnqueue();
      return packet_one;
    };

    L2capModuleFacadeService* facade_service_;
    L2capClassicModule* l2cap_layer_;
    os::Handler* handler_;
    std::unique_ptr<FixedChannelManager> fixed_channel_manager_;
    std::unique_ptr<FixedChannelService> service_;
    std::unique_ptr<FixedChannel> channel_ = nullptr;
    Cid cid_;
  };

  l2cap::classic::L2capClassicModule* l2cap_layer_;
  ::bluetooth::os::Handler* facade_handler_;
  std::map<Cid, std::unique_ptr<L2capFixedChannelHelper>> connection_less_channel_helper_map_;

  class L2capStreamCallback : public ::bluetooth::grpc::GrpcEventStreamCallback<L2capPacket, L2capPacket> {
   public:
    L2capStreamCallback(L2capModuleFacadeService* service) : service_(service) {}

    ~L2capStreamCallback() {
      for (const auto& connection : service_->connection_less_channel_helper_map_) {
        if (subscribed_[connection.first] && connection.second->channel_ != nullptr) {
          connection.second->channel_->GetQueueUpEnd()->UnregisterDequeue();
          subscribed_[connection.first] = false;
        }
      }
    }

    void OnSubscribe() override {
      for (auto& connection : service_->connection_less_channel_helper_map_) {
        if (!subscribed_[connection.first] && connection.second->channel_ != nullptr) {
          connection.second->channel_->GetQueueUpEnd()->RegisterDequeue(
              service_->facade_handler_,
              common::Bind(&L2capFixedChannelHelper::on_incoming_packet, common::Unretained(connection.second.get())));
          subscribed_[connection.first] = true;
        }
      }
    }

    void OnUnsubscribe() override {
      for (const auto& connection : service_->connection_less_channel_helper_map_) {
        if (subscribed_[connection.first] && connection.second->channel_ != nullptr) {
          connection.second->channel_->GetQueueUpEnd()->UnregisterDequeue();
          subscribed_[connection.first] = false;
        }
      }
    }

    void OnWriteResponse(L2capPacket* response, const L2capPacket& event) override {
      response->CopyFrom(event);
    }

    L2capModuleFacadeService* service_;
    std::map<Cid, bool> subscribed_;

  } l2cap_stream_callback_{this};
  ::bluetooth::grpc::GrpcEventStream<L2capPacket, L2capPacket> l2cap_stream_{&l2cap_stream_callback_};

  std::mutex mutex_;
};

void L2capModuleFacadeModule::ListDependencies(ModuleList* list) {
  ::bluetooth::grpc::GrpcFacadeModule::ListDependencies(list);
  list->add<l2cap::classic::L2capClassicModule>();
  list->add<hci::HciLayer>();
}

void L2capModuleFacadeModule::Start() {
  ::bluetooth::grpc::GrpcFacadeModule::Start();
  GetDependency<hci::HciLayer>()->EnqueueCommand(hci::WriteScanEnableBuilder::Create(hci::ScanEnable::PAGE_SCAN_ONLY),
                                                 common::BindOnce([](hci::CommandCompleteView) {}), GetHandler());
  service_ = new L2capModuleFacadeService(GetDependency<l2cap::classic::L2capClassicModule>(), GetHandler());
}

void L2capModuleFacadeModule::Stop() {
  delete service_;
  ::bluetooth::grpc::GrpcFacadeModule::Stop();
}

::grpc::Service* L2capModuleFacadeModule::GetService() const {
  return service_;
}

const ModuleFactory L2capModuleFacadeModule::Factory =
    ::bluetooth::ModuleFactory([]() { return new L2capModuleFacadeModule(); });

}  // namespace classic
}  // namespace l2cap
}  // namespace bluetooth
