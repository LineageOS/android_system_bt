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

#include "facade.h"

#include <memory>
#include <mutex>

#include "common/blocking_queue.h"
#include "grpc/grpc_event_stream.h"
#include "hal/facade/api.grpc.pb.h"
#include "hal/hci_hal.h"
#include "hci/hci_packets.h"
#include "os/log.h"

using ::grpc::ServerAsyncResponseWriter;
using ::grpc::ServerAsyncWriter;
using ::grpc::ServerCompletionQueue;
using ::grpc::ServerContext;

namespace bluetooth {
namespace hal {
namespace facade {

class HciTransportationService
    : public HciTransportation::Service,
      public ::bluetooth::hal::HciHalCallbacks {
 public:
  HciTransportationService(HciHal* hal)
      : hal_(hal), hci_event_stream_(&hci_event_stream_callback_), hci_acl_stream_(&hci_acl_stream_callback_),
        hci_sco_stream_(&hci_sco_stream_callback_) {}

  ::grpc::Status SetLoopbackMode(::grpc::ServerContext* context,
                                 const ::bluetooth::hal::facade::LoopbackModeSettings* request,
                                 ::google::protobuf::Empty* response) override {
    bool enable = request->enable();
    auto packet = hci::WriteLoopbackModeBuilder::Create(enable ? hci::LoopbackMode::ENABLE_LOCAL
                                                               : hci::LoopbackMode::NO_LOOPBACK);
    std::shared_ptr<std::vector<uint8_t>> packet_bytes = std::make_shared<std::vector<uint8_t>>();
    hci::BitInserter it(*packet_bytes);
    packet->Serialize(it);
    hal_->sendHciCommand(*packet_bytes);
    return ::grpc::Status::OK;
  }

  ::grpc::Status SendHciCommand(::grpc::ServerContext* context, const ::bluetooth::hal::facade::HciCmdPacket* request,
                                ::google::protobuf::Empty* response) override {
    std::string req_string = request->payload();
    hal_->sendHciCommand(std::vector<uint8_t>(req_string.begin(), req_string.end()));
    return ::grpc::Status::OK;
  }

  ::grpc::Status SendHciAcl(::grpc::ServerContext* context, const ::bluetooth::hal::facade::HciAclPacket* request,
                            ::google::protobuf::Empty* response) override {
    std::string req_string = request->payload();
    hal_->sendAclData(std::vector<uint8_t>(req_string.begin(), req_string.end()));
    return ::grpc::Status::OK;
  }

  ::grpc::Status SendHciSco(::grpc::ServerContext* context, const ::bluetooth::hal::facade::HciScoPacket* request,
                            ::google::protobuf::Empty* response) override {
    std::string req_string = request->payload();
    hal_->sendScoData(std::vector<uint8_t>(req_string.begin(), req_string.end()));
    return ::grpc::Status::OK;
  }

  ::grpc::Status FetchHciEvent(::grpc::ServerContext* context, const ::bluetooth::facade::EventStreamRequest* request,
                               ::grpc::ServerWriter<HciEvtPacket>* writer) override {
    return hci_event_stream_.HandleRequest(context, request, writer);
  };

  ::grpc::Status FetchHciAcl(::grpc::ServerContext* context, const ::bluetooth::facade::EventStreamRequest* request,
                             ::grpc::ServerWriter<HciAclPacket>* writer) override {
    return hci_acl_stream_.HandleRequest(context, request, writer);
  };

  ::grpc::Status FetchHciSco(::grpc::ServerContext* context, const ::bluetooth::facade::EventStreamRequest* request,
                             ::grpc::ServerWriter<HciScoPacket>* writer) override {
    return hci_sco_stream_.HandleRequest(context, request, writer);
  };

  void hciEventReceived(bluetooth::hal::HciPacket event) override {
    std::string response_str = std::string(event.begin(), event.end());
    hci_event_stream_.OnIncomingEvent(event);
  }

  void aclDataReceived(bluetooth::hal::HciPacket data) override {
    hci_acl_stream_.OnIncomingEvent(data);
  }

  void scoDataReceived(bluetooth::hal::HciPacket data) override {
    hci_sco_stream_.OnIncomingEvent(data);
  }

 private:
  HciHal* hal_;

  class HciEventStreamCallback : public ::bluetooth::grpc::GrpcEventStreamCallback<HciEvtPacket, HciPacket> {
   public:
    void OnWriteResponse(HciEvtPacket* response, const HciPacket& event) override {
      std::string response_str = std::string(event.begin(), event.end());
      response->set_payload(std::string(event.begin(), event.end()));
    }
  } hci_event_stream_callback_;
  ::bluetooth::grpc::GrpcEventStream<HciEvtPacket, HciPacket> hci_event_stream_;

  class HciAclStreamCallback : public ::bluetooth::grpc::GrpcEventStreamCallback<HciAclPacket, HciPacket> {
   public:
    void OnWriteResponse(HciAclPacket* response, const HciPacket& event) override {
      response->set_payload(std::string(event.begin(), event.end()));
    }
  } hci_acl_stream_callback_;
  ::bluetooth::grpc::GrpcEventStream<HciAclPacket, HciPacket> hci_acl_stream_;

  class HciScoStreamCallback : public ::bluetooth::grpc::GrpcEventStreamCallback<HciScoPacket, HciPacket> {
   public:
    void OnWriteResponse(HciScoPacket* response, const HciPacket& event) override {
      response->set_payload(std::string(event.begin(), event.end()));
    }
  } hci_sco_stream_callback_;
  ::bluetooth::grpc::GrpcEventStream<HciScoPacket, HciPacket> hci_sco_stream_;
};

void HalFacadeModule::ListDependencies(ModuleList* list) {
  ::bluetooth::grpc::GrpcFacadeModule::ListDependencies(list);
  list->add<HciHal>();
}

void HalFacadeModule::Start() {
  ::bluetooth::grpc::GrpcFacadeModule::Start();
  auto hal = GetDependency<HciHal>();

  service_ = new HciTransportationService(hal);
  hal->registerIncomingPacketCallback(service_);
}

void HalFacadeModule::Stop() {
  delete service_;
}

::grpc::Service* HalFacadeModule::GetService() const {
  return service_;
}

const ModuleFactory HalFacadeModule::Factory = ::bluetooth::ModuleFactory([]() {
  return new HalFacadeModule();
});

}  // namespace facade
}  // namespace hal
}  // namespace bluetooth
