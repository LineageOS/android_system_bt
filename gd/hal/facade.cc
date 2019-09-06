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

#include "hal/facade.h"

#include <condition_variable>
#include <memory>
#include <mutex>

#include "common/blocking_queue.h"
#include "grpc/grpc_event_stream.h"
#include "hal/facade.grpc.pb.h"
#include "hal/hci_hal.h"
#include "hal/serialize_packet.h"
#include "hci/hci_packets.h"

using ::grpc::ServerAsyncResponseWriter;
using ::grpc::ServerAsyncWriter;
using ::grpc::ServerContext;

using ::bluetooth::facade::EventStreamRequest;

namespace bluetooth {
namespace hal {

class HciHalFacadeService
    : public HciHalFacade::Service,
      public ::bluetooth::hal::HciHalCallbacks {
 public:
  HciHalFacadeService(HciHal* hal)
      : hal_(hal), hci_event_stream_(&hci_event_stream_callback_), hci_acl_stream_(&hci_acl_stream_callback_),
        hci_sco_stream_(&hci_sco_stream_callback_) {
    hal->registerIncomingPacketCallback(this);
  }

  ~HciHalFacadeService() {
    hal_->unregisterIncomingPacketCallback();
  }

  ::grpc::Status SendHciResetCommand(::grpc::ServerContext* context, const ::google::protobuf::Empty* request,
                                     ::google::protobuf::Empty* response) override {
    std::unique_lock<std::mutex> lock(mutex_);
    can_send_hci_command_ = false;
    hal_->sendHciCommand(SerializePacket(hci::ResetBuilder::Create()));
    while (!can_send_hci_command_) {
      cv_.wait(lock);
    }
    return ::grpc::Status::OK;
  }

  ::grpc::Status SetLoopbackMode(::grpc::ServerContext* context,
                                 const ::bluetooth::hal::LoopbackModeSettings* request,
                                 ::google::protobuf::Empty* response) override {
    std::unique_lock<std::mutex> lock(mutex_);
    can_send_hci_command_ = false;
    bool enable = request->enable();
    hal_->sendHciCommand(SerializePacket(hci::WriteLoopbackModeBuilder::Create(
        enable ? hci::LoopbackMode::ENABLE_LOCAL : hci::LoopbackMode::NO_LOOPBACK)));
    while (!can_send_hci_command_) {
      cv_.wait(lock);
    }
    return ::grpc::Status::OK;
  }

  ::grpc::Status SetInquiry(::grpc::ServerContext* context, const ::bluetooth::hal::InquirySettings* request,
                            ::google::protobuf::Empty* response) override {
    std::unique_lock<std::mutex> lock(mutex_);
    can_send_hci_command_ = false;
    hal_->sendHciCommand(
        SerializePacket(hci::InquiryBuilder::Create(0x33 /* LAP=0x9e8b33 */, static_cast<uint8_t>(request->length()),
                                                    static_cast<uint8_t>(request->num_responses()))));
    while (!can_send_hci_command_) {
      cv_.wait(lock);
    }
    return ::grpc::Status::OK;
  }

  ::grpc::Status SendHciCommand(::grpc::ServerContext* context, const ::bluetooth::hal::HciCommandPacket* request,
                                ::google::protobuf::Empty* response) override {
    std::unique_lock<std::mutex> lock(mutex_);
    can_send_hci_command_ = false;
    std::string req_string = request->payload();
    hal_->sendHciCommand(std::vector<uint8_t>(req_string.begin(), req_string.end()));
    while (!can_send_hci_command_) {
      cv_.wait(lock);
    }
    return ::grpc::Status::OK;
  }

  ::grpc::Status SendHciAcl(::grpc::ServerContext* context, const ::bluetooth::hal::HciAclPacket* request,
                            ::google::protobuf::Empty* response) override {
    std::string req_string = request->payload();
    hal_->sendAclData(std::vector<uint8_t>(req_string.begin(), req_string.end()));
    return ::grpc::Status::OK;
  }

  ::grpc::Status SendHciSco(::grpc::ServerContext* context, const ::bluetooth::hal::HciScoPacket* request,
                            ::google::protobuf::Empty* response) override {
    std::string req_string = request->payload();
    hal_->sendScoData(std::vector<uint8_t>(req_string.begin(), req_string.end()));
    return ::grpc::Status::OK;
  }

  ::grpc::Status FetchHciEvent(::grpc::ServerContext* context, const EventStreamRequest* request,
                               ::grpc::ServerWriter<HciEventPacket>* writer) override {
    return hci_event_stream_.HandleRequest(context, request, writer);
  };

  ::grpc::Status FetchHciAcl(::grpc::ServerContext* context, const EventStreamRequest* request,
                             ::grpc::ServerWriter<HciAclPacket>* writer) override {
    return hci_acl_stream_.HandleRequest(context, request, writer);
  };

  ::grpc::Status FetchHciSco(::grpc::ServerContext* context, const EventStreamRequest* request,
                             ::grpc::ServerWriter<HciScoPacket>* writer) override {
    return hci_sco_stream_.HandleRequest(context, request, writer);
  };

  void hciEventReceived(bluetooth::hal::HciPacket event) override {
    std::string response_str = std::string(event.begin(), event.end());
    hci_event_stream_.OnIncomingEvent(event);
    can_send_hci_command_ = true;
    cv_.notify_one();
  }

  void aclDataReceived(bluetooth::hal::HciPacket data) override {
    hci_acl_stream_.OnIncomingEvent(data);
  }

  void scoDataReceived(bluetooth::hal::HciPacket data) override {
    hci_sco_stream_.OnIncomingEvent(data);
  }

 private:
  HciHal* hal_;
  bool can_send_hci_command_ = true;
  mutable std::mutex mutex_;
  std::condition_variable cv_;

  class HciEventStreamCallback : public ::bluetooth::grpc::GrpcEventStreamCallback<HciEventPacket, HciPacket> {
   public:
    void OnWriteResponse(HciEventPacket* response, const HciPacket& event) override {
      std::string response_str = std::string(event.begin(), event.end());
      response->set_payload(std::string(event.begin(), event.end()));
    }
  } hci_event_stream_callback_;
  ::bluetooth::grpc::GrpcEventStream<HciEventPacket, HciPacket> hci_event_stream_;

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

void HciHalFacadeModule::ListDependencies(ModuleList* list) {
  ::bluetooth::grpc::GrpcFacadeModule::ListDependencies(list);
  list->add<HciHal>();
}

void HciHalFacadeModule::Start() {
  ::bluetooth::grpc::GrpcFacadeModule::Start();
  service_ = new HciHalFacadeService(GetDependency<HciHal>());
}

void HciHalFacadeModule::Stop() {
  delete service_;
  ::bluetooth::grpc::GrpcFacadeModule::Stop();
}

::grpc::Service* HciHalFacadeModule::GetService() const {
  return service_;
}

const ModuleFactory HciHalFacadeModule::Factory = ::bluetooth::ModuleFactory([]() {
  return new HciHalFacadeModule();
});

}  // namespace hal
}  // namespace bluetooth
