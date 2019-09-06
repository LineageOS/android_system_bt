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

#include "hal/cert/cert.h"

#include <condition_variable>
#include <memory>
#include <mutex>

#include "common/blocking_queue.h"
#include "grpc/grpc_event_stream.h"
#include "hal/cert/api.grpc.pb.h"
#include "hal/hci_hal.h"
#include "hal/serialize_packet.h"
#include "hci/hci_packets.h"

namespace bluetooth {
namespace hal {
namespace cert {

class HciHalCertService : public HciHalCert::Service, public ::bluetooth::hal::HciHalCallbacks {
 public:
  HciHalCertService(HciHal* hal)
      : hal_(hal), hci_event_stream_(&hci_event_stream_callback_), hci_acl_stream_(&hci_acl_stream_callback_),
        hci_sco_stream_(&hci_sco_stream_callback_) {
    hal->registerIncomingPacketCallback(this);
  }

  ~HciHalCertService() {
    hal_->unregisterIncomingPacketCallback();
  }

  ::grpc::Status SendHciResetCommand(::grpc::ServerContext* context, const ::google::protobuf::Empty* request,
                                     ::google::protobuf::Empty* response) override {
    std::unique_lock<std::mutex> lock(mutex_);
    can_send_hci_command_ = false;
    hal_->sendHciCommand(SerializePacket(hci::ResetBuilder::Create()));
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    while (!can_send_hci_command_) {
      cv_.wait(lock);
    }
    return ::grpc::Status::OK;
  }

  ::grpc::Status SetScanMode(::grpc::ServerContext* context, const ScanModeSettings* request,
                             ::google::protobuf::Empty* response) override {
    std::unique_lock<std::mutex> lock(mutex_);
    can_send_hci_command_ = false;
    unsigned int mode = request->mode();
    hci::ScanEnable scan_enable;
    switch (mode) {
      case 0x00:
        scan_enable = hci::ScanEnable::NO_SCANS;
        break;
      case 0x01:
        scan_enable = hci::ScanEnable::INQUIRY_SCAN_ONLY;
        break;
      case 0x02:
        scan_enable = hci::ScanEnable::PAGE_SCAN_ONLY;
        break;
      case 0x03:
        scan_enable = hci::ScanEnable::INQUIRY_AND_PAGE_SCAN;
        break;
    }

    hal_->sendHciCommand(SerializePacket(hci::WriteScanEnableBuilder::Create(scan_enable)));
    while (!can_send_hci_command_) {
      cv_.wait(lock);
    }
    return ::grpc::Status::OK;
  }

  ::grpc::Status SendHciCommand(::grpc::ServerContext* context, const ::bluetooth::hal::cert::HciCommandPacket* request,
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

  ::grpc::Status SendHciAcl(::grpc::ServerContext* context, const ::bluetooth::hal::cert::HciAclPacket* request,
                            ::google::protobuf::Empty* response) override {
    std::string req_string = request->payload();
    hal_->sendAclData(std::vector<uint8_t>(req_string.begin(), req_string.end()));
    return ::grpc::Status::OK;
  }

  ::grpc::Status SendHciSco(::grpc::ServerContext* context, const ::bluetooth::hal::cert::HciScoPacket* request,
                            ::google::protobuf::Empty* response) override {
    std::string req_string = request->payload();
    hal_->sendScoData(std::vector<uint8_t>(req_string.begin(), req_string.end()));
    return ::grpc::Status::OK;
  }

  ::grpc::Status FetchHciEvent(::grpc::ServerContext* context, const ::bluetooth::facade::EventStreamRequest* request,
                               ::grpc::ServerWriter<HciEventPacket>* writer) override {
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

void HalCertModule::ListDependencies(ModuleList* list) {
  ::bluetooth::grpc::GrpcFacadeModule::ListDependencies(list);
  list->add<HciHal>();
}

void HalCertModule::Start() {
  ::bluetooth::grpc::GrpcFacadeModule::Start();
  service_ = new HciHalCertService(GetDependency<HciHal>());
}

void HalCertModule::Stop() {
  delete service_;
  ::bluetooth::grpc::GrpcFacadeModule::Stop();
}

::grpc::Service* HalCertModule::GetService() const {
  return service_;
}

const ModuleFactory HalCertModule::Factory = ::bluetooth::ModuleFactory([]() {
  return new HalCertModule();
});

}  // namespace cert
}  // namespace hal
}  // namespace bluetooth
