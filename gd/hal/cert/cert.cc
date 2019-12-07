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

#include "grpc/grpc_event_queue.h"
#include "hal/cert/api.grpc.pb.h"
#include "hal/hci_hal.h"
#include "hal/serialize_packet.h"
#include "hci/hci_packets.h"

namespace bluetooth {
namespace hal {
namespace cert {

class HciHalCertService : public HciHalCert::Service, public ::bluetooth::hal::HciHalCallbacks {
 public:
  explicit HciHalCertService(HciHal* hal) : hal_(hal) {
    hal->registerIncomingPacketCallback(this);
  }

  ~HciHalCertService() override {
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

  ::grpc::Status FetchHciEvent(::grpc::ServerContext* context, const ::google::protobuf::Empty* request,
                               ::grpc::ServerWriter<HciEventPacket>* writer) override {
    return pending_hci_events_.RunLoop(context, writer);
  };

  ::grpc::Status FetchHciAcl(::grpc::ServerContext* context, const ::google::protobuf::Empty* request,
                             ::grpc::ServerWriter<HciAclPacket>* writer) override {
    return pending_acl_events_.RunLoop(context, writer);
  };

  ::grpc::Status FetchHciSco(::grpc::ServerContext* context, const ::google::protobuf::Empty* request,
                             ::grpc::ServerWriter<HciScoPacket>* writer) override {
    return pending_sco_events_.RunLoop(context, writer);
  };

  void hciEventReceived(bluetooth::hal::HciPacket event) override {
    {
      HciEventPacket response;
      std::string response_str = std::string(event.begin(), event.end());
      response.set_payload(response_str);
      pending_hci_events_.OnIncomingEvent(std::move(response));
    }
    can_send_hci_command_ = true;
    cv_.notify_one();
  }

  void aclDataReceived(bluetooth::hal::HciPacket data) override {
    HciAclPacket response;
    std::string response_str = std::string(data.begin(), data.end());
    response.set_payload(response_str);
    pending_acl_events_.OnIncomingEvent(std::move(response));
  }

  void scoDataReceived(bluetooth::hal::HciPacket data) override {
    HciScoPacket response;
    std::string response_str = std::string(data.begin(), data.end());
    response.set_payload(response_str);
    pending_sco_events_.OnIncomingEvent(std::move(response));
  }

 private:
  HciHal* hal_;
  bool can_send_hci_command_ = true;
  mutable std::mutex mutex_;
  std::condition_variable cv_;
  ::bluetooth::grpc::GrpcEventQueue<HciEventPacket> pending_hci_events_{"FetchHciEvent"};
  ::bluetooth::grpc::GrpcEventQueue<HciAclPacket> pending_acl_events_{"FetchHciAcl"};
  ::bluetooth::grpc::GrpcEventQueue<HciScoPacket> pending_sco_events_{"FetchHciSco"};
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

const ModuleFactory HalCertModule::Factory = ::bluetooth::ModuleFactory([]() { return new HalCertModule(); });

}  // namespace cert
}  // namespace hal
}  // namespace bluetooth
