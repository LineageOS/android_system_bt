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
#include <thread>

#include "grpc/async_grpc.h"
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
  HciTransportationService(HciHal* hal) : hal_(hal) {
  }

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

  ::grpc::Status SendHciCmd(::grpc::ServerContext* context, const ::bluetooth::hal::facade::HciCmdPacket* request,
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

  void hciEventReceived(bluetooth::hal::HciPacket event) override {
    // TODO
  }

  void aclDataReceived(bluetooth::hal::HciPacket data) override {
    // TODO
  }

  void scoDataReceived(bluetooth::hal::HciPacket data) override {
    // TODO
  }
 private:
  HciHal* hal_;
};

void HalFacadeModule::ListDependencies(ModuleList* list) {
  ::bluetooth::grpc::GrpcFacadeModule::ListDependencies(list);
  list->add<HciHal>();
}

void HalFacadeModule::Start(const ModuleRegistry* registry) {
  ::bluetooth::grpc::GrpcFacadeModule::Start(registry);
  auto hal = registry->GetInstance<HciHal>();

  service_ = new HciTransportationService(hal);
  hal->registerIncomingPacketCallback(service_);
}

void HalFacadeModule::Stop(const ModuleRegistry* registry) {
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
