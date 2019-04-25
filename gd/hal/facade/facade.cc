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

namespace {

HalFacadeModule hci_cert_module_instance_;

void stop_stream_hci_evt();
void stop_stream_hci_acl();
void stop_stream_hci_sco();

class HciTransportationSyncService : public HciTransportation::Service {
 public:
  ::grpc::Status SetLoopbackMode(::grpc::ServerContext* context,
                                 const ::bluetooth::hal::facade::LoopbackModeSettings* request,
                                 ::google::protobuf::Empty* response) override {
    bool enable = request->enable();
    auto packet = hci::WriteLoopbackModeBuilder::Create(enable ? hci::LoopbackMode::ENABLE_LOCAL
                                                               : hci::LoopbackMode::NO_LOOPBACK);
    std::shared_ptr<std::vector<uint8_t>> packet_bytes = std::make_shared<std::vector<uint8_t>>();
    hci::BitInserter it(*packet_bytes);
    packet->Serialize(it);
    GetBluetoothHciHal()->sendHciCommand(*packet_bytes);
    return ::grpc::Status::OK;
  }

  ::grpc::Status SendHciCmd(::grpc::ServerContext* context, const ::bluetooth::hal::facade::HciCmdPacket* request,
                            ::google::protobuf::Empty* response) override {
    std::string req_string = request->payload();
    ::bluetooth::hal::GetBluetoothHciHal()->sendHciCommand(std::vector<uint8_t>(req_string.begin(), req_string.end()));
    return ::grpc::Status::OK;
  }

  ::grpc::Status SendHciAcl(::grpc::ServerContext* context, const ::bluetooth::hal::facade::HciAclPacket* request,
                            ::google::protobuf::Empty* response) override {
    std::string req_string = request->payload();
    ::bluetooth::hal::GetBluetoothHciHal()->sendAclData(std::vector<uint8_t>(req_string.begin(), req_string.end()));
    return ::grpc::Status::OK;
  }

  ::grpc::Status SendHciSco(::grpc::ServerContext* context, const ::bluetooth::hal::facade::HciScoPacket* request,
                            ::google::protobuf::Empty* response) override {
    std::string req_string = request->payload();
    ::bluetooth::hal::GetBluetoothHciHal()->sendScoData(std::vector<uint8_t>(req_string.begin(), req_string.end()));
    return ::grpc::Status::OK;
  }

  ::grpc::Status UnregisterHciEvt(::grpc::ServerContext* context, const ::google::protobuf::Empty* request,
                                  ::google::protobuf::Empty* response) override {
    stop_stream_hci_evt();
    return ::grpc::Status::OK;
  }
  ::grpc::Status UnregisterHciAcl(::grpc::ServerContext* context, const ::google::protobuf::Empty* request,
                                  ::google::protobuf::Empty* response) override {
    stop_stream_hci_acl();
    return ::grpc::Status::OK;
  }

  ::grpc::Status UnregisterHciSco(::grpc::ServerContext* context, const ::google::protobuf::Empty* request,
                                  ::google::protobuf::Empty* response) override {
    stop_stream_hci_sco();
    return ::grpc::Status::OK;
  }
};

using HciTransportationAsyncService =
    HciTransportation::WithAsyncMethod_RegisterHciEvt<HciTransportation::WithAsyncMethod_RegisterHciAcl<
        HciTransportation::WithAsyncMethod_RegisterHciSco<HciTransportationSyncService>>>;

HciTransportationAsyncService async_service_;

class RegisterHciEvtImpl : public grpc::GrpcAsyncServerStreamingHandler<::google::protobuf::Empty, HciEvtPacket>,
                           public HalFacadeModule::HciEvtListener {
 public:
  explicit RegisterHciEvtImpl(HciTransportationAsyncService* service, ::grpc::ServerCompletionQueue* cq)
      : service_(service), streaming_control_box_(this, cq) {
    streaming_control_box_.RequestNewRpc();
  }

  void OnReadyForNextRequest(::grpc::ServerContext* context, google::protobuf::Empty* req,
                             ServerAsyncWriter<HciEvtPacket>* res, ::grpc::CompletionQueue* new_call_cq,
                             ServerCompletionQueue* notification_cq, void* tag) override {
    service_->RequestRegisterHciEvt(context, req, res, new_call_cq, notification_cq, tag);
  }

  void OnRpcRequestReceived(google::protobuf::Empty) override {
    hci_cert_module_instance_.RegisterHciEvtListener(this);
  }

  void OnRpcFinished() override {
    streaming_control_box_.RequestNewRpc();
  }

  void operator()(const hal::HciPacket& hciPacket) override {
    HciEvtPacket packet;
    packet.set_payload(std::string(hciPacket.begin(), hciPacket.end()));
    streaming_control_box_.Write(packet);
  }

  void StopStream() {
    hci_cert_module_instance_.UnregisterHciEvtListener(this);
    streaming_control_box_.StopStreaming();
  }

 private:
  HciTransportationAsyncService* service_;
  grpc::GrpcAsyncServerStreamingControlBox<::google::protobuf::Empty, HciEvtPacket> streaming_control_box_;
};

class RegisterHciAclImpl : public grpc::GrpcAsyncServerStreamingHandler<::google::protobuf::Empty, HciAclPacket>,
                           public HalFacadeModule::HciAclListener {
 public:
  explicit RegisterHciAclImpl(HciTransportationAsyncService* service, ::grpc::ServerCompletionQueue* cq)
      : service_(service), streaming_control_box_(this, cq) {
    streaming_control_box_.RequestNewRpc();
  }

  void OnReadyForNextRequest(::grpc::ServerContext* context, google::protobuf::Empty* req,
                             ServerAsyncWriter<HciAclPacket>* res, ::grpc::CompletionQueue* new_call_cq,
                             ServerCompletionQueue* notification_cq, void* tag) override {
    service_->RequestRegisterHciAcl(context, req, res, new_call_cq, notification_cq, tag);
  }

  void OnRpcRequestReceived(google::protobuf::Empty) override {
    hci_cert_module_instance_.RegisterHciAclListener(this);
  }

  void OnRpcFinished() override {
    streaming_control_box_.RequestNewRpc();
  }

  void operator()(const hal::HciPacket& hciPacket) override {
    HciAclPacket packet;
    packet.set_payload(std::string(hciPacket.begin(), hciPacket.end()));
    streaming_control_box_.Write(packet);
  }

  void StopStream() {
    hci_cert_module_instance_.UnregisterHciAclListener(this);
    streaming_control_box_.StopStreaming();
  }

 private:
  HciTransportationAsyncService* service_;
  grpc::GrpcAsyncServerStreamingControlBox<::google::protobuf::Empty, HciAclPacket> streaming_control_box_;
};

class RegisterHciScoImpl : public grpc::GrpcAsyncServerStreamingHandler<::google::protobuf::Empty, HciScoPacket>,
                           public HalFacadeModule::HciScoListener {
 public:
  explicit RegisterHciScoImpl(HciTransportationAsyncService* service, ::grpc::ServerCompletionQueue* cq)
      : service_(service), streaming_control_box_(this, cq) {
    streaming_control_box_.RequestNewRpc();
  }

  void OnReadyForNextRequest(::grpc::ServerContext* context, google::protobuf::Empty* req,
                             ServerAsyncWriter<HciScoPacket>* res, ::grpc::CompletionQueue* new_call_cq,
                             ServerCompletionQueue* notification_cq, void* tag) override {
    service_->RequestRegisterHciSco(context, req, res, new_call_cq, notification_cq, tag);
  }

  void OnRpcRequestReceived(google::protobuf::Empty) override {
    hci_cert_module_instance_.RegisterHciScoListener(this);
  }

  void OnRpcFinished() override {
    streaming_control_box_.RequestNewRpc();
  }

  void operator()(const hal::HciPacket& hciPacket) override {
    HciScoPacket packet;
    packet.set_payload(std::string(hciPacket.begin(), hciPacket.end()));
    streaming_control_box_.Write(packet);
  }

  void StopStream() {
    hci_cert_module_instance_.UnregisterHciScoListener(this);
    streaming_control_box_.StopStreaming();
  }

 private:
  HciTransportationAsyncService* service_;
  grpc::GrpcAsyncServerStreamingControlBox<::google::protobuf::Empty, HciScoPacket> streaming_control_box_;
};

struct GrpcHelper {
  explicit GrpcHelper(::grpc::ServerCompletionQueue* cq)
      : hci_evt_impl_(&async_service_, cq), hci_acl_impl_(&async_service_, cq), hci_sco_impl_(&async_service_, cq) {}

  RegisterHciEvtImpl hci_evt_impl_;
  RegisterHciAclImpl hci_acl_impl_;
  RegisterHciScoImpl hci_sco_impl_;
};
GrpcHelper* grpc_helper_instance_ = nullptr;

void stop_stream_hci_evt() {
  grpc_helper_instance_->hci_evt_impl_.StopStream();
}

void stop_stream_hci_acl() {
  grpc_helper_instance_->hci_acl_impl_.StopStream();
}

void stop_stream_hci_sco() {
  grpc_helper_instance_->hci_sco_impl_.StopStream();
}

}  // namespace

class IncomingPacketCallback : public ::bluetooth::hal::BluetoothHciHalCallbacks {
 public:
  explicit IncomingPacketCallback(HalFacadeModule* hal_cert_module) : hal_cert_module_(hal_cert_module) {}

  void hciEventReceived(bluetooth::hal::HciPacket event) override {
    std::unique_lock<std::mutex> lock(hal_cert_module_->mutex_);
    for (auto* listener : hal_cert_module_->registered_evt_listener_) {
      (*listener)(event);
    }
  }

  void aclDataReceived(bluetooth::hal::HciPacket data) override {
    std::unique_lock<std::mutex> lock(hal_cert_module_->mutex_);
    for (auto* listener : hal_cert_module_->registered_acl_listener_) {
      (*listener)(data);
    }
  }

  void scoDataReceived(bluetooth::hal::HciPacket data) override {
    std::unique_lock<std::mutex> lock(hal_cert_module_->mutex_);
    for (auto* listener : hal_cert_module_->registered_sco_listener_) {
      (*listener)(data);
    }
  }

 private:
  HalFacadeModule* hal_cert_module_;
};

static IncomingPacketCallback* incoming_packet_callback_;

void HalFacadeModule::StartUp(::grpc::ServerCompletionQueue* cq) {
  std::unique_lock<std::mutex> lock(mutex_);
  incoming_packet_callback_ = new IncomingPacketCallback(this);
  hal::GetBluetoothHciHal()->registerIncomingPacketCallback(incoming_packet_callback_);

  grpc_helper_instance_ = new GrpcHelper(cq);
}

void HalFacadeModule::ShutDown() {
  std::unique_lock<std::mutex> lock(mutex_);
  delete grpc_helper_instance_;
  grpc_helper_instance_ = nullptr;
  delete incoming_packet_callback_;
  incoming_packet_callback_ = nullptr;
}

::grpc::Service* HalFacadeModule::GetModuleGrpcService() const {
  return &async_service_;
}

void HalFacadeModule::RegisterHciEvtListener(HciEvtListener* listener) {
  std::unique_lock<std::mutex> lock(mutex_);
  registered_evt_listener_.push_back(listener);
}

void HalFacadeModule::UnregisterHciEvtListener(HciEvtListener* listener) {
  std::unique_lock<std::mutex> lock(mutex_);
  registered_evt_listener_.remove(listener);
}

void HalFacadeModule::RegisterHciAclListener(HciAclListener* listener) {
  std::unique_lock<std::mutex> lock(mutex_);
  registered_acl_listener_.push_back(listener);
}

void HalFacadeModule::UnregisterHciAclListener(HciAclListener* listener) {
  std::unique_lock<std::mutex> lock(mutex_);
  registered_acl_listener_.remove(listener);
}

void HalFacadeModule::RegisterHciScoListener(HciScoListener* listener) {
  std::unique_lock<std::mutex> lock(mutex_);
  registered_sco_listener_.push_back(listener);
}

void HalFacadeModule::UnregisterHciScoListener(HciScoListener* listener) {
  std::unique_lock<std::mutex> lock(mutex_);
  registered_sco_listener_.remove(listener);
}

::bluetooth::facade::CertFacade* GetFacadeModule() {
  return &hci_cert_module_instance_;
}

}  // namespace facade
}  // namespace hal
}  // namespace bluetooth
