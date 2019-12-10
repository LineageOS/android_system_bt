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

#include "hci/cert/cert.h"

#include <condition_variable>
#include <memory>
#include <mutex>
#include <set>

#include "common/blocking_queue.h"
#include "grpc/grpc_event_queue.h"
#include "hci/cert/api.grpc.pb.h"
#include "hci/classic_security_manager.h"
#include "hci/controller.h"
#include "hci/hci_layer.h"
#include "hci/hci_packets.h"
#include "os/queue.h"
#include "packet/raw_builder.h"

using ::grpc::ServerAsyncResponseWriter;
using ::grpc::ServerAsyncWriter;
using ::grpc::ServerContext;

using ::bluetooth::common::Bind;
using ::bluetooth::common::BindOnce;
using ::bluetooth::packet::RawBuilder;

namespace bluetooth {
namespace hci {
namespace cert {

class AclManagerCertService : public AclManagerCert::Service {
 public:
  AclManagerCertService(Controller* controller, HciLayer* hci_layer, ::bluetooth::os::Handler* facade_handler)
      : controller_(controller), hci_layer_(hci_layer), handler_(facade_handler),
        acl_queue_end_(hci_layer_->GetAclQueueEnd()) {
    hci_layer_->RegisterEventHandler(EventCode::CONNECTION_COMPLETE,
                                     Bind(&AclManagerCertService::on_connection_complete, common::Unretained(this)),
                                     handler_);
    hci_layer_->RegisterEventHandler(EventCode::DISCONNECTION_COMPLETE,
                                     Bind(&AclManagerCertService::on_disconnection_complete, common::Unretained(this)),
                                     handler_);
    hci_layer_->RegisterEventHandler(EventCode::CONNECTION_REQUEST,
                                     Bind(&AclManagerCertService::on_incoming_connection, common::Unretained(this)),
                                     handler_);
    hci_layer_->RegisterEventHandler(
        EventCode::CONNECTION_PACKET_TYPE_CHANGED,
        Bind(&AclManagerCertService::on_connection_packet_type_changed, common::Unretained(this)), handler_);
    hci_layer_->RegisterEventHandler(EventCode::QOS_SETUP_COMPLETE,
                                     Bind(&AclManagerCertService::on_qos_setup_complete, common::Unretained(this)),
                                     handler_);
    hci_layer_->RegisterEventHandler(EventCode::ROLE_CHANGE,
                                     Bind(&AclManagerCertService::on_role_change, common::Unretained(this)), handler_);

    controller_->RegisterCompletedAclPacketsCallback(common::Bind([](uint16_t, uint16_t) { /* TODO check */ }),
                                                     handler_);
    acl_queue_end_->RegisterDequeue(handler_,
                                    Bind(&AclManagerCertService::on_incoming_packet, common::Unretained(this)));
  }

  void on_incoming_packet() {
    auto packet = acl_queue_end_->TryDequeue();
    ASSERT(packet->IsValid());
    AclData acl_data;
    if (connected_devices_.find(packet->GetHandle()) == connected_devices_.end()) {
      LOG_ERROR("Can't find remote device");
      return;
    }
    auto address = connected_devices_[packet->GetHandle()];
    acl_data.mutable_remote()->set_address(address.ToString());
    std::string data = std::string(packet->begin(), packet->end());
    acl_data.set_payload(data);
    pending_acl_data_.OnIncomingEvent(acl_data);
  }

  ~AclManagerCertService() {
    acl_queue_end_->UnregisterDequeue();
    hci_layer_->UnregisterEventHandler(EventCode::CONNECTION_REQUEST);
    hci_layer_->UnregisterEventHandler(EventCode::DISCONNECTION_COMPLETE);
    hci_layer_->UnregisterEventHandler(EventCode::CONNECTION_COMPLETE);
  }

  void on_connection_complete(EventPacketView packet) {
    ConnectionCompleteView connection_complete = ConnectionCompleteView::Create(std::move(packet));
    ASSERT(connection_complete.IsValid());
    auto status = connection_complete.GetStatus();
    auto address = connection_complete.GetBdAddr();
    auto handle = connection_complete.GetConnectionHandle();
    if (status == ErrorCode::SUCCESS) {
      connected_devices_.emplace(handle, address);
      ConnectionEvent event;
      event.mutable_remote()->set_address(address.ToString());
      pending_connection_complete_.OnIncomingEvent(event);
    } else {
      ConnectionFailedEvent event;
      event.mutable_remote()->set_address(address.ToString());
      event.set_reason(static_cast<uint32_t>(connection_complete.GetStatus()));
      pending_connection_failed_.OnIncomingEvent(event);
    }
  }

  void on_disconnection_complete(EventPacketView packet) {
    DisconnectionCompleteView disconnection_complete = DisconnectionCompleteView::Create(std::move(packet));
    ASSERT(disconnection_complete.IsValid());
    auto status = disconnection_complete.GetStatus();
    auto handle = disconnection_complete.GetConnectionHandle();
    auto device = connected_devices_.find(handle);

    ASSERT(device != connected_devices_.end());
    auto address = device->second;
    if (status == ErrorCode::SUCCESS) {
      connected_devices_.erase(handle);
      DisconnectionEvent event;
      event.mutable_remote()->set_address(address.ToString());
      event.set_reason(static_cast<uint32_t>(disconnection_complete.GetReason()));
      pending_disconnection_.OnIncomingEvent(event);
    }
  }

  void on_incoming_connection(EventPacketView packet) {
    ConnectionRequestView request = ConnectionRequestView::Create(packet);
    ASSERT(request.IsValid());
    Address address = request.GetBdAddr();
    if (accepted_devices_.find(address) != accepted_devices_.end()) {
      auto role = AcceptConnectionRequestRole::BECOME_MASTER;  // We prefer to be master
      hci_layer_->EnqueueCommand(AcceptConnectionRequestBuilder::Create(address, role),
                                 common::BindOnce([](CommandStatusView status) { /* TODO: check? */ }), handler_);
    } else {
      auto reason = RejectConnectionReason::LIMITED_RESOURCES;
      auto builder = RejectConnectionRequestBuilder::Create(address, reason);
      hci_layer_->EnqueueCommand(std::move(builder), BindOnce([](CommandStatusView status) { /* TODO: check? */ }),
                                 handler_);
    }
  }

  void on_connection_packet_type_changed(EventPacketView packet) { /*TODO*/
  }

  void on_qos_setup_complete(EventPacketView packet) { /*TODO*/
  }

  void on_role_change(EventPacketView packet) { /*TODO*/
  }

  ::grpc::Status SetPageScanMode(::grpc::ServerContext* context, const ::bluetooth::hci::cert::PageScanMode* request,
                                 ::google::protobuf::Empty* response) override {
    ScanEnable scan_enable = request->enabled() ? ScanEnable::PAGE_SCAN_ONLY : ScanEnable::NO_SCANS;
    std::promise<void> promise;
    auto future = promise.get_future();
    hci_layer_->EnqueueCommand(
        WriteScanEnableBuilder::Create(scan_enable),
        common::BindOnce([](std::promise<void> promise, CommandCompleteView) { promise.set_value(); },
                         std::move(promise)),
        handler_);
    future.wait();
    return ::grpc::Status::OK;
  }

  ::grpc::Status SetIncomingConnectionPolicy(::grpc::ServerContext* context,
                                             const ::bluetooth::hci::cert::IncomingConnectionPolicy* request,
                                             ::google::protobuf::Empty* response) override {
    std::unique_lock<std::mutex> lock(mutex_);
    Address peer;
    ASSERT(Address::FromString(request->remote().address(), peer));
    if (request->accepted()) {
      accepted_devices_.insert(peer);
    } else {
      accepted_devices_.erase(peer);
    }
    return ::grpc::Status::OK;
  }

  ::grpc::Status Connect(::grpc::ServerContext* context, const facade::BluetoothAddress* remote,
                         ::google::protobuf::Empty* response) override {
    std::unique_lock<std::mutex> lock(mutex_);

    uint16_t packet_type = 0x4408 /* DM 1,3,5 */ | 0x8810 /*DH 1,3,5 */;
    PageScanRepetitionMode page_scan_repetition_mode = PageScanRepetitionMode::R1;
    uint16_t clock_offset = 0;
    ClockOffsetValid clock_offset_valid = ClockOffsetValid::INVALID;
    CreateConnectionRoleSwitch allow_role_switch = CreateConnectionRoleSwitch::ALLOW_ROLE_SWITCH;

    Address peer;
    ASSERT(Address::FromString(remote->address(), peer));
    std::unique_ptr<CreateConnectionBuilder> packet = CreateConnectionBuilder::Create(
        peer, packet_type, page_scan_repetition_mode, clock_offset, clock_offset_valid, allow_role_switch);

    hci_layer_->EnqueueCommand(std::move(packet), common::BindOnce([](CommandStatusView status) {
                                 ASSERT(status.IsValid());
                                 ASSERT(status.GetCommandOpCode() == OpCode::CREATE_CONNECTION);
                               }),
                               handler_);

    return ::grpc::Status::OK;
  }

  ::grpc::Status Disconnect(::grpc::ServerContext* context, const facade::BluetoothAddress* request,
                            ::google::protobuf::Empty* response) override {
    std::unique_lock<std::mutex> lock(mutex_);
    Address peer;
    Address::FromString(request->address(), peer);
    uint16_t handle = find_connected_device_handle_by_address(peer);
    if (handle == kInvalidHandle) {
      return ::grpc::Status(::grpc::StatusCode::INVALID_ARGUMENT, "Invalid address");
    }

    DisconnectReason reason = DisconnectReason::REMOTE_USER_TERMINATED_CONNECTION;
    std::unique_ptr<DisconnectBuilder> packet = DisconnectBuilder::Create(handle, reason);
    hci_layer_->EnqueueCommand(std::move(packet), BindOnce([](CommandStatusView status) { /* TODO: check? */ }),
                               handler_);
    return ::grpc::Status::OK;
  }

  ::grpc::Status SendAclData(::grpc::ServerContext* context, const AclData* request,
                             ::google::protobuf::Empty* response) override {
    Address peer;
    Address::FromString(request->remote().address(), peer);
    auto handle = find_connected_device_handle_by_address(peer);
    if (handle == kInvalidHandle) {
      return ::grpc::Status(::grpc::StatusCode::INVALID_ARGUMENT, "Invalid address");
    }

    constexpr PacketBoundaryFlag packet_boundary_flag = PacketBoundaryFlag::FIRST_AUTOMATICALLY_FLUSHABLE;
    constexpr BroadcastFlag broadcast_flag = BroadcastFlag::POINT_TO_POINT;
    std::unique_ptr<RawBuilder> packet = std::make_unique<RawBuilder>();
    auto req_string = request->payload();
    packet->AddOctets(std::vector<uint8_t>(req_string.begin(), req_string.end()));
    auto acl_packet = AclPacketBuilder::Create(handle, packet_boundary_flag, broadcast_flag, std::move(packet));
    acl_enqueue_buffer_.Enqueue(std::move(acl_packet), handler_);
    return ::grpc::Status::OK;
  }

  ::grpc::Status FetchAclData(::grpc::ServerContext* context, const ::google::protobuf::Empty* request,
                              ::grpc::ServerWriter<AclData>* writer) override {
    return pending_acl_data_.RunLoop(context, writer);
  }

  ::grpc::Status FetchConnectionComplete(::grpc::ServerContext* context, const ::google::protobuf::Empty* request,
                                         ::grpc::ServerWriter<ConnectionEvent>* writer) override {
    return pending_connection_complete_.RunLoop(context, writer);
  };

  ::grpc::Status FetchConnectionFailed(::grpc::ServerContext* context, const ::google::protobuf::Empty* request,
                                       ::grpc::ServerWriter<ConnectionFailedEvent>* writer) override {
    return pending_connection_failed_.RunLoop(context, writer);
  };

  ::grpc::Status FetchDisconnection(::grpc::ServerContext* context, const ::google::protobuf::Empty* request,
                                    ::grpc::ServerWriter<DisconnectionEvent>* writer) override {
    return pending_disconnection_.RunLoop(context, writer);
  }

 private:
  Controller* controller_;
  HciLayer* hci_layer_;
  ::bluetooth::os::Handler* handler_;
  common::BidiQueueEnd<AclPacketBuilder, AclPacketView>* acl_queue_end_;
  os::EnqueueBuffer<AclPacketBuilder> acl_enqueue_buffer_{acl_queue_end_};
  mutable std::mutex mutex_;
  std::set<Address> accepted_devices_;
  std::map<uint16_t /* handle */, Address> connected_devices_;
  ::bluetooth::grpc::GrpcEventQueue<AclData> pending_acl_data_{"FetchAclData"};
  ::bluetooth::grpc::GrpcEventQueue<ConnectionEvent> pending_connection_complete_{"FetchConnectionComplete"};
  ::bluetooth::grpc::GrpcEventQueue<ConnectionFailedEvent> pending_connection_failed_{"FetchConnectionFailed"};
  ::bluetooth::grpc::GrpcEventQueue<DisconnectionEvent> pending_disconnection_{"FetchDisconnection"};

  constexpr static uint16_t kInvalidHandle = 0xffff;

  uint16_t find_connected_device_handle_by_address(Address address) {
    for (auto device : connected_devices_) {
      if (device.second == address) {
        return device.first;
      }
    }
    return kInvalidHandle;  // Can't find
  }
};

void AclManagerCertModule::ListDependencies(ModuleList* list) {
  ::bluetooth::grpc::GrpcFacadeModule::ListDependencies(list);
  list->add<Controller>();
  list->add<HciLayer>();
  list->add<ClassicSecurityManager>();
}

void AclManagerCertModule::Start() {
  ::bluetooth::grpc::GrpcFacadeModule::Start();
  service_ = new AclManagerCertService(GetDependency<Controller>(), GetDependency<HciLayer>(), GetHandler());
}

void AclManagerCertModule::Stop() {
  delete service_;
  ::bluetooth::grpc::GrpcFacadeModule::Stop();
}

::grpc::Service* AclManagerCertModule::GetService() const {
  return service_;
}

const ModuleFactory AclManagerCertModule::Factory =
    ::bluetooth::ModuleFactory([]() { return new AclManagerCertModule(); });

}  // namespace cert
}  // namespace hci
}  // namespace bluetooth
