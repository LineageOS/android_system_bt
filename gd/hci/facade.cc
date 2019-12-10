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

#include "hci/facade.h"

#include <condition_variable>
#include <memory>
#include <mutex>

#include "common/bind.h"
#include "common/blocking_queue.h"
#include "grpc/grpc_event_queue.h"
#include "hci/acl_manager.h"
#include "hci/classic_security_manager.h"
#include "hci/controller.h"
#include "hci/facade.grpc.pb.h"
#include "hci/hci_layer.h"
#include "hci/hci_packets.h"
#include "packet/raw_builder.h"

using ::grpc::ServerAsyncResponseWriter;
using ::grpc::ServerAsyncWriter;
using ::grpc::ServerContext;

using ::bluetooth::packet::RawBuilder;

namespace bluetooth {
namespace hci {

class AclManagerFacadeService : public AclManagerFacade::Service,
                                public ::bluetooth::hci::ConnectionCallbacks,
                                public ::bluetooth::hci::ConnectionManagementCallbacks,
                                public ::bluetooth::hci::AclManagerCallbacks {
 public:
  AclManagerFacadeService(AclManager* acl_manager, Controller* controller, HciLayer* hci_layer,
                          ::bluetooth::os::Handler* facade_handler)
      : acl_manager_(acl_manager), controller_(controller), hci_layer_(hci_layer), facade_handler_(facade_handler) {
    acl_manager_->RegisterCallbacks(this, facade_handler_);
    acl_manager_->RegisterAclManagerCallbacks(this, facade_handler_);
  }

  ::grpc::Status SetPageScanMode(::grpc::ServerContext* context, const ::bluetooth::hci::PageScanMode* request,
                                 ::google::protobuf::Empty* response) override {
    ScanEnable scan_enable = request->enabled() ? ScanEnable::PAGE_SCAN_ONLY : ScanEnable::NO_SCANS;
    std::promise<void> promise;
    auto future = promise.get_future();
    hci_layer_->EnqueueCommand(
        WriteScanEnableBuilder::Create(scan_enable),
        common::BindOnce([](std::promise<void> promise, CommandCompleteView) { promise.set_value(); },
                         std::move(promise)),
        facade_handler_);
    future.wait();
    return ::grpc::Status::OK;
  }

  ::grpc::Status Connect(::grpc::ServerContext* context, const facade::BluetoothAddress* request,
                         ::google::protobuf::Empty* response) override {
    Address peer;
    ASSERT(Address::FromString(request->address(), peer));
    acl_manager_->CreateConnection(peer);
    return ::grpc::Status::OK;
  }

  ::grpc::Status Disconnect(::grpc::ServerContext* context, const facade::BluetoothAddress* request,
                            ::google::protobuf::Empty* response) override {
    std::unique_lock<std::mutex> lock(acl_connections_mutex_);
    Address peer;
    Address::FromString(request->address(), peer);
    auto connection = acl_connections_.find(request->address());
    if (connection == acl_connections_.end()) {
      LOG_ERROR("Invalid address");
      return ::grpc::Status(::grpc::StatusCode::INVALID_ARGUMENT, "Invalid address");
    } else {
      connection->second->Disconnect(DisconnectReason::REMOTE_USER_TERMINATED_CONNECTION);
      return ::grpc::Status::OK;
    }
  }

  ::grpc::Status AuthenticationRequested(::grpc::ServerContext* context, const facade::BluetoothAddress* request,
                                         ::google::protobuf::Empty* response) override {
    std::unique_lock<std::mutex> lock(acl_connections_mutex_);
    Address peer;
    Address::FromString(request->address(), peer);
    auto connection = acl_connections_.find(request->address());
    if (connection == acl_connections_.end()) {
      LOG_ERROR("Invalid address");
      return ::grpc::Status(::grpc::StatusCode::INVALID_ARGUMENT, "Invalid address");
    } else {
      connection->second->AuthenticationRequested();
      return ::grpc::Status::OK;
    }
  };

  ::grpc::Status SendAclData(::grpc::ServerContext* context, const AclData* request,
                             ::google::protobuf::Empty* response) override {
    std::promise<void> promise;
    auto future = promise.get_future();
    {
      std::unique_lock<std::mutex> lock(acl_connections_mutex_);
      acl_connections_[request->remote().address()]->GetAclQueueEnd()->RegisterEnqueue(
          facade_handler_, common::Bind(&AclManagerFacadeService::enqueue_packet, common::Unretained(this),
                                        common::Unretained(request), common::Passed(std::move(promise))));
    }
    future.wait();
    return ::grpc::Status::OK;
  }

  std::unique_ptr<BasePacketBuilder> enqueue_packet(const AclData* request, std::promise<void> promise) {
    {
      std::unique_lock<std::mutex> lock(acl_connections_mutex_);
      acl_connections_[request->remote().address()]->GetAclQueueEnd()->UnregisterEnqueue();
    }
    std::string req_string = request->payload();
    std::unique_ptr<RawBuilder> packet = std::make_unique<RawBuilder>();
    packet->AddOctets(std::vector<uint8_t>(req_string.begin(), req_string.end()));
    promise.set_value();
    return packet;
  }

  ::grpc::Status FetchAclData(::grpc::ServerContext* context, const ::google::protobuf::Empty* request,
                              ::grpc::ServerWriter<AclData>* writer) override {
    {
      std::unique_lock<std::mutex> lock(acl_connections_mutex_);
      for (const auto& connection : acl_connections_) {
        auto remote_address = connection.second->GetAddress().ToString();
        connection.second->GetAclQueueEnd()->RegisterDequeue(
            facade_handler_,
            common::Bind(&AclManagerFacadeService::on_incoming_acl, common::Unretained(this), remote_address));
      }
      fetching_acl_data_ = true;
    }
    auto status = pending_acl_data_.RunLoop(context, writer);
    {
      std::unique_lock<std::mutex> lock(acl_connections_mutex_);
      fetching_acl_data_ = false;
      for (const auto& connection : acl_connections_) {
        connection.second->GetAclQueueEnd()->UnregisterDequeue();
      }
    }

    return status;
  }

  ::grpc::Status TestInternalHciCommands(::grpc::ServerContext* context, const ::google::protobuf::Empty* request,
                                         ::google::protobuf::Empty* response) {
    LocalVersionInformation local_version_information = controller_->GetControllerLocalVersionInformation();
    LOG_DEBUG("local name : %s", controller_->GetControllerLocalName().c_str());
    controller_->WriteLocalName("Device Under Test");
    LOG_DEBUG("new local name : %s", controller_->GetControllerLocalName().c_str());
    LOG_DEBUG("manufacturer name : %d", local_version_information.manufacturer_name_);
    LOG_DEBUG("hci version : %x", (uint16_t)local_version_information.hci_version_);
    LOG_DEBUG("lmp version : %x", (uint16_t)local_version_information.lmp_version_);
    LOG_DEBUG("supported commands : %x", controller_->GetControllerLocalSupportedCommands()[0]);
    LOG_DEBUG("local extended features :");

    controller_->SetEventMask(0x00001FFFFFFFFFFF);
    controller_->SetEventFilterInquiryResultAllDevices();
    ClassOfDevice class_of_device({0xab, 0xcd, 0xef});
    ClassOfDevice class_of_device_mask({0x12, 0x34, 0x56});
    controller_->SetEventFilterInquiryResultClassOfDevice(class_of_device, class_of_device_mask);
    Address bdaddr({0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc});
    controller_->SetEventFilterInquiryResultAddress(bdaddr);
    controller_->SetEventFilterConnectionSetupAllDevices(AutoAcceptFlag::AUTO_ACCEPT_OFF);
    controller_->SetEventFilterConnectionSetupClassOfDevice(class_of_device, class_of_device_mask,
                                                            AutoAcceptFlag::AUTO_ACCEPT_ON_ROLE_SWITCH_DISABLED);
    controller_->SetEventFilterConnectionSetupAddress(bdaddr, AutoAcceptFlag::AUTO_ACCEPT_ON_ROLE_SWITCH_ENABLED);
    controller_->SetEventFilterClearAll();
    controller_->HostBufferSize(0xFF00, 0xF1, 0xFF02, 0xFF03);
    return ::grpc::Status::OK;
  }

  ::grpc::Status TestInternalHciLeCommands(::grpc::ServerContext* context, const ::google::protobuf::Empty* request,
                                           ::google::protobuf::Empty* response) {
    LOG_DEBUG("le data packet length : %d", controller_->GetControllerLeBufferSize().le_data_packet_length_);
    LOG_DEBUG("total num le packets : %d", controller_->GetControllerLeBufferSize().total_num_le_packets_);
    LOG_DEBUG("le supported max tx octets : %d",
              controller_->GetControllerLeMaximumDataLength().supported_max_tx_octets_);
    LOG_DEBUG("le supported max tx times : %d", controller_->GetControllerLeMaximumDataLength().supported_max_tx_time_);
    LOG_DEBUG("le supported max rx octets : %d",
              controller_->GetControllerLeMaximumDataLength().supported_max_rx_octets_);
    LOG_DEBUG("le supported max rx times : %d", controller_->GetControllerLeMaximumDataLength().supported_max_rx_time_);
    LOG_DEBUG("le maximum advertising data length %d", controller_->GetControllerLeMaximumAdvertisingDataLength());
    LOG_DEBUG("le number of supported advertising sets %d",
              controller_->GetControllerLeNumberOfSupportedAdverisingSets());

    controller_->LeSetEventMask(0x000000000000001F);
    return ::grpc::Status::OK;
  }

  ::grpc::Status TestClassicConnectionManagementCommands(::grpc::ServerContext* context,
                                                         const facade::BluetoothAddress* request,
                                                         ::google::protobuf::Empty* response) {
    std::unique_lock<std::mutex> lock(acl_connections_mutex_);
    Address peer;
    Address::FromString(request->address(), peer);
    auto connection = acl_connections_.find(request->address());
    if (connection == acl_connections_.end()) {
      LOG_ERROR("Invalid address");
      return ::grpc::Status(::grpc::StatusCode::INVALID_ARGUMENT, "Invalid address");
    } else {
      // TODO add individual grpc command if necessary
      connection->second->RoleDiscovery();
      connection->second->WriteLinkPolicySettings(0x07);
      connection->second->ReadLinkPolicySettings();
      connection->second->SniffSubrating(0x1234, 0x1234, 0x1234);
      connection->second->WriteAutomaticFlushTimeout(0x07FF);
      connection->second->ReadAutomaticFlushTimeout();
      connection->second->ReadTransmitPowerLevel(TransmitPowerLevelType::CURRENT);
      connection->second->ReadTransmitPowerLevel(TransmitPowerLevelType::MAXIMUM);
      connection->second->WriteLinkSupervisionTimeout(0x5678);
      connection->second->ReadLinkSupervisionTimeout();
      connection->second->ReadFailedContactCounter();
      connection->second->ResetFailedContactCounter();
      connection->second->ReadLinkQuality();
      connection->second->ReadAfhChannelMap();
      connection->second->ReadRssi();
      connection->second->ReadClock(WhichClock::LOCAL);
      connection->second->ReadClock(WhichClock::PICONET);

      connection->second->ChangeConnectionPacketType(0xEE1C);
      connection->second->SetConnectionEncryption(Enable::ENABLED);
      connection->second->ChangeConnectionLinkKey();
      connection->second->ReadClockOffset();
      connection->second->HoldMode(0x0500, 0x0020);
      connection->second->SniffMode(0x0500, 0x0020, 0x0040, 0x0014);
      connection->second->ExitSniffMode();
      connection->second->QosSetup(ServiceType::BEST_EFFORT, 0x1234, 0x1233, 0x1232, 0x1231);
      connection->second->FlowSpecification(FlowDirection::OUTGOING_FLOW, ServiceType::BEST_EFFORT, 0x1234, 0x1233,
                                            0x1232, 0x1231);
      connection->second->Flush();

      acl_manager_->MasterLinkKey(KeyFlag::TEMPORARY);
      acl_manager_->SwitchRole(peer, Role::MASTER);
      acl_manager_->WriteDefaultLinkPolicySettings(0x07);
      acl_manager_->ReadDefaultLinkPolicySettings();
      return ::grpc::Status::OK;
    }
  }

  void on_incoming_acl(std::string address) {
    std::unique_lock<std::mutex> lock(acl_connections_mutex_);
    auto connection = acl_connections_.find(address);
    if (connection == acl_connections_.end()) {
      LOG_ERROR("Invalid address");
      return;
    }

    auto packet = connection->second->GetAclQueueEnd()->TryDequeue();
    auto acl_packet = AclPacketView::Create(*packet);
    AclData acl_data;
    acl_data.mutable_remote()->set_address(address);
    std::string data(acl_packet.begin(), acl_packet.end());
    acl_data.set_payload(data);
    pending_acl_data_.OnIncomingEvent(acl_data);
  }

  void OnConnectSuccess(std::unique_ptr<::bluetooth::hci::AclConnection> connection) override {
    std::unique_lock<std::mutex> lock(acl_connections_mutex_);
    auto addr = connection->GetAddress();
    std::shared_ptr<::bluetooth::hci::AclConnection> shared_connection = std::move(connection);
    acl_connections_.emplace(addr.ToString(), shared_connection);
    if (fetching_acl_data_) {
      auto remote_address = shared_connection->GetAddress().ToString();
      shared_connection->GetAclQueueEnd()->RegisterDequeue(
          facade_handler_,
          common::Bind(&AclManagerFacadeService::on_incoming_acl, common::Unretained(this), remote_address));
    }
    shared_connection->RegisterDisconnectCallback(
        common::BindOnce(&AclManagerFacadeService::on_disconnect, common::Unretained(this), addr.ToString()),
        facade_handler_);
    shared_connection->RegisterCallbacks(this, facade_handler_);
    {
      ConnectionEvent response;
      response.mutable_remote()->set_address(shared_connection->GetAddress().ToString());
      response.set_connection_handle(shared_connection->GetHandle());
      pending_connection_complete_.OnIncomingEvent(response);
    }
  }

  void OnMasterLinkKeyComplete(uint16_t connection_handle, KeyFlag key_flag) override {
    LOG_DEBUG("OnMasterLinkKeyComplete connection_handle:%d", connection_handle);
  }

  void OnRoleChange(Address bd_addr, Role new_role) override {
    LOG_DEBUG("OnRoleChange bd_addr:%s, new_role:%d", bd_addr.ToString().c_str(), (uint8_t)new_role);
  }

  void OnReadDefaultLinkPolicySettingsComplete(uint16_t default_link_policy_settings) override {
    LOG_DEBUG("OnReadDefaultLinkPolicySettingsComplete default_link_policy_settings:%d", default_link_policy_settings);
  }

  void on_disconnect(const std::string& address, ErrorCode code) {
    std::unique_lock<std::mutex> lock(acl_connections_mutex_);
    auto connection = acl_connections_.find(address);
    if (connection != acl_connections_.end()) {
      if (fetching_acl_data_) {
        connection->second->GetAclQueueEnd()->UnregisterDequeue();
      }
      connection->second->Finish();
    }
    acl_connections_.erase(address);
    DisconnectionEvent event;
    event.mutable_remote()->set_address(address);
    event.set_reason(static_cast<uint32_t>(code));
    pending_disconnection_.OnIncomingEvent(event);
  }

  ::grpc::Status FetchConnectionComplete(::grpc::ServerContext* context, const ::google::protobuf::Empty* request,
                                         ::grpc::ServerWriter<ConnectionEvent>* writer) override {
    return pending_connection_complete_.RunLoop(context, writer);
  };

  void OnConnectFail(Address address, ::bluetooth::hci::ErrorCode reason) override {
    ConnectionFailedEvent event;
    event.mutable_remote()->set_address(address.ToString());
    event.set_reason(static_cast<uint32_t>(reason));
    pending_connection_failed_.OnIncomingEvent(event);
  }

  void OnConnectionPacketTypeChanged(uint16_t packet_type) override {
    LOG_DEBUG("OnConnectionPacketTypeChanged packet_type:%d", packet_type);
  }

  void OnAuthenticationComplete() override {
    LOG_DEBUG("OnAuthenticationComplete");
  }

  void OnEncryptionChange(EncryptionEnabled enabled) override {
    LOG_DEBUG("OnConnectionPacketTypeChanged enabled:%d", (uint8_t)enabled);
  }

  void OnChangeConnectionLinkKeyComplete() override {
    LOG_DEBUG("OnChangeConnectionLinkKeyComplete");
  };

  void OnReadClockOffsetComplete(uint16_t clock_offset) override {
    LOG_DEBUG("OnReadClockOffsetComplete clock_offset:%d", clock_offset);
  };

  void OnModeChange(Mode current_mode, uint16_t interval) override {
    LOG_DEBUG("OnModeChange Mode:%d, interval:%d", (uint8_t)current_mode, interval);
  };

  void OnQosSetupComplete(ServiceType service_type, uint32_t token_rate, uint32_t peak_bandwidth, uint32_t latency,
                          uint32_t delay_variation) override {
    LOG_DEBUG("OnQosSetupComplete service_type:%d, token_rate:%d, peak_bandwidth:%d, latency:%d, delay_variation:%d",
              (uint8_t)service_type, token_rate, peak_bandwidth, latency, delay_variation);
  }

  void OnFlowSpecificationComplete(FlowDirection flow_direction, ServiceType service_type, uint32_t token_rate,
                                   uint32_t token_bucket_size, uint32_t peak_bandwidth,
                                   uint32_t access_latency) override {
    LOG_DEBUG(
        "OnFlowSpecificationComplete flow_direction:%d. service_type:%d, token_rate:%d, token_bucket_size:%d, "
        "peak_bandwidth:%d, access_latency:%d",
        (uint8_t)flow_direction, (uint8_t)service_type, token_rate, token_bucket_size, peak_bandwidth, access_latency);
  }

  void OnFlushOccurred() override {
    LOG_DEBUG("OnFlushOccurred");
  }

  void OnRoleDiscoveryComplete(Role current_role) override {
    LOG_DEBUG("OnRoleDiscoveryComplete current_role:%d", (uint8_t)current_role);
  }

  void OnReadLinkPolicySettingsComplete(uint16_t link_policy_settings) override {
    LOG_DEBUG("OnReadLinkPolicySettingsComplete link_policy_settings:%d", link_policy_settings);
  }

  void OnReadAutomaticFlushTimeoutComplete(uint16_t flush_timeout) override {
    LOG_DEBUG("OnReadAutomaticFlushTimeoutComplete flush_timeout:%d", flush_timeout);
  }

  void OnReadTransmitPowerLevelComplete(uint8_t transmit_power_level) override {
    LOG_DEBUG("OnReadTransmitPowerLevelComplete transmit_power_level:%d", transmit_power_level);
  }

  void OnReadLinkSupervisionTimeoutComplete(uint16_t link_supervision_timeout) override {
    LOG_DEBUG("OnReadLinkSupervisionTimeoutComplete link_supervision_timeout:%d", link_supervision_timeout);
  }

  void OnReadFailedContactCounterComplete(uint16_t failed_contact_counter) override {
    LOG_DEBUG("OnReadFailedContactCounterComplete failed_contact_counter:%d", failed_contact_counter);
  }

  void OnReadLinkQualityComplete(uint8_t link_quality) override {
    LOG_DEBUG("OnReadLinkQualityComplete link_quality:%d", link_quality);
  }

  void OnReadAfhChannelMapComplete(AfhMode afh_mode, std::array<uint8_t, 10> afh_channel_map) {
    LOG_DEBUG("OnReadAfhChannelMapComplete afh_mode:%d", (uint8_t)afh_mode);
  }

  void OnReadRssiComplete(uint8_t rssi) override {
    LOG_DEBUG("OnReadRssiComplete rssi:%d", rssi);
  }

  void OnReadClockComplete(uint32_t clock, uint16_t accuracy) override {
    LOG_DEBUG("OnReadClockComplete clock:%d, accuracy:%d", clock, accuracy);
  }

  ::grpc::Status FetchConnectionFailed(::grpc::ServerContext* context, const ::google::protobuf::Empty* request,
                                       ::grpc::ServerWriter<ConnectionFailedEvent>* writer) override {
    return pending_connection_failed_.RunLoop(context, writer);
  };

  ::grpc::Status FetchDisconnection(::grpc::ServerContext* context, const ::google::protobuf::Empty* request,
                                    ::grpc::ServerWriter<DisconnectionEvent>* writer) override {
    return pending_disconnection_.RunLoop(context, writer);
  }

 private:
  AclManager* acl_manager_;
  Controller* controller_;
  HciLayer* hci_layer_;
  ::bluetooth::os::Handler* facade_handler_;
  mutable std::mutex acl_connections_mutex_;
  std::map<std::string, std::shared_ptr<AclConnection>> acl_connections_;
  bool fetching_acl_data_ = false;
  ::bluetooth::grpc::GrpcEventQueue<AclData> pending_acl_data_{"FetchAclData"};
  ::bluetooth::grpc::GrpcEventQueue<ConnectionEvent> pending_connection_complete_{"FetchConnectionComplete"};
  ::bluetooth::grpc::GrpcEventQueue<ConnectionFailedEvent> pending_connection_failed_{"FetchConnectionFailed"};
  ::bluetooth::grpc::GrpcEventQueue<DisconnectionEvent> pending_disconnection_{"FetchDisconnection"};
};

void AclManagerFacadeModule::ListDependencies(ModuleList* list) {
  ::bluetooth::grpc::GrpcFacadeModule::ListDependencies(list);
  list->add<AclManager>();
  list->add<Controller>();
  list->add<HciLayer>();
}

void AclManagerFacadeModule::Start() {
  ::bluetooth::grpc::GrpcFacadeModule::Start();
  service_ = new AclManagerFacadeService(GetDependency<AclManager>(), GetDependency<Controller>(),
                                         GetDependency<HciLayer>(), GetHandler());
}

void AclManagerFacadeModule::Stop() {
  delete service_;
  ::bluetooth::grpc::GrpcFacadeModule::Stop();
}

::grpc::Service* AclManagerFacadeModule::GetService() const {
  return service_;
}

const ModuleFactory AclManagerFacadeModule::Factory =
    ::bluetooth::ModuleFactory([]() { return new AclManagerFacadeModule(); });

class ClassicSecurityManagerFacadeService : public ClassicSecurityManagerFacade::Service,
                                            public ::bluetooth::hci::ClassicSecurityCommandCallbacks {
 public:
  ClassicSecurityManagerFacadeService(ClassicSecurityManager* classic_security_manager, Controller* controller,
                                      HciLayer* hci_layer, ::bluetooth::os::Handler* facade_handler)
      : classic_security_manager_(classic_security_manager), facade_handler_(facade_handler) {
    classic_security_manager_->RegisterCallbacks(this, facade_handler_);
  }

  ::grpc::Status LinkKeyRequestReply(::grpc::ServerContext* context,
                                     const ::bluetooth::hci::LinkKeyRequestReplyMessage* request,
                                     ::google::protobuf::Empty* response) {
    std::unique_lock<std::mutex> lock(mutex_);
    Address peer;
    common::LinkKey link_key;
    ASSERT(Address::FromString(request->remote().address(), peer));
    ASSERT(common::LinkKey::FromString(request->link_key(), link_key));
    classic_security_manager_->LinkKeyRequestReply(peer, link_key);
    return ::grpc::Status::OK;
  };

  ::grpc::Status LinkKeyRequestNegativeReply(::grpc::ServerContext* context,
                                             const ::bluetooth::facade::BluetoothAddress* request,
                                             ::google::protobuf::Empty* response) {
    std::unique_lock<std::mutex> lock(mutex_);
    Address peer;
    ASSERT(Address::FromString(request->address(), peer));
    classic_security_manager_->LinkKeyRequestNegativeReply(peer);
    return ::grpc::Status::OK;
  }

  ::grpc::Status PinCodeRequestReply(::grpc::ServerContext* context,
                                     const ::bluetooth::hci::PinCodeRequestReplyMessage* request,
                                     ::google::protobuf::Empty* response) {
    std::unique_lock<std::mutex> lock(mutex_);
    Address peer;
    ASSERT(Address::FromString(request->remote().address(), peer));
    uint8_t len = request->len();
    std::string pin_code = request->pin_code();
    classic_security_manager_->PinCodeRequestReply(peer, len, pin_code);
    return ::grpc::Status::OK;
  };

  ::grpc::Status PinCodeRequestNegativeReply(::grpc::ServerContext* context,
                                             const ::bluetooth::facade::BluetoothAddress* request,
                                             ::google::protobuf::Empty* response) {
    std::unique_lock<std::mutex> lock(mutex_);
    Address peer;
    ASSERT(Address::FromString(request->address(), peer));
    classic_security_manager_->PinCodeRequestNegativeReply(peer);
    return ::grpc::Status::OK;
  }

  ::grpc::Status IoCapabilityRequestReply(::grpc::ServerContext* context,
                                          const ::bluetooth::hci::IoCapabilityRequestReplyMessage* request,
                                          ::google::protobuf::Empty* response) {
    std::unique_lock<std::mutex> lock(mutex_);
    Address peer;
    ASSERT(Address::FromString(request->remote().address(), peer));
    IoCapability io_capability = (IoCapability)request->io_capability();
    OobDataPresent oob_present = (OobDataPresent)request->oob_present();
    AuthenticationRequirements authentication_requirements =
        (AuthenticationRequirements)request->authentication_requirements();
    classic_security_manager_->IoCapabilityRequestReply(peer, io_capability, oob_present, authentication_requirements);
    return ::grpc::Status::OK;
  };

  ::grpc::Status IoCapabilityRequestNegativeReply(
      ::grpc::ServerContext* context, const ::bluetooth::hci::IoCapabilityRequestNegativeReplyMessage* request,
      ::google::protobuf::Empty* response) {
    std::unique_lock<std::mutex> lock(mutex_);
    Address peer;
    ASSERT(Address::FromString(request->remote().address(), peer));
    ErrorCode reason = (ErrorCode)request->reason();
    classic_security_manager_->IoCapabilityRequestNegativeReply(peer, reason);
    return ::grpc::Status::OK;
  };

  ::grpc::Status UserConfirmationRequestReply(::grpc::ServerContext* context,
                                              const ::bluetooth::facade::BluetoothAddress* request,
                                              ::google::protobuf::Empty* response) {
    std::unique_lock<std::mutex> lock(mutex_);
    Address peer;
    ASSERT(Address::FromString(request->address(), peer));
    classic_security_manager_->UserConfirmationRequestReply(peer);
    return ::grpc::Status::OK;
  }

  ::grpc::Status UserConfirmationRequestNegativeReply(::grpc::ServerContext* context,
                                                      const ::bluetooth::facade::BluetoothAddress* request,
                                                      ::google::protobuf::Empty* response) {
    std::unique_lock<std::mutex> lock(mutex_);
    Address peer;
    ASSERT(Address::FromString(request->address(), peer));
    classic_security_manager_->UserConfirmationRequestNegativeReply(peer);
    return ::grpc::Status::OK;
  }

  ::grpc::Status UserPasskeyRequestReply(::grpc::ServerContext* context,
                                         const ::bluetooth::hci::UserPasskeyRequestReplyMessage* request,
                                         ::google::protobuf::Empty* response) {
    std::unique_lock<std::mutex> lock(mutex_);
    Address peer;
    ASSERT(Address::FromString(request->remote().address(), peer));
    uint32_t passkey = request->passkey();
    classic_security_manager_->UserPasskeyRequestReply(peer, passkey);
    return ::grpc::Status::OK;
  };

  ::grpc::Status UserPasskeyRequestNegativeReply(::grpc::ServerContext* context,
                                                 const ::bluetooth::facade::BluetoothAddress* request,
                                                 ::google::protobuf::Empty* response) {
    std::unique_lock<std::mutex> lock(mutex_);
    Address peer;
    ASSERT(Address::FromString(request->address(), peer));
    classic_security_manager_->UserPasskeyRequestNegativeReply(peer);
    return ::grpc::Status::OK;
  }

  ::grpc::Status RemoteOobDataRequestReply(::grpc::ServerContext* context,
                                           const ::bluetooth::hci::RemoteOobDataRequestReplyMessage* request,
                                           ::google::protobuf::Empty* response) {
    std::unique_lock<std::mutex> lock(mutex_);
    Address peer;
    ASSERT(Address::FromString(request->remote().address(), peer));
    std::string c_string = request->c();
    std::string r_string = request->r();
    std::array<uint8_t, 16> c;
    std::array<uint8_t, 16> r;
    std::copy(std::begin(c_string), std::end(c_string), std::begin(c));
    std::copy(std::begin(r_string), std::end(r_string), std::begin(r));
    classic_security_manager_->RemoteOobDataRequestReply(peer, c, r);
    return ::grpc::Status::OK;
  };

  ::grpc::Status RemoteOobDataRequestNegativeReply(::grpc::ServerContext* context,
                                                   const ::bluetooth::facade::BluetoothAddress* request,
                                                   ::google::protobuf::Empty* response) {
    std::unique_lock<std::mutex> lock(mutex_);
    Address peer;
    ASSERT(Address::FromString(request->address(), peer));
    classic_security_manager_->RemoteOobDataRequestNegativeReply(peer);
    return ::grpc::Status::OK;
  }

  ::grpc::Status ReadStoredLinkKey(::grpc::ServerContext* context,
                                   const ::bluetooth::hci::ReadStoredLinkKeyMessage* request,
                                   ::google::protobuf::Empty* response) {
    std::unique_lock<std::mutex> lock(mutex_);
    Address peer;
    ASSERT(Address::FromString(request->remote().address(), peer));
    ReadStoredLinkKeyReadAllFlag read_all_flag = (ReadStoredLinkKeyReadAllFlag)request->read_all_flag();
    classic_security_manager_->ReadStoredLinkKey(peer, read_all_flag);
    return ::grpc::Status::OK;
  };

  ::grpc::Status WriteStoredLinkKey(::grpc::ServerContext* context,
                                    const ::bluetooth::hci::WriteStoredLinkKeyMessage* request,
                                    ::google::protobuf::Empty* response) {
    std::unique_lock<std::mutex> lock(mutex_);
    uint8_t num_keys_to_write = request->num_keys_to_write();
    std::vector<KeyAndAddress> keys;
    for (size_t i = 0; i < num_keys_to_write; i++) {
      KeyAndAddress key;
      common::LinkKey link_key;
      ASSERT(Address::FromString(request->remote().address(), key.address_));
      ASSERT(common::LinkKey::FromString(request->link_keys(), link_key));
      std::copy(std::begin(link_key.link_key), std::end(link_key.link_key), std::begin(key.link_key_));
      keys.push_back(key);
    }

    classic_security_manager_->WriteStoredLinkKey(keys);
    return ::grpc::Status::OK;
  };

  ::grpc::Status DeleteStoredLinkKey(::grpc::ServerContext* context,
                                     const ::bluetooth::hci::DeleteStoredLinkKeyMessage* request,
                                     ::google::protobuf::Empty* response) {
    std::unique_lock<std::mutex> lock(mutex_);
    Address peer;
    ASSERT(Address::FromString(request->remote().address(), peer));
    DeleteStoredLinkKeyDeleteAllFlag delete_all_flag = (DeleteStoredLinkKeyDeleteAllFlag)request->delete_all_flag();
    classic_security_manager_->DeleteStoredLinkKey(peer, delete_all_flag);
    return ::grpc::Status::OK;
  };

  ::grpc::Status RefreshEncryptionKey(::grpc::ServerContext* context,
                                      const ::bluetooth::hci::RefreshEncryptionKeyMessage* request,
                                      ::google::protobuf::Empty* response) {
    std::unique_lock<std::mutex> lock(mutex_);
    classic_security_manager_->RefreshEncryptionKey(request->connection_handle());
    return ::grpc::Status::OK;
  };

  ::grpc::Status ReadSimplePairingMode(::grpc::ServerContext* context, const ::google::protobuf::Empty* request,
                                       ::google::protobuf::Empty* response) {
    std::unique_lock<std::mutex> lock(mutex_);
    classic_security_manager_->ReadSimplePairingMode();
    return ::grpc::Status::OK;
  };

  ::grpc::Status WriteSimplePairingMode(::grpc::ServerContext* context,
                                        const ::bluetooth::hci::WriteSimplePairingModeMessage* request,
                                        ::google::protobuf::Empty* response) {
    std::unique_lock<std::mutex> lock(mutex_);
    Enable simple_pairing_mode = (Enable)request->simple_pairing_mode();
    classic_security_manager_->WriteSimplePairingMode(simple_pairing_mode);
    return ::grpc::Status::OK;
  };

  ::grpc::Status ReadLocalOobData(::grpc::ServerContext* context, const ::google::protobuf::Empty* request,
                                  ::google::protobuf::Empty* response) {
    std::unique_lock<std::mutex> lock(mutex_);
    classic_security_manager_->ReadLocalOobData();
    return ::grpc::Status::OK;
  };

  ::grpc::Status SendKeypressNotification(::grpc::ServerContext* context,
                                          const ::bluetooth::hci::SendKeypressNotificationMessage* request,
                                          ::google::protobuf::Empty* response) {
    std::unique_lock<std::mutex> lock(mutex_);
    Address peer;
    ASSERT(Address::FromString(request->remote().address(), peer));
    KeypressNotificationType notification_type = (KeypressNotificationType)request->notification_type();
    classic_security_manager_->SendKeypressNotification(peer, notification_type);
    return ::grpc::Status::OK;
  };

  ::grpc::Status ReadLocalOobExtendedData(::grpc::ServerContext* context, const ::google::protobuf::Empty* request,
                                          ::google::protobuf::Empty* response) {
    std::unique_lock<std::mutex> lock(mutex_);
    classic_security_manager_->ReadLocalOobExtendedData();
    return ::grpc::Status::OK;
  };

  ::grpc::Status ReadEncryptionKeySize(::grpc::ServerContext* context,
                                       const ::bluetooth::hci::ReadEncryptionKeySizeMessage* request,
                                       ::google::protobuf::Empty* response) {
    std::unique_lock<std::mutex> lock(mutex_);
    classic_security_manager_->ReadEncryptionKeySize(request->connection_handle());
    return ::grpc::Status::OK;
  };

  ::grpc::Status FetchCommandCompleteEvent(::grpc::ServerContext* context, const ::google::protobuf::Empty* request,
                                           ::grpc::ServerWriter<CommandCompleteEvent>* writer) override {
    return pending_connection_complete_.RunLoop(context, writer);
  };

  void OnCommandComplete(CommandCompleteView status) override {
    CommandCompleteEvent response;
    response.set_command_opcode(static_cast<uint32_t>(status.GetCommandOpCode()));
    pending_connection_complete_.OnIncomingEvent(response);
  }

 private:
  ClassicSecurityManager* classic_security_manager_;
  mutable std::mutex mutex_;
  ::bluetooth::os::Handler* facade_handler_;
  ::bluetooth::grpc::GrpcEventQueue<CommandCompleteEvent> pending_connection_complete_{"FetchCommandCompleteEvent"};
};

void ClassicSecurityManagerFacadeModule::ListDependencies(ModuleList* list) {
  ::bluetooth::grpc::GrpcFacadeModule::ListDependencies(list);
  list->add<ClassicSecurityManager>();
  list->add<Controller>();
  list->add<HciLayer>();
}

void ClassicSecurityManagerFacadeModule::Start() {
  ::bluetooth::grpc::GrpcFacadeModule::Start();
  service_ = new ClassicSecurityManagerFacadeService(
      GetDependency<ClassicSecurityManager>(), GetDependency<Controller>(), GetDependency<HciLayer>(), GetHandler());
}

void ClassicSecurityManagerFacadeModule::Stop() {
  delete service_;
  ::bluetooth::grpc::GrpcFacadeModule::Stop();
}

::grpc::Service* ClassicSecurityManagerFacadeModule::GetService() const {
  return service_;
}

const ModuleFactory ClassicSecurityManagerFacadeModule::Factory =
    ::bluetooth::ModuleFactory([]() { return new ClassicSecurityManagerFacadeModule(); });

}  // namespace hci
}  // namespace bluetooth
