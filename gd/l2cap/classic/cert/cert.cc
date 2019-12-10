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

#include <condition_variable>
#include <cstdint>
#include <memory>
#include <mutex>
#include <queue>
#include <unordered_map>

#include "common/blocking_queue.h"
#include "grpc/grpc_event_queue.h"
#include "hci/acl_manager.h"
#include "hci/cert/cert.h"
#include "hci/hci_packets.h"
#include "l2cap/classic/cert/api.grpc.pb.h"
#include "l2cap/classic/cert/cert.h"
#include "l2cap/classic/l2cap_classic_module.h"
#include "l2cap/l2cap_packets.h"
#include "os/log.h"
#include "packet/raw_builder.h"

using ::grpc::ServerAsyncResponseWriter;
using ::grpc::ServerAsyncWriter;
using ::grpc::ServerContext;

using ::bluetooth::packet::RawBuilder;
using ::bluetooth::l2cap::classic::cert::L2capPacket;

namespace bluetooth {
namespace l2cap {
namespace classic {
namespace cert {

using namespace facade;

class L2capClassicModuleCertService : public L2capClassicModuleCert::Service {
 public:
  L2capClassicModuleCertService(hci::AclManager* acl_manager, os::Handler* facade_handler)
      : handler_(facade_handler), acl_manager_(acl_manager) {
    ASSERT(handler_ != nullptr);
    acl_manager_->RegisterCallbacks(&acl_callbacks, handler_);
  }

  ::grpc::Status SetupLink(::grpc::ServerContext* context,
                           const ::bluetooth::l2cap::classic::cert::SetupLinkRequest* request,
                           ::bluetooth::l2cap::classic::cert::SetupLinkResponse* response) override {
    hci::Address address;
    hci::Address::FromString(request->remote().address(), address);
    LOG_INFO("%s", address.ToString().c_str());
    acl_manager_->CreateConnection(address);
    return ::grpc::Status::OK;
  }

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

  ::grpc::Status SendIFrame(::grpc::ServerContext* context, const ::bluetooth::l2cap::classic::cert::IFrame* request,
                            ::bluetooth::l2cap::classic::cert::SendIFrameResult* response) override {
    std::unique_ptr<RawBuilder> packet = std::make_unique<RawBuilder>();
    auto req_string = request->information();
    packet->AddOctets(std::vector<uint8_t>(req_string.begin(), req_string.end()));
    std::unique_ptr<BasePacketBuilder> l2cap_builder;
    auto f = static_cast<Final>(request->f());
    if (request->sar() == static_cast<int>(SegmentationAndReassembly::START)) {
      l2cap_builder = EnhancedInformationStartFrameBuilder::Create(
          request->channel(), request->tx_seq(), f, request->req_seq(), request->sdu_size(), std::move(packet));
    } else {
      l2cap_builder = EnhancedInformationFrameBuilder::Create(
          request->channel(), request->tx_seq(), f, request->req_seq(),
          static_cast<SegmentationAndReassembly>(request->sar()), std::move(packet));
    }
    outgoing_packet_queue_.push(std::move(l2cap_builder));
    send_packet_from_queue();
    return ::grpc::Status::OK;
  }

  ::grpc::Status SendSFrame(::grpc::ServerContext* context, const ::bluetooth::l2cap::classic::cert::SFrame* request,
                            ::bluetooth::l2cap::classic::cert::SendSFrameResult* response) override {
    auto f = static_cast<Final>(request->f());
    auto p = static_cast<Poll>(request->p());
    auto s = static_cast<SupervisoryFunction>(request->s());
    auto builder = EnhancedSupervisoryFrameBuilder::Create(request->channel(), s, p, f, request->req_seq());
    outgoing_packet_queue_.push(std::move(builder));
    send_packet_from_queue();
    return ::grpc::Status::OK;
  }

  ::grpc::Status SendConnectionRequest(::grpc::ServerContext* context, const cert::ConnectionRequest* request,
                                       ::google::protobuf::Empty* response) override {
    auto builder = ConnectionRequestBuilder::Create(request->signal_id(), request->psm(), request->scid());
    auto l2cap_builder = BasicFrameBuilder::Create(kClassicSignallingCid, std::move(builder));
    outgoing_packet_queue_.push(std::move(l2cap_builder));
    send_packet_from_queue();
    return ::grpc::Status::OK;
  }

  ::grpc::Status SendConnectionResponse(
      ::grpc::ServerContext* context, const ::bluetooth::l2cap::classic::cert::ConnectionResponse* request,
      ::bluetooth::l2cap::classic::cert::SendConnectionResponseResult* response) override {
    auto builder = ConnectionResponseBuilder::Create(request->signal_id(), request->dcid(), request->scid(),
                                                     ConnectionResponseResult::SUCCESS,
                                                     ConnectionResponseStatus::NO_FURTHER_INFORMATION_AVAILABLE);
    auto l2cap_builder = BasicFrameBuilder::Create(kClassicSignallingCid, std::move(builder));
    outgoing_packet_queue_.push(std::move(l2cap_builder));
    send_packet_from_queue();
    return ::grpc::Status::OK;
  }

  ::grpc::Status SendConfigurationRequest(
      ::grpc::ServerContext* context, const ::bluetooth::l2cap::classic::cert::ConfigurationRequest* request,
      ::bluetooth::l2cap::classic::cert::SendConfigurationRequestResult* response) override {
    std::vector<std::unique_ptr<ConfigurationOption>> config;
    if (request->retransmission_config().mode() == ChannelRetransmissionFlowControlMode::ERTM) {
      auto option = std::make_unique<RetransmissionAndFlowControlConfigurationOption>();
      option->mode_ = RetransmissionAndFlowControlModeOption::ENHANCED_RETRANSMISSION;
      option->tx_window_size_ = 10;
      option->max_transmit_ = 20;
      option->retransmission_time_out_ = 2000;
      option->monitor_time_out_ = 12000;
      option->maximum_pdu_size_ = 1010;
      config.push_back(std::move(option));
      auto no_fcs = std::make_unique<FrameCheckSequenceOption>();
      no_fcs->fcs_type_ = FcsType::NO_FCS;
      config.push_back(std::move(no_fcs));
    }
    auto builder = ConfigurationRequestBuilder::Create(request->signal_id(), request->dcid(), Continuation::END,
                                                       std::move(config));
    auto l2cap_builder = BasicFrameBuilder::Create(kClassicSignallingCid, std::move(builder));
    outgoing_packet_queue_.push(std::move(l2cap_builder));
    send_packet_from_queue();
    return ::grpc::Status::OK;
  }

  ::grpc::Status SendConfigurationResponse(
      ::grpc::ServerContext* context, const ::bluetooth::l2cap::classic::cert::ConfigurationResponse* request,
      ::bluetooth::l2cap::classic::cert::SendConfigurationResponseResult* response) override {
    std::vector<std::unique_ptr<ConfigurationOption>> config;
    if (request->retransmission_config().mode() == ChannelRetransmissionFlowControlMode::ERTM) {
      auto option = std::make_unique<RetransmissionAndFlowControlConfigurationOption>();
      option->mode_ = RetransmissionAndFlowControlModeOption::ENHANCED_RETRANSMISSION;
      option->tx_window_size_ = 5;
      option->max_transmit_ = 1;
      option->retransmission_time_out_ = 1000;
      option->monitor_time_out_ = 2000;
      option->maximum_pdu_size_ = 1010;
      config.push_back(std::move(option));
    }
    auto builder = ConfigurationResponseBuilder::Create(request->signal_id(), request->scid(), Continuation::END,
                                                        ConfigurationResponseResult::SUCCESS, std::move(config));
    auto l2cap_builder = BasicFrameBuilder::Create(kClassicSignallingCid, std::move(builder));
    outgoing_packet_queue_.push(std::move(l2cap_builder));
    send_packet_from_queue();
    return ::grpc::Status::OK;
  }

  ::grpc::Status SendDisconnectionRequest(::grpc::ServerContext* context, const cert::DisconnectionRequest* request,
                                          ::google::protobuf::Empty* response) override {
    auto builder = DisconnectionRequestBuilder::Create(request->signal_id(), request->dcid(), request->scid());
    auto l2cap_builder = BasicFrameBuilder::Create(kClassicSignallingCid, std::move(builder));
    outgoing_packet_queue_.push(std::move(l2cap_builder));
    send_packet_from_queue();

    return ::grpc::Status::OK;
  }

  ::grpc::Status SendDisconnectionResponse(
      ::grpc::ServerContext* context, const ::bluetooth::l2cap::classic::cert::DisconnectionResponse* request,
      ::bluetooth::l2cap::classic::cert::SendDisconnectionResponseResult* response) override {
    auto builder = DisconnectionResponseBuilder::Create(request->signal_id(), request->dcid(), request->scid());
    auto l2cap_builder = BasicFrameBuilder::Create(kClassicSignallingCid, std::move(builder));
    outgoing_packet_queue_.push(std::move(l2cap_builder));
    send_packet_from_queue();
    return ::grpc::Status::OK;
  }

  ::grpc::Status SendInformationRequest(
      ::grpc::ServerContext* context, const ::bluetooth::l2cap::classic::cert::InformationRequest* request,
      ::bluetooth::l2cap::classic::cert::SendInformationRequestResult* response) override {
    switch (request->type()) {
      case InformationRequestType::CONNECTIONLESS_MTU: {
        auto builder =
            InformationRequestBuilder::Create(request->signal_id(), InformationRequestInfoType::CONNECTIONLESS_MTU);
        auto l2cap_builder = BasicFrameBuilder::Create(kClassicSignallingCid, std::move(builder));
        outgoing_packet_queue_.push(std::move(l2cap_builder));
        send_packet_from_queue();
        break;
      }
      case InformationRequestType::EXTENDED_FEATURES: {
        auto builder = InformationRequestBuilder::Create(request->signal_id(),
                                                         InformationRequestInfoType::EXTENDED_FEATURES_SUPPORTED);
        auto l2cap_builder = BasicFrameBuilder::Create(kClassicSignallingCid, std::move(builder));
        outgoing_packet_queue_.push(std::move(l2cap_builder));
        send_packet_from_queue();
        break;
      }
      case InformationRequestType::FIXED_CHANNELS: {
        auto builder = InformationRequestBuilder::Create(request->signal_id(),
                                                         InformationRequestInfoType::FIXED_CHANNELS_SUPPORTED);
        auto l2cap_builder = BasicFrameBuilder::Create(kClassicSignallingCid, std::move(builder));
        outgoing_packet_queue_.push(std::move(l2cap_builder));
        send_packet_from_queue();
        break;
      }
      default:
        break;
    }
    return ::grpc::Status::OK;
  }

  ::grpc::Status SendInformationResponse(
      ::grpc::ServerContext* context, const ::bluetooth::l2cap::classic::cert::InformationResponse* request,
      ::bluetooth::l2cap::classic::cert::SendInformationResponseResult* response) override {
    switch (request->type()) {
      case InformationRequestType::CONNECTIONLESS_MTU: {
        auto builder = InformationResponseConnectionlessMtuBuilder::Create(request->signal_id(),
                                                                           InformationRequestResult::SUCCESS, 100);
        auto l2cap_builder = BasicFrameBuilder::Create(kClassicSignallingCid, std::move(builder));
        outgoing_packet_queue_.push(std::move(l2cap_builder));
        send_packet_from_queue();
        break;
      }
      case InformationRequestType::EXTENDED_FEATURES: {
        auto builder = InformationResponseExtendedFeaturesBuilder::Create(
            request->signal_id(), InformationRequestResult::SUCCESS, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0);
        auto l2cap_builder = BasicFrameBuilder::Create(kClassicSignallingCid, std::move(builder));
        outgoing_packet_queue_.push(std::move(l2cap_builder));
        send_packet_from_queue();
        break;
      }
      case InformationRequestType::FIXED_CHANNELS: {
        constexpr uint64_t kSignallingChannelMask = 0x02;
        auto builder = InformationResponseFixedChannelsBuilder::Create(
            request->signal_id(), InformationRequestResult::SUCCESS, kSignallingChannelMask);
        auto l2cap_builder = BasicFrameBuilder::Create(kClassicSignallingCid, std::move(builder));
        outgoing_packet_queue_.push(std::move(l2cap_builder));
        send_packet_from_queue();
        break;
      }
      default:
        break;
    }

    return ::grpc::Status::OK;
  }

  std::unique_ptr<packet::BasePacketBuilder> enqueue_packet_to_acl() {
    auto basic_frame_builder = std::move(outgoing_packet_queue_.front());
    outgoing_packet_queue_.pop();
    if (outgoing_packet_queue_.empty()) {
      acl_connection_->GetAclQueueEnd()->UnregisterEnqueue();
    }
    return basic_frame_builder;
  }

  ::grpc::Status FetchL2capLog(::grpc::ServerContext* context, const ::google::protobuf::Empty* request,
                               ::grpc::ServerWriter<FetchL2capLogResponse>* writer) override {
    return pending_l2cap_log_.RunLoop(context, writer);
  }

  void LogEvent(const FetchL2capLogResponse& response) {
    pending_l2cap_log_.OnIncomingEvent(response);
  }

  void on_incoming_packet() {
    auto packet = acl_connection_->GetAclQueueEnd()->TryDequeue();
    BasicFrameView basic_frame_view = BasicFrameView::Create(*packet);
    ASSERT(basic_frame_view.IsValid());
    L2capPacket l2cap_packet;
    auto payload = basic_frame_view.GetPayload();
    std::string data = std::string(payload.begin(), payload.end());
    l2cap_packet.set_payload(data);
    l2cap_packet.set_channel(basic_frame_view.GetChannelId());
    if (basic_frame_view.GetChannelId() == kClassicSignallingCid) {
      ControlView control_view = ControlView::Create(basic_frame_view.GetPayload());
      ASSERT(control_view.IsValid());
      handle_signalling_packet(control_view);
    } else {
      FetchL2capLogResponse response;
      response.mutable_data_packet()->set_channel(basic_frame_view.GetChannelId());
      response.mutable_data_packet()->set_payload(data);
      LogEvent(response);
    }
  }

  void send_packet_from_queue() {
    if (outgoing_packet_queue_.size() == 1) {
      acl_connection_->GetAclQueueEnd()->RegisterEnqueue(
          handler_, common::Bind(&L2capClassicModuleCertService::enqueue_packet_to_acl, common::Unretained(this)));
    }
  }

  void handle_signalling_packet(ControlView control_view) {
    auto code = control_view.GetCode();
    switch (code) {
      case CommandCode::COMMAND_REJECT: {
        CommandRejectView view = CommandRejectView::Create(control_view);
        ASSERT(view.IsValid());
        FetchL2capLogResponse response;
        response.mutable_command_reject()->set_signal_id(control_view.GetIdentifier());
        LogEvent(response);
        break;
      }
      case CommandCode::CONNECTION_REQUEST: {
        ConnectionRequestView view = ConnectionRequestView::Create(control_view);
        ASSERT(view.IsValid());
        FetchL2capLogResponse response;
        response.mutable_connection_request()->set_signal_id(control_view.GetIdentifier());
        response.mutable_connection_request()->set_scid(view.GetSourceCid());
        response.mutable_connection_request()->set_psm(view.GetPsm());
        LogEvent(response);
        break;
      }
      case CommandCode::CONNECTION_RESPONSE: {
        ConnectionResponseView view = ConnectionResponseView::Create(control_view);
        ASSERT(view.IsValid());
        FetchL2capLogResponse response;
        response.mutable_connection_response()->set_signal_id(control_view.GetIdentifier());
        response.mutable_connection_response()->set_scid(view.GetSourceCid());
        response.mutable_connection_response()->set_dcid(view.GetDestinationCid());
        LogEvent(response);
        break;
      }

      case CommandCode::CONFIGURATION_REQUEST: {
        ConfigurationRequestView view = ConfigurationRequestView::Create(control_view);
        ASSERT(view.IsValid());
        FetchL2capLogResponse response;
        response.mutable_configuration_request()->set_signal_id(control_view.GetIdentifier());
        response.mutable_configuration_request()->set_dcid(view.GetDestinationCid());

        for (auto& option : view.GetConfig()) {
          if (option->type_ == ConfigurationOptionType::RETRANSMISSION_AND_FLOW_CONTROL) {
            auto config = RetransmissionAndFlowControlConfigurationOption::Specialize(option.get());
            response.mutable_configuration_request()->mutable_retransmission_config()->set_mode(
                ChannelRetransmissionFlowControlMode::ERTM);
            response.mutable_configuration_request()->mutable_retransmission_config()->set_tx_window(
                config->tx_window_size_);
            response.mutable_configuration_request()->mutable_retransmission_config()->set_max_transmit(
                config->max_transmit_);
            response.mutable_configuration_request()->mutable_retransmission_config()->set_retransmit_timeout(
                config->retransmission_time_out_);
            response.mutable_configuration_request()->mutable_retransmission_config()->set_monitor_timeout(
                config->monitor_time_out_);
            response.mutable_configuration_request()->mutable_retransmission_config()->set_mps(
                config->maximum_pdu_size_);
          }
        }
        LogEvent(response);
        break;
      }
      case CommandCode::CONFIGURATION_RESPONSE: {
        ConfigurationResponseView view = ConfigurationResponseView::Create(control_view);
        ASSERT(view.IsValid());
        FetchL2capLogResponse response;
        response.mutable_configuration_response()->set_signal_id(control_view.GetIdentifier());
        response.mutable_configuration_response()->set_scid(view.GetSourceCid());
        LogEvent(response);
        break;
      }
      case CommandCode::DISCONNECTION_REQUEST: {
        DisconnectionRequestView view = DisconnectionRequestView::Create(control_view);
        ASSERT(view.IsValid());
        FetchL2capLogResponse response;
        response.mutable_disconnection_request()->set_signal_id(control_view.GetIdentifier());
        response.mutable_disconnection_request()->set_dcid(view.GetDestinationCid());
        response.mutable_disconnection_request()->set_scid(view.GetSourceCid());
        LogEvent(response);
        break;
      }
      case CommandCode::DISCONNECTION_RESPONSE: {
        DisconnectionResponseView view = DisconnectionResponseView::Create(control_view);
        ASSERT(view.IsValid());
        FetchL2capLogResponse response;
        response.mutable_disconnection_response()->set_signal_id(control_view.GetIdentifier());
        response.mutable_disconnection_response()->set_dcid(view.GetDestinationCid());
        response.mutable_disconnection_response()->set_scid(view.GetSourceCid());
        LogEvent(response);
        break;
      }
      case CommandCode::ECHO_RESPONSE: {
        EchoResponseView view = EchoResponseView::Create(control_view);
        ASSERT(view.IsValid());
        FetchL2capLogResponse response;
        response.mutable_echo_response()->set_signal_id(control_view.GetIdentifier());
        LogEvent(response);
        break;
      }
      case CommandCode::INFORMATION_REQUEST: {
        InformationRequestView information_request_view = InformationRequestView::Create(control_view);
        if (!information_request_view.IsValid()) {
          return;
        }
        FetchL2capLogResponse log_response;
        log_response.mutable_information_request()->set_signal_id(control_view.GetIdentifier());
        auto type = information_request_view.GetInfoType();
        switch (type) {
          case InformationRequestInfoType::CONNECTIONLESS_MTU: {
            log_response.mutable_information_request()->set_type(InformationRequestType::CONNECTIONLESS_MTU);
            break;
          }
          case InformationRequestInfoType::EXTENDED_FEATURES_SUPPORTED: {
            log_response.mutable_information_request()->set_type(InformationRequestType::EXTENDED_FEATURES);
            break;
          }
          case InformationRequestInfoType::FIXED_CHANNELS_SUPPORTED: {
            log_response.mutable_information_request()->set_type(InformationRequestType::FIXED_CHANNELS);
            break;
          }
        }
        LogEvent(log_response);
        break;
      }
      case CommandCode::INFORMATION_RESPONSE: {
        InformationResponseView information_response_view = InformationResponseView::Create(control_view);
        if (!information_response_view.IsValid()) {
          return;
        }
        FetchL2capLogResponse log_response;
        log_response.mutable_information_response()->set_signal_id(control_view.GetIdentifier());
        auto type = information_response_view.GetInfoType();
        switch (type) {
          case InformationRequestInfoType::CONNECTIONLESS_MTU: {
            auto view = InformationResponseConnectionlessMtuView::Create(information_response_view);
            if (!view.IsValid()) {
              return;
            }
            log_response.mutable_information_response()->set_type(InformationRequestType::CONNECTIONLESS_MTU);
            log_response.mutable_information_response()->set_information_value(view.GetConnectionlessMtu());
            break;
          }
          case InformationRequestInfoType::EXTENDED_FEATURES_SUPPORTED: {
            auto view = InformationResponseExtendedFeaturesView::Create(information_response_view);
            if (!view.IsValid()) {
              return;
            }
            log_response.mutable_information_response()->set_type(InformationRequestType::EXTENDED_FEATURES);
            int mask = view.GetEnhancedRetransmissionMode() << 3 | view.GetFcsOption() << 5;
            log_response.mutable_information_response()->set_information_value(mask);
            break;
          }
          case InformationRequestInfoType::FIXED_CHANNELS_SUPPORTED: {
            auto view = InformationResponseFixedChannelsView::Create(information_response_view);
            if (!view.IsValid()) {
              return;
            }
            log_response.mutable_information_response()->set_type(InformationRequestType::FIXED_CHANNELS);
            log_response.mutable_information_response()->set_information_value(view.GetFixedChannels());
            break;
          }
        }
        LogEvent(log_response);
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
  ::bluetooth::grpc::GrpcEventQueue<FetchL2capLogResponse> pending_l2cap_log_{"FetchL2capLog"};

  class AclCallbacks : public hci::ConnectionCallbacks {
   public:
    AclCallbacks(L2capClassicModuleCertService* module) : module_(module) {}
    void OnConnectSuccess(std::unique_ptr<hci::AclConnection> connection) override {
      module_->acl_connection_ = std::move(connection);
      module_->acl_connection_->RegisterDisconnectCallback(common::BindOnce([](hci::ErrorCode) {}), module_->handler_);
      module_->acl_connection_->GetAclQueueEnd()->RegisterDequeue(
          module_->handler_,
          common::Bind(&L2capClassicModuleCertService::on_incoming_packet, common::Unretained(module_)));
      dequeue_registered_ = true;
      FetchL2capLogResponse response;
      response.mutable_link_up()->mutable_remote()->set_address(module_->acl_connection_->GetAddress().ToString());
      module_->LogEvent(response);
    }
    void OnConnectFail(hci::Address address, hci::ErrorCode reason) override {}

    ~AclCallbacks() {
      if (dequeue_registered_) {
        module_->acl_connection_->GetAclQueueEnd()->UnregisterDequeue();
      }
    }

    bool dequeue_registered_ = false;

    L2capClassicModuleCertService* module_;
  } acl_callbacks{this};

  std::mutex mutex_;
};

void L2capClassicModuleCertModule::ListDependencies(ModuleList* list) {
  ::bluetooth::grpc::GrpcFacadeModule::ListDependencies(list);
  list->add<hci::AclManager>();
  list->add<hci::HciLayer>();
}

void L2capClassicModuleCertModule::Start() {
  ::bluetooth::grpc::GrpcFacadeModule::Start();
  GetDependency<hci::HciLayer>()->EnqueueCommand(hci::WriteScanEnableBuilder::Create(hci::ScanEnable::PAGE_SCAN_ONLY),
                                                 common::BindOnce([](hci::CommandCompleteView) {}), GetHandler());
  service_ = new L2capClassicModuleCertService(GetDependency<hci::AclManager>(), GetHandler());
}

void L2capClassicModuleCertModule::Stop() {
  delete service_;
  ::bluetooth::grpc::GrpcFacadeModule::Stop();
}

::grpc::Service* L2capClassicModuleCertModule::GetService() const {
  return service_;
}

const ModuleFactory L2capClassicModuleCertModule::Factory =
    ::bluetooth::ModuleFactory([]() { return new L2capClassicModuleCertModule(); });

}  // namespace cert
}  // namespace classic
}  // namespace l2cap
}  // namespace bluetooth
