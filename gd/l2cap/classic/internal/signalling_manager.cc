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

#include "l2cap/classic/internal/signalling_manager.h"

#include <chrono>

#include "common/bind.h"
#include "l2cap/classic/internal/link.h"
#include "l2cap/l2cap_packets.h"
#include "os/log.h"
#include "packet/raw_builder.h"

namespace bluetooth {
namespace l2cap {
namespace classic {
namespace internal {
static constexpr auto kTimeout = std::chrono::seconds(3);

ClassicSignallingManager::ClassicSignallingManager(os::Handler* handler, Link* link,
                                                   DynamicChannelServiceManagerImpl* dynamic_service_manager,
                                                   DynamicChannelAllocator* channel_allocator,
                                                   FixedChannelServiceManagerImpl* fixed_service_manager)
    : handler_(handler), link_(link), dynamic_service_manager_(dynamic_service_manager),
      channel_allocator_(channel_allocator), fixed_service_manager_(fixed_service_manager), alarm_(handler) {
  ASSERT(handler_ != nullptr);
  ASSERT(link_ != nullptr);
  signalling_channel_ = link_->AllocateFixedChannel(kClassicSignallingCid, {});
  signalling_channel_->GetQueueUpEnd()->RegisterDequeue(
      handler_, common::Bind(&ClassicSignallingManager::on_incoming_packet, common::Unretained(this)));
  enqueue_buffer_ =
      std::make_unique<os::EnqueueBuffer<packet::BasePacketBuilder>>(signalling_channel_->GetQueueUpEnd());
}

ClassicSignallingManager::~ClassicSignallingManager() {
  enqueue_buffer_.reset();
  signalling_channel_->GetQueueUpEnd()->UnregisterDequeue();
  signalling_channel_ = nullptr;
}

void ClassicSignallingManager::OnCommandReject(CommandRejectView command_reject_view) {
  SignalId signal_id = command_reject_view.GetIdentifier();
  if (pending_command_.signal_id_ != signal_id) {
    LOG_WARN("Unknown command reject");
    return;
  }
  pending_command_ = {};

  LOG_INFO("Command rejected");
}

void ClassicSignallingManager::SendConnectionRequest(Psm psm, Cid local_cid) {
  PendingCommand pending_command = {next_signal_id_, CommandCode::CONNECTION_REQUEST, psm, local_cid, {}, {}};
  next_signal_id_++;
  pending_commands_.push(pending_command);
  if (pending_commands_.size() == 1) {
    handle_send_next_command();
  }
}

void ClassicSignallingManager::SendConfigurationRequest() {}

void ClassicSignallingManager::SendDisconnectionRequest(Cid local_cid, Cid remote_cid) {
  PendingCommand pending_command = {next_signal_id_, CommandCode::DISCONNECTION_REQUEST, {}, local_cid, remote_cid, {}};
  next_signal_id_++;
  pending_commands_.push(pending_command);
  if (pending_commands_.size() == 1) {
    handle_send_next_command();
  }
}

void ClassicSignallingManager::SendInformationRequest(InformationRequestInfoType type) {
  PendingCommand pending_command = {next_signal_id_, CommandCode::INFORMATION_REQUEST, {}, {}, {}, type};
  next_signal_id_++;
  pending_commands_.push(pending_command);
  if (pending_commands_.size() == 1) {
    handle_send_next_command();
  }
}

void ClassicSignallingManager::SendEchoRequest(std::unique_ptr<packet::RawBuilder> payload) {
  LOG_WARN("Not supported");
}

void ClassicSignallingManager::OnConnectionRequest(SignalId signal_id, Psm psm, Cid remote_cid) {
  if (!IsPsmValid(psm)) {
    LOG_WARN("Invalid psm received from remote psm:%d remote_cid:%d", psm, remote_cid);
    send_connection_response(signal_id, remote_cid, kInvalidCid, ConnectionResponseResult::PSM_NOT_SUPPORTED,
                             ConnectionResponseStatus::NO_FURTHER_INFORMATION_AVAILABLE);
    return;
  }

  if (remote_cid == kInvalidCid) {
    LOG_WARN("Invalid remote cid received from remote psm:%d remote_cid:%d", psm, remote_cid);
    send_connection_response(signal_id, remote_cid, kInvalidCid, ConnectionResponseResult::INVALID_CID,
                             ConnectionResponseStatus::NO_FURTHER_INFORMATION_AVAILABLE);
    return;
  }
  if (channel_allocator_->IsPsmUsed(psm)) {
    LOG_WARN("Psm already exists");
    send_connection_response(signal_id, remote_cid, kInvalidCid, ConnectionResponseResult::PSM_NOT_SUPPORTED,
                             ConnectionResponseStatus::NO_FURTHER_INFORMATION_AVAILABLE);
    return;
  }

  if (!dynamic_service_manager_->IsServiceRegistered(psm)) {
    LOG_INFO("Service for this psm (%d) is not registered", psm);
    send_connection_response(signal_id, remote_cid, kInvalidCid, ConnectionResponseResult::PSM_NOT_SUPPORTED,
                             ConnectionResponseStatus::NO_FURTHER_INFORMATION_AVAILABLE);
    return;
  }

  auto new_channel = link_->AllocateDynamicChannel(psm, remote_cid, {});
  if (new_channel == nullptr) {
    LOG_WARN("Can't allocate dynamic channel");
    return;
  }
  send_connection_response(signal_id, remote_cid, new_channel->GetCid(), ConnectionResponseResult::SUCCESS,
                           ConnectionResponseStatus::NO_FURTHER_INFORMATION_AVAILABLE);
  std::unique_ptr<DynamicChannel> channel = std::make_unique<DynamicChannel>(new_channel, handler_);
  dynamic_service_manager_->GetService(psm)->NotifyChannelCreation(std::move(channel));
}

void ClassicSignallingManager::OnConnectionResponse(SignalId signal_id, Cid cid, Cid remote_cid,
                                                    ConnectionResponseResult result, ConnectionResponseStatus status) {
  if (pending_command_.signal_id_ != signal_id || pending_command_.command_code_ != CommandCode::CONNECTION_REQUEST) {
    LOG_WARN("Received unexpected connection response");
    return;
  }
  if (pending_command_.source_cid_ != cid) {
    LOG_WARN("SCID doesn't match");
    return;
  }
  if (result != ConnectionResponseResult::SUCCESS) {
    return;
  }
  Psm pending_psm = pending_command_.psm_;
  pending_command_ = {};
  auto new_channel = link_->AllocateDynamicChannel(pending_psm, remote_cid, {});
  if (new_channel == nullptr) {
    LOG_WARN("Can't allocate dynamic channel");
    return;
  }
  send_connection_response(signal_id, remote_cid, new_channel->GetCid(), ConnectionResponseResult::SUCCESS,
                           ConnectionResponseStatus::NO_FURTHER_INFORMATION_AVAILABLE);
  std::unique_ptr<DynamicChannel> channel = std::make_unique<DynamicChannel>(new_channel, handler_);
  dynamic_service_manager_->GetService(pending_psm)->NotifyChannelCreation(std::move(channel));
  alarm_.Cancel();
}

void ClassicSignallingManager::OnConfigurationRequest(SignalId signal_id, Cid cid, Continuation is_continuation,
                                                      std::vector<std::unique_ptr<ConfigurationOption>> option) {}

void ClassicSignallingManager::OnConfigurationResponse(SignalId signal_id, Cid cid, Continuation is_continuation,
                                                       ConfigurationResponseResult result,
                                                       std::vector<std::unique_ptr<ConfigurationOption>> option) {}

void ClassicSignallingManager::OnDisconnectionRequest(SignalId signal_id, Cid cid, Cid remote_cid) {
  // TODO: check cid match
  auto channel = channel_allocator_->FindChannelByCid(cid);
  if (channel == nullptr) {
    LOG_WARN("Disconnect request for an unknown channel");
    return;
  }
  auto builder = DisconnectionResponseBuilder::Create(signal_id.Value(), remote_cid, cid);
  enqueue_buffer_->Enqueue(std::move(builder), handler_);
  channel->OnClosed(hci::ErrorCode::SUCCESS);
  link_->FreeDynamicChannel(cid);
}

void ClassicSignallingManager::OnDisconnectionResponse(SignalId signal_id, Cid cid, Cid remote_cid) {
  if (pending_command_.signal_id_ != signal_id ||
      pending_command_.command_code_ != CommandCode::DISCONNECTION_REQUEST) {
    return;
  }

  auto channel = channel_allocator_->FindChannelByCid(cid);
  if (channel == nullptr) {
    LOG_WARN("Disconnect response for an unknown channel");
    return;
  }

  channel->OnClosed(hci::ErrorCode::SUCCESS);
  link_->FreeDynamicChannel(cid);
}

void ClassicSignallingManager::OnEchoRequest(SignalId signal_id, const PacketView<kLittleEndian>& packet) {
  std::vector<uint8_t> packet_vector{packet.begin(), packet.end()};
  auto raw_builder = std::make_unique<packet::RawBuilder>();
  raw_builder->AddOctets(packet_vector);
  auto builder = EchoRequestBuilder::Create(signal_id.Value(), std::move(raw_builder));
  enqueue_buffer_->Enqueue(std::move(builder), handler_);
}

void ClassicSignallingManager::OnEchoResponse(SignalId signal_id, const PacketView<kLittleEndian>& packet) {
  if (pending_command_.signal_id_ != signal_id || pending_command_.command_code_ != CommandCode::ECHO_REQUEST) {
    return;
  }
  LOG_INFO("Echo response received");
}

void ClassicSignallingManager::OnInformationRequest(SignalId signal_id, InformationRequestInfoType type) {
  switch (type) {
    case InformationRequestInfoType::CONNECTIONLESS_MTU: {
      auto response = InformationResponseConnectionlessMtuBuilder::Create(signal_id.Value(),
                                                                          InformationRequestResult::NOT_SUPPORTED, 0);
      enqueue_buffer_->Enqueue(std::move(response), handler_);
      return;
    }
    case InformationRequestInfoType::EXTENDED_FEATURES_SUPPORTED: {
      // TODO: implement this response
      auto response = InformationResponseExtendedFeaturesBuilder::Create(
          signal_id.Value(), InformationRequestResult::NOT_SUPPORTED, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
      enqueue_buffer_->Enqueue(std::move(response), handler_);
      return;
    }
    case InformationRequestInfoType::FIXED_CHANNELS_SUPPORTED: {
      auto response = InformationResponseFixedChannelsBuilder::Create(
          signal_id.Value(), InformationRequestResult::SUCCESS, fixed_service_manager_->GetSupportedFixedChannelMask());
      enqueue_buffer_->Enqueue(std::move(response), handler_);
      return;
    }
  }
}

void ClassicSignallingManager::OnInformationResponse(SignalId signal_id, const InformationResponseView& view) {
  if (pending_command_.signal_id_ != signal_id || pending_command_.command_code_ != CommandCode::INFORMATION_REQUEST) {
    return;
  }
  if (view.GetResult() != InformationRequestResult::SUCCESS) {
    return;
  }
}

void ClassicSignallingManager::on_incoming_packet() {
  auto packet = signalling_channel_->GetQueueUpEnd()->TryDequeue();
  ControlView control_packet_view = ControlView::Create(*packet);
  if (!control_packet_view.IsValid()) {
    LOG_WARN("Invalid signalling packet received");
    return;
  }
  auto code = control_packet_view.GetCode();
  switch (code) {
    case CommandCode::COMMAND_REJECT: {
      CommandRejectView command_reject_view = CommandRejectView::Create(control_packet_view);
      if (!command_reject_view.IsValid()) {
        return;
      }
      OnCommandReject(command_reject_view);
      return;
    }
    case CommandCode::CONNECTION_REQUEST: {
      ConnectionRequestView connection_request_view = ConnectionRequestView::Create(control_packet_view);
      if (!connection_request_view.IsValid()) {
        return;
      }
      OnConnectionRequest(control_packet_view.GetIdentifier(), connection_request_view.GetPsm(),
                          connection_request_view.GetSourceCid());
      return;
    }
    case CommandCode::CONNECTION_RESPONSE: {
      ConnectionResponseView connection_response_view = ConnectionResponseView::Create(control_packet_view);
      if (!connection_response_view.IsValid()) {
        return;
      }
      OnConnectionResponse(connection_response_view.GetIdentifier(), connection_response_view.GetDestinationCid(),
                           connection_response_view.GetSourceCid(), connection_response_view.GetResult(),
                           connection_response_view.GetStatus());
      return;
    }
    case CommandCode::CONFIGURATION_REQUEST: {
      ConfigurationRequestView configuration_request_view = ConfigurationRequestView::Create(control_packet_view);
      if (!configuration_request_view.IsValid()) {
        return;
      }
      OnConfigurationRequest(configuration_request_view.GetIdentifier(), configuration_request_view.GetDestinationCid(),
                             configuration_request_view.GetContinuation(), configuration_request_view.GetConfig());
      return;
    }
    case CommandCode::CONFIGURATION_RESPONSE: {
      ConfigurationResponseView configuration_response_view = ConfigurationResponseView::Create(control_packet_view);
      if (!configuration_response_view.IsValid()) {
        return;
      }
      OnConfigurationResponse(configuration_response_view.GetIdentifier(), configuration_response_view.GetSourceCid(),
                              configuration_response_view.GetContinuation(), configuration_response_view.GetResult(),
                              configuration_response_view.GetConfig());
    }
    case CommandCode::DISCONNECTION_REQUEST: {
      DisconnectionRequestView disconnection_request_view = DisconnectionRequestView::Create(control_packet_view);
      if (!disconnection_request_view.IsValid()) {
        return;
      }
      OnDisconnectionRequest(disconnection_request_view.GetIdentifier(), disconnection_request_view.GetDestinationCid(),
                             disconnection_request_view.GetSourceCid());
      return;
    }
    case CommandCode::DISCONNECTION_RESPONSE: {
      DisconnectionResponseView disconnection_response_view = DisconnectionResponseView::Create(control_packet_view);
      if (!disconnection_response_view.IsValid()) {
        return;
      }
      OnDisconnectionResponse(disconnection_response_view.GetIdentifier(),
                              disconnection_response_view.GetDestinationCid(),
                              disconnection_response_view.GetSourceCid());
      return;
    }
    case CommandCode::ECHO_REQUEST: {
      EchoRequestView echo_request_view = EchoRequestView::Create(control_packet_view);
      if (!echo_request_view.IsValid()) {
        return;
      }
      OnEchoRequest(echo_request_view.GetIdentifier(), echo_request_view.GetPayload());
      return;
    }
    case CommandCode::ECHO_RESPONSE: {
      EchoResponseView echo_response_view = EchoResponseView::Create(control_packet_view);
      if (!echo_response_view.IsValid()) {
        return;
      }
      OnEchoResponse(echo_response_view.GetIdentifier(), echo_response_view.GetPayload());
      return;
    }
    case CommandCode::INFORMATION_REQUEST: {
      InformationRequestView information_request_view = InformationRequestView::Create(control_packet_view);
      if (!information_request_view.IsValid()) {
        return;
      }
      OnInformationRequest(information_request_view.GetIdentifier(), information_request_view.GetInfoType());
      return;
    }
    case CommandCode::INFORMATION_RESPONSE: {
      InformationResponseView information_response_view = InformationResponseView::Create(control_packet_view);
      if (!information_response_view.IsValid()) {
        return;
      }
      OnInformationResponse(information_response_view.GetIdentifier(), information_response_view);
      return;
    }
    default:
      LOG_WARN("Unhandled event 0x%x", static_cast<int>(code));
      return;
  }
}

void ClassicSignallingManager::send_connection_response(SignalId signal_id, Cid remote_cid, Cid local_cid,
                                                        ConnectionResponseResult result,
                                                        ConnectionResponseStatus status) {
  auto builder = ConnectionResponseBuilder::Create(signal_id.Value(), remote_cid, local_cid, result, status);
  enqueue_buffer_->Enqueue(std::move(builder), handler_);
}

void ClassicSignallingManager::on_command_timeout() {
  LOG_WARN("Response time out");
  // TODO: drop the link?
}

void ClassicSignallingManager::handle_send_next_command() {
  if (pending_commands_.empty()) {
    return;
  }
  pending_command_ = pending_commands_.front();
  pending_commands_.pop();

  auto signal_id = pending_command_.signal_id_;
  auto psm = pending_command_.psm_;
  auto source_cid = pending_command_.source_cid_;
  auto destination_cid = pending_command_.destination_cid_;
  auto info_type = pending_command_.info_type_;
  switch (pending_command_.command_code_) {
    case CommandCode::CONNECTION_REQUEST: {
      auto builder = ConnectionRequestBuilder::Create(signal_id.Value(), psm, source_cid);
      enqueue_buffer_->Enqueue(std::move(builder), handler_);
      alarm_.Schedule(common::BindOnce(&ClassicSignallingManager::on_command_timeout, common::Unretained(this)),
                      kTimeout);
      break;
    }
    case CommandCode::CONFIGURATION_REQUEST:
      break;
    case CommandCode::DISCONNECTION_REQUEST: {
      auto builder = DisconnectionRequestBuilder::Create(signal_id.Value(), destination_cid, source_cid);
      enqueue_buffer_->Enqueue(std::move(builder), handler_);
      alarm_.Schedule(common::BindOnce(&ClassicSignallingManager::on_command_timeout, common::Unretained(this)),
                      kTimeout);
      break;
    }
    case CommandCode::INFORMATION_REQUEST: {
      auto builder = InformationRequestBuilder::Create(signal_id.Value(), info_type);
      enqueue_buffer_->Enqueue(std::move(builder), handler_);
      alarm_.Schedule(common::BindOnce(&ClassicSignallingManager::on_command_timeout, common::Unretained(this)),
                      kTimeout);
      break;
    }
    default:
      LOG_WARN("Unsupported command code 0x%x", static_cast<int>(pending_command_.command_code_));
  }
}

}  // namespace internal
}  // namespace classic
}  // namespace l2cap
}  // namespace bluetooth
