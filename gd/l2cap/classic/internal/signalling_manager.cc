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
  if (pending_commands_.empty()) {
    LOG_WARN("Unexpected command reject: no pending request");
    return;
  }
  auto last_sent_command = std::move(pending_commands_.front());
  pending_commands_.pop();

  SignalId signal_id = command_reject_view.GetIdentifier();
  if (last_sent_command.signal_id_ != signal_id) {
    LOG_WARN("Unknown command reject");
    return;
  }
  handle_send_next_command();

  LOG_INFO("Command rejected");
}

void ClassicSignallingManager::SendConnectionRequest(Psm psm, Cid local_cid) {
  PendingCommand pending_command = {next_signal_id_, CommandCode::CONNECTION_REQUEST, psm, local_cid, {}, {}, {}};
  next_signal_id_++;
  pending_commands_.push(std::move(pending_command));
  if (pending_commands_.size() == 1) {
    handle_send_next_command();
  }
}

void ClassicSignallingManager::SendConfigurationRequest(Cid remote_cid,
                                                        std::vector<std::unique_ptr<ConfigurationOption>> config) {
  PendingCommand pending_command = {next_signal_id_,  CommandCode::CONFIGURATION_REQUEST, {}, {}, remote_cid, {},
                                    std::move(config)};
  next_signal_id_++;
  pending_commands_.push(std::move(pending_command));
  if (pending_commands_.size() == 1) {
    handle_send_next_command();
  }
}

void ClassicSignallingManager::SendDisconnectionRequest(Cid local_cid, Cid remote_cid) {
  PendingCommand pending_command = {
      next_signal_id_, CommandCode::DISCONNECTION_REQUEST, {}, local_cid, remote_cid, {}, {}};
  next_signal_id_++;
  pending_commands_.push(std::move(pending_command));
  if (pending_commands_.size() == 1) {
    handle_send_next_command();
  }
}

void ClassicSignallingManager::SendInformationRequest(InformationRequestInfoType type) {
  PendingCommand pending_command = {next_signal_id_, CommandCode::INFORMATION_REQUEST, {}, {}, {}, type, {}};
  next_signal_id_++;
  pending_commands_.push(std::move(pending_command));
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
  SendConfigurationRequest(remote_cid, {});
}

void ClassicSignallingManager::OnConnectionResponse(SignalId signal_id, Cid remote_cid, Cid cid,
                                                    ConnectionResponseResult result, ConnectionResponseStatus status) {
  if (pending_commands_.empty()) {
    LOG_WARN("Unexpected response: no pending request");
    return;
  }
  auto last_sent_command = std::move(pending_commands_.front());
  pending_commands_.pop();
  if (last_sent_command.signal_id_ != signal_id || last_sent_command.command_code_ != CommandCode::CONNECTION_REQUEST) {
    LOG_WARN("Received unexpected connection response");
    return;
  }
  if (last_sent_command.source_cid_ != cid) {
    LOG_WARN("SCID doesn't match: expected %d, received %d", last_sent_command.source_cid_, cid);
    handle_send_next_command();
    return;
  }
  if (result != ConnectionResponseResult::SUCCESS) {
    handle_send_next_command();
    return;
  }
  Psm pending_psm = last_sent_command.psm_;
  auto new_channel = link_->AllocateReservedDynamicChannel(cid, pending_psm, remote_cid, {});
  if (new_channel == nullptr) {
    LOG_WARN("Can't allocate dynamic channel");
    handle_send_next_command();
    return;
  }
  alarm_.Cancel();
  SendConfigurationRequest(remote_cid, {});
  handle_send_next_command();
}

void ClassicSignallingManager::OnConfigurationRequest(SignalId signal_id, Cid cid, Continuation is_continuation,
                                                      std::vector<std::unique_ptr<ConfigurationOption>> option) {
  auto channel = channel_allocator_->FindChannelByCid(cid);
  if (channel == nullptr) {
    LOG_WARN("Configuration request for an unknown channel");
    return;
  }
  auto response = ConfigurationResponseBuilder::Create(signal_id.Value(), channel->GetRemoteCid(), is_continuation,
                                                       ConfigurationResponseResult::SUCCESS, {});
  enqueue_buffer_->Enqueue(std::move(response), handler_);
  handle_send_next_command();
  channel->SetIncomingConfigurationStatus(DynamicChannelImpl::ConfigurationStatus::CONFIGURED);
  if (channel->GetOutgoingConfigurationStatus() == DynamicChannelImpl::ConfigurationStatus::CONFIGURED) {
    std::unique_ptr<DynamicChannel> user_channel = std::make_unique<DynamicChannel>(channel, handler_);
    dynamic_service_manager_->GetService(channel->GetPsm())->NotifyChannelCreation(std::move(user_channel));
  }
}

void ClassicSignallingManager::OnConfigurationResponse(SignalId signal_id, Cid cid, Continuation is_continuation,
                                                       ConfigurationResponseResult result,
                                                       std::vector<std::unique_ptr<ConfigurationOption>> option) {
  if (pending_commands_.empty()) {
    LOG_WARN("Unexpected response: no pending request");
    return;
  }

  auto last_sent_command = std::move(pending_commands_.front());
  pending_commands_.pop();

  auto channel = channel_allocator_->FindChannelByCid(cid);
  if (channel == nullptr) {
    LOG_WARN("Configuration request for an unknown channel");
    handle_send_next_command();
    return;
  }
  channel->SetOutgoingConfigurationStatus(DynamicChannelImpl::ConfigurationStatus::CONFIGURED);
  if (channel->GetIncomingConfigurationStatus() == DynamicChannelImpl::ConfigurationStatus::CONFIGURED) {
    std::unique_ptr<DynamicChannel> user_channel = std::make_unique<DynamicChannel>(channel, handler_);
    dynamic_service_manager_->GetService(channel->GetPsm())->NotifyChannelCreation(std::move(user_channel));
  }
  alarm_.Cancel();
  handle_send_next_command();
}

void ClassicSignallingManager::OnDisconnectionRequest(SignalId signal_id, Cid cid, Cid remote_cid) {
  // TODO: check cid match
  auto channel = channel_allocator_->FindChannelByCid(cid);
  if (channel == nullptr) {
    LOG_WARN("Disconnect request for an unknown channel");
    return;
  }
  auto builder = DisconnectionResponseBuilder::Create(signal_id.Value(), cid, remote_cid);
  enqueue_buffer_->Enqueue(std::move(builder), handler_);
  channel->OnClosed(hci::ErrorCode::SUCCESS);
  link_->FreeDynamicChannel(cid);
  handle_send_next_command();
}

void ClassicSignallingManager::OnDisconnectionResponse(SignalId signal_id, Cid remote_cid, Cid cid) {
  if (pending_commands_.empty()) {
    LOG_WARN("Unexpected response: no pending request");
    return;
  }
  auto last_sent_command = std::move(pending_commands_.front());
  pending_commands_.pop();
  alarm_.Cancel();

  if (last_sent_command.signal_id_ != signal_id ||
      last_sent_command.command_code_ != CommandCode::DISCONNECTION_REQUEST) {
    return;
  }

  auto channel = channel_allocator_->FindChannelByCid(cid);
  if (channel == nullptr) {
    LOG_WARN("Disconnect response for an unknown channel");
    handle_send_next_command();
    return;
  }

  channel->OnClosed(hci::ErrorCode::SUCCESS);
  link_->FreeDynamicChannel(cid);
  handle_send_next_command();
}

void ClassicSignallingManager::OnEchoRequest(SignalId signal_id, const PacketView<kLittleEndian>& packet) {
  std::vector<uint8_t> packet_vector{packet.begin(), packet.end()};
  auto raw_builder = std::make_unique<packet::RawBuilder>();
  raw_builder->AddOctets(packet_vector);
  auto builder = EchoResponseBuilder::Create(signal_id.Value(), std::move(raw_builder));
  enqueue_buffer_->Enqueue(std::move(builder), handler_);
  handle_send_next_command();
}

void ClassicSignallingManager::OnEchoResponse(SignalId signal_id, const PacketView<kLittleEndian>& packet) {
  if (pending_commands_.empty()) {
    LOG_WARN("Unexpected response: no pending request");
    return;
  }
  auto last_sent_command = std::move(pending_commands_.front());
  pending_commands_.pop();

  if (last_sent_command.signal_id_ != signal_id || last_sent_command.command_code_ != CommandCode::ECHO_REQUEST) {
    return;
  }
  LOG_INFO("Echo response received");
  alarm_.Cancel();
  handle_send_next_command();
}

void ClassicSignallingManager::OnInformationRequest(SignalId signal_id, InformationRequestInfoType type) {
  switch (type) {
    case InformationRequestInfoType::CONNECTIONLESS_MTU: {
      auto response = InformationResponseConnectionlessMtuBuilder::Create(signal_id.Value(),
                                                                          InformationRequestResult::NOT_SUPPORTED, 0);
      enqueue_buffer_->Enqueue(std::move(response), handler_);
      break;
    }
    case InformationRequestInfoType::EXTENDED_FEATURES_SUPPORTED: {
      // TODO: implement this response
      auto response = InformationResponseExtendedFeaturesBuilder::Create(
          signal_id.Value(), InformationRequestResult::NOT_SUPPORTED, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
      enqueue_buffer_->Enqueue(std::move(response), handler_);
      break;
    }
    case InformationRequestInfoType::FIXED_CHANNELS_SUPPORTED: {
      auto response = InformationResponseFixedChannelsBuilder::Create(
          signal_id.Value(), InformationRequestResult::SUCCESS, fixed_service_manager_->GetSupportedFixedChannelMask());
      enqueue_buffer_->Enqueue(std::move(response), handler_);
      break;
    }
  }
}

void ClassicSignallingManager::OnInformationResponse(SignalId signal_id, const InformationResponseView& view) {
  if (pending_commands_.empty()) {
    LOG_WARN("Unexpected response: no pending request");
    return;
  }
  auto last_sent_command = std::move(pending_commands_.front());
  pending_commands_.pop();

  if (last_sent_command.signal_id_ != signal_id ||
      last_sent_command.command_code_ != CommandCode::INFORMATION_REQUEST) {
    return;
  }
  // TODO (hsz): Store the information response
  alarm_.Cancel();
  handle_send_next_command();
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
      return;
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
      auto builder = CommandRejectNotUnderstoodBuilder::Create(control_packet_view.GetIdentifier());
      enqueue_buffer_->Enqueue(std::move(builder), handler_);
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
  link_->OnAclDisconnected(hci::ErrorCode::SUCCESS);
}

void ClassicSignallingManager::handle_send_next_command() {
  if (pending_commands_.empty()) {
    return;
  }
  auto& last_sent_command = pending_commands_.front();

  auto signal_id = last_sent_command.signal_id_;
  auto psm = last_sent_command.psm_;
  auto source_cid = last_sent_command.source_cid_;
  auto destination_cid = last_sent_command.destination_cid_;
  auto info_type = last_sent_command.info_type_;
  auto config = std::move(last_sent_command.config_);
  switch (last_sent_command.command_code_) {
    case CommandCode::CONNECTION_REQUEST: {
      auto builder = ConnectionRequestBuilder::Create(signal_id.Value(), psm, source_cid);
      enqueue_buffer_->Enqueue(std::move(builder), handler_);
      alarm_.Schedule(common::BindOnce(&ClassicSignallingManager::on_command_timeout, common::Unretained(this)),
                      kTimeout);
      break;
    }
    case CommandCode::CONFIGURATION_REQUEST: {
      auto builder =
          ConfigurationRequestBuilder::Create(signal_id.Value(), destination_cid, Continuation::END, std::move(config));
      enqueue_buffer_->Enqueue(std::move(builder), handler_);
      alarm_.Schedule(common::BindOnce(&ClassicSignallingManager::on_command_timeout, common::Unretained(this)),
                      kTimeout);
      break;
    }
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
      LOG_WARN("Unsupported command code 0x%x", static_cast<int>(last_sent_command.command_code_));
  }
}

}  // namespace internal
}  // namespace classic
}  // namespace l2cap
}  // namespace bluetooth
