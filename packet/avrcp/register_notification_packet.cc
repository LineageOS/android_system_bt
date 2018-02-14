/*
 * Copyright 2018 The Android Open Source Project
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

#include <base/logging.h>

#include "register_notification_packet.h"

namespace bluetooth {
namespace avrcp {

std::unique_ptr<RegisterNotificationResponseBuilder>
RegisterNotificationResponseBuilder::MakePlaybackStatusBuilder(
    bool interim, uint8_t play_status) {
  std::unique_ptr<RegisterNotificationResponseBuilder> builder(
      new RegisterNotificationResponseBuilder(interim,
                                              Event::PLAYBACK_STATUS_CHANGED));

  builder->data_ = play_status;
  return builder;
}

std::unique_ptr<RegisterNotificationResponseBuilder>
RegisterNotificationResponseBuilder::MakeTrackChangedBuilder(
    bool interim, uint64_t track_uid) {
  std::unique_ptr<RegisterNotificationResponseBuilder> builder(
      new RegisterNotificationResponseBuilder(interim, Event::TRACK_CHANGED));

  builder->data_ = track_uid;
  return builder;
}

std::unique_ptr<RegisterNotificationResponseBuilder>
RegisterNotificationResponseBuilder::MakePlaybackPositionBuilder(
    bool interim, uint32_t playback_pos) {
  std::unique_ptr<RegisterNotificationResponseBuilder> builder(
      new RegisterNotificationResponseBuilder(interim,
                                              Event::PLAYBACK_POS_CHANGED));

  builder->data_ = playback_pos;
  return builder;
}

std::unique_ptr<RegisterNotificationResponseBuilder>
RegisterNotificationResponseBuilder::MakeNowPlayingBuilder(bool interim) {
  std::unique_ptr<RegisterNotificationResponseBuilder> builder(
      new RegisterNotificationResponseBuilder(
          interim, Event::NOW_PLAYING_CONTENT_CHANGED));
  return builder;
}

std::unique_ptr<RegisterNotificationResponseBuilder>
RegisterNotificationResponseBuilder::MakeAvailablePlayersBuilder(bool interim) {
  std::unique_ptr<RegisterNotificationResponseBuilder> builder(
      new RegisterNotificationResponseBuilder(
          interim, Event::AVAILABLE_PLAYERS_CHANGED));
  return builder;
}

std::unique_ptr<RegisterNotificationResponseBuilder>
RegisterNotificationResponseBuilder::MakeAddressedPlayerBuilder(
    bool interim, uint16_t player_id, uint16_t uid_counter) {
  std::unique_ptr<RegisterNotificationResponseBuilder> builder(
      new RegisterNotificationResponseBuilder(interim,
                                              Event::ADDRESSED_PLAYER_CHANGED));

  LOG(ERROR) << loghex(player_id);
  builder->data_ = ((uint32_t)player_id) << 16;
  LOG(ERROR) << loghex(builder->data_);
  builder->data_ |= uid_counter;
  LOG(ERROR) << loghex(builder->data_);

  return builder;
}

std::unique_ptr<RegisterNotificationResponseBuilder>
RegisterNotificationResponseBuilder::MakeUidsChangedBuilder(
    bool interim, uint16_t uid_counter) {
  std::unique_ptr<RegisterNotificationResponseBuilder> builder(
      new RegisterNotificationResponseBuilder(interim, Event::UIDS_CHANGED));

  builder->data_ = uid_counter;
  return builder;
}

size_t RegisterNotificationResponseBuilder::size() const {
  size_t data_size = 0;
  if (event_ == Event::PLAYBACK_STATUS_CHANGED)
    data_size = 1;
  else if (event_ == Event::TRACK_CHANGED)
    data_size = 8;
  else if (event_ == Event::PLAYBACK_POS_CHANGED)
    data_size = 4;

  return VendorPacket::kMinSize() + 1 + data_size;
}

bool RegisterNotificationResponseBuilder::Serialize(
    const std::shared_ptr<::bluetooth::Packet>& pkt) {
  ReserveSpace(pkt, size());

  PacketBuilder::PushHeader(pkt);

  size_t data_size = 0;
  if (event_ == Event::PLAYBACK_STATUS_CHANGED)
    data_size = 1;
  else if (event_ == Event::TRACK_CHANGED)
    data_size = 8;
  else if (event_ == Event::PLAYBACK_POS_CHANGED)
    data_size = 4;

  VendorPacketBuilder::PushHeader(pkt, 1 + data_size);

  AddPayloadOctets1(pkt, static_cast<uint8_t>(event_));
  if (event_ == Event::PLAYBACK_STATUS_CHANGED) {
    uint8_t playback_status = data_ & 0xFF;
    AddPayloadOctets1(pkt, playback_status);
  } else if (event_ == Event::TRACK_CHANGED) {
    AddPayloadOctets8(pkt, base::ByteSwap(data_));
  } else if (event_ == Event::PLAYBACK_POS_CHANGED) {
    uint32_t playback_pos = data_ & 0xFFFFFFFF;
    AddPayloadOctets4(pkt, base::ByteSwap(playback_pos));
  } else if (event_ == Event::ADDRESSED_PLAYER_CHANGED) {
    uint16_t uid_counter = data_ & 0xFFFF;
    uint16_t player_id = (data_ >> 16) & 0xFFFF;
    AddPayloadOctets2(pkt, base::ByteSwap(player_id));
    AddPayloadOctets2(pkt, base::ByteSwap(uid_counter));
  } else if (event_ == Event::UIDS_CHANGED) {
    uint16_t uid_counter = data_ & 0xFFFF;
    AddPayloadOctets2(pkt, base::ByteSwap(uid_counter));
  }

  return true;
}

Event RegisterNotificationRequest::GetEventRegistered() const {
  auto value = *(begin() + VendorPacket::kMinSize());
  return static_cast<Event>(value);
}

uint32_t RegisterNotificationRequest::GetInterval() const {
  auto it = begin() + VendorPacket::kMinSize() + static_cast<size_t>(1);
  return base::ByteSwap(it.extract<uint32_t>());
}

bool RegisterNotificationRequest::IsValid() const {
  return (size() == kMinSize());
}

std::string RegisterNotificationRequest::ToString() const {
  std::stringstream ss;
  ss << "RegisterNotificationPacket: " << std::endl;
  ss << "  └ cType = " << GetCType() << std::endl;
  ss << "  └ Subunit Type = " << loghex(GetSubunitType()) << std::endl;
  ss << "  └ Subunit ID = " << loghex(GetSubunitId()) << std::endl;
  ss << "  └ OpCode = " << GetOpcode() << std::endl;
  ss << "  └ Company ID = " << loghex(GetCompanyId()) << std::endl;
  ss << "  └ Command PDU = " << GetCommandPdu() << std::endl;
  ss << "  └ PacketType = " << GetPacketType() << std::endl;
  ss << "  └ Parameter Length = " << loghex(GetParameterLength()) << std::endl;
  ss << "  └ Event Registered = " << GetEventRegistered() << std::endl;
  ss << "  └ Interval = " << loghex(GetInterval()) << std::endl;
  ss << std::endl;

  return ss.str();
}

}  // namespace avrcp
}  // namespace bluetooth