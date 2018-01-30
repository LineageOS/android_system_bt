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

#pragma once

#include <base/sys_byteorder.h>

// This file contains the different AVRCP Constants
namespace bluetooth {
namespace avrcp {

constexpr uint32_t BLUETOOTH_COMPANY_ID = 0x001958;

enum class CType : uint8_t {
  CONTROL = 0x0,
  STATUS = 0x1,
  NOTIFY = 0x3,
  ACCEPTED = 0x9,
  REJECTED = 0xa,
  STABLE = 0xc,
  CHANGED = 0xd,
  INTERIM = 0xf,
};

enum class Opcode : uint8_t {
  VENDOR = 0x00,
  UNIT_INFO = 0x30,
  SUBUNIT_INFO = 0x31,
  PASS_THROUGH = 0x7c,
};

// Found in AVRCP_v1.6.1 Section 4.5 Table 4.5
// Searching can be done in the spec by Camel Casing the constant name
enum class CommandPdu : uint8_t {
  GET_CAPABILITIES = 0x10,
  LIST_APPLICATION_SETTING_ATTRIBUTES = 0x11,
  GET_ELEMENT_ATTRIBUTES = 0x20,
  GET_PLAY_STATUS = 0x30,
  REGISTER_NOTIFICATION = 0x31,
};

enum class PacketType : uint8_t {
  SINGLE = 0x00,
};

enum class Capability : uint8_t {
  COMPANY_ID = 0x02,
  EVENTS_SUPPORTED = 0x03,
};

// Found in AVRCP_v1.6.1 Section 28 Appendix H
enum class Event : uint8_t {
  PLAYBACK_STATUS_CHANGED = 0x01,
  TRACK_CHANGED = 0x02,
  PLAYBACK_POS_CHANGED = 0x05,
  PLAYER_APPLICATION_SETTING_CHANGED = 0x08,
  NOW_PLAYING_CONTENT_CHANGED = 0x09,
  AVAILABLE_PLAYERS_CHANGED = 0x0a,
  ADDRESSED_PLAYER_CHANGED = 0x0b,
  UIDS_CHANGED = 0x0c,
  VOLUME_CHANGED = 0x0d,
};

enum class Attribute : uint32_t {
  TITLE = 0x01,
  ARTIST_NAME,
  ALBUM_NAME,
  TRACK_NUMBER,
  TOTAL_NUMBER_OF_TRACKS,
  GENRE,
  PLAYING_TIME,
  DEFAULT_COVER_ART,
};

enum class Status : uint8_t {
  INVALID_COMMAND = 0x00,
  INVALID_PARAMETER,
  PARAMETER_CONTENT_ERROR,
  INTERNAL_ERROR,
  NO_ERROR,
  UIDS_CHANGED,
  RESERVED,
  INVALID_DIRECTION,
  NOT_A_DIRECTORY,
  DOES_NOT_EXIST,
  INVALID_SCOPE,
  RANGE_OUT_OF_BOUNDS,
  FOLDER_ITEM_NOT_PLAYABLE,
  MEDIA_IN_USE,
  NOW_PLAYING_LIST_FULL,
  SEARCH_NOT_SUPPORTED,
  SEARCH_IN_PROGRESS,
  INVALID_PLAYER_ID,
  PLAYER_NOT_BROWSABLE,
  PLAYER_NOT_ADDRESSED,
  NO_VALID_SEARCH_RESULTS,
  NO_AVAILABLE_PLAYERS,
  ADDRESSED_PLAYER_CHANGED,
};

using AttributeEntry = std::pair<Attribute, std::string>;

}  // namespace avrcp
}  // namespace bluetooth