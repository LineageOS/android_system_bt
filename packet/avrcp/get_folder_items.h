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

#include "avrcp_browse_packet.h"

namespace bluetooth {
namespace avrcp {

class GetFolderItemsResponseBuilder : public BrowsePacketBuilder {
 public:
  virtual ~GetFolderItemsResponseBuilder() = default;
  static std::unique_ptr<GetFolderItemsResponseBuilder> MakePlayerListBuilder(
      Status status, uint16_t uid_counter);
  static std::unique_ptr<GetFolderItemsResponseBuilder> MakeVFSBuilder(
      Status status, uint16_t uid_counter);
  static std::unique_ptr<GetFolderItemsResponseBuilder> MakeNowPlayingBuilder(
      Status status, uint16_t uid_counter);

  virtual size_t size() const override;
  virtual bool Serialize(
      const std::shared_ptr<::bluetooth::Packet>& pkt) override;

  void AddMediaPlayer(MediaPlayerItem item);
  void AddSong(MediaElementItem item);
  void AddFolder(FolderItem item);

 protected:
  Scope scope_;
  std::vector<MediaListItem> items_;
  Status status_;
  uint16_t uid_counter_;

  GetFolderItemsResponseBuilder(Scope scope, Status status,
                                uint16_t uid_counter)
      : BrowsePacketBuilder(BrowsePdu::GET_FOLDER_ITEMS),
        scope_(scope),
        status_(status),
        uid_counter_(uid_counter){};

 private:
  void PushMediaListItem(const std::shared_ptr<::bluetooth::Packet>& pkt,
                         const MediaListItem& item);
  void PushMediaPlayerItem(const std::shared_ptr<::bluetooth::Packet>& pkt,
                           const MediaPlayerItem& item);
  void PushMediaElementItem(const std::shared_ptr<::bluetooth::Packet>& pkt,
                            const MediaElementItem& item);
  void PushFolderItem(const std::shared_ptr<::bluetooth::Packet>& pkt,
                      const FolderItem& item);
};

class GetFolderItemsRequest : public BrowsePacket {
 public:
  virtual ~GetFolderItemsRequest() = default;

  /**
   * Avrcp Change Path Packet Layout
   *   BrowsePacket:
   *     uint8_t pdu_;
   *     uint16_t length_;
   *   GetFolderItemsRequest:
   *     uint8_t scope_;
   *     uint32_t start_item_;
   *     uint32_t end_item_;
   *     uint8_t attr_count_;
   *     uint32_t[] attr_requested_;
   */
  static constexpr size_t kMinSize() { return BrowsePacket::kMinSize() + 10; }

  Scope GetScope() const;
  uint32_t GetStartItem() const;
  uint32_t GetEndItem() const;
  uint8_t GetNumAttributes() const;
  std::vector<Attribute> GetAttributesRequested() const;

  virtual bool IsValid() const override;
  virtual std::string ToString() const override;

 protected:
  using BrowsePacket::BrowsePacket;
};

}  // namespace avrcp
}  // namespace bluetooth