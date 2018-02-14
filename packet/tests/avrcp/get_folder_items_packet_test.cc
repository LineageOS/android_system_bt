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

#include <gtest/gtest.h>

#include "avrcp_test_packets.h"
#include "get_folder_items.h"
#include "packet_test_helper.h"

namespace bluetooth {
namespace avrcp {

using TestGetFolderItemsReqPacket = TestPacketType<GetFolderItemsRequest>;

TEST(GetFolderItemsResponseBuilderTest, builderMediaPlayerSizeTest) {
  auto builder = GetFolderItemsResponseBuilder::MakePlayerListBuilder(
      Status::NO_ERROR, 0x0000);
  // If there are no items, then the only data in the packet is the status
  ASSERT_EQ(builder->size(), get_folder_items_error_response.size());

  auto player = MediaPlayerItem(0x0001, "com.google.android.music", true);
  builder->AddMediaPlayer(player);
  ASSERT_EQ(builder->size(), get_folder_items_media_player_response.size());
}

TEST(GetFolderItemsResponseBuilderTest, builderMediaPlayerAddTest) {
  auto builder = GetFolderItemsResponseBuilder::MakePlayerListBuilder(
      Status::NO_ERROR, 0x0000);
  auto player = MediaPlayerItem(0x0001, "com.google.android.music", true);
  builder->AddMediaPlayer(player);

  auto test_packet = TestGetFolderItemsReqPacket::Make();
  builder->Serialize(test_packet);
  ASSERT_EQ(test_packet->GetData(), get_folder_items_media_player_response);
}

TEST(GetFolderItemsResponseBuilderTest, builderFolderSizeTest) {
  auto builder =
      GetFolderItemsResponseBuilder::MakeVFSBuilder(Status::NO_ERROR, 0x0000);
  ASSERT_EQ(builder->size(), get_folder_items_error_response.size());

  auto folder = FolderItem(0x0000000000000001, 0x00, true, "Test Folder");
  builder->AddFolder(folder);
  ASSERT_EQ(builder->size(), get_folder_items_folder_response.size());
}

TEST(GetFolderItemsResponseBuilderTest, builderFolderAddTest) {
  auto builder =
      GetFolderItemsResponseBuilder::MakeVFSBuilder(Status::NO_ERROR, 0x0000);
  auto folder = FolderItem(0x0000000000000001, 0x00, true, "Test Folder");
  builder->AddFolder(folder);

  auto test_packet = TestGetFolderItemsReqPacket::Make();
  builder->Serialize(test_packet);
  ASSERT_EQ(test_packet->GetData(), get_folder_items_folder_response);
}

TEST(GetFolderItemsResponseBuilderTest, builderSongSizeTest) {
  auto builder = GetFolderItemsResponseBuilder::MakeNowPlayingBuilder(
      Status::NO_ERROR, 0x0000);
  ASSERT_EQ(builder->size(), get_folder_items_error_response.size());

  std::map<Attribute, std::string> attributes;
  attributes.insert(AttributeEntry(Attribute::TITLE, "Test Title"));
  auto song = MediaElementItem(0x02, "Test Title", attributes);
  builder->AddSong(song);
  ASSERT_EQ(builder->size(), get_folder_items_song_response.size());
}

TEST(GetFolderItemsResponseBuilderTest, builderSongAddTest) {
  auto builder = GetFolderItemsResponseBuilder::MakeNowPlayingBuilder(
      Status::NO_ERROR, 0x0000);
  std::map<Attribute, std::string> attributes;
  attributes.insert(AttributeEntry(Attribute::TITLE, "Test Title"));
  auto song = MediaElementItem(0x02, "Test Title", attributes);
  builder->AddSong(song);

  auto test_packet = TestGetFolderItemsReqPacket::Make();
  builder->Serialize(test_packet);
  ASSERT_EQ(test_packet->GetData(), get_folder_items_song_response);
}

TEST(GetFolderItemsResponseBuilderTest, builderNoItemsTest) {
  auto builder = GetFolderItemsResponseBuilder::MakePlayerListBuilder(
      Status::NO_ERROR, 0x0000);
  auto test_packet = TestGetFolderItemsReqPacket::Make();
  builder->Serialize(test_packet);
  ASSERT_EQ(test_packet->GetData(), get_folder_items_error_response);

  builder =
      GetFolderItemsResponseBuilder::MakeVFSBuilder(Status::NO_ERROR, 0x0000);
  test_packet = TestGetFolderItemsReqPacket::Make();
  builder->Serialize(test_packet);
  ASSERT_EQ(test_packet->GetData(), get_folder_items_error_response);

  builder = GetFolderItemsResponseBuilder::MakeNowPlayingBuilder(
      Status::NO_ERROR, 0x0000);
  test_packet = TestGetFolderItemsReqPacket::Make();
  builder->Serialize(test_packet);
  ASSERT_EQ(test_packet->GetData(), get_folder_items_error_response);
}

TEST(GetFolderItemsResponseBuilderTest, builderErrorStatusTest) {
  std::vector<uint8_t> get_folder_items_inv_scope = {0x71, 0x00, 0x01, 0x0a};

  auto builder = GetFolderItemsResponseBuilder::MakePlayerListBuilder(
      Status::INVALID_SCOPE, 0x0000);

  // Check that the status remains INVALID_SCOPE even though there are zero
  // items
  auto test_packet = TestGetFolderItemsReqPacket::Make();
  builder->Serialize(test_packet);
  ASSERT_EQ(test_packet->GetData(), get_folder_items_inv_scope);

  auto player = MediaPlayerItem(0x0001, "com.google.android.music", true);
  builder->AddMediaPlayer(player);

  // Check to make sure that even though we added an item, it doesn't get
  // written to the packet
  test_packet = TestGetFolderItemsReqPacket::Make();
  builder->Serialize(test_packet);
  ASSERT_EQ(test_packet->GetData(), get_folder_items_inv_scope);
}

TEST(GetFolderItemsResponseBuilderTest, builderDeathTest) {
  auto player = MediaPlayerItem(0x0001, "com.google.android.music", true);
  auto folder = FolderItem(0x01, 0x00, true, "test folder");
  auto song =
      MediaElementItem(0x01, "test song", std::map<Attribute, std::string>());

  auto builder = GetFolderItemsResponseBuilder::MakePlayerListBuilder(
      Status::NO_ERROR, 0x0000);
  ASSERT_DEATH(builder->AddFolder(folder), "scope_ == Scope::VFS");
  ASSERT_DEATH(builder->AddSong(song),
               "scope_ == Scope::VFS \\|\\| scope_ == Scope::NOW_PLAYING");

  builder =
      GetFolderItemsResponseBuilder::MakeVFSBuilder(Status::NO_ERROR, 0x0000);
  ASSERT_DEATH(builder->AddMediaPlayer(player),
               "scope_ == Scope::MEDIA_PLAYER_LIST");

  builder = GetFolderItemsResponseBuilder::MakeNowPlayingBuilder(
      Status::NO_ERROR, 0x0000);
  ASSERT_DEATH(builder->AddMediaPlayer(player),
               "scope_ == Scope::MEDIA_PLAYER_LIST");
  ASSERT_DEATH(builder->AddFolder(folder), "scope_ == Scope::VFS");
}

TEST(GetFolderItemsRequestTest, getterTest) {
  auto test_packet =
      TestGetFolderItemsReqPacket::Make(get_folder_items_request_vfs);

  ASSERT_EQ(test_packet->GetScope(), Scope::VFS);
  ASSERT_EQ(test_packet->GetStartItem(), 0x00000000u);
  ASSERT_EQ(test_packet->GetEndItem(), 0x00000005u);
  ASSERT_EQ(test_packet->GetNumAttributes(), 1);

  std::vector<Attribute> attribute_list = {Attribute::TITLE};
  ASSERT_EQ(test_packet->GetAttributesRequested(), attribute_list);
}

}  // namespace avrcp
}  // namespace bluetooth