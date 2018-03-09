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

#include <algorithm>
#include <iostream>

#include <base/bind.h>
#include <base/logging.h>
#include <base/threading/thread.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "avrcp_packet.h"
#include "avrcp_test_helper.h"
#include "device.h"
#include "tests/avrcp/avrcp_test_packets.h"
#include "tests/packet_test_helper.h"

namespace bluetooth {
namespace avrcp {

// TODO (apanicke): All the tests below are just basic positive unit tests.
// Add more tests to increase code coverage.

using AvrcpResponse = std::unique_ptr<::bluetooth::PacketBuilder>;
using TestAvrcpPacket = TestPacketType<Packet>;
using TestBrowsePacket = TestPacketType<BrowsePacket>;

using ::testing::_;
using ::testing::MockFunction;
using ::testing::Mock;
using ::testing::NiceMock;
using ::testing::Return;

// TODO (apanicke): All the tests below are just basic positive unit tests.
// Add more tests to increase code coverage.
class AvrcpDeviceTest : public ::testing::Test {
 public:
  virtual void SetUp() override {
    // NOTE: We use a wrapper lambda for the MockFunction in order to
    // add a const qualifier to the response. Otherwise the MockFunction
    // type doesn't match the callback type and a compiler error occurs.
    base::Callback<void(uint8_t, bool, AvrcpResponse)> cb = base::Bind(
        [](MockFunction<void(uint8_t, bool, const AvrcpResponse&)>* a,
           uint8_t b, bool c, AvrcpResponse d) { a->Call(b, c, d); },
        &response_cb);

    // TODO (apanicke): Test setting avrc13 to false once we have full
    // functionality.
    test_device = new Device(RawAddress::kAny, true, cb);
  }

  virtual void TearDown() override {
    delete test_device;
    Mock::VerifyAndClear(&response_cb);
  }

  void SendMessage(uint8_t label, std::shared_ptr<Packet> message) {
    test_device->MessageReceived(label, message);
  }

  void SendBrowseMessage(uint8_t label, std::shared_ptr<BrowsePacket> message) {
    test_device->BrowseMessageReceived(label, message);
  }

  MockFunction<void(uint8_t, bool, const AvrcpResponse&)> response_cb;
  Device* test_device;
};

TEST_F(AvrcpDeviceTest, addressTest) {
  base::Callback<void(uint8_t, bool, AvrcpResponse)> cb =
      base::Bind([](MockFunction<void(uint8_t, bool, const AvrcpResponse&)>* a,
                    uint8_t b, bool c, AvrcpResponse d) { a->Call(b, c, d); },
                 &response_cb);

  Device device(RawAddress::kAny, true, cb);
  ASSERT_EQ(device.GetAddress(), RawAddress::kAny);
}

TEST_F(AvrcpDeviceTest, trackChangedTest) {
  MockMediaInterface interface;
  NiceMock<MockA2dpInterface> a2dp_interface;

  test_device->RegisterInterfaces(&interface, &a2dp_interface, nullptr);

  SongInfo info = {"test_id",
                   {// The attribute map
                    AttributeEntry(Attribute::TITLE, "Test Song"),
                    AttributeEntry(Attribute::ARTIST_NAME, "Test Artist"),
                    AttributeEntry(Attribute::ALBUM_NAME, "Test Album"),
                    AttributeEntry(Attribute::TRACK_NUMBER, "1"),
                    AttributeEntry(Attribute::TOTAL_NUMBER_OF_TRACKS, "2"),
                    AttributeEntry(Attribute::GENRE, "Test Genre"),
                    AttributeEntry(Attribute::PLAYING_TIME, "1000")}};
  std::vector<SongInfo> list = {info};

  EXPECT_CALL(interface, GetNowPlayingList(_))
      .Times(2)
      .WillRepeatedly(InvokeCb<0>("test_id", list));

  // Test the interim response for track changed
  auto interim_response =
      RegisterNotificationResponseBuilder::MakeTrackChangedBuilder(true, 0x01);
  EXPECT_CALL(response_cb,
              Call(1, false, matchPacket(std::move(interim_response))))
      .Times(1);

  auto request =
      RegisterNotificationRequestBuilder::MakeBuilder(Event::TRACK_CHANGED, 0);
  auto pkt = TestAvrcpPacket::Make();
  request->Serialize(pkt);
  SendMessage(1, pkt);

  // Test the changed response for track changed
  auto changed_response =
      RegisterNotificationResponseBuilder::MakeTrackChangedBuilder(false, 0x01);
  EXPECT_CALL(response_cb,
              Call(1, false, matchPacket(std::move(changed_response))))
      .Times(1);

  test_device->HandleTrackUpdate();
}

TEST_F(AvrcpDeviceTest, playStatusTest) {
  MockMediaInterface interface;
  NiceMock<MockA2dpInterface> a2dp_interface;

  test_device->RegisterInterfaces(&interface, &a2dp_interface, nullptr);

  PlayStatus status1 = {0x1234, 0x5678, PlayState::PLAYING};
  PlayStatus status2 = {0x1234, 0x5678, PlayState::STOPPED};

  EXPECT_CALL(interface, GetPlayStatus(_))
      .Times(2)
      .WillOnce(InvokeCb<0>(status1))
      .WillOnce(InvokeCb<0>(status2));

  // Pretend the device is active
  EXPECT_CALL(a2dp_interface, active_peer())
      .WillRepeatedly(Return(test_device->GetAddress()));

  // Test the interim response for play status changed
  auto interim_response =
      RegisterNotificationResponseBuilder::MakePlaybackStatusBuilder(
          true, PlayState::PLAYING);
  EXPECT_CALL(response_cb,
              Call(1, false, matchPacket(std::move(interim_response))))
      .Times(1);

  auto request = RegisterNotificationRequestBuilder::MakeBuilder(
      Event::PLAYBACK_STATUS_CHANGED, 0);
  auto pkt = TestAvrcpPacket::Make();
  request->Serialize(pkt);
  SendMessage(1, pkt);

  // Test the changed response for play status changed
  auto changed_response =
      RegisterNotificationResponseBuilder::MakePlaybackStatusBuilder(
          false, PlayState::STOPPED);
  EXPECT_CALL(response_cb,
              Call(1, false, matchPacket(std::move(changed_response))))
      .Times(1);
  test_device->HandlePlayStatusUpdate();
}

TEST_F(AvrcpDeviceTest, playPositionTest) {
  MockMediaInterface interface;
  NiceMock<MockA2dpInterface> a2dp_interface;

  test_device->RegisterInterfaces(&interface, &a2dp_interface, nullptr);

  PlayStatus status1 = {0x1234, 0x5678, PlayState::PLAYING};
  PlayStatus status2 = {0x5678, 0x9ABC, PlayState::STOPPED};

  EXPECT_CALL(interface, GetPlayStatus(_))
      .Times(2)
      .WillOnce(InvokeCb<0>(status1))
      .WillOnce(InvokeCb<0>(status2));

  // Pretend the device is active
  EXPECT_CALL(a2dp_interface, active_peer())
      .WillRepeatedly(Return(test_device->GetAddress()));

  // Test the interim response for play status changed
  auto interim_response =
      RegisterNotificationResponseBuilder::MakePlaybackStatusBuilder(
          true, PlayState::PLAYING);
  EXPECT_CALL(response_cb,
              Call(1, false, matchPacket(std::move(interim_response))))
      .Times(1);

  auto request = RegisterNotificationRequestBuilder::MakeBuilder(
      Event::PLAYBACK_STATUS_CHANGED, 0);
  auto pkt = TestAvrcpPacket::Make();
  request->Serialize(pkt);
  SendMessage(1, pkt);

  // Test the changed response for play status changed
  auto changed_response =
      RegisterNotificationResponseBuilder::MakePlaybackStatusBuilder(
          false, PlayState::STOPPED);
  EXPECT_CALL(response_cb,
              Call(1, false, matchPacket(std::move(changed_response))))
      .Times(1);
  test_device->HandlePlayStatusUpdate();
}

TEST_F(AvrcpDeviceTest, nowPlayingTest) {
  MockMediaInterface interface;
  NiceMock<MockA2dpInterface> a2dp_interface;

  test_device->RegisterInterfaces(&interface, &a2dp_interface, nullptr);

  // Test the interim response for now playing list changed
  auto interim_response =
      RegisterNotificationResponseBuilder::MakeNowPlayingBuilder(true);
  EXPECT_CALL(response_cb,
              Call(1, false, matchPacket(std::move(interim_response))))
      .Times(1);

  auto request = RegisterNotificationRequestBuilder::MakeBuilder(
      Event::NOW_PLAYING_CONTENT_CHANGED, 0);
  auto pkt = TestAvrcpPacket::Make();
  request->Serialize(pkt);
  SendMessage(1, pkt);

  // Test the changed response for now playing list changed
  auto changed_response =
      RegisterNotificationResponseBuilder::MakeNowPlayingBuilder(false);
  EXPECT_CALL(response_cb,
              Call(1, false, matchPacket(std::move(changed_response))))
      .Times(1);
  test_device->HandleNowPlayingUpdate();
}

TEST_F(AvrcpDeviceTest, getPlayStatusTest) {
  MockMediaInterface interface;
  NiceMock<MockA2dpInterface> a2dp_interface;

  test_device->RegisterInterfaces(&interface, &a2dp_interface, nullptr);

  PlayStatus status = {0x1234, 0x5678, PlayState::PLAYING};

  EXPECT_CALL(interface, GetPlayStatus(_))
      .Times(1)
      .WillOnce(InvokeCb<0>(status));

  // Pretend the device is active
  EXPECT_CALL(a2dp_interface, active_peer())
      .WillRepeatedly(Return(test_device->GetAddress()));

  auto expected_response = GetPlayStatusResponseBuilder::MakeBuilder(
      0x5678, 0x1234, PlayState::PLAYING);
  EXPECT_CALL(response_cb,
              Call(1, false, matchPacket(std::move(expected_response))))
      .Times(1);

  auto request = TestAvrcpPacket::Make(get_play_status_request);
  SendMessage(1, request);
}

TEST_F(AvrcpDeviceTest, getElementAttributesTest) {
  MockMediaInterface interface;
  NiceMock<MockA2dpInterface> a2dp_interface;

  test_device->RegisterInterfaces(&interface, &a2dp_interface, nullptr);

  SongInfo info = {"test_id",
                   {// The attribute map
                    AttributeEntry(Attribute::TITLE, "Test Song"),
                    AttributeEntry(Attribute::ARTIST_NAME, "Test Artist"),
                    AttributeEntry(Attribute::ALBUM_NAME, "Test Album"),
                    AttributeEntry(Attribute::TRACK_NUMBER, "1"),
                    AttributeEntry(Attribute::TOTAL_NUMBER_OF_TRACKS, "2"),
                    AttributeEntry(Attribute::GENRE, "Test Genre"),
                    AttributeEntry(Attribute::PLAYING_TIME, "1000")}};

  EXPECT_CALL(interface, GetSongInfo(_)).WillRepeatedly(InvokeCb<0>(info));

  auto compare_to_partial = GetElementAttributesResponseBuilder::MakeBuilder();
  compare_to_partial->AddAttributeEntry(Attribute::TITLE, "Test Song");
  EXPECT_CALL(response_cb,
              Call(2, false, matchPacket(std::move(compare_to_partial))))
      .Times(1);
  SendMessage(2, TestAvrcpPacket::Make(get_element_attributes_request_partial));

  auto compare_to_full = GetElementAttributesResponseBuilder::MakeBuilder();
  compare_to_full->AddAttributeEntry(Attribute::TITLE, "Test Song")
      ->AddAttributeEntry(Attribute::ARTIST_NAME, "Test Artist")
      ->AddAttributeEntry(Attribute::ALBUM_NAME, "Test Album")
      ->AddAttributeEntry(Attribute::TRACK_NUMBER, "1")
      ->AddAttributeEntry(Attribute::TOTAL_NUMBER_OF_TRACKS, "2")
      ->AddAttributeEntry(Attribute::GENRE, "Test Genre")
      ->AddAttributeEntry(Attribute::PLAYING_TIME, "1000");
  EXPECT_CALL(response_cb,
              Call(3, false, matchPacket(std::move(compare_to_full))))
      .Times(1);
  SendMessage(3, TestAvrcpPacket::Make(get_element_attributes_request_full));
}

TEST_F(AvrcpDeviceTest, getMediaPlayerListTest) {
  MockMediaInterface interface;
  NiceMock<MockA2dpInterface> a2dp_interface;

  test_device->RegisterInterfaces(&interface, &a2dp_interface, nullptr);

  MediaPlayerInfo info = {0, "Test Player", true};
  std::vector<MediaPlayerInfo> list = {info};

  EXPECT_CALL(interface, GetMediaPlayerList(_))
      .Times(1)
      .WillOnce(InvokeCb<0>(0, list));

  auto expected_response = GetFolderItemsResponseBuilder::MakePlayerListBuilder(
      Status::NO_ERROR, 0x0000);
  expected_response->AddMediaPlayer(MediaPlayerItem(0, "Test Player", true));
  EXPECT_CALL(response_cb,
              Call(1, true, matchPacket(std::move(expected_response))))
      .Times(1);

  auto request = TestBrowsePacket::Make(get_folder_items_request);
  SendBrowseMessage(1, request);
}

TEST_F(AvrcpDeviceTest, getNowPlayingListTest) {
  MockMediaInterface interface;
  NiceMock<MockA2dpInterface> a2dp_interface;

  test_device->RegisterInterfaces(&interface, &a2dp_interface, nullptr);

  SongInfo info = {"test_id",
                   {// The attribute map
                    AttributeEntry(Attribute::TITLE, "Test Song"),
                    AttributeEntry(Attribute::ARTIST_NAME, "Test Artist"),
                    AttributeEntry(Attribute::ALBUM_NAME, "Test Album"),
                    AttributeEntry(Attribute::TRACK_NUMBER, "1"),
                    AttributeEntry(Attribute::TOTAL_NUMBER_OF_TRACKS, "2"),
                    AttributeEntry(Attribute::GENRE, "Test Genre"),
                    AttributeEntry(Attribute::PLAYING_TIME, "1000")}};
  std::vector<SongInfo> list = {info};

  EXPECT_CALL(interface, GetNowPlayingList(_))
      .WillRepeatedly(InvokeCb<0>("test_id", list));

  auto expected_response = GetFolderItemsResponseBuilder::MakeNowPlayingBuilder(
      Status::NO_ERROR, 0x0000);
  expected_response->AddSong(MediaElementItem(1, "Test Song", info.attributes));
  EXPECT_CALL(response_cb,
              Call(1, true, matchPacket(std::move(expected_response))))
      .Times(1);

  auto request = TestBrowsePacket::Make(get_folder_items_request_now_playing);
  SendBrowseMessage(1, request);
}

TEST_F(AvrcpDeviceTest, getVFSFolderTest) {
  MockMediaInterface interface;
  NiceMock<MockA2dpInterface> a2dp_interface;

  test_device->RegisterInterfaces(&interface, &a2dp_interface, nullptr);

  FolderInfo info = {"test_id", true, "Test Folder"};
  ListItem item = {ListItem::FOLDER, info, SongInfo()};
  std::vector<ListItem> list = {item};

  EXPECT_CALL(interface, GetFolderItems(_, "", _))
      .Times(1)
      .WillOnce(InvokeCb<2>(list));

  auto expected_response =
      GetFolderItemsResponseBuilder::MakeVFSBuilder(Status::NO_ERROR, 0x0000);
  expected_response->AddFolder(FolderItem(1, 0, true, "Test Folder"));
  EXPECT_CALL(response_cb,
              Call(1, true, matchPacket(std::move(expected_response))))
      .Times(1);

  auto request = TestBrowsePacket::Make(get_folder_items_request_vfs);
  SendBrowseMessage(1, request);
}

TEST_F(AvrcpDeviceTest, getItemAttributesNowPlayingTest) {
  MockMediaInterface interface;
  NiceMock<MockA2dpInterface> a2dp_interface;

  test_device->RegisterInterfaces(&interface, &a2dp_interface, nullptr);

  SongInfo info = {"test_id",
                   {// The attribute map
                    AttributeEntry(Attribute::TITLE, "Test Song"),
                    AttributeEntry(Attribute::ARTIST_NAME, "Test Artist"),
                    AttributeEntry(Attribute::ALBUM_NAME, "Test Album"),
                    AttributeEntry(Attribute::TRACK_NUMBER, "1"),
                    AttributeEntry(Attribute::TOTAL_NUMBER_OF_TRACKS, "2"),
                    AttributeEntry(Attribute::GENRE, "Test Genre"),
                    AttributeEntry(Attribute::PLAYING_TIME, "1000")}};
  std::vector<SongInfo> list = {info};

  EXPECT_CALL(interface, GetNowPlayingList(_))
      .WillRepeatedly(InvokeCb<0>("test_id", list));

  auto compare_to_full =
      GetItemAttributesResponseBuilder::MakeBuilder(Status::NO_ERROR);
  compare_to_full->AddAttributeEntry(Attribute::TITLE, "Test Song")
      ->AddAttributeEntry(Attribute::ARTIST_NAME, "Test Artist")
      ->AddAttributeEntry(Attribute::ALBUM_NAME, "Test Album")
      ->AddAttributeEntry(Attribute::TRACK_NUMBER, "1")
      ->AddAttributeEntry(Attribute::TOTAL_NUMBER_OF_TRACKS, "2")
      ->AddAttributeEntry(Attribute::GENRE, "Test Genre")
      ->AddAttributeEntry(Attribute::PLAYING_TIME, "1000");
  EXPECT_CALL(response_cb,
              Call(1, true, matchPacket(std::move(compare_to_full))))
      .Times(1);

  auto request =
      TestBrowsePacket::Make(get_item_attributes_request_all_attributes);
  SendBrowseMessage(1, request);
}

TEST_F(AvrcpDeviceTest, volumeChangedTest) {
  MockMediaInterface interface;
  NiceMock<MockA2dpInterface> a2dp_interface;
  MockVolumeInterface vol_interface;

  test_device->RegisterInterfaces(&interface, &a2dp_interface, &vol_interface);

  auto reg_notif =
      RegisterNotificationRequestBuilder::MakeBuilder(Event::VOLUME_CHANGED, 0);
  EXPECT_CALL(response_cb, Call(_, false, matchPacket(std::move(reg_notif))))
      .Times(1);
  test_device->RegisterVolumeChanged();

  EXPECT_CALL(vol_interface, DeviceConnected(test_device->GetAddress(), _))
      .Times(1)
      .WillOnce(InvokeCb<1>(0x30));
  auto set_vol = SetAbsoluteVolumeRequestBuilder::MakeBuilder(0x30);
  EXPECT_CALL(response_cb, Call(_, false, matchPacket(std::move(set_vol))))
      .Times(1);

  auto response = TestAvrcpPacket::Make(interim_volume_changed_notification);
  SendMessage(1, response);

  EXPECT_CALL(vol_interface, SetVolume(0x47)).Times(1);
  auto reg_notif2 =
      RegisterNotificationRequestBuilder::MakeBuilder(Event::VOLUME_CHANGED, 0);
  EXPECT_CALL(response_cb, Call(_, false, matchPacket(std::move(reg_notif2))))
      .Times(1);
  response = TestAvrcpPacket::Make(changed_volume_changed_notification);
  SendMessage(1, response);
  response = TestAvrcpPacket::Make(interim_volume_changed_notification);
  SendMessage(1, response);
}

}  // namespace avrcp
}  // namespace bluetooth