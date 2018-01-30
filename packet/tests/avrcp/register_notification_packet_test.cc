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

#include <gtest/gtest.h>

#include "avrcp_test_packets.h"
#include "packet_test_helper.h"
#include "register_notification_packet.h"

namespace bluetooth {
namespace avrcp {

using TestRegNotifReqPacket = TestPacketType<RegisterNotificationRequest>;

TEST(RegisterNotificationRequestTest, getterTest) {
  auto test_packet =
      TestRegNotifReqPacket::Make(register_play_status_notification);

  ASSERT_EQ(test_packet->GetEventRegistered(), Event::PLAYBACK_STATUS_CHANGED);
  ASSERT_EQ(test_packet->GetInterval(), 5u);
}

TEST(RegisterNotificationRequestTest, validTest) {
  auto test_packet =
      TestRegNotifReqPacket::Make(register_play_status_notification);
  ASSERT_TRUE(test_packet->IsValid());
}

TEST(RegisterNotificationRequestTest, invalidTest) {
  std::vector<uint8_t> packet_copy = register_play_status_notification;
  packet_copy.push_back(0x00);
  auto test_packet = TestRegNotifReqPacket::Make(packet_copy);
  ASSERT_FALSE(test_packet->IsValid());

  std::vector<uint8_t> short_packet = {0, 1, 2, 3, 4};
  test_packet = TestRegNotifReqPacket::Make(short_packet);
  ASSERT_FALSE(test_packet->IsValid());
}

TEST(RegisterNotificationResponseTest, playStatusBuilderTest) {
  auto builder = RegisterNotificationResponseBuilder::MakePlaybackStatusBuilder(
      true, 0x00);
  ASSERT_EQ(builder->size(), interim_play_status_notification.size());
  auto test_packet = TestRegNotifReqPacket::Make();
  builder->Serialize(test_packet);
  ASSERT_EQ(test_packet->GetData(), interim_play_status_notification);
}

TEST(RegisterNotificationResponseTest, trackChangedBuilderTest) {
  auto builder = RegisterNotificationResponseBuilder::MakeTrackChangedBuilder(
      true, 0x0000000000000000);
  ASSERT_EQ(builder->size(), interim_track_changed_notification.size());
  auto test_packet = TestRegNotifReqPacket::Make();
  builder->Serialize(test_packet);
  ASSERT_EQ(test_packet->GetData(), interim_track_changed_notification);
}

TEST(RegisterNotificationResponseTest, playPositionBuilderTest) {
  auto builder =
      RegisterNotificationResponseBuilder::MakePlaybackPositionBuilder(
          false, 0x00000000);
  ASSERT_EQ(builder->size(), changed_play_pos_notification.size());
  auto test_packet = TestRegNotifReqPacket::Make();
  builder->Serialize(test_packet);
  ASSERT_EQ(test_packet->GetData(), changed_play_pos_notification);
}

}  // namespace avrcp
}  // namespace bluetooth