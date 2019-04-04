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

#include "packet/parser/test/test_packets.h"

#include <gtest/gtest.h>
#include <forward_list>
#include <memory>

#include "os/log.h"
#include "packet/bit_inserter.h"
#include "packet/raw_builder.h"

using bluetooth::packet::BitInserter;
using bluetooth::packet::kLittleEndian;
using bluetooth::packet::RawBuilder;
using std::vector;

namespace {
vector<uint8_t> child_two_two_three = {
    0x20 /* Reserved : 4, FourBits::TWO */,
    0x03 /* FourBits::THREE, Reserved : 4 */,
};
vector<uint8_t> child = {
    0x12 /* fixed */,
    0x02 /* Size of the payload */,
    0xa1 /* First byte of the payload */,
    0xa2,
    0xb1 /* footer */,
    0xc1 /* First byte of the FCS */,
    0xc2,
};

}  // namespace

namespace bluetooth {
namespace packet {
namespace parser {

TEST(GeneratedPacketTest, testChildTwoTwoThree) {
  auto packet = ChildTwoTwoThreeBuilder::Create();

  ASSERT_EQ(child_two_two_three.size(), packet->size());

  std::shared_ptr<std::vector<uint8_t>> packet_bytes = std::make_shared<std::vector<uint8_t>>();
  BitInserter it(*packet_bytes);
  packet->Serialize(it);

  ASSERT_EQ(packet_bytes->size(), child_two_two_three.size());
  for (size_t i = 0; i < child_two_two_three.size(); i++) {
    ASSERT_EQ(packet_bytes->at(i), child_two_two_three[i]);
  }

  PacketView<kLittleEndian> packet_bytes_view(packet_bytes);
  ParentView wrong_view(packet_bytes_view);
  ASSERT_FALSE(wrong_view.IsValid());

  ParentTwoView parent_view(packet_bytes_view);
  ASSERT_TRUE(parent_view.IsValid());
  ASSERT_EQ(FourBits::TWO, parent_view.GetFourBits());

  ChildTwoTwoView child_view(packet_bytes_view);
  ASSERT_TRUE(child_view.IsValid());
  ASSERT_EQ(FourBits::THREE, child_view.GetMoreBits());

  ChildTwoTwoThreeView grandchild_view(packet_bytes_view);
  ASSERT_TRUE(grandchild_view.IsValid());
}

TEST(GeneratedPacketTest, testChild) {
  auto packet = ChildBuilder::Create(0xa2a1 /* field_name */, 0xb1 /* footer */, 0xc2c1 /* fcs */);

  ASSERT_EQ(child.size(), packet->size());

  std::shared_ptr<std::vector<uint8_t>> packet_bytes = std::make_shared<std::vector<uint8_t>>();
  BitInserter it(*packet_bytes);
  packet->Serialize(it);

  ASSERT_EQ(packet_bytes->size(), child.size());
  for (size_t i = 0; i < child.size(); i++) {
    ASSERT_EQ(packet_bytes->at(i), child[i]);
  }

  PacketView<kLittleEndian> packet_bytes_view(packet_bytes);
  ParentView parent_view(packet_bytes_view);
  ASSERT_TRUE(parent_view.IsValid());
  auto payload = parent_view.GetPayload();

  ASSERT_EQ(child[1 /* skip fixed field */], payload.size());
  for (size_t i = 0; i < payload.size(); i++) {
    ASSERT_EQ(child[i + 2 /* fixed & size */], payload[i]);
  }

  ChildView child_view(packet_bytes_view);
  ASSERT_TRUE(child_view.IsValid());

  ASSERT_EQ(0xa2a1, child_view.GetFieldName());
}

}  // namespace parser
}  // namespace packet
}  // namespace bluetooth
