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

#include "common/address.h"
#include "os/log.h"
#include "packet/bit_inserter.h"
#include "packet/raw_builder.h"

using ::bluetooth::common::Address;
using ::bluetooth::packet::BitInserter;
using ::bluetooth::packet::kLittleEndian;
using ::bluetooth::packet::RawBuilder;
using std::vector;

namespace {
vector<uint8_t> child_two_two_three = {
    0x20 /* Reserved : 4, FourBits::TWO */,
    0x03 /* FourBits::THREE, Reserved : 4 */,
};
vector<uint8_t> child = {
    0x12 /* fixed */, 0x02 /* Size of the payload */, 0xa1 /* First byte of the payload */, 0xa2, 0xb1 /* footer */,
};
vector<uint8_t> child_with_address = {
    0x34 /* TwoBytes */,
    0x12,
    0xa6 /* First byte of the address */,
    0xa5,
    0xa4,
    0xa3,
    0xa2,
    0xa1,
    0xb6 /* Second address*/,
    0xb5,
    0xb4,
    0xb3,
    0xb2,
    0xb1,
};

}  // namespace

namespace bluetooth {
namespace packet {
namespace parser {
using namespace test;

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
  ParentView wrong_view = ParentView::Create(packet_bytes_view);
  ASSERT_FALSE(wrong_view.IsValid());

  ParentTwoView parent_view = ParentTwoView::Create(packet_bytes_view);
  ASSERT_TRUE(parent_view.IsValid());
  ASSERT_EQ(FourBits::TWO, parent_view.GetFourBits());

  ChildTwoTwoView child_view = ChildTwoTwoView::Create(parent_view);
  ASSERT_TRUE(child_view.IsValid());
  ASSERT_EQ(FourBits::THREE, child_view.GetMoreBits());

  ChildTwoTwoThreeView grandchild_view = ChildTwoTwoThreeView::Create(child_view);
  ASSERT_TRUE(grandchild_view.IsValid());
}

TEST(GeneratedPacketTest, testChild) {
  uint16_t field_name = 0xa2a1;
  uint8_t footer = 0xb1;
  auto packet = ChildBuilder::Create(field_name, footer);

  ASSERT_EQ(child.size(), packet->size());

  std::shared_ptr<std::vector<uint8_t>> packet_bytes = std::make_shared<std::vector<uint8_t>>();
  BitInserter it(*packet_bytes);
  packet->Serialize(it);

  ASSERT_EQ(packet_bytes->size(), child.size());
  for (size_t i = 0; i < child.size(); i++) {
    ASSERT_EQ(packet_bytes->at(i), child[i]);
  }

  PacketView<kLittleEndian> packet_bytes_view(packet_bytes);
  ParentView parent_view = ParentView::Create(packet_bytes_view);
  ASSERT_TRUE(parent_view.IsValid());
  auto payload = parent_view.GetPayload();

  ASSERT_EQ(child[1 /* skip fixed field */], payload.size());
  for (size_t i = 0; i < payload.size(); i++) {
    ASSERT_EQ(child[i + 2 /* fixed & size */], payload[i]);
  }

  ChildView child_view = ChildView::Create(parent_view);
  ASSERT_TRUE(child_view.IsValid());

  ASSERT_EQ(field_name, child_view.GetFieldName());
}

TEST(GeneratedPacketTest, testValidateDeath) {
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
  ParentView wrong_view = ParentView::Create(packet_bytes_view);
  ASSERT_DEATH(wrong_view.GetPayload(), "validated");
}

TEST(GeneratedPacketTest, testValidatedParentDeath) {
  uint16_t field_name = 0xa2a1;
  uint8_t footer = 0xb1;
  auto packet = ChildBuilder::Create(field_name, footer);

  ASSERT_EQ(child.size(), packet->size());

  std::shared_ptr<std::vector<uint8_t>> packet_bytes = std::make_shared<std::vector<uint8_t>>();
  BitInserter it(*packet_bytes);
  packet->Serialize(it);

  ASSERT_EQ(packet_bytes->size(), child.size());
  for (size_t i = 0; i < child.size(); i++) {
    ASSERT_EQ(packet_bytes->at(i), child[i]);
  }

  PacketView<kLittleEndian> packet_bytes_view(packet_bytes);
  ParentView parent_view = ParentView::Create(packet_bytes_view);
  ASSERT_TRUE(parent_view.IsValid());
  auto payload = parent_view.GetPayload();

  ASSERT_EQ(child[1 /* skip fixed field */], payload.size());
  for (size_t i = 0; i < payload.size(); i++) {
    ASSERT_EQ(child[i + 2 /* fixed & size */], payload[i]);
  }

  ChildView child_view = ChildView::Create(parent_view);
  ASSERT_DEATH(child_view.GetFieldName(), "validated");
}

TEST(GeneratedPacketTest, testChildWithAddress) {
  Address address_a;
  ASSERT_TRUE(Address::FromString("A1:A2:A3:A4:A5:A6", address_a));
  Address address_b;
  ASSERT_TRUE(Address::FromString("B1:B2:B3:B4:B5:B6", address_b));
  auto packet = ChildWithAddressBuilder::Create(address_a, address_b);

  ASSERT_EQ(child_with_address.size(), packet->size());

  std::shared_ptr<std::vector<uint8_t>> packet_bytes = std::make_shared<std::vector<uint8_t>>();
  BitInserter it(*packet_bytes);
  packet->Serialize(it);

  ASSERT_EQ(packet_bytes->size(), child_with_address.size());
  for (size_t i = 0; i < child_with_address.size(); i++) {
    ASSERT_EQ(packet_bytes->at(i), child_with_address[i]);
  }

  PacketView<kLittleEndian> packet_bytes_view(packet_bytes);
  ParentWithAddressView parent_view = ParentWithAddressView::Create(packet_bytes_view);
  ASSERT_TRUE(parent_view.IsValid());
  ASSERT_EQ(address_a, parent_view.GetAddress());

  ChildWithAddressView child_view = ChildWithAddressView::Create(parent_view);
  ASSERT_TRUE(child_view.IsValid());

  ASSERT_EQ(address_a, child_view.GetAddress());
  ASSERT_EQ(address_a, ((ParentWithAddressView)child_view).GetAddress());
  ASSERT_EQ(address_b, child_view.GetChildAddress());
}

namespace {
vector<uint8_t> parent_with_sum = {
    0x11 /* TwoBytes */, 0x12, 0x21 /* Sum Bytes */, 0x22, 0x43 /* Sum, excluding TwoBytes */, 0x00,
};

}  // namespace

TEST(GeneratedPacketTest, testParentWithSum) {
  uint16_t two_bytes = 0x1211;
  uint16_t sum_bytes = 0x2221;
  auto packet = ParentWithSumBuilder::Create(two_bytes, sum_bytes, std::make_unique<packet::RawBuilder>());

  ASSERT_EQ(parent_with_sum.size(), packet->size());

  std::shared_ptr<std::vector<uint8_t>> packet_bytes = std::make_shared<std::vector<uint8_t>>();
  BitInserter it(*packet_bytes);
  packet->Serialize(it);

  ASSERT_EQ(packet_bytes->size(), parent_with_sum.size());
  for (size_t i = 0; i < parent_with_sum.size(); i++) {
    ASSERT_EQ(packet_bytes->at(i), parent_with_sum[i]);
  }

  PacketView<kLittleEndian> packet_bytes_view(packet_bytes);
  ParentWithSumView parent_view = ParentWithSumView::Create(packet_bytes_view);
  ASSERT_TRUE(parent_view.IsValid());
  ASSERT_EQ(two_bytes, parent_view.GetTwoBytes());

  // Corrupt checksum
  packet_bytes->back()++;
  PacketView<kLittleEndian> corrupted_bytes_view(packet_bytes);
  ParentWithSumView corrupted_view = ParentWithSumView::Create(corrupted_bytes_view);
  ASSERT_FALSE(corrupted_view.IsValid());
}

namespace {
vector<uint8_t> child_with_nested_sum = {
    0x11 /* TwoBytes */,
    0x12,
    0x21 /* Sum Bytes */,
    0x22,
    0x31 /* More Bytes */,
    0x32,
    0x33,
    0x34,
    0xca /* Nested Sum */,
    0x00,
    0xd7 /* Sum, excluding TwoBytes */,
    0x01,
};

}  // namespace

TEST(GeneratedPacketTest, testChildWithNestedSum) {
  uint16_t two_bytes = 0x1211;
  uint16_t sum_bytes = 0x2221;
  uint32_t more_bytes = 0x34333231;
  auto packet = ChildWithNestedSumBuilder::Create(two_bytes, sum_bytes, more_bytes);

  ASSERT_EQ(child_with_nested_sum.size(), packet->size());

  std::shared_ptr<std::vector<uint8_t>> packet_bytes = std::make_shared<std::vector<uint8_t>>();
  BitInserter it(*packet_bytes);
  packet->Serialize(it);

  ASSERT_EQ(packet_bytes->size(), child_with_nested_sum.size());
  for (size_t i = 0; i < child_with_nested_sum.size(); i++) {
    ASSERT_EQ(packet_bytes->at(i), child_with_nested_sum[i]);
  }

  PacketView<kLittleEndian> packet_bytes_view(packet_bytes);
  ParentWithSumView parent_view = ParentWithSumView::Create(packet_bytes_view);
  ASSERT_TRUE(parent_view.IsValid());
  ASSERT_EQ(two_bytes, parent_view.GetTwoBytes());

  ChildWithNestedSumView child_view = ChildWithNestedSumView::Create(parent_view);
  ASSERT_TRUE(child_view.IsValid());

  ASSERT_EQ(more_bytes, child_view.GetMoreBytes());
}

namespace {
vector<uint8_t> parent_size_modifier = {
    0x02 /* Size */,
    0x11 /* TwoBytes */,
    0x12,
};

}  // namespace

TEST(GeneratedPacketTest, testParentSizeModifier) {
  uint16_t two_bytes = 0x1211;
  auto packet = ParentSizeModifierBuilder::Create(std::make_unique<RawBuilder>(), two_bytes);

  ASSERT_EQ(parent_size_modifier.size(), packet->size());

  std::shared_ptr<std::vector<uint8_t>> packet_bytes = std::make_shared<std::vector<uint8_t>>();
  BitInserter it(*packet_bytes);
  packet->Serialize(it);

  ASSERT_EQ(parent_size_modifier.size(), packet_bytes->size());
  for (size_t i = 0; i < parent_size_modifier.size(); i++) {
    ASSERT_EQ(parent_size_modifier[i], packet_bytes->at(i));
  }

  PacketView<kLittleEndian> packet_bytes_view(packet_bytes);
  ParentSizeModifierView parent_view = ParentSizeModifierView::Create(packet_bytes_view);
  ASSERT_TRUE(parent_view.IsValid());
  ASSERT_EQ(two_bytes, parent_view.GetTwoBytes());
}

namespace {
vector<uint8_t> child_size_modifier = {
    0x06 /* PayloadSize (TwoBytes + MoreBytes)*/,
    0x31 /* MoreBytes */,
    0x32,
    0x33,
    0x34,
    0x11 /* TwoBytes = 0x1211 */,
    0x12,
};

}  // namespace

TEST(GeneratedPacketTest, testChildSizeModifier) {
  uint16_t two_bytes = 0x1211;
  uint32_t more_bytes = 0x34333231;
  auto packet = ChildSizeModifierBuilder::Create(more_bytes);

  ASSERT_EQ(child_size_modifier.size(), packet->size());

  std::shared_ptr<std::vector<uint8_t>> packet_bytes = std::make_shared<std::vector<uint8_t>>();
  BitInserter it(*packet_bytes);
  packet->Serialize(it);

  ASSERT_EQ(child_size_modifier.size(), packet_bytes->size());
  for (size_t i = 0; i < child_size_modifier.size(); i++) {
    ASSERT_EQ(child_size_modifier[i], packet_bytes->at(i));
  }

  PacketView<kLittleEndian> packet_bytes_view(packet_bytes);
  ParentSizeModifierView parent_view = ParentSizeModifierView::Create(packet_bytes_view);
  ASSERT_TRUE(parent_view.IsValid());
  ASSERT_EQ(two_bytes, parent_view.GetTwoBytes());

  ChildSizeModifierView child_view = ChildSizeModifierView::Create(parent_view);
  ASSERT_TRUE(child_view.IsValid());

  ASSERT_EQ(more_bytes, child_view.GetMoreBytes());
}
}  // namespace parser
}  // namespace packet
}  // namespace bluetooth
