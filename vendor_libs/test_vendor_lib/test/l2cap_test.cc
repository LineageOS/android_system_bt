/******************************************************************************
 *
 *  Copyright (C) 2017 Google, Inc.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at:
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 ******************************************************************************/

#include "l2cap_packet.h"
#include "l2cap_test_packets.h"

#include <gtest/gtest.h>
#include <memory>

using std::unique_ptr;
using std::vector;

namespace test_vendor_lib {

class L2capTest : public ::testing::Test {
 public:
  L2capTest() {}

  void compare_packets(vector<uint8_t>& complete_packet,
                       vector<uint8_t>& assembled_packet) {
    ASSERT_EQ(complete_packet.size() - 4, assembled_packet.size());

    for (size_t i = 0; i < assembled_packet.size(); i++) {
      ASSERT_EQ(complete_packet[i + 4], assembled_packet[i]);
    }
  }

  L2capSdu update_fcs(vector<uint8_t> sdu) {
    sdu.resize(sdu.size() - 2);

    return L2capSdu::L2capSduBuilder(sdu);
  }

  ~L2capTest() = default;
};

TEST_F(L2capTest, assembleTest) {
  vector<L2capSdu> test_packet;
  vector<uint8_t> assembled_payload;

  // Test 1: Pass correct packets.
  test_packet.push_back(L2capSdu(good_sdu[0]));
  test_packet.push_back(L2capSdu(good_sdu[1]));
  test_packet.push_back(L2capSdu(good_sdu[2]));

  unique_ptr<L2capPacket> test_1 = L2capPacket::assemble(test_packet);
  EXPECT_NE(test_1, nullptr);

  if (test_1 != nullptr) {
    assembled_payload = test_1->get_l2cap_payload();

    compare_packets(good_l2cap_packet, assembled_payload);

    assembled_payload.clear();
  }
  test_packet.clear();

  test_packet.push_back(L2capSdu(l2cap_test_packet_1));
  test_packet.push_back(L2capSdu(l2cap_test_packet_2));
  test_packet.push_back(L2capSdu(l2cap_test_packet_3));
  test_packet.push_back(L2capSdu(l2cap_test_packet_4));
  test_packet.push_back(L2capSdu(l2cap_test_packet_5));
  test_packet.push_back(L2capSdu(l2cap_test_packet_6));
  test_packet.push_back(L2capSdu(l2cap_test_packet_7));
  test_packet.push_back(L2capSdu(l2cap_test_packet_8));
  test_packet.push_back(L2capSdu(l2cap_test_packet_9));

  test_1 = L2capPacket::assemble(test_packet);
  EXPECT_NE(test_1, nullptr);

  if (test_1 != nullptr) {
    assembled_payload = test_1->get_l2cap_payload();
    compare_packets(complete_l2cap_packet, assembled_payload);

    assembled_payload.clear();
  }
  test_packet.clear();

  // Test 2: Pass out of order packets.
  test_packet.push_back(L2capSdu(good_sdu[1]));
  test_packet.push_back(L2capSdu(good_sdu[0]));
  test_packet.push_back(L2capSdu(good_sdu[2]));

  unique_ptr<L2capPacket> test_2 = L2capPacket::assemble(test_packet);
  EXPECT_EQ(test_2, nullptr);

  test_packet.clear();

  test_packet.push_back(L2capSdu(l2cap_test_packet_1));
  test_packet.push_back(L2capSdu(l2cap_test_packet_3));
  test_packet.push_back(L2capSdu(l2cap_test_packet_2));
  test_packet.push_back(L2capSdu(l2cap_test_packet_6));
  test_packet.push_back(L2capSdu(l2cap_test_packet_5));
  test_packet.push_back(L2capSdu(l2cap_test_packet_4));
  test_packet.push_back(L2capSdu(l2cap_test_packet_8));
  test_packet.push_back(L2capSdu(l2cap_test_packet_7));
  test_packet.push_back(L2capSdu(l2cap_test_packet_9));

  test_2 = L2capPacket::assemble(test_packet);
  EXPECT_EQ(test_2, nullptr);

  test_packet.clear();

  // Test 3: Pass packets missing the finished control bytes.
  test_packet.push_back(L2capSdu(good_sdu[0]));
  test_packet.push_back(L2capSdu(good_sdu[1]));

  unique_ptr<L2capPacket> test_3 = L2capPacket::assemble(test_packet);
  EXPECT_EQ(test_3, nullptr);

  test_packet.clear();

  test_packet.push_back(L2capSdu(l2cap_test_packet_1));
  test_packet.push_back(L2capSdu(l2cap_test_packet_2));
  test_packet.push_back(L2capSdu(l2cap_test_packet_3));
  test_packet.push_back(L2capSdu(l2cap_test_packet_4));
  test_packet.push_back(L2capSdu(l2cap_test_packet_5));
  test_packet.push_back(L2capSdu(l2cap_test_packet_6));
  test_packet.push_back(L2capSdu(l2cap_test_packet_7));
  test_packet.push_back(L2capSdu(l2cap_test_packet_8));

  test_3 = L2capPacket::assemble(test_packet);
  EXPECT_EQ(test_3, nullptr);

  test_packet.clear();

  // Test 4: Pass packets with incorrect frame check sequences.
  test_packet.push_back(L2capSdu(good_sdu[0]));
  good_sdu[1][good_sdu[1].size() - 1]++;
  test_packet.push_back(L2capSdu(good_sdu[1]));
  good_sdu[1][good_sdu[1].size() - 1]--;
  test_packet.push_back(L2capSdu(good_sdu[2]));

  unique_ptr<L2capPacket> test_4 = L2capPacket::assemble(test_packet);
  EXPECT_EQ(test_4, nullptr);

  test_packet.clear();

  test_packet.push_back(L2capSdu(l2cap_test_packet_1));
  test_packet.push_back(L2capSdu(l2cap_test_packet_2));
  test_packet.push_back(L2capSdu(l2cap_test_packet_3));
  test_packet.push_back(L2capSdu(l2cap_test_packet_4));
  l2cap_test_packet_5[l2cap_test_packet_5.size() - 1]++;
  test_packet.push_back(L2capSdu(l2cap_test_packet_5));
  l2cap_test_packet_5[l2cap_test_packet_5.size() - 1]--;
  test_packet.push_back(L2capSdu(l2cap_test_packet_6));
  test_packet.push_back(L2capSdu(l2cap_test_packet_7));
  test_packet.push_back(L2capSdu(l2cap_test_packet_8));
  test_packet.push_back(L2capSdu(l2cap_test_packet_9));

  test_4 = L2capPacket::assemble(test_packet);
  EXPECT_EQ(test_4, nullptr);

  test_packet.clear();

  // Test 5: Pass a packet with an empty payload.
  test_packet.push_back(L2capSdu(empty_sdu_payload[0]));
  test_packet.push_back(L2capSdu(empty_sdu_payload[1]));

  unique_ptr<L2capPacket> test_5 = L2capPacket::assemble(test_packet);
  EXPECT_NE(test_5, nullptr);

  if (test_5 != nullptr) {
    EXPECT_EQ(test_5->get_l2cap_cid(), 0x0047);
    assembled_payload = test_5->get_l2cap_payload();
    compare_packets(empty_l2cap_payload, assembled_payload);

    assembled_payload.clear();
  }
  test_packet.clear();

  // Test 6: Pass a SDU with all the control bytes set to as the starting bytes.
  test_packet.push_back(L2capSdu(all_first_packet[0]));
  test_packet.push_back(L2capSdu(all_first_packet[1]));
  test_packet.push_back(L2capSdu(all_first_packet[2]));

  unique_ptr<L2capPacket> test_6 = L2capPacket::assemble(test_packet);
  EXPECT_EQ(test_6, nullptr);

  test_packet.clear();

  // Test 7: Pass SDUs with mixed channel ids.
  test_packet.push_back(L2capSdu(good_sdu[0]));
  good_sdu[1][2]++;
  test_packet.push_back(update_fcs(good_sdu[1]));
  good_sdu[1][2]--;
  test_packet.push_back(L2capSdu(good_sdu[2]));

  unique_ptr<L2capPacket> test_7 = L2capPacket::assemble(test_packet);
  EXPECT_EQ(test_7, nullptr);

  test_packet.clear();

  test_packet.push_back(L2capSdu(l2cap_test_packet_1));
  l2cap_test_packet_2[2]++;
  test_packet.push_back(update_fcs(l2cap_test_packet_2));
  l2cap_test_packet_2[2]--;
  test_packet.push_back(L2capSdu(l2cap_test_packet_3));
  test_packet.push_back(L2capSdu(l2cap_test_packet_4));
  l2cap_test_packet_5[2]++;
  test_packet.push_back(update_fcs(l2cap_test_packet_5));
  l2cap_test_packet_5[2]--;
  test_packet.push_back(L2capSdu(l2cap_test_packet_6));
  test_packet.push_back(L2capSdu(l2cap_test_packet_7));
  l2cap_test_packet_8[2]--;
  test_packet.push_back(update_fcs(l2cap_test_packet_8));
  l2cap_test_packet_8[2]++;
  test_packet.push_back(L2capSdu(l2cap_test_packet_9));

  test_7 = L2capPacket::assemble(test_packet);
  EXPECT_EQ(test_7, nullptr);

  test_packet.clear();

  // Test 8: Pass a complete l2cap packet.
  test_packet.push_back(L2capSdu(one_sdu[0]));

  unique_ptr<L2capPacket> test_8 = L2capPacket::assemble(test_packet);
  EXPECT_NE(test_8, nullptr);

  test_packet.clear();

  // Test 9: Pass SDUs with incorrect TxSeq.
  good_sdu[0][4] += 4;
  test_packet.push_back(update_fcs(good_sdu[0]));
  good_sdu[0][4] -= 4;
  test_packet.push_back(L2capSdu(good_sdu[1]));
  test_packet.push_back(L2capSdu(good_sdu[2]));

  unique_ptr<L2capPacket> test_9 = L2capPacket::assemble(test_packet);
  EXPECT_EQ(test_9, nullptr);

  test_packet.clear();

  // Test 10: Pass SDUs with an incorrect total SDU length
  good_sdu[0][7]++;
  test_packet.push_back(update_fcs(good_sdu[0]));
  good_sdu[0][7]--;
  test_packet.push_back(L2capSdu(good_sdu[1]));
  test_packet.push_back(L2capSdu(good_sdu[2]));

  unique_ptr<L2capPacket> test_10 = L2capPacket::assemble(test_packet);
  EXPECT_EQ(test_10, nullptr);

  test_packet.clear();

  l2cap_test_packet_1[6]++;
  test_packet.push_back(update_fcs(l2cap_test_packet_1));
  l2cap_test_packet_1[6]--;
  test_packet.push_back(L2capSdu(l2cap_test_packet_2));
  test_packet.push_back(L2capSdu(l2cap_test_packet_3));
  test_packet.push_back(L2capSdu(l2cap_test_packet_4));
  test_packet.push_back(L2capSdu(l2cap_test_packet_5));
  test_packet.push_back(L2capSdu(l2cap_test_packet_6));
  test_packet.push_back(L2capSdu(l2cap_test_packet_7));
  test_packet.push_back(L2capSdu(l2cap_test_packet_8));
  test_packet.push_back(L2capSdu(l2cap_test_packet_9));

  test_10 = L2capPacket::assemble(test_packet);

  EXPECT_EQ(test_10, nullptr);

  test_packet.clear();
}  // assembleTest

}  // namespace test_vendor_lib
