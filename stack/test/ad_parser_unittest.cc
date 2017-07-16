/******************************************************************************
 *
 *  Copyright (C) 2017 The Android Open Source Project
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

#include <gtest/gtest.h>
#include "advertise_data_parser.h"

TEST(AdvertiseDataParserTest, IsValidEmpty) {
  const std::vector<uint8_t> data0;
  EXPECT_TRUE(AdvertiseDataParser::IsValid(data0));

  // Single empty field allowed (treated as zero padding).
  const std::vector<uint8_t> data1{0x00};
  EXPECT_TRUE(AdvertiseDataParser::IsValid(data1));
}

TEST(AdvertiseDataParserTest, IsValidBad) {
  // Single field, field empty.
  const std::vector<uint8_t> data0{0x01};
  EXPECT_FALSE(AdvertiseDataParser::IsValid(data0));

  // Single field, first field length too long.
  const std::vector<uint8_t> data1{0x05, 0x02, 0x00, 0x00, 0x00};
  EXPECT_FALSE(AdvertiseDataParser::IsValid(data1));

  // Two fields, second field length too long.
  const std::vector<uint8_t> data2{0x02, 0x02, 0x00, 0x02, 0x00};
  EXPECT_FALSE(AdvertiseDataParser::IsValid(data2));

  // Two fields, second field empty.
  const std::vector<uint8_t> data3{0x02, 0x02, 0x00, 0x01};
  EXPECT_FALSE(AdvertiseDataParser::IsValid(data3));

  // Non-zero padding at end of packet.
  const std::vector<uint8_t> data4{0x03, 0x02, 0x01, 0x02, 0x02, 0x03, 0x01,
                                   0x00, 0x00, 0xBA, 0xBA, 0x00, 0x00};
  EXPECT_FALSE(AdvertiseDataParser::IsValid(data1));

  // Non-zero padding at end of packet.
  const std::vector<uint8_t> data5{0x03, 0x02, 0x01, 0x02, 0x02,
                                   0x03, 0x01, 0x00, 0xBA};
  EXPECT_FALSE(AdvertiseDataParser::IsValid(data1));
}

TEST(AdvertiseDataParserTest, IsValidGood) {
  // Single field.
  const std::vector<uint8_t> data0{0x03, 0x02, 0x01, 0x02};
  EXPECT_TRUE(AdvertiseDataParser::IsValid(data0));

  // Two fields.
  const std::vector<uint8_t> data1{0x03, 0x02, 0x01, 0x02, 0x02, 0x03, 0x01};
  EXPECT_TRUE(AdvertiseDataParser::IsValid(data1));

  // Zero padding at end of packet.
  const std::vector<uint8_t> data2{0x03, 0x02, 0x01, 0x02,
                                   0x02, 0x03, 0x01, 0x00};
  EXPECT_TRUE(AdvertiseDataParser::IsValid(data2));

  // zero padding at end of packet, sample data from real device
  const std::vector<uint8_t> data3{
      0x10, 0x096, 0x85, 0x44, 0x32, 0x04, 0x74, 0x32, 0x03, 0x13, 0x93,
      0xa,  0x32,  0x39, 0x3a, 0x65, 0x32, 0x05, 0x12, 0x50, 0x00, 0x50,
      0x00, 0x02,  0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  EXPECT_TRUE(AdvertiseDataParser::IsValid(data3));
}

TEST(AdvertiseDataParserTest, GetFieldByType) {
  // Single field.
  const std::vector<uint8_t> data0{0x03, 0x02, 0x01, 0x02};

  uint8_t p_length;
  const uint8_t* data =
      AdvertiseDataParser::GetFieldByType(data0, 0x02, &p_length);
  EXPECT_EQ(data0.data() + 2, data);
  EXPECT_EQ(2, p_length);

  // Two fields, second field length too long.
  const std::vector<uint8_t> data1{0x02, 0x02, 0x00, 0x03, 0x00};

  // First field is ok.
  data = AdvertiseDataParser::GetFieldByType(data1, 0x02, &p_length);
  EXPECT_EQ(data1.data() + 2, data);
  EXPECT_EQ(0x01, p_length);

  // Second field have bad length.
  data = AdvertiseDataParser::GetFieldByType(data1, 0x03, &p_length);
  EXPECT_EQ(nullptr, data);
  EXPECT_EQ(0, p_length);
}