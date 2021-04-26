/*
 *  Copyright 2021 The Android Open Source Project
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
 */

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <cstring>
#include <map>

#include "osi/include/log.h"
#include "stack/include/hcidefs.h"
#include "stack/include/l2cdefs.h"
#include "test/mock/mock_hcic_hcicmds.h"

std::map<std::string, int> mock_function_count_map;

namespace mock = test::mock::hcic_hcicmds;

namespace {

using testing::_;
using testing::DoAll;
using testing::NotNull;
using testing::Pointee;
using testing::Return;
using testing::SaveArg;
using testing::SaveArgPointee;
using testing::StrEq;
using testing::StrictMock;
using testing::Test;

class StackHciTest : public Test {
 public:
 protected:
  void SetUp() override { mock_function_count_map.clear(); }
  void TearDown() override {}
};

TEST_F(StackHciTest, hci_preamble) {
  {
    HciDataPreamble preamble;

    ASSERT_EQ(sizeof(preamble), HCI_DATA_PREAMBLE_SIZE);

    preamble.bits.handle = 0xfff;
    preamble.bits.boundary = 0x3;
    preamble.bits.broadcast = 0x1;
    preamble.bits.unused15 = 0x0;
    preamble.bits.length = 0xffff;

    ASSERT_EQ(0x7fff, preamble.raw.word0);
    ASSERT_EQ(0xffff, preamble.raw.word1);

    const uint8_t exp[] = {0xff, 0x7f, 0xff, 0xff};
    uint8_t act[sizeof(preamble)];
    preamble.Serialize(act);
    ASSERT_EQ(0, std::memcmp(exp, act, sizeof(preamble)));
  }

  {
    HciDataPreamble preamble;
    preamble.raw.word0 =
        0x123 | (L2CAP_PKT_START_NON_FLUSHABLE << L2CAP_PKT_TYPE_SHIFT);
    preamble.raw.word1 = 0x4567;

    ASSERT_EQ(sizeof(preamble), HCI_DATA_PREAMBLE_SIZE);

    ASSERT_EQ(0x0123, preamble.raw.word0);
    ASSERT_EQ(0x4567, preamble.raw.word1);

    const uint8_t exp[] = {0x23, 0x01, 0x67, 0x45};
    uint8_t act[sizeof(preamble)];
    preamble.Serialize(act);
    ASSERT_EQ(0, std::memcmp(exp, act, sizeof(preamble)));
  }
  {
    HciDataPreamble preamble;
    preamble.raw.word0 = 0x123 | (L2CAP_PKT_START << L2CAP_PKT_TYPE_SHIFT);
    preamble.raw.word1 = 0x4567;

    ASSERT_EQ(sizeof(preamble), HCI_DATA_PREAMBLE_SIZE);

    ASSERT_EQ(0x2123, preamble.raw.word0);
    ASSERT_EQ(0x4567, preamble.raw.word1);

    const uint8_t exp[] = {0x23, 0x21, 0x67, 0x45};
    uint8_t act[sizeof(preamble)];
    preamble.Serialize(act);
    ASSERT_EQ(0, std::memcmp(exp, act, sizeof(preamble)));
  }

  {
    HciDataPreamble preamble;
    preamble.raw.word0 = 0x0 | (L2CAP_PKT_START << L2CAP_PKT_TYPE_SHIFT);
    preamble.raw.word1 = 0x0;

    ASSERT_EQ(sizeof(preamble), HCI_DATA_PREAMBLE_SIZE);

    ASSERT_EQ(0x2000, preamble.raw.word0);
    ASSERT_EQ(0x0000, preamble.raw.word1);

    const uint8_t exp[] = {0x00, 0x20, 0x00, 0x00};
    uint8_t act[sizeof(preamble)];
    preamble.Serialize(act);
    ASSERT_EQ(0, std::memcmp(exp, act, sizeof(preamble)));
  }

  {
    HciDataPreamble preamble;
    preamble.raw.word0 = 0x0 | (L2CAP_PKT_START << L2CAP_PKT_TYPE_SHIFT);
    preamble.raw.word1 = 0x0;

    ASSERT_TRUE(preamble.IsFlushable());

    preamble.raw.word0 =
        0x0 | (L2CAP_PKT_START << L2CAP_PKT_START_NON_FLUSHABLE);
    ASSERT_TRUE(!preamble.IsFlushable());
  }
}

}  // namespace
