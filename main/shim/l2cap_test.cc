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

#include <gtest/gtest.h>
#include <cstdint>

#define LOG_TAG "bt_shim_test"

#include "osi/include/log.h"
#include "shim/l2cap.h"
#include "shim/stub/stack.h"
#include "types/raw_address.h"

namespace bluetooth {
namespace legacy {

namespace {

constexpr uint16_t kPsm = 123;
constexpr uint16_t kCid = 987;
constexpr size_t kDataBufferSize = 1024;

uint8_t bt_hdr_data[] = {
    0x00, 0x00,                                     /* event */
    0x08, 0x00,                                     /* len */
    0x00, 0x00,                                     /* offset */
    0x00, 0x00,                                     /* layer specific */
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, /* data */
    0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, /* data */
};

class L2capTest;
L2capTest* l2cap_test_ = nullptr;

class L2capTest : public ::testing::Test {
 public:
  static shim::L2cap* l2cap_;

  struct {
    int L2caConnectCfmCb;
    int L2caConnectPndCb;
    int L2caConfigIndCb;
    int L2caConfigCfmCb;
    int L2caDisconnectIndCb;
    int L2caDisconnectCfmCb;
    int L2caQosViolationIndCb;
    int L2caDataIndCb;
    int L2caCongestionStatusCb;
    int L2caTxCompleteCb;
    int L2caCreditsReceivedCb;
  } cnt_{
      .L2caConnectCfmCb = 0,
      .L2caConnectPndCb = 0,
      .L2caConfigIndCb = 0,
      .L2caConfigCfmCb = 0,
      .L2caDisconnectIndCb = 0,
      .L2caDisconnectCfmCb = 0,
      .L2caQosViolationIndCb = 0,
      .L2caDataIndCb = 0,
      .L2caCongestionStatusCb = 0,
      .L2caTxCompleteCb = 0,
      .L2caCreditsReceivedCb = 0,
  };

 protected:
  void SetUp() override {
    l2cap_ = new shim::L2cap();
    l2cap_test_ = this;
  }

  void TearDown() override {
    delete l2cap_;
    l2cap_ = nullptr;
  }

  uint8_t data_buffer_[kDataBufferSize];
};

shim::L2cap* L2capTest::l2cap_ = nullptr;
// Indication of remotely initiated connection response sent
void L2caConnectIndCb(const RawAddress& raw_address, uint16_t a, uint16_t b,
                      uint8_t c) {
  LOG_INFO(LOG_TAG, "%s", __func__);
}

// Confirms locally initiated connection request completed
void L2caConnectCfmCb(uint16_t cid, uint16_t result) {
  l2cap_test_->cnt_.L2caConnectCfmCb++;
  LOG_INFO(LOG_TAG, "%s cid:%hd result:%hd", __func__, cid, result);
}

void L2caConnectPndCb(uint16_t cid) {
  l2cap_test_->cnt_.L2caConnectPndCb++;
  LOG_INFO(LOG_TAG, "%s", __func__);
}

// Indication of remotely initiated configuration response sent
void L2caConfigIndCb(uint16_t cid, tL2CAP_CFG_INFO* callbacks) {
  l2cap_test_->cnt_.L2caConfigIndCb++;
  LOG_INFO(LOG_TAG, "%s", __func__);
}

// Confirms locally initiated config request completed
void L2caConfigCfmCb(uint16_t cid, tL2CAP_CFG_INFO* callbacks) {
  l2cap_test_->cnt_.L2caConfigCfmCb++;
  LOG_INFO(LOG_TAG, "%s", __func__);
}

// Indication of remotely initiated disconnection response sent
void L2caDisconnectIndCb(uint16_t cid, bool needs_ack) {
  l2cap_test_->cnt_.L2caDisconnectIndCb++;
  LOG_INFO(LOG_TAG, "%s", __func__);
}

// Confirms locally initiated disconnect request completed
void L2caDisconnectCfmCb(uint16_t cid, uint16_t result) {
  l2cap_test_->cnt_.L2caDisconnectCfmCb++;
  LOG_INFO(LOG_TAG, "%s", __func__);
}

void L2caQosViolationIndCb(const RawAddress& raw_address) {
  l2cap_test_->cnt_.L2caQosViolationIndCb++;
  LOG_INFO(LOG_TAG, "%s", __func__);
}

void L2caDataIndCb(uint16_t cid, BT_HDR* bt_hdr) {
  l2cap_test_->cnt_.L2caDataIndCb++;
  LOG_INFO(LOG_TAG, "%s", __func__);
}

void L2caCongestionStatusCb(uint16_t cid, bool is_congested) {
  l2cap_test_->cnt_.L2caCongestionStatusCb++;
  LOG_INFO(LOG_TAG, "%s", __func__);
}

void L2caTxCompleteCb(uint16_t cid, uint16_t sdu_cnt) {
  l2cap_test_->cnt_.L2caTxCompleteCb++;
  LOG_INFO(LOG_TAG, "%s", __func__);
}

void L2caCreditsReceivedCb(uint16_t cid, uint16_t credits_received,
                           uint16_t credit_count) {
  l2cap_test_->cnt_.L2caCreditsReceivedCb++;
  LOG_INFO(LOG_TAG, "%s", __func__);
}

tL2CAP_APPL_INFO test_callbacks{
    .pL2CA_ConnectInd_Cb = L2caConnectIndCb,
    .pL2CA_ConnectCfm_Cb = L2caConnectCfmCb,
    .pL2CA_ConnectPnd_Cb = L2caConnectPndCb,
    .pL2CA_ConfigInd_Cb = L2caConfigIndCb,
    .pL2CA_ConfigCfm_Cb = L2caConfigCfmCb,
    .pL2CA_DisconnectInd_Cb = L2caDisconnectIndCb,
    .pL2CA_DisconnectCfm_Cb = L2caDisconnectCfmCb,
    .pL2CA_QoSViolationInd_Cb = L2caQosViolationIndCb,
    .pL2CA_DataInd_Cb = L2caDataIndCb,
    .pL2CA_CongestionStatus_Cb = L2caCongestionStatusCb,
    .pL2CA_TxComplete_Cb = L2caTxCompleteCb,
    .pL2CA_CreditsReceived_Cb = L2caCreditsReceivedCb,
};

TEST_F(L2capTest, RegisterService) {
  l2cap_->RegisterService(kPsm, &test_callbacks, false, nullptr);
  CHECK(test_stack_.test_l2cap_.registered_service_.count(kPsm) == 1);
}

TEST_F(L2capTest, UnregisterService) {
  l2cap_->RegisterService(kPsm, &test_callbacks, false, nullptr);
  CHECK(test_stack_.test_l2cap_.registered_service_.count(kPsm) == 1);
  l2cap_->UnregisterService(kPsm);
  CHECK(test_stack_.test_l2cap_.registered_service_.count(kPsm) == 0);
}

TEST_F(L2capTest, CreateConnection_NotRegistered) {
  RawAddress raw_address;
  std::string string_address("11:22:33:44:55:66");
  RawAddress::FromString(string_address, raw_address);
  uint16_t cid = l2cap_->CreateConnection(kPsm, raw_address);
  CHECK(cid == 0);
}

TEST_F(L2capTest, CreateConnection_Registered) {
  test_stack_.test_l2cap_.cid_ = kCid;
  l2cap_->RegisterService(kPsm, &test_callbacks, false, nullptr);

  RawAddress raw_address;
  std::string string_address("11:22:33:44:55:66");
  RawAddress::FromString(string_address, raw_address);
  uint16_t cid = l2cap_->CreateConnection(kPsm, raw_address);
  CHECK(cid != 0);
}

TEST_F(L2capTest, CreateConnection_ConnectResponse) {
  test_stack_.test_l2cap_.cid_ = kCid;
  l2cap_->RegisterService(kPsm, &test_callbacks, false, nullptr);

  RawAddress raw_address;
  std::string string_address("11:22:33:44:55:66");
  RawAddress::FromString(string_address, raw_address);
  uint16_t cid = l2cap_->CreateConnection(kPsm, raw_address);
  CHECK(cid != 0);

  CHECK(l2cap_->ConnectResponse(raw_address, 0, cid, 0, 0, nullptr));
}

TEST_F(L2capTest, CreateConnection_ConfigRequest) {
  test_stack_.test_l2cap_.cid_ = kCid;
  l2cap_->RegisterService(kPsm, &test_callbacks, false, nullptr);

  RawAddress raw_address;
  std::string string_address("11:22:33:44:55:66");
  RawAddress::FromString(string_address, raw_address);
  uint16_t cid = l2cap_->CreateConnection(kPsm, raw_address);
  CHECK(cid != 0);

  // Simulate a successful connection response
  l2cap_->OnLocalInitiatedConnectionCreated("11:22:33:44:55:66", kPsm, kCid);
  CHECK(cnt_.L2caConnectCfmCb == 1);

  CHECK(l2cap_->ConfigRequest(cid, nullptr));
}

TEST_F(L2capTest, CreateConnection_ConfigResponse) {
  test_stack_.test_l2cap_.cid_ = kCid;
  l2cap_->RegisterService(kPsm, &test_callbacks, false, nullptr);

  RawAddress raw_address;
  std::string string_address("11:22:33:44:55:66");
  RawAddress::FromString(string_address, raw_address);
  uint16_t cid = l2cap_->CreateConnection(kPsm, raw_address);
  CHECK(cid != 0);

  // Simulate a successful connection response
  l2cap_->OnLocalInitiatedConnectionCreated("11:22:33:44:55:66", kPsm, kCid);
  CHECK(cnt_.L2caConnectCfmCb == 1);

  CHECK(l2cap_->ConfigResponse(cid, nullptr));
}

TEST_F(L2capTest, CreateConnection_DisconnectRequest) {
  test_stack_.test_l2cap_.cid_ = kCid;
  l2cap_->RegisterService(kPsm, &test_callbacks, false, nullptr);

  RawAddress raw_address;
  std::string string_address("11:22:33:44:55:66");
  RawAddress::FromString(string_address, raw_address);
  uint16_t cid = l2cap_->CreateConnection(kPsm, raw_address);
  CHECK(cid != 0);

  // Simulate a successful connection response
  l2cap_->OnLocalInitiatedConnectionCreated("11:22:33:44:55:66", kPsm, kCid);
  CHECK(cnt_.L2caConnectCfmCb == 1);

  CHECK(l2cap_->DisconnectRequest(cid));
}

TEST_F(L2capTest, CreateConnection_DisconnectResponse) {
  test_stack_.test_l2cap_.cid_ = kCid;
  l2cap_->RegisterService(kPsm, &test_callbacks, false, nullptr);

  RawAddress raw_address;
  std::string string_address("11:22:33:44:55:66");
  RawAddress::FromString(string_address, raw_address);
  uint16_t cid = l2cap_->CreateConnection(kPsm, raw_address);
  CHECK(cid != 0);

  // Simulate a successful connection response
  l2cap_->OnLocalInitiatedConnectionCreated("11:22:33:44:55:66", kPsm, kCid);
  CHECK(cnt_.L2caConnectCfmCb == 1);

  CHECK(l2cap_->DisconnectResponse(cid));
}

TEST_F(L2capTest, CreateConnection_WithHandshake) {
  test_stack_.test_l2cap_.cid_ = kCid;
  l2cap_->RegisterService(kPsm, &test_callbacks, false, nullptr);

  RawAddress raw_address;
  std::string string_address("11:22:33:44:55:66");
  RawAddress::FromString(string_address, raw_address);
  uint16_t cid = l2cap_->CreateConnection(kPsm, raw_address);
  CHECK(cid != 0);

  // Simulate a successful connection response
  l2cap_->OnLocalInitiatedConnectionCreated("11:22:33:44:55:66", kPsm, kCid);
  CHECK(cnt_.L2caConnectCfmCb == 1);

  CHECK(l2cap_->ConfigRequest(cid, nullptr) == true);
  CHECK(cnt_.L2caConfigCfmCb == 1);
  CHECK(cnt_.L2caConfigIndCb == 1);

  BT_HDR* bt_hdr = (BT_HDR*)bt_hdr_data;

  test_stack_.test_l2cap_.data_buffer_ = data_buffer_;
  test_stack_.test_l2cap_.data_buffer_size_ = kDataBufferSize;

  l2cap_->Write(cid, bt_hdr);

  CHECK(data_buffer_[0] == 0x11);
  CHECK(data_buffer_[1] == 0x22);
  CHECK(data_buffer_[2] == 0x33);
  CHECK(data_buffer_[3] == 0x44);
  CHECK(data_buffer_[4] == 0x55);
  CHECK(data_buffer_[5] == 0x66);
  CHECK(data_buffer_[6] == 0x77);
  CHECK(data_buffer_[7] == 0x88);
  CHECK(data_buffer_[8] == 0x00);
}

}  // namespace
}  // namespace legacy
}  // namespace bluetooth
