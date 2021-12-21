/*
 * Copyright 2020 The Android Open Source Project
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

//#include <dlfcn.h>
#include <gtest/gtest.h>

#include "osi/include/allocator.h"
#include "stack/include/avdt_api.h"
#include "stack/avdt/avdt_int.h"
#include "stack/test/common/mock_stack_avdt_msg.h"

#ifndef UNUSED_ATTR
#define UNUSED_ATTR
#endif

// Global trace level referred in the code under test
uint8_t appl_trace_level = BT_TRACE_LEVEL_VERBOSE;

void LogMsg(uint32_t trace_set_mask, const char* fmt_str, ...) { }

// All mock requires this symbol to count calling times
std::map<std::string, int> mock_function_count_map;

class StackAvdtpTest : public ::testing::Test {
 protected:
  StackAvdtpTest() = default;

  virtual ~StackAvdtpTest() = default;
 protected:
  static AvdtpRcb reg_ctrl_block_;
  static uint8_t callback_event_;
  static uint8_t scb_handle_;

 protected:
  static void AvdtConnCallback(uint8_t handle, const RawAddress& bd_addr,
                               uint8_t event, tAVDT_CTRL* p_data,
                               uint8_t scb_index) {
    mock_function_count_map[__func__]++;
    callback_event_ = event;
  }

  static void StreamCtrlCallback(uint8_t handle, const RawAddress& bd_addr,
                                 uint8_t event, tAVDT_CTRL* p_data,
                                 uint8_t scb_index) {
    mock_function_count_map[__func__]++;
    callback_event_ = event;
  }

  static void AvdtReportCallback(uint8_t handle, AVDT_REPORT_TYPE type,
                                 tAVDT_REPORT_DATA* p_data) {
    mock_function_count_map[__func__]++;
  }

  static void SetUpTestCase() {
    reg_ctrl_block_.ctrl_mtu = 672;
    reg_ctrl_block_.ret_tout = 4;
    reg_ctrl_block_.sig_tout = 4;
    reg_ctrl_block_.idle_tout = 10;
    reg_ctrl_block_.scb_index = 0;
    AVDT_Register(&reg_ctrl_block_, AvdtConnCallback);

    uint8_t peer_id = 1;
    scb_handle_ = 0;
    AvdtpStreamConfig avdtp_stream_config{};
    avdtp_stream_config.cfg.psc_mask = AVDT_PSC_DELAY_RPT;
    avdtp_stream_config.p_avdt_ctrl_cback = StreamCtrlCallback;
    avdtp_stream_config.p_report_cback = AvdtReportCallback;
    avdtp_stream_config.tsep = AVDT_TSEP_SNK;
    // We have to reuse the stream since there is only AVDT_NUM_SEPS *
    // AVDT_NUM_LINKS
    ASSERT_EQ(AVDT_CreateStream(peer_id, &scb_handle_, avdtp_stream_config), AVDT_SUCCESS);
  }

  static void TearDownTestCase() { AVDT_Deregister(); }

  void SetUp() override {
    callback_event_ = AVDT_MAX_EVT + 1;
    mock_function_count_map.clear();
  }

  void TearDown() override {
    auto pscb = avdt_scb_by_hdl(scb_handle_);
    tAVDT_SCB_EVT data;
    // clean up the SCB state
    avdt_scb_event(pscb, AVDT_SCB_MSG_ABORT_RSP_EVT, &data);
    avdt_scb_event(pscb, AVDT_SCB_TC_CLOSE_EVT, &data);
    ASSERT_EQ(AVDT_RemoveStream(scb_handle_), AVDT_SUCCESS);
    // fallback to default settings (delay report + sink)
    pscb->stream_config.cfg.psc_mask = AVDT_PSC_DELAY_RPT;
    pscb->stream_config.tsep = AVDT_TSEP_SNK;
  }
};

AvdtpRcb StackAvdtpTest::reg_ctrl_block_{};
uint8_t StackAvdtpTest::callback_event_ = AVDT_MAX_EVT + 1;
uint8_t StackAvdtpTest::scb_handle_ = 0;

TEST_F(StackAvdtpTest, test_delay_report_as_accept) {
  // Get SCB ready to send response
  auto pscb = avdt_scb_by_hdl(scb_handle_);
  pscb->in_use = true;

  // Send SetConfig response
  uint8_t label = 0;
  uint8_t err_code = 0;
  uint8_t category = 0;

  mock_avdt_msg_send_cmd_clear_history();
  mock_avdt_msg_send_rsp_clear_history();
  ASSERT_EQ(AVDT_ConfigRsp(scb_handle_, label, err_code, category), AVDT_SUCCESS);

  // Config response sent
  ASSERT_EQ(mock_function_count_map["avdt_msg_send_rsp"], 1);
  ASSERT_EQ(mock_avdt_msg_send_rsp_get_sig_id_at(0), AVDT_SIG_SETCONFIG);

  // Delay report command sent
  ASSERT_EQ(mock_function_count_map["avdt_msg_send_cmd"], 1);
  ASSERT_EQ(mock_avdt_msg_send_cmd_get_sig_id_at(0), AVDT_SIG_DELAY_RPT);

  // Delay report confirmed
  tAVDT_SCB_EVT data;
  ASSERT_EQ(mock_function_count_map["StreamCtrlCallback"], 0);
  avdt_scb_hdl_delay_rpt_rsp(pscb, &data);
  ASSERT_EQ(callback_event_, AVDT_DELAY_REPORT_CFM_EVT);
}

TEST_F(StackAvdtpTest, test_no_delay_report_if_not_sink) {
  // Get SCB ready to send response
  auto pscb = avdt_scb_by_hdl(scb_handle_);
  pscb->in_use = true;

  // Change the scb to SRC
  pscb->stream_config.tsep = AVDT_TSEP_SRC;

  // Send SetConfig response
  uint8_t label = 0;
  uint8_t err_code = 0;
  uint8_t category = 0;
  ASSERT_EQ(AVDT_ConfigRsp(scb_handle_, label, err_code, category), AVDT_SUCCESS);
  ASSERT_EQ(mock_function_count_map["avdt_msg_send_rsp"], 1); // Config response sent
  ASSERT_EQ(mock_function_count_map["avdt_msg_send_cmd"], 0); // Delay report command not sent
}

TEST_F(StackAvdtpTest, test_no_delay_report_if_not_enabled) {
  // Get SCB ready to send response
  auto pscb = avdt_scb_by_hdl(scb_handle_);
  pscb->in_use = true;

  // Disable the scb's delay report mask
  pscb->stream_config.cfg.psc_mask &= ~AVDT_PSC_DELAY_RPT;

  // Send SetConfig response
  uint8_t label = 0;
  uint8_t err_code = 0;
  uint8_t category = 0;
  ASSERT_EQ(AVDT_ConfigRsp(scb_handle_, label, err_code, category), AVDT_SUCCESS);
  ASSERT_EQ(mock_function_count_map["avdt_msg_send_rsp"], 1); // Config response sent
  ASSERT_EQ(mock_function_count_map["avdt_msg_send_cmd"], 0); // Delay report command not sent
}

TEST_F(StackAvdtpTest, test_delay_report_as_init) {
  auto pscb = avdt_scb_by_hdl(scb_handle_);
  pscb->in_use = true;

  tAVDT_SCB_EVT data;

  // Delay report -> Open command
  mock_avdt_msg_send_cmd_clear_history();
  avdt_scb_event(pscb, AVDT_SCB_MSG_SETCONFIG_RSP_EVT, &data);
  ASSERT_EQ(mock_function_count_map["avdt_msg_send_cmd"], 2);
  ASSERT_EQ(mock_avdt_msg_send_cmd_get_sig_id_at(0), AVDT_SIG_DELAY_RPT);
  ASSERT_EQ(mock_avdt_msg_send_cmd_get_sig_id_at(1), AVDT_SIG_OPEN);
}

TEST_F(StackAvdtpTest, test_SR_reporting_handler) {
  constexpr uint8_t sender_report_packet[] = {
      // Header
      0x80, 0xc8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      // Sender Info
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      // Report Block #1
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  uint16_t packet_length = sizeof(sender_report_packet);
  tAVDT_SCB_EVT data;
  auto pscb = avdt_scb_by_hdl(scb_handle_);

  data.p_pkt = (BT_HDR*)osi_calloc(sizeof(BT_HDR) + packet_length);
  *data.p_pkt = {.len = packet_length, .layer_specific = AVDT_CHAN_REPORT};
  memcpy(data.p_pkt->data, sender_report_packet, packet_length);
  avdt_scb_hdl_pkt(pscb, &data);
  ASSERT_EQ(mock_function_count_map["AvdtReportCallback"], 1);

  // no payload
  data.p_pkt = (BT_HDR*)osi_calloc(sizeof(BT_HDR) + packet_length);
  *data.p_pkt = {.layer_specific = AVDT_CHAN_REPORT};
  memcpy(data.p_pkt->data, sender_report_packet, packet_length);
  avdt_scb_hdl_pkt(pscb, &data);
  ASSERT_EQ(mock_function_count_map["AvdtReportCallback"], 1);

  // only reporting header
  data.p_pkt = (BT_HDR*)osi_calloc(sizeof(BT_HDR) + packet_length);
  *data.p_pkt = {.len = 8, .layer_specific = AVDT_CHAN_REPORT};
  memcpy(data.p_pkt->data, sender_report_packet, packet_length);
  avdt_scb_hdl_pkt(pscb, &data);
  ASSERT_EQ(mock_function_count_map["AvdtReportCallback"], 1);

  // reporting header + sender info
  data.p_pkt = (BT_HDR*)osi_calloc(sizeof(BT_HDR) + packet_length);
  *data.p_pkt = {.len = 28, .layer_specific = AVDT_CHAN_REPORT};
  memcpy(data.p_pkt->data, sender_report_packet, packet_length);
  avdt_scb_hdl_pkt(pscb, &data);
  ASSERT_EQ(mock_function_count_map["AvdtReportCallback"], 2);
}

TEST_F(StackAvdtpTest, test_RR_reporting_handler) {
  constexpr uint8_t receiver_report_packet[] = {
      // Header
      0x80, 0xc9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      // Report Block #1
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  uint16_t packet_length = sizeof(receiver_report_packet);
  tAVDT_SCB_EVT data;
  auto pscb = avdt_scb_by_hdl(scb_handle_);

  data.p_pkt = (BT_HDR*)osi_calloc(sizeof(BT_HDR) + packet_length);
  *data.p_pkt = {.len = packet_length, .layer_specific = AVDT_CHAN_REPORT};
  memcpy(data.p_pkt->data, receiver_report_packet, packet_length);
  avdt_scb_hdl_pkt(pscb, &data);
  ASSERT_EQ(mock_function_count_map["AvdtReportCallback"], 1);

  // no payload
  data.p_pkt = (BT_HDR*)osi_calloc(sizeof(BT_HDR) + packet_length);
  *data.p_pkt = {.layer_specific = AVDT_CHAN_REPORT};
  memcpy(data.p_pkt->data, receiver_report_packet, packet_length);
  avdt_scb_hdl_pkt(pscb, &data);
  ASSERT_EQ(mock_function_count_map["AvdtReportCallback"], 1);

  // only reporting header
  data.p_pkt = (BT_HDR*)osi_calloc(sizeof(BT_HDR) + packet_length);
  *data.p_pkt = {.len = 8, .layer_specific = AVDT_CHAN_REPORT};
  memcpy(data.p_pkt->data, receiver_report_packet, packet_length);
  avdt_scb_hdl_pkt(pscb, &data);
  ASSERT_EQ(mock_function_count_map["AvdtReportCallback"], 1);

  // reporting header + report block
  data.p_pkt = (BT_HDR*)osi_calloc(sizeof(BT_HDR) + packet_length);
  *data.p_pkt = {.len = 32, .layer_specific = AVDT_CHAN_REPORT};
  memcpy(data.p_pkt->data, receiver_report_packet, packet_length);
  avdt_scb_hdl_pkt(pscb, &data);
  ASSERT_EQ(mock_function_count_map["AvdtReportCallback"], 2);
}

TEST_F(StackAvdtpTest, test_SDES_reporting_handler) {
  constexpr uint8_t source_description_packet[] = {// Header
                                                   0x80, 0xca, 0x00, 0x00,
                                                   // Chunk #1
                                                   0x00, 0x00, 0x00, 0x00,
                                                   // SDES Item (CNAME=1)
                                                   0x01, 0x05, 0x00, 0x00, 0x00,
                                                   0x00, 0x00, 0x00};
  uint16_t packet_length = sizeof(source_description_packet);
  tAVDT_SCB_EVT data;
  auto pscb = avdt_scb_by_hdl(scb_handle_);

  data.p_pkt = (BT_HDR*)osi_calloc(sizeof(BT_HDR) + packet_length);
  *data.p_pkt = {.len = packet_length, .layer_specific = AVDT_CHAN_REPORT};
  memcpy(data.p_pkt->data, source_description_packet, packet_length);
  avdt_scb_hdl_pkt(pscb, &data);
  ASSERT_EQ(mock_function_count_map["AvdtReportCallback"], 1);

  // no payload
  data.p_pkt = (BT_HDR*)osi_calloc(sizeof(BT_HDR) + packet_length);
  *data.p_pkt = {.layer_specific = AVDT_CHAN_REPORT};
  memcpy(data.p_pkt->data, source_description_packet, packet_length);
  avdt_scb_hdl_pkt(pscb, &data);
  ASSERT_EQ(mock_function_count_map["AvdtReportCallback"], 1);

  // only reporting header
  data.p_pkt = (BT_HDR*)osi_calloc(sizeof(BT_HDR) + packet_length);
  *data.p_pkt = {.len = 4, .layer_specific = AVDT_CHAN_REPORT};
  memcpy(data.p_pkt->data, source_description_packet, packet_length);
  avdt_scb_hdl_pkt(pscb, &data);
  ASSERT_EQ(mock_function_count_map["AvdtReportCallback"], 1);

  // SDES Item (CNAME) with empty value
  data.p_pkt = (BT_HDR*)osi_calloc(sizeof(BT_HDR) + packet_length);
  *data.p_pkt = {.len = 10, .layer_specific = AVDT_CHAN_REPORT};
  memcpy(data.p_pkt->data, source_description_packet, packet_length);
  avdt_scb_hdl_pkt(pscb, &data);
  ASSERT_EQ(mock_function_count_map["AvdtReportCallback"], 1);

  // SDES Item (not CNAME) which is not supported
  data.p_pkt = (BT_HDR*)osi_calloc(sizeof(BT_HDR) + packet_length);
  *data.p_pkt = {.len = 10, .layer_specific = AVDT_CHAN_REPORT};
  memcpy(data.p_pkt->data, source_description_packet, packet_length);
  *(data.p_pkt->data + 8) = 0x02;
  *(data.p_pkt->data + 9) = 0x00;
  avdt_scb_hdl_pkt(pscb, &data);
  ASSERT_EQ(mock_function_count_map["AvdtReportCallback"], 1);
}
