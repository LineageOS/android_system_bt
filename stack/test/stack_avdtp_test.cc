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
  static AvdtpRcb _reg;
  static uint8_t _expected_stream_event;

  uint8_t scb_handle_;

 protected:
  static void _avdtcallback(UNUSED_ATTR uint8_t handle, const RawAddress& bd_addr,
   uint8_t event, tAVDT_CTRL* p_data, uint8_t scb_index) {
    mock_function_count_map[__func__]++;
  }

  static void _streamcallback(uint8_t handle, const RawAddress& bd_addr,
   uint8_t event, tAVDT_CTRL* p_data,
   uint8_t scb_index) {
    mock_function_count_map[__func__]++;
    ASSERT_EQ(event, _expected_stream_event);
  };

  static void SetUpTestCase() {
    _reg.ctrl_mtu = 672;
    _reg.ret_tout = 4;
    _reg.sig_tout = 4;
    _reg.idle_tout = 10;
    _reg.scb_index = 0;
    AVDT_Register(&_reg, _avdtcallback);
  }

  static void TearDownTestCase() {
    AVDT_Deregister();
  }

  void SetUp() override {
    uint8_t peer_id = 1;
    scb_handle_ = 0;
    _expected_stream_event = 0;
    AvdtpStreamConfig avdtp_stream_config;
    avdtp_stream_config.cfg.psc_mask = AVDT_PSC_DELAY_RPT;
    avdtp_stream_config.tsep = AVDT_TSEP_SNK;
    avdtp_stream_config.p_avdt_ctrl_cback = _streamcallback;
    mock_function_count_map["_streamcallback"] = 0;

    ASSERT_EQ(AVDT_CreateStream(peer_id, &scb_handle_, avdtp_stream_config), AVDT_SUCCESS);
  }

  void TearDown() override {
    ASSERT_EQ(AVDT_RemoveStream(scb_handle_), AVDT_SUCCESS);
  }

  void StreamCallBackExpect(uint8_t event) {
    _expected_stream_event = event;
  }
};

AvdtpRcb StackAvdtpTest::_reg{};
uint8_t StackAvdtpTest::_expected_stream_event = 0;

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
  mock_function_count_map["avdt_msg_send_rsp"] = 0;
  mock_function_count_map["avdt_msg_send_cmd"] = 0;
  ASSERT_EQ(AVDT_ConfigRsp(scb_handle_, label, err_code, category), AVDT_SUCCESS);

  // Config response sent
  ASSERT_EQ(mock_function_count_map["avdt_msg_send_rsp"], 1);
  ASSERT_EQ(mock_avdt_msg_send_rsp_get_sig_id_at(0), AVDT_SIG_SETCONFIG);

  // Delay report command sent
  ASSERT_EQ(mock_function_count_map["avdt_msg_send_cmd"], 1);
  ASSERT_EQ(mock_avdt_msg_send_cmd_get_sig_id_at(0), AVDT_SIG_DELAY_RPT);

  // Delay report confirmed
  tAVDT_SCB_EVT data;
  ASSERT_EQ(mock_function_count_map["_streamcallback"], 0);
  StreamCallBackExpect(AVDT_DELAY_REPORT_CFM_EVT);
  avdt_scb_hdl_delay_rpt_rsp(pscb, &data);
  ASSERT_EQ(mock_function_count_map["_streamcallback"], 1);
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
  mock_function_count_map["avdt_msg_send_rsp"] = 0;
  mock_function_count_map["avdt_msg_send_cmd"] = 0;
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
  mock_function_count_map["avdt_msg_send_rsp"] = 0;
  mock_function_count_map["avdt_msg_send_cmd"] = 0;
  ASSERT_EQ(AVDT_ConfigRsp(scb_handle_, label, err_code, category), AVDT_SUCCESS);
  ASSERT_EQ(mock_function_count_map["avdt_msg_send_rsp"], 1); // Config response sent
  ASSERT_EQ(mock_function_count_map["avdt_msg_send_cmd"], 0); // Delay report command not sent
}

TEST_F(StackAvdtpTest, test_delay_report_as_init) {
  auto pscb = avdt_scb_by_hdl(scb_handle_);

  tAVDT_SCB_EVT data;

  mock_function_count_map["avdt_msg_send_cmd"] = 0;

  // Delay report -> Open command
  mock_avdt_msg_send_cmd_clear_history();
  avdt_scb_event(pscb, AVDT_SCB_MSG_SETCONFIG_RSP_EVT, &data);
  ASSERT_EQ(mock_function_count_map["avdt_msg_send_cmd"], 2);
  ASSERT_EQ(mock_avdt_msg_send_cmd_get_sig_id_at(0), AVDT_SIG_DELAY_RPT);
  ASSERT_EQ(mock_avdt_msg_send_cmd_get_sig_id_at(1), AVDT_SIG_OPEN);
}

