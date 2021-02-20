#include <base/logging.h>
#include <gtest/gtest.h>
#include "bta_hfp_api.h"

#undef LOG_TAG
#include "btif/src/btif_hf_client.cc"

static tBTA_HF_CLIENT_FEAT gFeatures;


uint8_t btif_trace_level = BT_TRACE_LEVEL_WARNING;
void LogMsg(uint32_t trace_set_mask, const char* fmt_str, ...) {}
tBTA_STATUS BTA_HfClientEnable(tBTA_HF_CLIENT_CBACK* p_cback,
                               tBTA_HF_CLIENT_FEAT features,
                               const char* p_service_name) {
  gFeatures = features;
  return BTA_SUCCESS;
}
void BTA_HfClientDisable(void) { }
bt_status_t btif_transfer_context(tBTIF_CBACK* p_cback, uint16_t event,
                                  char* p_params, int param_len,
                                  tBTIF_COPY_CBACK* p_copy_cback) {
  return BT_STATUS_SUCCESS;
}
void btif_queue_advance() {}
const char* dump_hf_client_event(uint16_t event) {
  return "UNKNOWN MSG ID";
}

class BtifHfClientTest : public ::testing::Test {
 protected:
  void SetUp() override {
    gFeatures = BTIF_HF_CLIENT_FEATURES;
  }

  void TearDown() override {}
};

TEST_F(BtifHfClientTest, test_btif_hf_cleint_service) {
  bool enable = true;

  btif_hf_client_execute_service(enable);
  ASSERT_EQ((gFeatures & BTA_HF_CLIENT_FEAT_ESCO_S4) > 0,
            BTA_HFP_VERSION >= HFP_VERSION_1_7);
}
