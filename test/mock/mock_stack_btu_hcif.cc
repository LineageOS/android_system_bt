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

/*
 * Generated mock file from original source file
 *   Functions generated:9
 */

#include <map>
#include <string>

extern std::map<std::string, int> mock_function_count_map;

#define LOG_TAG "bt_btu_hcif"
#include <base/bind.h>
#include <base/location.h>
#include <cstdint>
#include "btif/include/btif_config.h"
#include "common/metrics.h"
#include "device/include/controller.h"
#include "osi/include/log.h"
#include "stack/include/acl_hci_link_interface.h"
#include "stack/include/ble_acl_interface.h"
#include "stack/include/ble_hci_link_interface.h"
#include "stack/include/btm_iso_api.h"
#include "stack/include/btu.h"
#include "stack/include/dev_hci_link_interface.h"
#include "stack/include/gatt_api.h"
#include "stack/include/hci_evt_length.h"
#include "stack/include/hcidefs.h"
#include "stack/include/inq_hci_link_interface.h"
#include "stack/include/l2cap_hci_link_interface.h"
#include "stack/include/sco_hci_link_interface.h"
#include "stack/include/sec_hci_link_interface.h"

#ifndef UNUSED_ATTR
#define UNUSED_ATTR
#endif

using hci_cmd_cb = base::OnceCallback<void(
    uint8_t* /* return_parameters */, uint16_t /* return_parameters_length*/)>;

struct cmd_with_cb_data {
  hci_cmd_cb cb;
  base::Location posted_from;
};

void btu_hcif_log_event_metrics(uint8_t evt_code, uint8_t* p_event) {
  mock_function_count_map[__func__]++;
}
void btu_hcif_process_event(UNUSED_ATTR uint8_t controller_id, BT_HDR* p_msg) {
  mock_function_count_map[__func__]++;
}
void btu_hcif_send_cmd(UNUSED_ATTR uint8_t controller_id, BT_HDR* p_buf) {
  mock_function_count_map[__func__]++;
}
void btu_hcif_send_cmd_with_cb(const base::Location& posted_from,
                               uint16_t opcode, uint8_t* params,
                               uint8_t params_len, hci_cmd_cb cb) {
  mock_function_count_map[__func__]++;
}
void cmd_with_cb_data_cleanup(cmd_with_cb_data* cb_wrapper) {
  mock_function_count_map[__func__]++;
}
void cmd_with_cb_data_init(cmd_with_cb_data* cb_wrapper) {
  mock_function_count_map[__func__]++;
}
