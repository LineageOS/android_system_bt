/******************************************************************************
 *
 *  Copyright 2009-2012 Broadcom Corporation
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

/*******************************************************************************
 *
 *  Filename:      bluetooth.c
 *
 *  Description:   Bluetooth HAL implementation
 *
 ******************************************************************************/

#define LOG_TAG "bt_btif"

#include <base/logging.h>
#include <hardware/bluetooth.h>
#include <hardware/bluetooth_headset_interface.h>
#include <hardware/bt_av.h>
#include <hardware/bt_gatt.h>
#include <hardware/bt_hd.h>
#include <hardware/bt_hearing_aid.h>
#include <hardware/bt_hf_client.h>
#include <hardware/bt_hh.h>
#include <hardware/bt_le_audio.h>
#include <hardware/bt_pan.h>
#include <hardware/bt_rc.h>
#include <hardware/bt_sdp.h>
#include <hardware/bt_sock.h>
#include <hardware/bt_vc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "bt_utils.h"
#include "bta/include/bta_hearing_aid_api.h"
#include "bta/include/bta_hf_client_api.h"
#include "btif/avrcp/avrcp_service.h"
#include "btif_a2dp.h"
#include "btif_activity_attribution.h"
#include "btif_api.h"
#include "btif_av.h"
#include "btif_bqr.h"
#include "btif_config.h"
#include "btif_debug.h"
#include "btif_debug_btsnoop.h"
#include "btif_debug_conn.h"
#include "btif_hf.h"
#include "btif_keystore.h"
#include "btif_metrics_logging.h"
#include "btif_storage.h"
#include "btsnoop.h"
#include "btsnoop_mem.h"
#include "common/address_obfuscator.h"
#include "common/metric_id_allocator.h"
#include "common/metrics.h"
#include "common/os_utils.h"
#include "device/include/interop.h"
#include "gd/common/init_flags.h"
#include "main/shim/dumpsys.h"
#include "main/shim/shim.h"
#include "osi/include/alarm.h"
#include "osi/include/allocation_tracker.h"
#include "osi/include/log.h"
#include "osi/include/osi.h"
#include "osi/include/wakelock.h"
#include "stack/gatt/connection_manager.h"
#include "stack/include/avdt_api.h"
#include "stack/include/btm_api.h"
#include "stack/include/btu.h"
#include "stack_manager.h"

using bluetooth::hearing_aid::HearingAidInterface;
using bluetooth::le_audio::LeAudioClientInterface;
using bluetooth::vc::VolumeControlInterface;

/*******************************************************************************
 *  Static variables
 ******************************************************************************/

static bt_callbacks_t* bt_hal_cbacks = NULL;
bool restricted_mode = false;
bool common_criteria_mode = false;
const int CONFIG_COMPARE_ALL_PASS = 0b11;
int common_criteria_config_compare_result = CONFIG_COMPARE_ALL_PASS;
bool is_local_device_atv = false;

/*******************************************************************************
 *  Externs
 ******************************************************************************/

/* list all extended interfaces here */

/* handsfree profile - client */
extern const bthf_client_interface_t* btif_hf_client_get_interface();
/* advanced audio profile */
extern const btav_source_interface_t* btif_av_get_src_interface();
extern const btav_sink_interface_t* btif_av_get_sink_interface();
/*rfc l2cap*/
extern const btsock_interface_t* btif_sock_get_interface();
/* hid host profile */
extern const bthh_interface_t* btif_hh_get_interface();
/* hid device profile */
extern const bthd_interface_t* btif_hd_get_interface();
/*pan*/
extern const btpan_interface_t* btif_pan_get_interface();
/* gatt */
extern const btgatt_interface_t* btif_gatt_get_interface();
/* avrc target */
extern const btrc_interface_t* btif_rc_get_interface();
/* avrc controller */
extern const btrc_ctrl_interface_t* btif_rc_ctrl_get_interface();
/*SDP search client*/
extern const btsdp_interface_t* btif_sdp_get_interface();
/*Hearing Aid client*/
extern HearingAidInterface* btif_hearing_aid_get_interface();
/* LeAudio testi client */
extern LeAudioClientInterface* btif_le_audio_get_interface();
/* Volume Control client */
extern VolumeControlInterface* btif_volume_control_get_interface();

/*******************************************************************************
 *  Functions
 ******************************************************************************/

static bool interface_ready(void) { return bt_hal_cbacks != NULL; }
void set_hal_cbacks(bt_callbacks_t* callbacks) { bt_hal_cbacks = callbacks; }

static bool is_profile(const char* p1, const char* p2) {
  CHECK(p1);
  CHECK(p2);
  return strlen(p1) == strlen(p2) && strncmp(p1, p2, strlen(p2)) == 0;
}

/*****************************************************************************
 *
 *   BLUETOOTH HAL INTERFACE FUNCTIONS
 *
 ****************************************************************************/

static int init(bt_callbacks_t* callbacks, bool start_restricted,
                bool is_common_criteria_mode, int config_compare_result,
                const char** init_flags, bool is_atv) {
  LOG_INFO(
      "%s: start restricted = %d ; common criteria mode = %d, config compare "
      "result = %d",
      __func__, start_restricted, is_common_criteria_mode,
      config_compare_result);

  bluetooth::common::InitFlags::Load(init_flags);

  if (interface_ready()) return BT_STATUS_DONE;

#ifdef BLUEDROID_DEBUG
  allocation_tracker_init();
#endif

  set_hal_cbacks(callbacks);

  restricted_mode = start_restricted;
  common_criteria_mode = is_common_criteria_mode;
  common_criteria_config_compare_result = config_compare_result;
  is_local_device_atv = is_atv;

  stack_manager_get_interface()->init_stack();
  btif_debug_init();
  return BT_STATUS_SUCCESS;
}

static int enable() {
  if (!interface_ready()) return BT_STATUS_NOT_READY;

  stack_manager_get_interface()->start_up_stack_async();
  return BT_STATUS_SUCCESS;
}

static int disable(void) {
  if (!interface_ready()) return BT_STATUS_NOT_READY;

  stack_manager_get_interface()->shut_down_stack_async();
  return BT_STATUS_SUCCESS;
}

static void cleanup(void) { stack_manager_get_interface()->clean_up_stack(); }

bool is_restricted_mode() { return restricted_mode; }
bool is_common_criteria_mode() {
  return is_bluetooth_uid() && common_criteria_mode;
}
// if common criteria mode disable, will always return
// CONFIG_COMPARE_ALL_PASS(0b11) indicate don't check config checksum.
int get_common_criteria_config_compare_result() {
  return is_common_criteria_mode() ? common_criteria_config_compare_result
                                   : CONFIG_COMPARE_ALL_PASS;
}

bool is_atv_device() { return is_local_device_atv; }

static int get_adapter_properties(void) {
  if (!btif_is_enabled()) return BT_STATUS_NOT_READY;

  do_in_main_thread(FROM_HERE, base::BindOnce(btif_get_adapter_properties));
  return BT_STATUS_SUCCESS;
}

static int get_adapter_property(bt_property_type_t type) {
  /* Allow get_adapter_property only for BDADDR and BDNAME if BT is disabled */
  if (!btif_is_enabled() && (type != BT_PROPERTY_BDADDR) &&
      (type != BT_PROPERTY_BDNAME) && (type != BT_PROPERTY_CLASS_OF_DEVICE))
    return BT_STATUS_NOT_READY;

  do_in_main_thread(FROM_HERE, base::BindOnce(btif_get_adapter_property, type));
  return BT_STATUS_SUCCESS;
}

static int set_adapter_property(const bt_property_t* property) {
  if (!btif_is_enabled()) return BT_STATUS_NOT_READY;

  switch (property->type) {
    case BT_PROPERTY_BDNAME:
    case BT_PROPERTY_ADAPTER_SCAN_MODE:
    case BT_PROPERTY_ADAPTER_DISCOVERY_TIMEOUT:
    case BT_PROPERTY_CLASS_OF_DEVICE:
    case BT_PROPERTY_LOCAL_IO_CAPS:
    case BT_PROPERTY_LOCAL_IO_CAPS_BLE:
      break;
    default:
      return BT_STATUS_FAIL;
  }

  do_in_main_thread(FROM_HERE, base::BindOnce(
                                   [](bt_property_t* property) {
                                     btif_set_adapter_property(property);
                                     osi_free(property);
                                   },
                                   property_deep_copy(property)));
  return BT_STATUS_SUCCESS;
}

int get_remote_device_properties(RawAddress* remote_addr) {
  if (!btif_is_enabled()) return BT_STATUS_NOT_READY;

  do_in_main_thread(FROM_HERE, base::BindOnce(btif_get_remote_device_properties,
                                              *remote_addr));
  return BT_STATUS_SUCCESS;
}

int get_remote_device_property(RawAddress* remote_addr,
                               bt_property_type_t type) {
  if (!btif_is_enabled()) return BT_STATUS_NOT_READY;

  do_in_main_thread(FROM_HERE, base::BindOnce(btif_get_remote_device_property,
                                              *remote_addr, type));
  return BT_STATUS_SUCCESS;
}

int set_remote_device_property(RawAddress* remote_addr,
                               const bt_property_t* property) {
  if (!btif_is_enabled()) return BT_STATUS_NOT_READY;

  do_in_main_thread(
      FROM_HERE, base::BindOnce(
                     [](RawAddress remote_addr, bt_property_t* property) {
                       btif_set_remote_device_property(&remote_addr, property);
                       osi_free(property);
                     },
                     *remote_addr, property_deep_copy(property)));
  return BT_STATUS_SUCCESS;
}

int get_remote_services(RawAddress* remote_addr) {
  if (!interface_ready()) return BT_STATUS_NOT_READY;

  do_in_main_thread(FROM_HERE,
                    base::BindOnce(btif_dm_get_remote_services, *remote_addr,
                                   BT_TRANSPORT_UNKNOWN));
  return BT_STATUS_SUCCESS;
}

static int start_discovery(void) {
  if (!interface_ready()) return BT_STATUS_NOT_READY;

  do_in_main_thread(FROM_HERE, base::BindOnce(btif_dm_start_discovery));
  return BT_STATUS_SUCCESS;
}

static int cancel_discovery(void) {
  if (!interface_ready()) return BT_STATUS_NOT_READY;

  do_in_main_thread(FROM_HERE, base::BindOnce(btif_dm_cancel_discovery));
  return BT_STATUS_SUCCESS;
}

static int create_bond(const RawAddress* bd_addr, int transport) {
  if (!interface_ready()) return BT_STATUS_NOT_READY;
  if (btif_dm_pairing_is_busy()) return BT_STATUS_BUSY;

  do_in_main_thread(FROM_HERE,
                    base::BindOnce(btif_dm_create_bond, *bd_addr, transport));
  return BT_STATUS_SUCCESS;
}

static int create_bond_out_of_band(const RawAddress* bd_addr, int transport,
                                   const bt_oob_data_t* p192_data,
                                   const bt_oob_data_t* p256_data) {
  if (!interface_ready()) return BT_STATUS_NOT_READY;
  if (btif_dm_pairing_is_busy()) return BT_STATUS_BUSY;

  do_in_main_thread(FROM_HERE,
                    base::BindOnce(btif_dm_create_bond_out_of_band, *bd_addr,
                                   transport, *p192_data, *p256_data));
  return BT_STATUS_SUCCESS;
}

static int generate_local_oob_data(tBT_TRANSPORT transport) {
  LOG_INFO("%s", __func__);
  if (!interface_ready()) return BT_STATUS_NOT_READY;

  return do_in_main_thread(
      FROM_HERE, base::BindOnce(btif_dm_generate_local_oob_data, transport));
}

static int cancel_bond(const RawAddress* bd_addr) {
  if (!interface_ready()) return BT_STATUS_NOT_READY;

  do_in_main_thread(FROM_HERE, base::BindOnce(btif_dm_cancel_bond, *bd_addr));
  return BT_STATUS_SUCCESS;
}

static int remove_bond(const RawAddress* bd_addr) {
  if (is_restricted_mode() && !btif_storage_is_restricted_device(bd_addr))
    return BT_STATUS_SUCCESS;

  if (!interface_ready()) return BT_STATUS_NOT_READY;

  do_in_main_thread(FROM_HERE, base::BindOnce(btif_dm_remove_bond, *bd_addr));
  return BT_STATUS_SUCCESS;
}

static int get_connection_state(const RawAddress* bd_addr) {
  if (!interface_ready()) return 0;

  return btif_dm_get_connection_state(bd_addr);
}

static int pin_reply(const RawAddress* bd_addr, uint8_t accept, uint8_t pin_len,
                     bt_pin_code_t* pin_code) {
  if (!interface_ready()) return BT_STATUS_NOT_READY;
  if (pin_code == nullptr || pin_len > PIN_CODE_LEN) return BT_STATUS_FAIL;

  do_in_main_thread(FROM_HERE, base::BindOnce(btif_dm_pin_reply, *bd_addr,
                                              accept, pin_len, *pin_code));
  return BT_STATUS_SUCCESS;
}

static int ssp_reply(const RawAddress* bd_addr, bt_ssp_variant_t variant,
                     uint8_t accept, uint32_t passkey) {
  if (!interface_ready()) return BT_STATUS_NOT_READY;
  if (variant == BT_SSP_VARIANT_PASSKEY_ENTRY) return BT_STATUS_FAIL;

  do_in_main_thread(
      FROM_HERE, base::BindOnce(btif_dm_ssp_reply, *bd_addr, variant, accept));
  return BT_STATUS_SUCCESS;
}

static int read_energy_info() {
  if (!interface_ready()) return BT_STATUS_NOT_READY;

  do_in_main_thread(FROM_HERE, base::BindOnce(btif_dm_read_energy_info));
  return BT_STATUS_SUCCESS;
}

static void dump(int fd, const char** arguments) {
  btif_debug_conn_dump(fd);
  btif_debug_bond_event_dump(fd);
  btif_debug_a2dp_dump(fd);
  btif_debug_av_dump(fd);
  bta_debug_av_dump(fd);
  stack_debug_avdtp_api_dump(fd);
  bluetooth::avrcp::AvrcpService::DebugDump(fd);
  btif_debug_config_dump(fd);
  BTA_HfClientDumpStatistics(fd);
  wakelock_debug_dump(fd);
  osi_allocator_debug_dump(fd);
  alarm_debug_dump(fd);
  HearingAid::DebugDump(fd);
  connection_manager::dump(fd);
  bluetooth::bqr::DebugDump(fd);
  if (bluetooth::shim::is_any_gd_enabled()) {
    bluetooth::shim::Dump(fd, arguments);
  } else {
#if (BTSNOOP_MEM == TRUE)
    btif_debug_btsnoop_dump(fd);
#endif
  }
}

static void dumpMetrics(std::string* output) {
  bluetooth::common::BluetoothMetricsLogger::GetInstance()->WriteString(output);
}

static const void* get_profile_interface(const char* profile_id) {
  LOG_INFO("%s: id = %s", __func__, profile_id);

  /* sanity check */
  if (!interface_ready()) return NULL;

  /* check for supported profile interfaces */
  if (is_profile(profile_id, BT_PROFILE_HANDSFREE_ID))
    return bluetooth::headset::GetInterface();

  if (is_profile(profile_id, BT_PROFILE_HANDSFREE_CLIENT_ID))
    return btif_hf_client_get_interface();

  if (is_profile(profile_id, BT_PROFILE_SOCKETS_ID))
    return btif_sock_get_interface();

  if (is_profile(profile_id, BT_PROFILE_PAN_ID))
    return btif_pan_get_interface();

  if (is_profile(profile_id, BT_PROFILE_ADVANCED_AUDIO_ID))
    return btif_av_get_src_interface();

  if (is_profile(profile_id, BT_PROFILE_ADVANCED_AUDIO_SINK_ID))
    return btif_av_get_sink_interface();

  if (is_profile(profile_id, BT_PROFILE_HIDHOST_ID))
    return btif_hh_get_interface();

  if (is_profile(profile_id, BT_PROFILE_HIDDEV_ID))
    return btif_hd_get_interface();

  if (is_profile(profile_id, BT_PROFILE_SDP_CLIENT_ID))
    return btif_sdp_get_interface();

  if (is_profile(profile_id, BT_PROFILE_GATT_ID))
    return btif_gatt_get_interface();

  if (is_profile(profile_id, BT_PROFILE_AV_RC_ID))
    return btif_rc_get_interface();

  if (is_profile(profile_id, BT_PROFILE_AV_RC_CTRL_ID))
    return btif_rc_ctrl_get_interface();

  if (is_profile(profile_id, BT_PROFILE_HEARING_AID_ID))
    return btif_hearing_aid_get_interface();

  if (is_profile(profile_id, BT_KEYSTORE_ID))
    return bluetooth::bluetooth_keystore::getBluetoothKeystoreInterface();

  if (is_profile(profile_id, BT_ACTIVITY_ATTRIBUTION_ID)) {
    return bluetooth::activity_attribution::get_activity_attribution_instance();
  }

  if (is_profile(profile_id, BT_PROFILE_LE_AUDIO_ID))
    return btif_le_audio_get_interface();

  if (is_profile(profile_id, BT_PROFILE_VC_ID))
    return btif_volume_control_get_interface();

  return NULL;
}

int dut_mode_configure(uint8_t enable) {
  if (!interface_ready()) return BT_STATUS_NOT_READY;
  if (!stack_manager_get_interface()->get_stack_is_running())
    return BT_STATUS_NOT_READY;

  do_in_main_thread(FROM_HERE, base::BindOnce(btif_dut_mode_configure, enable));
  return BT_STATUS_SUCCESS;
}

int dut_mode_send(uint16_t opcode, uint8_t* buf, uint8_t len) {
  if (!interface_ready()) return BT_STATUS_NOT_READY;
  if (!btif_is_dut_mode()) return BT_STATUS_FAIL;

  uint8_t* copy = (uint8_t*)osi_calloc(len);
  memcpy(copy, buf, len);

  do_in_main_thread(FROM_HERE,
                    base::BindOnce(
                        [](uint16_t opcode, uint8_t* buf, uint8_t len) {
                          btif_dut_mode_send(opcode, buf, len);
                          osi_free(buf);
                        },
                        opcode, copy, len));
  return BT_STATUS_SUCCESS;
}

int le_test_mode(uint16_t opcode, uint8_t* buf, uint8_t len) {
  if (!interface_ready()) return BT_STATUS_NOT_READY;

  switch (opcode) {
    case HCI_BLE_TRANSMITTER_TEST:
      if (len != 3) return BT_STATUS_PARM_INVALID;
      do_in_main_thread(FROM_HERE, base::BindOnce(btif_ble_transmitter_test,
                                                  buf[0], buf[1], buf[2]));
      break;
    case HCI_BLE_RECEIVER_TEST:
      if (len != 1) return BT_STATUS_PARM_INVALID;
      do_in_main_thread(FROM_HERE,
                        base::BindOnce(btif_ble_receiver_test, buf[0]));
      break;
    case HCI_BLE_TEST_END:
      do_in_main_thread(FROM_HERE, base::BindOnce(btif_ble_test_end));
      break;
    default:
      return BT_STATUS_UNSUPPORTED;
  }
  return BT_STATUS_SUCCESS;
}

static bt_os_callouts_t* wakelock_os_callouts_saved = nullptr;

static int acquire_wake_lock_cb(const char* lock_name) {
  return do_in_jni_thread(
      FROM_HERE, base::Bind(base::IgnoreResult(
                                wakelock_os_callouts_saved->acquire_wake_lock),
                            lock_name));
}

static int release_wake_lock_cb(const char* lock_name) {
  return do_in_jni_thread(
      FROM_HERE, base::Bind(base::IgnoreResult(
                                wakelock_os_callouts_saved->release_wake_lock),
                            lock_name));
}

static bt_os_callouts_t wakelock_os_callouts_jni = {
    sizeof(wakelock_os_callouts_jni),
    nullptr /* not used */,
    acquire_wake_lock_cb,
    release_wake_lock_cb,
};

static int set_os_callouts(bt_os_callouts_t* callouts) {
  wakelock_os_callouts_saved = callouts;
  wakelock_set_os_callouts(&wakelock_os_callouts_jni);
  return BT_STATUS_SUCCESS;
}

static int config_clear(void) {
  LOG_INFO("%s", __func__);
  return btif_config_clear() ? BT_STATUS_SUCCESS : BT_STATUS_FAIL;
}

static bluetooth::avrcp::ServiceInterface* get_avrcp_service(void) {
  return bluetooth::avrcp::AvrcpService::GetServiceInterface();
}

static std::string obfuscate_address(const RawAddress& address) {
  return bluetooth::common::AddressObfuscator::GetInstance()->Obfuscate(
      address);
}

static int get_metric_id(const RawAddress& address) {
  return allocate_metric_id_from_metric_id_allocator(address);
}

static int set_dynamic_audio_buffer_size(int codec, int size) {
  return btif_set_dynamic_audio_buffer_size(codec, size);
}

EXPORT_SYMBOL bt_interface_t bluetoothInterface = {
    sizeof(bluetoothInterface),
    init,
    enable,
    disable,
    cleanup,
    get_adapter_properties,
    get_adapter_property,
    set_adapter_property,
    get_remote_device_properties,
    get_remote_device_property,
    set_remote_device_property,
    nullptr,
    get_remote_services,
    start_discovery,
    cancel_discovery,
    create_bond,
    create_bond_out_of_band,
    remove_bond,
    cancel_bond,
    get_connection_state,
    pin_reply,
    ssp_reply,
    get_profile_interface,
    dut_mode_configure,
    dut_mode_send,
    le_test_mode,
    set_os_callouts,
    read_energy_info,
    dump,
    dumpMetrics,
    config_clear,
    interop_database_clear,
    interop_database_add,
    get_avrcp_service,
    obfuscate_address,
    get_metric_id,
    set_dynamic_audio_buffer_size,
    generate_local_oob_data};

// callback reporting helpers

bt_property_t* property_deep_copy_array(int num_properties,
                                        bt_property_t* properties) {
  bt_property_t* copy = nullptr;
  if (num_properties > 0) {
    size_t content_len = 0;
    for (int i = 0; i < num_properties; i++) {
      auto len = properties[i].len;
      if (len > 0) {
        content_len += len;
      }
    }

    copy = (bt_property_t*)osi_calloc((sizeof(bt_property_t) * num_properties) +
                                      content_len);
    uint8_t* content = (uint8_t*)(copy + num_properties);

    for (int i = 0; i < num_properties; i++) {
      auto len = properties[i].len;
      copy[i].type = properties[i].type;
      copy[i].len = len;
      if (len <= 0) {
        continue;
      }
      copy[i].val = content;
      memcpy(content, properties[i].val, len);
      content += len;
    }
  }
  return copy;
}

void invoke_adapter_state_changed_cb(bt_state_t state) {
  do_in_jni_thread(FROM_HERE, base::BindOnce(
                                  [](bt_state_t state) {
                                    HAL_CBACK(bt_hal_cbacks,
                                              adapter_state_changed_cb, state);
                                  },
                                  state));
}

void invoke_adapter_properties_cb(bt_status_t status, int num_properties,
                                  bt_property_t* properties) {
  do_in_jni_thread(FROM_HERE,
                   base::BindOnce(
                       [](bt_status_t status, int num_properties,
                          bt_property_t* properties) {
                         HAL_CBACK(bt_hal_cbacks, adapter_properties_cb, status,
                                   num_properties, properties);
                         if (properties) {
                           osi_free(properties);
                         }
                       },
                       status, num_properties,
                       property_deep_copy_array(num_properties, properties)));
}

void invoke_remote_device_properties_cb(bt_status_t status, RawAddress bd_addr,
                                        int num_properties,
                                        bt_property_t* properties) {
  do_in_jni_thread(
      FROM_HERE, base::BindOnce(
                     [](bt_status_t status, RawAddress bd_addr,
                        int num_properties, bt_property_t* properties) {
                       HAL_CBACK(bt_hal_cbacks, remote_device_properties_cb,
                                 status, &bd_addr, num_properties, properties);
                       if (properties) {
                         osi_free(properties);
                       }
                     },
                     status, bd_addr, num_properties,
                     property_deep_copy_array(num_properties, properties)));
}

void invoke_device_found_cb(int num_properties, bt_property_t* properties) {
  do_in_jni_thread(FROM_HERE,
                   base::BindOnce(
                       [](int num_properties, bt_property_t* properties) {
                         HAL_CBACK(bt_hal_cbacks, device_found_cb,
                                   num_properties, properties);
                         if (properties) {
                           osi_free(properties);
                         }
                       },
                       num_properties,
                       property_deep_copy_array(num_properties, properties)));
}

void invoke_discovery_state_changed_cb(bt_discovery_state_t state) {
  do_in_jni_thread(FROM_HERE, base::BindOnce(
                                  [](bt_discovery_state_t state) {
                                    HAL_CBACK(bt_hal_cbacks,
                                              discovery_state_changed_cb,
                                              state);
                                  },
                                  state));
}

void invoke_pin_request_cb(RawAddress bd_addr, bt_bdname_t bd_name,
                           uint32_t cod, bool min_16_digit) {
  do_in_jni_thread(FROM_HERE, base::BindOnce(
                                  [](RawAddress bd_addr, bt_bdname_t bd_name,
                                     uint32_t cod, bool min_16_digit) {
                                    HAL_CBACK(bt_hal_cbacks, pin_request_cb,
                                              &bd_addr, &bd_name, cod,
                                              min_16_digit);
                                  },
                                  bd_addr, bd_name, cod, min_16_digit));
}

void invoke_ssp_request_cb(RawAddress bd_addr, bt_bdname_t bd_name,
                           uint32_t cod, bt_ssp_variant_t pairing_variant,
                           uint32_t pass_key) {
  do_in_jni_thread(FROM_HERE,
                   base::BindOnce(
                       [](RawAddress bd_addr, bt_bdname_t bd_name, uint32_t cod,
                          bt_ssp_variant_t pairing_variant, uint32_t pass_key) {
                         HAL_CBACK(bt_hal_cbacks, ssp_request_cb, &bd_addr,
                                   &bd_name, cod, pairing_variant, pass_key);
                       },
                       bd_addr, bd_name, cod, pairing_variant, pass_key));
}

void invoke_oob_data_request_cb(tBT_TRANSPORT t, bool valid, Octet16 c,
                                Octet16 r, RawAddress raw_address,
                                uint8_t address_type) {
  LOG_INFO("%s", __func__);
  bt_oob_data_t oob_data = {};
  char* local_name;
  BTM_ReadLocalDeviceName(&local_name);
  for (int i = 0; i < BTM_MAX_LOC_BD_NAME_LEN; i++) {
    oob_data.device_name[i] = local_name[i];
  }

  // Set the local address
  int j = 5;
  for (int i = 0; i < 6; i++) {
    oob_data.address[i] = raw_address.address[j];
    j--;
  }
  oob_data.address[6] = address_type;

  // Each value (for C and R) is 16 octets in length
  bool c_empty = true;
  for (int i = 0; i < 16; i++) {
    // C cannot be all 0s, if so then we want to fail
    if (c[i] != 0) c_empty = false;
    oob_data.c[i] = c[i];
    // R is optional and may be empty
    oob_data.r[i] = r[i];
  }
  oob_data.is_valid = valid && !c_empty;
  // The oob_data_length is 2 octects in length.  The value includes the length
  // of itself. 16 + 16 + 2 = 34 Data 0x0022 Little Endian order 0x2200
  oob_data.oob_data_length[0] = 0;
  oob_data.oob_data_length[1] = 34;
  bt_status_t status = do_in_jni_thread(
      FROM_HERE, base::BindOnce(
                     [](tBT_TRANSPORT t, bt_oob_data_t oob_data) {
                       HAL_CBACK(bt_hal_cbacks, generate_local_oob_data_cb, t,
                                 oob_data);
                     },
                     t, oob_data));
  if (status != BT_STATUS_SUCCESS) {
    LOG_ERROR("%s: Failed to call callback!", __func__);
  }
}

void invoke_bond_state_changed_cb(bt_status_t status, RawAddress bd_addr,
                                  bt_bond_state_t state) {
  do_in_jni_thread(
      FROM_HERE,
      base::BindOnce(
          [](bt_status_t status, RawAddress bd_addr, bt_bond_state_t state) {
            HAL_CBACK(bt_hal_cbacks, bond_state_changed_cb, status, &bd_addr,
                      state);
          },
          status, bd_addr, state));
}

void invoke_acl_state_changed_cb(bt_status_t status, RawAddress bd_addr,
                                 bt_acl_state_t state, bt_hci_error_code_t hci_reason) {
  do_in_jni_thread(
      FROM_HERE,
      base::BindOnce(
          [](bt_status_t status, RawAddress bd_addr, bt_acl_state_t state,
             bt_hci_error_code_t hci_reason) {
            HAL_CBACK(bt_hal_cbacks, acl_state_changed_cb, status, &bd_addr,
                      state, hci_reason);
          },
          status, bd_addr, state, hci_reason));
}

void invoke_thread_evt_cb(bt_cb_thread_evt event) {
  do_in_jni_thread(FROM_HERE, base::BindOnce(
                                  [](bt_cb_thread_evt event) {
                                    HAL_CBACK(bt_hal_cbacks, thread_evt_cb,
                                              event);
                                    if (event == DISASSOCIATE_JVM) {
                                      bt_hal_cbacks = NULL;
                                    }
                                  },
                                  event));
}

void invoke_le_test_mode_cb(bt_status_t status, uint16_t count) {
  do_in_jni_thread(FROM_HERE, base::BindOnce(
                                  [](bt_status_t status, uint16_t count) {
                                    HAL_CBACK(bt_hal_cbacks, le_test_mode_cb,
                                              status, count);
                                  },
                                  status, count));
}

// takes ownership of |uid_data|
void invoke_energy_info_cb(bt_activity_energy_info energy_info,
                           bt_uid_traffic_t* uid_data) {
  do_in_jni_thread(
      FROM_HERE,
      base::BindOnce(
          [](bt_activity_energy_info energy_info, bt_uid_traffic_t* uid_data) {
            HAL_CBACK(bt_hal_cbacks, energy_info_cb, &energy_info, uid_data);
            osi_free(uid_data);
          },
          energy_info, uid_data));
}

void invoke_link_quality_report_cb(
    uint64_t timestamp, int report_id, int rssi, int snr,
    int retransmission_count, int packets_not_receive_count,
    int negative_acknowledgement_count) {
  do_in_jni_thread(
      FROM_HERE,
      base::BindOnce(
          [](uint64_t timestamp, int report_id, int rssi, int snr,
             int retransmission_count, int packets_not_receive_count,
             int negative_acknowledgement_count) {
            HAL_CBACK(bt_hal_cbacks, link_quality_report_cb,
                      timestamp, report_id, rssi, snr, retransmission_count,
                      packets_not_receive_count,
                      negative_acknowledgement_count);
          },
          timestamp, report_id, rssi, snr, retransmission_count,
          packets_not_receive_count, negative_acknowledgement_count));
}
