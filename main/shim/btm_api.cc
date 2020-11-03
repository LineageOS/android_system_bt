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

#define LOG_TAG "bt_shim_btm"

#include <base/callback.h>

#include <mutex>

#include "common/metric_id_allocator.h"
#include "common/time_util.h"
#include "device/include/controller.h"
#include "gd/common/callback.h"
#include "gd/neighbor/name.h"
#include "gd/os/log.h"
#include "gd/security/security_module.h"
#include "gd/security/ui.h"
#include "main/shim/btm.h"
#include "main/shim/btm_api.h"
#include "main/shim/controller.h"
#include "main/shim/helpers.h"
#include "main/shim/shim.h"
#include "main/shim/stack.h"
#include "stack/btm/btm_int_types.h"
#include "types/raw_address.h"

using bluetooth::common::MetricIdAllocator;

#define BTIF_DM_DEFAULT_INQ_MAX_RESULTS 0
#define BTIF_DM_DEFAULT_INQ_MAX_DURATION 10

/**
 * Legacy bluetooth module global control block state
 *
 * Mutex is used to synchronize access from the shim
 * layer into the global control block.  This is used
 * by the shim despite potentially arbitrary
 * unsynchronized access by the legacy stack.
 */
extern tBTM_CB btm_cb;
std::mutex btm_cb_mutex_;

extern bool btm_inq_find_bdaddr(const RawAddress& p_bda);
extern tINQ_DB_ENT* btm_inq_db_find(const RawAddress& raw_address);
extern tINQ_DB_ENT* btm_inq_db_new(const RawAddress& p_bda);

/**
 * Legacy bluetooth btm stack entry points
 */
extern void btm_acl_update_inquiry_status(uint8_t status);
extern void btm_clear_all_pending_le_entry(void);
extern void btm_clr_inq_result_flt(void);
extern void btm_set_eir_uuid(uint8_t* p_eir, tBTM_INQ_RESULTS* p_results);
extern void btm_sort_inq_result(void);
extern void btm_process_inq_complete(uint8_t status, uint8_t result_type);

static bool is_classic_device(tBT_DEVICE_TYPE device_type) {
  return device_type == BT_DEVICE_TYPE_BREDR;
}

static bool has_classic_device(tBT_DEVICE_TYPE device_type) {
  return device_type & BT_DEVICE_TYPE_BREDR;
}

void btm_api_process_inquiry_result(const RawAddress& raw_address,
                                    uint8_t page_scan_rep_mode,
                                    DEV_CLASS device_class,
                                    uint16_t clock_offset) {
  tINQ_DB_ENT* p_i = btm_inq_db_find(raw_address);

  if (p_i == nullptr) {
    p_i = btm_inq_db_new(raw_address);
    CHECK(p_i != nullptr);
  } else if (p_i->inq_count == btm_cb.btm_inq_vars.inq_counter &&
             is_classic_device(p_i->inq_info.results.device_type)) {
    return;
  }

  p_i->inq_info.results.page_scan_rep_mode = page_scan_rep_mode;
  p_i->inq_info.results.page_scan_per_mode = 0;  // RESERVED
  p_i->inq_info.results.page_scan_mode = 0;      // RESERVED
  p_i->inq_info.results.dev_class[0] = device_class[0];
  p_i->inq_info.results.dev_class[1] = device_class[1];
  p_i->inq_info.results.dev_class[2] = device_class[2];
  p_i->inq_info.results.clock_offset = clock_offset | BTM_CLOCK_OFFSET_VALID;
  p_i->inq_info.results.inq_result_type = BTM_INQ_RESULT_BR;
  p_i->inq_info.results.rssi = BTM_INQ_RES_IGNORE_RSSI;

  p_i->time_of_resp = bluetooth::common::time_get_os_boottime_ms();
  p_i->inq_count = btm_cb.btm_inq_vars.inq_counter;
  p_i->inq_info.appl_knows_rem_name = false;

  if (p_i->inq_count != btm_cb.btm_inq_vars.inq_counter) {
    p_i->inq_info.results.device_type = BT_DEVICE_TYPE_BREDR;
    btm_cb.btm_inq_vars.inq_cmpl_info.num_resp++;
    p_i->scan_rsp = false;
  } else {
    p_i->inq_info.results.device_type |= BT_DEVICE_TYPE_BREDR;
  }

  if (btm_cb.btm_inq_vars.p_inq_results_cb == nullptr) {
    return;
  }

  (btm_cb.btm_inq_vars.p_inq_results_cb)(&p_i->inq_info.results, nullptr, 0);
}

void btm_api_process_inquiry_result_with_rssi(RawAddress raw_address,
                                              uint8_t page_scan_rep_mode,
                                              DEV_CLASS device_class,
                                              uint16_t clock_offset,
                                              int8_t rssi) {
  tINQ_DB_ENT* p_i = btm_inq_db_find(raw_address);

  bool update = false;
  if (btm_inq_find_bdaddr(raw_address)) {
    if (p_i != nullptr &&
        (rssi > p_i->inq_info.results.rssi || p_i->inq_info.results.rssi == 0 ||
         has_classic_device(p_i->inq_info.results.device_type))) {
      update = true;
    }
  }

  bool is_new = true;
  if (p_i == nullptr) {
    p_i = btm_inq_db_new(raw_address);
    CHECK(p_i != nullptr);
  } else if (p_i->inq_count == btm_cb.btm_inq_vars.inq_counter &&
             is_classic_device(p_i->inq_info.results.device_type)) {
    is_new = false;
  }

  p_i->inq_info.results.rssi = rssi;

  if (is_new) {
    p_i->inq_info.results.page_scan_rep_mode = page_scan_rep_mode;
    p_i->inq_info.results.page_scan_per_mode = 0;  // RESERVED
    p_i->inq_info.results.page_scan_mode = 0;      // RESERVED
    p_i->inq_info.results.dev_class[0] = device_class[0];
    p_i->inq_info.results.dev_class[1] = device_class[1];
    p_i->inq_info.results.dev_class[2] = device_class[2];
    p_i->inq_info.results.clock_offset = clock_offset | BTM_CLOCK_OFFSET_VALID;
    p_i->inq_info.results.inq_result_type = BTM_INQ_RESULT_BR;

    p_i->time_of_resp = bluetooth::common::time_get_os_boottime_ms();
    p_i->inq_count = btm_cb.btm_inq_vars.inq_counter;
    p_i->inq_info.appl_knows_rem_name = false;

    if (p_i->inq_count != btm_cb.btm_inq_vars.inq_counter) {
      p_i->inq_info.results.device_type = BT_DEVICE_TYPE_BREDR;
      btm_cb.btm_inq_vars.inq_cmpl_info.num_resp++;
      p_i->scan_rsp = false;
    } else {
      p_i->inq_info.results.device_type |= BT_DEVICE_TYPE_BREDR;
    }
  }

  if (btm_cb.btm_inq_vars.p_inq_results_cb == nullptr) {
    return;
  }

  if (is_new || update) {
    (btm_cb.btm_inq_vars.p_inq_results_cb)(&p_i->inq_info.results, nullptr, 0);
  }
}
void btm_api_process_extended_inquiry_result(RawAddress raw_address,
                                             uint8_t page_scan_rep_mode,
                                             DEV_CLASS device_class,
                                             uint16_t clock_offset, int8_t rssi,
                                             const uint8_t* eir_data,
                                             size_t eir_len) {
  tINQ_DB_ENT* p_i = btm_inq_db_find(raw_address);

  bool update = false;
  if (btm_inq_find_bdaddr(raw_address) && p_i != nullptr) {
    update = true;
  }

  bool is_new = true;
  if (p_i == nullptr) {
    p_i = btm_inq_db_new(raw_address);
  } else if (p_i->inq_count == btm_cb.btm_inq_vars.inq_counter &&
             (p_i->inq_info.results.device_type == BT_DEVICE_TYPE_BREDR)) {
    is_new = false;
  }

  p_i->inq_info.results.rssi = rssi;

  if (is_new) {
    p_i->inq_info.results.page_scan_rep_mode = page_scan_rep_mode;
    p_i->inq_info.results.page_scan_per_mode = 0;  // RESERVED
    p_i->inq_info.results.page_scan_mode = 0;      // RESERVED
    p_i->inq_info.results.dev_class[0] = device_class[0];
    p_i->inq_info.results.dev_class[1] = device_class[1];
    p_i->inq_info.results.dev_class[2] = device_class[2];
    p_i->inq_info.results.clock_offset = clock_offset | BTM_CLOCK_OFFSET_VALID;
    p_i->inq_info.results.inq_result_type = BTM_INQ_RESULT_BR;

    p_i->time_of_resp = bluetooth::common::time_get_os_boottime_ms();
    p_i->inq_count = btm_cb.btm_inq_vars.inq_counter;
    p_i->inq_info.appl_knows_rem_name = false;

    if (p_i->inq_count != btm_cb.btm_inq_vars.inq_counter) {
      p_i->inq_info.results.device_type = BT_DEVICE_TYPE_BREDR;
      btm_cb.btm_inq_vars.inq_cmpl_info.num_resp++;
      p_i->scan_rsp = false;
    } else {
      p_i->inq_info.results.device_type |= BT_DEVICE_TYPE_BREDR;
    }
  }

  if (btm_cb.btm_inq_vars.p_inq_results_cb == nullptr) {
    return;
  }

  if (is_new || update) {
    memset(p_i->inq_info.results.eir_uuid, 0,
           BTM_EIR_SERVICE_ARRAY_SIZE * (BTM_EIR_ARRAY_BITS / 8));
    btm_set_eir_uuid(const_cast<uint8_t*>(eir_data), &p_i->inq_info.results);
    uint8_t* p_eir_data = const_cast<uint8_t*>(eir_data);
    (btm_cb.btm_inq_vars.p_inq_results_cb)(&p_i->inq_info.results, p_eir_data,
                                           eir_len);
  }
}

namespace {
std::unordered_map<bluetooth::hci::AddressWithType, bt_bdname_t>
    address_name_map_;

std::unordered_map<bluetooth::hci::IoCapability, int> gd_legacy_io_caps_map_ = {
    {bluetooth::hci::IoCapability::DISPLAY_ONLY, BTM_IO_CAP_OUT},
    {bluetooth::hci::IoCapability::DISPLAY_YES_NO, BTM_IO_CAP_IO},
    {bluetooth::hci::IoCapability::KEYBOARD_ONLY, BTM_IO_CAP_IN},
    {bluetooth::hci::IoCapability::NO_INPUT_NO_OUTPUT, BTM_IO_CAP_NONE},
};

std::unordered_map<bluetooth::hci::AuthenticationRequirements, int>
    gd_legacy_auth_reqs_map_ = {
        {bluetooth::hci::AuthenticationRequirements::NO_BONDING,
         BTM_AUTH_SP_NO},
        {bluetooth::hci::AuthenticationRequirements::NO_BONDING_MITM_PROTECTION,
         BTM_AUTH_SP_YES},
        {bluetooth::hci::AuthenticationRequirements::DEDICATED_BONDING,
         BTM_AUTH_AP_NO},
        {bluetooth::hci::AuthenticationRequirements::
             DEDICATED_BONDING_MITM_PROTECTION,
         BTM_AUTH_AP_YES},
        {bluetooth::hci::AuthenticationRequirements::GENERAL_BONDING,
         BTM_AUTH_SPGB_NO},
        {bluetooth::hci::AuthenticationRequirements::
             GENERAL_BONDING_MITM_PROTECTION,
         BTM_AUTH_SPGB_YES},
};
}

class ShimUi : public bluetooth::security::UI {
 public:
  static ShimUi* GetInstance() {
    static ShimUi instance;
    return &instance;
  }

  ShimUi(const ShimUi&) = delete;
  ShimUi& operator=(const ShimUi&) = delete;

  void SetBtaCallbacks(const tBTM_APPL_INFO* bta_callbacks) {
    bta_callbacks_ = bta_callbacks;
    if (bta_callbacks->p_pin_callback == nullptr) {
      LOG_INFO("UNIMPLEMENTED %s pin_callback", __func__);
    }

    if (bta_callbacks->p_link_key_callback == nullptr) {
      LOG_INFO("UNIMPLEMENTED %s link_key_callback", __func__);
    }

    if (bta_callbacks->p_auth_complete_callback == nullptr) {
      LOG_INFO("UNIMPLEMENTED %s auth_complete_callback", __func__);
    }

    if (bta_callbacks->p_bond_cancel_cmpl_callback == nullptr) {
      LOG_INFO("UNIMPLEMENTED %s bond_cancel_complete_callback", __func__);
    }

    if (bta_callbacks->p_le_callback == nullptr) {
      LOG_INFO("UNIMPLEMENTED %s le_callback", __func__);
    }

    if (bta_callbacks->p_le_key_callback == nullptr) {
      LOG_INFO("UNIMPLEMENTED %s le_key_callback", __func__);
    }
  }

  void DisplayPairingPrompt(const bluetooth::hci::AddressWithType& address,
                            std::string name) {
    waiting_for_pairing_prompt_ = true;
    bt_bdname_t legacy_name{0};
    memcpy(legacy_name.name, name.data(), name.length());
    // TODO(optedoblivion): Handle callback to BTA for BLE
  }

  void Cancel(const bluetooth::hci::AddressWithType& address) {
    LOG(WARNING) << " ■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■ " << __func__;
  }

  void HandleConfirm(bluetooth::security::ConfirmationData data) {
    const bluetooth::hci::AddressWithType& address = data.GetAddressWithType();
    uint32_t numeric_value = data.GetNumericValue();
    bt_bdname_t legacy_name{0};
    memcpy(legacy_name.name, data.GetName().data(), data.GetName().length());

    if (bta_callbacks_->p_sp_callback) {
      // Call sp_cback for IO_REQ
      tBTM_SP_IO_REQ io_req_evt_data;
      io_req_evt_data.bd_addr = bluetooth::ToRawAddress(address.GetAddress());
      // Local IO Caps (Phone is always DisplayYesNo)
      io_req_evt_data.io_cap = BTM_IO_CAP_IO;
      // Local Auth Reqs (Phone is always DEDICATED_BONDING)
      io_req_evt_data.auth_req = BTM_AUTH_AP_NO;
      io_req_evt_data.oob_data = BTM_OOB_NONE;
      (*bta_callbacks_->p_sp_callback)(BTM_SP_IO_REQ_EVT,
                                       (tBTM_SP_EVT_DATA*)&io_req_evt_data);

      // Call sp_cback for IO_RSP
      tBTM_SP_IO_RSP io_rsp_evt_data;
      io_rsp_evt_data.bd_addr = bluetooth::ToRawAddress(address.GetAddress());
      io_rsp_evt_data.io_cap = gd_legacy_io_caps_map_[data.GetRemoteIoCaps()];
      io_rsp_evt_data.auth_req =
          gd_legacy_auth_reqs_map_[data.GetRemoteAuthReqs()];
      io_rsp_evt_data.auth_req = BTM_AUTH_AP_YES;
      io_rsp_evt_data.oob_data = BTM_OOB_NONE;
      (*bta_callbacks_->p_sp_callback)(BTM_SP_IO_RSP_EVT,
                                       (tBTM_SP_EVT_DATA*)&io_rsp_evt_data);

      // Call sp_cback for USER_CONFIRMATION
      tBTM_SP_EVT_DATA user_cfm_req_evt_data;
      user_cfm_req_evt_data.cfm_req.bd_addr =
          bluetooth::ToRawAddress(address.GetAddress());
      user_cfm_req_evt_data.cfm_req.num_val = numeric_value;
      // If we pop a dialog then it isn't just_works
      user_cfm_req_evt_data.cfm_req.just_works = data.IsJustWorks();

      address_name_map_.emplace(address, legacy_name);
      memcpy((char*)user_cfm_req_evt_data.cfm_req.bd_name, legacy_name.name,
             BD_NAME_LEN);

      (*bta_callbacks_->p_sp_callback)(BTM_SP_CFM_REQ_EVT,
                                       &user_cfm_req_evt_data);
    }
  }

  void DisplayConfirmValue(bluetooth::security::ConfirmationData data) {
    waiting_for_pairing_prompt_ = false;
    data.SetJustWorks(false);
    HandleConfirm(data);
  }

  void DisplayYesNoDialog(bluetooth::security::ConfirmationData data) {
    waiting_for_pairing_prompt_ = false;
    data.SetJustWorks(true);
    HandleConfirm(data);
  }

  void DisplayEnterPasskeyDialog(bluetooth::security::ConfirmationData data) {
    waiting_for_pairing_prompt_ = false;
    LOG_WARN("UNIMPLEMENTED, Passkey not supported in GD");
  }

  void DisplayPasskey(bluetooth::security::ConfirmationData data) {
    waiting_for_pairing_prompt_ = false;
    LOG_WARN("UNIMPLEMENTED, Passkey not supported in GD");
  }

  bool waiting_for_pairing_prompt_ = false;

 private:
  ShimUi() : bta_callbacks_(nullptr) {}
  ~ShimUi() {}
  const tBTM_APPL_INFO* bta_callbacks_;
};

ShimUi* shim_ui_ = nullptr;

class ShimBondListener : public bluetooth::security::ISecurityManagerListener {
 public:
  static ShimBondListener* GetInstance() {
    static ShimBondListener instance;
    return &instance;
  }

  ShimBondListener(const ShimBondListener&) = delete;
  ShimBondListener& operator=(const ShimBondListener&) = delete;

  void SetBtaCallbacks(const tBTM_APPL_INFO* bta_callbacks) {
    bta_callbacks_ = bta_callbacks;
    if (bta_callbacks->p_pin_callback == nullptr) {
      LOG_INFO("UNIMPLEMENTED %s pin_callback", __func__);
    }

    if (bta_callbacks->p_link_key_callback == nullptr) {
      LOG_INFO("UNIMPLEMENTED %s link_key_callback", __func__);
    }

    if (bta_callbacks->p_auth_complete_callback == nullptr) {
      LOG_INFO("UNIMPLEMENTED %s auth_complete_callback", __func__);
    }

    if (bta_callbacks->p_bond_cancel_cmpl_callback == nullptr) {
      LOG_INFO("UNIMPLEMENTED %s bond_cancel_complete_callback", __func__);
    }

    if (bta_callbacks->p_le_callback == nullptr) {
      LOG_INFO("UNIMPLEMENTED %s le_callback", __func__);
    }

    if (bta_callbacks->p_le_key_callback == nullptr) {
      LOG_INFO("UNIMPLEMENTED %s le_key_callback", __func__);
    }
  }

  void OnDeviceBonded(bluetooth::hci::AddressWithType device) override {
    // Call sp_cback for LINK_KEY_NOTIFICATION
    // Call AUTHENTICATION_COMPLETE callback
    if (device.GetAddressType() ==
        bluetooth::hci::AddressType::PUBLIC_DEVICE_ADDRESS) {
      auto it = address_name_map_.find(device);
      bt_bdname_t tmp_name;
      if (it != address_name_map_.end()) {
        tmp_name = it->second;
      }
      BD_NAME name;
      memcpy((char*)name, tmp_name.name, BD_NAME_LEN);

      if (*bta_callbacks_->p_link_key_callback) {
        LinkKey key;  // Never want to send the key to the stack
        (*bta_callbacks_->p_link_key_callback)(
            bluetooth::ToRawAddress(device.GetAddress()), 0, name, key,
            BTM_LKEY_TYPE_COMBINATION);
      }
      if (*bta_callbacks_->p_auth_complete_callback) {
        (*bta_callbacks_->p_auth_complete_callback)(
            bluetooth::ToRawAddress(device.GetAddress()), 0, name, BTM_SUCCESS);
      }
    }
    MetricIdAllocator::GetInstance().AllocateId(
        bluetooth::ToRawAddress(device.GetAddress()));
    if (!MetricIdAllocator::GetInstance().SaveDevice(
            bluetooth::ToRawAddress(device.GetAddress()))) {
      LOG(FATAL) << __func__ << ": Fail to save metric id for device "
                 << bluetooth::ToRawAddress(device.GetAddress());
    }
  }

  void OnDeviceUnbonded(bluetooth::hci::AddressWithType device) override {
    if (bta_callbacks_->p_bond_cancel_cmpl_callback) {
      (*bta_callbacks_->p_bond_cancel_cmpl_callback)(BTM_SUCCESS);
    }
    MetricIdAllocator::GetInstance().ForgetDevice(
        bluetooth::ToRawAddress(device.GetAddress()));
  }

  void OnDeviceBondFailed(bluetooth::hci::AddressWithType device,
                          bluetooth::security::PairingFailure status) override {
    auto it = address_name_map_.find(device);
    bt_bdname_t tmp_name;
    if (it != address_name_map_.end()) {
      tmp_name = it->second;
    }
    BD_NAME name;
    memcpy((char*)name, tmp_name.name, BD_NAME_LEN);

    if (bta_callbacks_->p_auth_complete_callback) {
      (*bta_callbacks_->p_auth_complete_callback)(
          bluetooth::ToRawAddress(device.GetAddress()), 0, name,
          BTM_NOT_AUTHORIZED);
    }
  }

  void OnEncryptionStateChanged(
      bluetooth::hci::EncryptionChangeView encryption_change_view) override {
    // TODO(optedoblivion): Find BTA callback for this to call
  }

 private:
  ShimBondListener() : bta_callbacks_(nullptr) {}
  ~ShimBondListener() {}
  const tBTM_APPL_INFO* bta_callbacks_;
};

tBTM_STATUS bluetooth::shim::BTM_StartInquiry(tBTM_INQ_RESULTS_CB* p_results_cb,
                                              tBTM_CMPL_CB* p_cmpl_cb) {
  CHECK(p_results_cb != nullptr);
  CHECK(p_cmpl_cb != nullptr);

  tBTM_INQ_PARMS inqparms = {};
  inqparms.mode = BTM_GENERAL_INQUIRY | BTM_BLE_GENERAL_INQUIRY;
  inqparms.duration = BTIF_DM_DEFAULT_INQ_MAX_DURATION;

  std::lock_guard<std::mutex> lock(btm_cb_mutex_);

  btm_cb.btm_inq_vars.inq_cmpl_info.num_resp = 0;

  Stack::GetInstance()->GetBtm()->StartActiveScanning();
  if (inqparms.duration != 0) {
    Stack::GetInstance()->GetBtm()->SetScanningTimer(
        inqparms.duration * 1000, common::BindOnce([]() {
          LOG_INFO("%s scanning timeout popped", __func__);
          std::lock_guard<std::mutex> lock(btm_cb_mutex_);
          Stack::GetInstance()->GetBtm()->StopActiveScanning();
        }));
  }

  Stack::GetInstance()->GetBtm()->StartActiveScanning();

  uint8_t classic_mode = inqparms.mode & 0x0f;
  if (!Stack::GetInstance()->GetBtm()->StartInquiry(
          classic_mode, inqparms.duration, 0,
          [](uint16_t status, uint8_t inquiry_mode) {
            LOG_INFO("%s Inquiry is complete status:%hd inquiry_mode:%hhd",
                     __func__, status, inquiry_mode);
            btm_cb.btm_inq_vars.inqparms.mode &= ~(inquiry_mode);

            btm_acl_update_inquiry_status(BTM_INQUIRY_COMPLETE);
            if (btm_cb.btm_inq_vars.inq_active) {
              btm_cb.btm_inq_vars.inq_cmpl_info.status = status;
              btm_clear_all_pending_le_entry();
              btm_cb.btm_inq_vars.state = BTM_INQ_INACTIVE_STATE;

              /* Increment so the start of a next inquiry has a new count */
              btm_cb.btm_inq_vars.inq_counter++;

              btm_clr_inq_result_flt();

              if ((status == BTM_SUCCESS) &&
                  controller_get_interface()
                      ->supports_rssi_with_inquiry_results()) {
                btm_sort_inq_result();
              }

              btm_cb.btm_inq_vars.inq_active = BTM_INQUIRY_INACTIVE;
              btm_cb.btm_inq_vars.p_inq_results_cb = nullptr;
              btm_cb.btm_inq_vars.p_inq_cmpl_cb = nullptr;

              if (btm_cb.btm_inq_vars.p_inq_cmpl_cb != nullptr) {
                LOG_INFO("%s Sending inquiry completion to upper layer",
                         __func__);
                (btm_cb.btm_inq_vars.p_inq_cmpl_cb)(
                    (tBTM_INQUIRY_CMPL*)&btm_cb.btm_inq_vars.inq_cmpl_info);
                btm_cb.btm_inq_vars.p_inq_cmpl_cb = nullptr;
              }
            }
          })) {
    LOG_WARN("%s Unable to start inquiry", __func__);
    return BTM_ERR_PROCESSING;
  }

  btm_cb.btm_inq_vars.state = BTM_INQ_ACTIVE_STATE;
  btm_cb.btm_inq_vars.p_inq_cmpl_cb = p_cmpl_cb;
  btm_cb.btm_inq_vars.p_inq_results_cb = p_results_cb;
  btm_cb.btm_inq_vars.inq_active = inqparms.mode;

  btm_acl_update_inquiry_status(BTM_INQUIRY_STARTED);

  return BTM_CMD_STARTED;
}

tBTM_STATUS bluetooth::shim::BTM_SetDiscoverability(uint16_t discoverable_mode,
                                                    uint16_t window,
                                                    uint16_t interval) {
  uint16_t classic_discoverable_mode = discoverable_mode & 0xff;
  uint16_t le_discoverable_mode = discoverable_mode >> 8;

  if (window == 0) window = BTM_DEFAULT_DISC_WINDOW;
  if (interval == 0) interval = BTM_DEFAULT_DISC_INTERVAL;

  switch (le_discoverable_mode) {
    case kDiscoverableModeOff:
      Stack::GetInstance()->GetBtm()->StopAdvertising();
      break;
    case kLimitedDiscoverableMode:
    case kGeneralDiscoverableMode:
      Stack::GetInstance()->GetBtm()->StartAdvertising();
      break;
    default:
      LOG_WARN("%s Unexpected le discoverability mode:%d", __func__,
               le_discoverable_mode);
  }

  switch (classic_discoverable_mode) {
    case kDiscoverableModeOff:
      Stack::GetInstance()->GetBtm()->SetClassicDiscoverabilityOff();
      break;
    case kLimitedDiscoverableMode:
      Stack::GetInstance()->GetBtm()->SetClassicLimitedDiscoverability(
          window, interval);
      break;
    case kGeneralDiscoverableMode:
      Stack::GetInstance()->GetBtm()->SetClassicGeneralDiscoverability(
          window, interval);
      break;
    default:
      LOG_WARN("%s Unexpected classic discoverability mode:%d", __func__,
               classic_discoverable_mode);
  }
  return BTM_SUCCESS;
}

void bluetooth::shim::BTM_EnableInterlacedInquiryScan() {
  Stack::GetInstance()->GetBtm()->SetInterlacedInquiryScan();
}

tBTM_STATUS bluetooth::shim::BTM_BleObserve(bool start, uint8_t duration_sec,
                                            tBTM_INQ_RESULTS_CB* p_results_cb,
                                            tBTM_CMPL_CB* p_cmpl_cb) {
  if (start) {
    CHECK(p_results_cb != nullptr);
    CHECK(p_cmpl_cb != nullptr);

    std::lock_guard<std::mutex> lock(btm_cb_mutex_);

    if (btm_cb.ble_ctr_cb.is_ble_observe_active()) {
      LOG_WARN("%s Observing already active", __func__);
      return BTM_WRONG_MODE;
    }

    btm_cb.ble_ctr_cb.p_obs_results_cb = p_results_cb;
    btm_cb.ble_ctr_cb.p_obs_cmpl_cb = p_cmpl_cb;
    Stack::GetInstance()->GetBtm()->StartObserving();
    btm_cb.ble_ctr_cb.set_ble_observe_active();

    if (duration_sec != 0) {
      Stack::GetInstance()->GetBtm()->SetObservingTimer(
          duration_sec * 1000, common::BindOnce([]() {
            LOG_INFO("%s observing timeout popped", __func__);

            Stack::GetInstance()->GetBtm()->CancelObservingTimer();
            Stack::GetInstance()->GetBtm()->StopObserving();

            std::lock_guard<std::mutex> lock(btm_cb_mutex_);
            btm_cb.ble_ctr_cb.reset_ble_observe();

            if (btm_cb.ble_ctr_cb.p_obs_cmpl_cb) {
              (btm_cb.ble_ctr_cb.p_obs_cmpl_cb)(
                  &btm_cb.btm_inq_vars.inq_cmpl_info);
            }
            btm_cb.ble_ctr_cb.p_obs_results_cb = nullptr;
            btm_cb.ble_ctr_cb.p_obs_cmpl_cb = nullptr;

            btm_cb.btm_inq_vars.inqparms.mode &= ~(BTM_BLE_INQUIRY_MASK);

            btm_acl_update_inquiry_status(BTM_INQUIRY_COMPLETE);

            btm_clear_all_pending_le_entry();
            btm_cb.btm_inq_vars.state = BTM_INQ_INACTIVE_STATE;

            btm_cb.btm_inq_vars.inq_counter++;
            btm_clr_inq_result_flt();
            btm_sort_inq_result();

            btm_cb.btm_inq_vars.inq_active = BTM_INQUIRY_INACTIVE;
            btm_cb.btm_inq_vars.p_inq_results_cb = NULL;
            btm_cb.btm_inq_vars.p_inq_cmpl_cb = NULL;

            if (btm_cb.btm_inq_vars.p_inq_cmpl_cb) {
              (btm_cb.btm_inq_vars.p_inq_cmpl_cb)(
                  (tBTM_INQUIRY_CMPL*)&btm_cb.btm_inq_vars.inq_cmpl_info);
              btm_cb.btm_inq_vars.p_inq_cmpl_cb = nullptr;
            }
          }));
    }
  } else {
    std::lock_guard<std::mutex> lock(btm_cb_mutex_);

    if (!btm_cb.ble_ctr_cb.is_ble_observe_active()) {
      LOG_WARN("%s Observing already inactive", __func__);
    }
    Stack::GetInstance()->GetBtm()->CancelObservingTimer();
    Stack::GetInstance()->GetBtm()->StopObserving();
    btm_cb.ble_ctr_cb.reset_ble_observe();
    Stack::GetInstance()->GetBtm()->StopObserving();
    if (btm_cb.ble_ctr_cb.p_obs_cmpl_cb) {
      (btm_cb.ble_ctr_cb.p_obs_cmpl_cb)(&btm_cb.btm_inq_vars.inq_cmpl_info);
    }
    btm_cb.ble_ctr_cb.p_obs_results_cb = nullptr;
    btm_cb.ble_ctr_cb.p_obs_cmpl_cb = nullptr;
  }
  return BTM_CMD_STARTED;
}

void bluetooth::shim::BTM_EnableInterlacedPageScan() {
  Stack::GetInstance()->GetBtm()->SetInterlacedPageScan();
}

tBTM_STATUS bluetooth::shim::BTM_SetInquiryMode(uint8_t inquiry_mode) {
  switch (inquiry_mode) {
    case kStandardInquiryResult:
      Stack::GetInstance()->GetBtm()->SetStandardInquiryResultMode();
      break;
    case kInquiryResultWithRssi:
      Stack::GetInstance()->GetBtm()->SetInquiryWithRssiResultMode();
      break;
    case kExtendedInquiryResult:
      Stack::GetInstance()->GetBtm()->SetExtendedInquiryResultMode();
      break;
    default:
      return BTM_ILLEGAL_VALUE;
  }
  return BTM_SUCCESS;
}

tBTM_STATUS bluetooth::shim::BTM_SetConnectability(uint16_t page_mode,
                                                   uint16_t window,
                                                   uint16_t interval) {
  uint16_t classic_connectible_mode = page_mode & 0xff;
  uint16_t le_connectible_mode = page_mode >> 8;

  if (!window) window = BTM_DEFAULT_CONN_WINDOW;
  if (!interval) interval = BTM_DEFAULT_CONN_INTERVAL;

  switch (le_connectible_mode) {
    case kConnectibleModeOff:
      Stack::GetInstance()->GetBtm()->StopConnectability();
      break;
    case kConnectibleModeOn:
      Stack::GetInstance()->GetBtm()->StartConnectability();
      break;
    default:
      return BTM_ILLEGAL_VALUE;
      break;
  }

  switch (classic_connectible_mode) {
    case kConnectibleModeOff:
      Stack::GetInstance()->GetBtm()->SetClassicConnectibleOff();
      break;
    case kConnectibleModeOn:
      Stack::GetInstance()->GetBtm()->SetClassicConnectibleOn();
      break;
    default:
      return BTM_ILLEGAL_VALUE;
      break;
  }
  return BTM_SUCCESS;
}

uint16_t bluetooth::shim::BTM_IsInquiryActive(void) {
  if (Stack::GetInstance()->GetBtm()->IsGeneralInquiryActive()) {
    return BTM_GENERAL_INQUIRY_ACTIVE;
  }
  return BTM_INQUIRY_INACTIVE;
}

void bluetooth::shim::BTM_CancelInquiry(void) {
  LOG_INFO("%s Cancel inquiry", __func__);
  Stack::GetInstance()->GetBtm()->CancelInquiry();

  btm_cb.btm_inq_vars.state = BTM_INQ_INACTIVE_STATE;
  btm_clr_inq_result_flt();

  Stack::GetInstance()->GetBtm()->CancelScanningTimer();
  Stack::GetInstance()->GetBtm()->StopActiveScanning();

  btm_cb.ble_ctr_cb.reset_ble_inquiry();

  btm_cb.btm_inq_vars.inqparms.mode &=
      ~(btm_cb.btm_inq_vars.inqparms.mode & BTM_BLE_INQUIRY_MASK);

  btm_acl_update_inquiry_status(BTM_INQUIRY_COMPLETE);
  /* Ignore any stray or late complete messages if the inquiry is not active */
  if (btm_cb.btm_inq_vars.inq_active) {
    btm_cb.btm_inq_vars.inq_cmpl_info.status = BTM_SUCCESS;
    btm_clear_all_pending_le_entry();

    if (controller_get_interface()->supports_rssi_with_inquiry_results()) {
      btm_sort_inq_result();
    }

    btm_cb.btm_inq_vars.inq_active = BTM_INQUIRY_INACTIVE;
    btm_cb.btm_inq_vars.p_inq_results_cb = nullptr;
    btm_cb.btm_inq_vars.p_inq_cmpl_cb = nullptr;
    btm_cb.btm_inq_vars.inq_counter++;

    if (btm_cb.btm_inq_vars.p_inq_cmpl_cb != nullptr) {
      LOG_INFO("%s Sending cancel inquiry completion to upper layer", __func__);
      (btm_cb.btm_inq_vars.p_inq_cmpl_cb)(
          (tBTM_INQUIRY_CMPL*)&btm_cb.btm_inq_vars.inq_cmpl_info);
      btm_cb.btm_inq_vars.p_inq_cmpl_cb = nullptr;
    }
  }
}

tBTM_STATUS bluetooth::shim::BTM_ReadRemoteDeviceName(
    const RawAddress& raw_address, tBTM_CMPL_CB* callback,
    tBT_TRANSPORT transport) {
  CHECK(callback != nullptr);
  tBTM_STATUS status = BTM_NO_RESOURCES;

  switch (transport) {
    case BT_TRANSPORT_LE:
      status = Stack::GetInstance()->GetBtm()->ReadLeRemoteDeviceName(
          raw_address, callback);
      break;
    case BT_TRANSPORT_BR_EDR:
      status = Stack::GetInstance()->GetBtm()->ReadClassicRemoteDeviceName(
          raw_address, callback);
      break;
    default:
      LOG_WARN("%s Unspecified transport:%d", __func__, transport);
      break;
  }
  return status;
}

tBTM_STATUS bluetooth::shim::BTM_CancelRemoteDeviceName(void) {
  return Stack::GetInstance()->GetBtm()->CancelAllReadRemoteDeviceName();
}

tBTM_INQ_INFO* bluetooth::shim::BTM_InqDbRead(const RawAddress& p_bda) {
  LOG_INFO("UNIMPLEMENTED %s", __func__);
  return nullptr;
}

tBTM_INQ_INFO* bluetooth::shim::BTM_InqDbFirst(void) {
  LOG_INFO("UNIMPLEMENTED %s", __func__);
  return nullptr;
}

tBTM_INQ_INFO* bluetooth::shim::BTM_InqDbNext(tBTM_INQ_INFO* p_cur) {
  LOG_INFO("UNIMPLEMENTED %s", __func__);
  CHECK(p_cur != nullptr);
  return nullptr;
}

tBTM_STATUS bluetooth::shim::BTM_ClearInqDb(const RawAddress* p_bda) {
  LOG_INFO("UNIMPLEMENTED %s", __func__);
  if (p_bda == nullptr) {
    // clear all entries
  } else {
    // clear specific entry
  }
  return BTM_NO_RESOURCES;
}

tBTM_STATUS bluetooth::shim::BTM_WriteEIR(BT_HDR* p_buff) {
  LOG_INFO("UNIMPLEMENTED %s", __func__);
  CHECK(p_buff != nullptr);
  return BTM_NO_RESOURCES;
}

bool bluetooth::shim::BTM_HasEirService(const uint32_t* p_eir_uuid,
                                        uint16_t uuid16) {
  LOG_INFO("UNIMPLEMENTED %s", __func__);
  CHECK(p_eir_uuid != nullptr);
  return false;
}

tBTM_EIR_SEARCH_RESULT bluetooth::shim::BTM_HasInquiryEirService(
    tBTM_INQ_RESULTS* p_results, uint16_t uuid16) {
  LOG_INFO("UNIMPLEMENTED %s", __func__);
  CHECK(p_results != nullptr);
  return BTM_EIR_UNKNOWN;
}

void bluetooth::shim::BTM_AddEirService(uint32_t* p_eir_uuid, uint16_t uuid16) {
  LOG_INFO("UNIMPLEMENTED %s", __func__);
  CHECK(p_eir_uuid != nullptr);
}

void bluetooth::shim::BTM_RemoveEirService(uint32_t* p_eir_uuid,
                                           uint16_t uuid16) {
  LOG_INFO("UNIMPLEMENTED %s", __func__);
  CHECK(p_eir_uuid != nullptr);
}

uint8_t bluetooth::shim::BTM_GetEirSupportedServices(uint32_t* p_eir_uuid,
                                                     uint8_t** p,
                                                     uint8_t max_num_uuid16,
                                                     uint8_t* p_num_uuid16) {
  LOG_INFO("UNIMPLEMENTED %s", __func__);
  CHECK(p_eir_uuid != nullptr);
  CHECK(p != nullptr);
  CHECK(*p != nullptr);
  CHECK(p_num_uuid16 != nullptr);
  return BTM_NO_RESOURCES;
}

uint8_t bluetooth::shim::BTM_GetEirUuidList(uint8_t* p_eir, size_t eir_len,
                                            uint8_t uuid_size,
                                            uint8_t* p_num_uuid,
                                            uint8_t* p_uuid_list,
                                            uint8_t max_num_uuid) {
  LOG_INFO("UNIMPLEMENTED %s", __func__);
  CHECK(p_eir != nullptr);
  CHECK(p_num_uuid != nullptr);
  CHECK(p_uuid_list != nullptr);
  return 0;
}

void bluetooth::shim::BTM_SecAddBleDevice(const RawAddress& bd_addr,
                                          tBT_DEVICE_TYPE dev_type,
                                          tBLE_ADDR_TYPE addr_type) {
  LOG_INFO("UNIMPLEMENTED %s", __func__);
}

void bluetooth::shim::BTM_SecAddBleKey(const RawAddress& bd_addr,
                                       tBTM_LE_KEY_VALUE* p_le_key,
                                       tBTM_LE_KEY_TYPE key_type) {
  LOG_INFO("UNIMPLEMENTED %s", __func__);
  CHECK(p_le_key != nullptr);
}

void bluetooth::shim::BTM_BleLoadLocalKeys(uint8_t key_type,
                                           tBTM_BLE_LOCAL_KEYS* p_key) {
  LOG_INFO("UNIMPLEMENTED %s", __func__);
  CHECK(p_key != nullptr);
}

static Octet16 bogus_root;

/** Returns local device encryption root (ER) */
const Octet16& bluetooth::shim::BTM_GetDeviceEncRoot() {
  LOG_INFO("UNIMPLEMENTED %s", __func__);
  return bogus_root;
}

/** Returns local device identity root (IR). */
const Octet16& bluetooth::shim::BTM_GetDeviceIDRoot() {
  LOG_INFO("UNIMPLEMENTED %s", __func__);
  return bogus_root;
}

/** Return local device DHK. */
const Octet16& bluetooth::shim::BTM_GetDeviceDHK() {
  LOG_INFO("UNIMPLEMENTED %s", __func__);
  return bogus_root;
}

void bluetooth::shim::BTM_ReadConnectionAddr(const RawAddress& remote_bda,
                                             RawAddress& local_conn_addr,
                                             tBLE_ADDR_TYPE* p_addr_type) {
  LOG_INFO("UNIMPLEMENTED %s", __func__);
  CHECK(p_addr_type != nullptr);
}

bool bluetooth::shim::BTM_ReadRemoteConnectionAddr(
    const RawAddress& pseudo_addr, RawAddress& conn_addr,
    tBLE_ADDR_TYPE* p_addr_type) {
  LOG_INFO("UNIMPLEMENTED %s", __func__);
  CHECK(p_addr_type != nullptr);
  return false;
}

void bluetooth::shim::BTM_SecurityGrant(const RawAddress& bd_addr,
                                        uint8_t res) {
  LOG_INFO("UNIMPLEMENTED %s", __func__);
}

void bluetooth::shim::BTM_BleOobDataReply(const RawAddress& bd_addr,
                                          uint8_t res, uint8_t len,
                                          uint8_t* p_data) {
  LOG_INFO("UNIMPLEMENTED %s", __func__);
  CHECK(p_data != nullptr);
}

void bluetooth::shim::BTM_BleSecureConnectionOobDataReply(
    const RawAddress& bd_addr, uint8_t* p_c, uint8_t* p_r) {
  LOG_INFO("UNIMPLEMENTED %s", __func__);
  CHECK(p_c != nullptr);
  CHECK(p_r != nullptr);
}

void bluetooth::shim::BTM_BleSetConnScanParams(uint32_t scan_interval,
                                               uint32_t scan_window) {
  LOG_INFO("UNIMPLEMENTED %s", __func__);
}

void bluetooth::shim::BTM_BleSetPrefConnParams(const RawAddress& bd_addr,
                                               uint16_t min_conn_int,
                                               uint16_t max_conn_int,
                                               uint16_t peripheral_latency,
                                               uint16_t supervision_tout) {
  LOG_INFO("UNIMPLEMENTED %s", __func__);
}

void bluetooth::shim::BTM_ReadDevInfo(const RawAddress& remote_bda,
                                      tBT_DEVICE_TYPE* p_dev_type,
                                      tBLE_ADDR_TYPE* p_addr_type) {
  LOG_INFO("UNIMPLEMENTED %s", __func__);
  CHECK(p_dev_type != nullptr);
  CHECK(p_addr_type != nullptr);
}

bool bluetooth::shim::BTM_ReadConnectedTransportAddress(
    RawAddress* remote_bda, tBT_TRANSPORT transport) {
  LOG_INFO("UNIMPLEMENTED %s", __func__);
  CHECK(remote_bda != nullptr);
  return false;
}

void bluetooth::shim::BTM_BleReceiverTest(uint8_t rx_freq,
                                          tBTM_CMPL_CB* p_cmd_cmpl_cback) {
  LOG_INFO("UNIMPLEMENTED %s", __func__);
  CHECK(p_cmd_cmpl_cback != nullptr);
}

void bluetooth::shim::BTM_BleTransmitterTest(uint8_t tx_freq,
                                             uint8_t test_data_len,
                                             uint8_t packet_payload,
                                             tBTM_CMPL_CB* p_cmd_cmpl_cback) {
  LOG_INFO("UNIMPLEMENTED %s", __func__);
  CHECK(p_cmd_cmpl_cback != nullptr);
}

void bluetooth::shim::BTM_BleTestEnd(tBTM_CMPL_CB* p_cmd_cmpl_cback) {
  LOG_INFO("UNIMPLEMENTED %s", __func__);
  CHECK(p_cmd_cmpl_cback != nullptr);
}

bool bluetooth::shim::BTM_UseLeLink(const RawAddress& raw_address) {
  return Stack::GetInstance()->GetBtm()->UseLeLink(raw_address);
}

tBTM_STATUS bluetooth::shim::BTM_SetBleDataLength(const RawAddress& bd_addr,
                                                  uint16_t tx_pdu_length) {
  LOG_INFO("UNIMPLEMENTED %s", __func__);
  return BTM_NO_RESOURCES;
}

void bluetooth::shim::BTM_BleReadPhy(
    const RawAddress& bd_addr,
    base::Callback<void(uint8_t tx_phy, uint8_t rx_phy, uint8_t status)> cb) {
  LOG_INFO("UNIMPLEMENTED %s", __func__);
}

void bluetooth::shim::BTM_BleSetPhy(const RawAddress& bd_addr, uint8_t tx_phys,
                                    uint8_t rx_phys, uint16_t phy_options) {
  LOG_INFO("UNIMPLEMENTED %s", __func__);
}

bool bluetooth::shim::BTM_BleDataSignature(const RawAddress& bd_addr,
                                           uint8_t* p_text, uint16_t len,
                                           BLE_SIGNATURE signature) {
  LOG_INFO("UNIMPLEMENTED %s", __func__);
  CHECK(p_text != nullptr);
  return false;
}

bool bluetooth::shim::BTM_BleVerifySignature(const RawAddress& bd_addr,
                                             uint8_t* p_orig, uint16_t len,
                                             uint32_t counter,
                                             uint8_t* p_comp) {
  LOG_INFO("UNIMPLEMENTED %s", __func__);
  CHECK(p_orig != nullptr);
  CHECK(p_comp != nullptr);
  return false;
}

bool bluetooth::shim::BTM_GetLeSecurityState(const RawAddress& bd_addr,
                                             uint8_t* p_le_dev_sec_flags,
                                             uint8_t* p_le_key_size) {
  LOG_INFO("UNIMPLEMENTED %s", __func__);
  CHECK(p_le_dev_sec_flags != nullptr);
  CHECK(p_le_key_size != nullptr);
  return false;
}

bool bluetooth::shim::BTM_BleSecurityProcedureIsRunning(
    const RawAddress& bd_addr) {
  LOG_INFO("UNIMPLEMENTED %s", __func__);
  return false;
}

uint8_t bluetooth::shim::BTM_BleGetSupportedKeySize(const RawAddress& bd_addr) {
  LOG_INFO("UNIMPLEMENTED %s", __func__);
  return 0;
}

/**
 * This function update(add,delete or clear) the adv local name filtering
 * condition.
 */
void bluetooth::shim::BTM_LE_PF_local_name(tBTM_BLE_SCAN_COND_OP action,
                                           tBTM_BLE_PF_FILT_INDEX filt_index,
                                           std::vector<uint8_t> name,
                                           tBTM_BLE_PF_CFG_CBACK cb) {
  LOG_INFO("UNIMPLEMENTED %s", __func__);
}

void bluetooth::shim::BTM_LE_PF_srvc_data(tBTM_BLE_SCAN_COND_OP action,
                                          tBTM_BLE_PF_FILT_INDEX filt_index) {
  LOG_INFO("UNIMPLEMENTED %s", __func__);
}

void bluetooth::shim::BTM_LE_PF_manu_data(
    tBTM_BLE_SCAN_COND_OP action, tBTM_BLE_PF_FILT_INDEX filt_index,
    uint16_t company_id, uint16_t company_id_mask, std::vector<uint8_t> data,
    std::vector<uint8_t> data_mask, tBTM_BLE_PF_CFG_CBACK cb) {
  LOG_INFO("UNIMPLEMENTED %s", __func__);
}

void bluetooth::shim::BTM_LE_PF_srvc_data_pattern(
    tBTM_BLE_SCAN_COND_OP action, tBTM_BLE_PF_FILT_INDEX filt_index,
    std::vector<uint8_t> data, std::vector<uint8_t> data_mask,
    tBTM_BLE_PF_CFG_CBACK cb) {
  LOG_INFO("UNIMPLEMENTED %s", __func__);
}

void bluetooth::shim::BTM_LE_PF_addr_filter(tBTM_BLE_SCAN_COND_OP action,
                                            tBTM_BLE_PF_FILT_INDEX filt_index,
                                            tBLE_BD_ADDR addr,
                                            tBTM_BLE_PF_CFG_CBACK cb) {
  LOG_INFO("UNIMPLEMENTED %s", __func__);
}

void bluetooth::shim::BTM_LE_PF_uuid_filter(tBTM_BLE_SCAN_COND_OP action,
                                            tBTM_BLE_PF_FILT_INDEX filt_index,
                                            tBTM_BLE_PF_COND_TYPE filter_type,
                                            const bluetooth::Uuid& uuid,
                                            tBTM_BLE_PF_LOGIC_TYPE cond_logic,
                                            const bluetooth::Uuid& uuid_mask,
                                            tBTM_BLE_PF_CFG_CBACK cb) {
  LOG_INFO("UNIMPLEMENTED %s", __func__);
}

void bluetooth::shim::BTM_LE_PF_set(tBTM_BLE_PF_FILT_INDEX filt_index,
                                    std::vector<ApcfCommand> commands,
                                    tBTM_BLE_PF_CFG_CBACK cb) {
  LOG_INFO("UNIMPLEMENTED %s", __func__);
}

void bluetooth::shim::BTM_LE_PF_clear(tBTM_BLE_PF_FILT_INDEX filt_index,
                                      tBTM_BLE_PF_CFG_CBACK cb) {
  LOG_INFO("UNIMPLEMENTED %s", __func__);
}

void bluetooth::shim::BTM_BleAdvFilterParamSetup(
    int action, tBTM_BLE_PF_FILT_INDEX filt_index,
    std::unique_ptr<btgatt_filt_param_setup_t> p_filt_params,
    tBTM_BLE_PF_PARAM_CB cb) {
  LOG_INFO("UNIMPLEMENTED %s", __func__);
}

void bluetooth::shim::BTM_BleUpdateAdvFilterPolicy(tBTM_BLE_AFP adv_policy) {
  LOG_INFO("UNIMPLEMENTED %s", __func__);
}

void bluetooth::shim::BTM_BleEnableDisableFilterFeature(
    uint8_t enable, tBTM_BLE_PF_STATUS_CBACK p_stat_cback) {
  LOG_INFO("UNIMPLEMENTED %s", __func__);
}

uint8_t bluetooth::shim::BTM_BleMaxMultiAdvInstanceCount() {
  return Stack::GetInstance()->GetBtm()->GetNumberOfAdvertisingInstances();
}

bool bluetooth::shim::BTM_BleLocalPrivacyEnabled(void) {
  return controller_get_interface()->supports_ble_privacy();
}

tBTM_STATUS bluetooth::shim::BTM_SecBond(const RawAddress& bd_addr,
                                         tBLE_ADDR_TYPE addr_type,
                                         tBT_TRANSPORT transport,
                                         int device_type) {
  return Stack::GetInstance()->GetBtm()->CreateBond(bd_addr, addr_type,
                                                    transport, device_type);
}

bool bluetooth::shim::BTM_SecRegister(const tBTM_APPL_INFO* bta_callbacks) {
  CHECK(bta_callbacks != nullptr);
  LOG_INFO("%s Registering security application", __func__);

  if (bta_callbacks->p_pin_callback == nullptr) {
    LOG_INFO("UNIMPLEMENTED %s pin_callback", __func__);
  }

  if (bta_callbacks->p_link_key_callback == nullptr) {
    LOG_INFO("UNIMPLEMENTED %s link_key_callback", __func__);
  }

  if (bta_callbacks->p_auth_complete_callback == nullptr) {
    LOG_INFO("UNIMPLEMENTED %s auth_complete_callback", __func__);
  }

  if (bta_callbacks->p_bond_cancel_cmpl_callback == nullptr) {
    LOG_INFO("UNIMPLEMENTED %s bond_cancel_complete_callback", __func__);
  }

  if (bta_callbacks->p_le_callback == nullptr) {
    LOG_INFO("UNIMPLEMENTED %s le_callback", __func__);
  }

  if (bta_callbacks->p_le_key_callback == nullptr) {
    LOG_INFO("UNIMPLEMENTED %s le_key_callback", __func__);
  }

  ShimBondListener::GetInstance()->SetBtaCallbacks(bta_callbacks);

  bluetooth::shim::GetSecurityModule()
      ->GetSecurityManager()
      ->RegisterCallbackListener(ShimBondListener::GetInstance(),
                                 bluetooth::shim::GetGdShimHandler());

  ShimUi::GetInstance()->SetBtaCallbacks(bta_callbacks);

  bluetooth::shim::GetSecurityModule()
      ->GetSecurityManager()
      ->SetUserInterfaceHandler(ShimUi::GetInstance(),
                                bluetooth::shim::GetGdShimHandler());

  return true;
}

tBTM_STATUS bluetooth::shim::BTM_SecBondCancel(const RawAddress& bd_addr) {
  if (Stack::GetInstance()->GetBtm()->CancelBond(bd_addr)) {
    return BTM_SUCCESS;
  } else {
    return BTM_UNKNOWN_ADDR;
  }
}

bool bluetooth::shim::BTM_SecAddDevice(const RawAddress& bd_addr,
                                       DEV_CLASS dev_class, BD_NAME bd_name,
                                       uint8_t* features, LinkKey* link_key,
                                       uint8_t key_type, uint8_t pin_length) {
  // Check if GD has a security record for the device
  return BTM_SUCCESS;
}

bool bluetooth::shim::BTM_SecDeleteDevice(const RawAddress& bd_addr) {
  return Stack::GetInstance()->GetBtm()->RemoveBond(bd_addr);
}

void bluetooth::shim::BTM_ConfirmReqReply(tBTM_STATUS res,
                                          const RawAddress& bd_addr) {
  // Send for both Classic and LE until we can determine the type
  bool accept = res == BTM_SUCCESS;
  hci::AddressWithType address = ToAddressWithType(bd_addr, 0);
  hci::AddressWithType address2 = ToAddressWithType(bd_addr, 1);
  auto security_manager =
      bluetooth::shim::GetSecurityModule()->GetSecurityManager();
  if (ShimUi::GetInstance()->waiting_for_pairing_prompt_) {
    LOG(INFO) << "interpreting confirmation as pairing accept " << address;
    security_manager->OnPairingPromptAccepted(address, accept);
    security_manager->OnPairingPromptAccepted(address2, accept);
    ShimUi::GetInstance()->waiting_for_pairing_prompt_ = false;
  } else {
    LOG(INFO) << "interpreting confirmation as yes/no confirmation " << address;
    security_manager->OnConfirmYesNo(address, accept);
    security_manager->OnConfirmYesNo(address2, accept);
  }
}

uint16_t bluetooth::shim::BTM_GetHCIConnHandle(const RawAddress& remote_bda,
                                               tBT_TRANSPORT transport) {
  return Stack::GetInstance()->GetBtm()->GetAclHandle(remote_bda, transport);
}

static void remote_name_request_complete_noop(void* p_name){
    // Should notify BTM_Sec, but we should use GD SMP.
};

void bluetooth::shim::SendRemoteNameRequest(const RawAddress& raw_address) {
  Stack::GetInstance()->GetBtm()->ReadClassicRemoteDeviceName(
      raw_address, remote_name_request_complete_noop);
}

tBTM_STATUS bluetooth::shim::btm_sec_mx_access_request(
    const RawAddress& bd_addr, bool is_originator,
    uint16_t security_requirement, tBTM_SEC_CALLBACK* p_callback,
    void* p_ref_data) {
  // Security has already been fulfilled by the l2cap connection, so reply back
  // that everything is totally fine and legit and definitely not two kids in a
  // trenchcoat

  if (p_callback) {
    (*p_callback)(&bd_addr, false, p_ref_data, BTM_SUCCESS);
  }
  return BTM_SUCCESS;
}

tBTM_STATUS bluetooth::shim::BTM_SetEncryption(const RawAddress& bd_addr,
                                               tBT_TRANSPORT transport,
                                               tBTM_SEC_CALLBACK* p_callback,
                                               void* p_ref_data,
                                               tBTM_BLE_SEC_ACT sec_act) {
  // When we just bond a device, encryption is already done
  (*p_callback)(&bd_addr, transport, p_ref_data, BTM_SUCCESS);

  // TODO(hsz): Re-encrypt the link after first bonded

  return BTM_SUCCESS;
}

void bluetooth::shim::BTM_SecClearSecurityFlags(const RawAddress& bd_addr) {
  // TODO(optedoblivion): Call RemoveBond on device address
}

char* bluetooth::shim::BTM_SecReadDevName(const RawAddress& address) {
  static char name[] = "TODO: See if this is needed";
  return name;
}

bool bluetooth::shim::BTM_SecAddRmtNameNotifyCallback(
    tBTM_RMT_NAME_CALLBACK* p_callback) {
  // TODO(optedoblivion): keep track of callback
  LOG_WARN("Unimplemented");
  return true;
}

bool bluetooth::shim::BTM_SecDeleteRmtNameNotifyCallback(
    tBTM_RMT_NAME_CALLBACK* p_callback) {
  // TODO(optedoblivion): stop keeping track of callback
  LOG_WARN("Unimplemented");
  return true;
}

void bluetooth::shim::BTM_PINCodeReply(const RawAddress& bd_addr, uint8_t res,
                                       uint8_t pin_len, uint8_t* p_pin) {
  ASSERT_LOG(!bluetooth::shim::is_gd_shim_enabled(), "Unreachable code path");
}

void bluetooth::shim::BTM_RemoteOobDataReply(tBTM_STATUS res,
                                             const RawAddress& bd_addr,
                                             const Octet16& c,
                                             const Octet16& r) {
  ASSERT_LOG(!bluetooth::shim::is_gd_shim_enabled(), "Unreachable code path");
}

tBTM_STATUS bluetooth::shim::BTM_SetDeviceClass(DEV_CLASS dev_class) {
  // TODO(optedoblivion): see if we need this, I don't think we do
  LOG_WARN("Unimplemented");
  return BTM_SUCCESS;
}

static std::unordered_map<intptr_t,
                          bluetooth::common::ContextualOnceCallback<void(bool)>>
    security_enforce_callback_map;
static intptr_t security_enforce_callback_counter = 0;

static void security_enforce_result_callback(const RawAddress* bd_addr,
                                             tBT_TRANSPORT trasnport,
                                             void* p_ref_data,
                                             tBTM_STATUS result) {
  intptr_t counter = (intptr_t)p_ref_data;
  if (security_enforce_callback_map.count(security_enforce_callback_counter) ==
      0) {
    LOG(ERROR) << __func__ << "Unknown callback";
    return;
  }
  auto& callback = security_enforce_callback_map[counter];
  std::move(callback).Invoke(result == BTM_SUCCESS);
  security_enforce_callback_map.erase(counter);
}

class SecurityEnforcementShim
    : public bluetooth::l2cap::classic::SecurityEnforcementInterface {
 public:
  void Enforce(bluetooth::hci::AddressWithType remote,
               bluetooth::l2cap::classic::SecurityPolicy policy,
               ResultCallback result_callback) override {
    uint16_t sec_mask = 0;
    switch (policy) {
      case bluetooth::l2cap::classic::SecurityPolicy::
          _SDP_ONLY_NO_SECURITY_WHATSOEVER_PLAINTEXT_TRANSPORT_OK:
        break;
      case bluetooth::l2cap::classic::SecurityPolicy::ENCRYPTED_TRANSPORT:
        sec_mask = BTM_SEC_IN_AUTHENTICATE | BTM_SEC_IN_ENCRYPT |
                   BTM_SEC_OUT_AUTHENTICATE | BTM_SEC_OUT_ENCRYPT;
        break;
      case bluetooth::l2cap::classic::SecurityPolicy::BEST:
      case bluetooth::l2cap::classic::SecurityPolicy::
          AUTHENTICATED_ENCRYPTED_TRANSPORT:
        sec_mask = BTM_SEC_IN_AUTHENTICATE | BTM_SEC_IN_ENCRYPT |
                   BTM_SEC_IN_MITM | BTM_SEC_OUT_AUTHENTICATE |
                   BTM_SEC_OUT_ENCRYPT | BTM_SEC_OUT_MITM;
        break;
    }
    auto bd_addr = bluetooth::ToRawAddress(remote.GetAddress());
    btm_sec_l2cap_access_req_by_requirement(
        bd_addr, sec_mask, true, security_enforce_result_callback,
        (void*)security_enforce_callback_counter);
    security_enforce_callback_counter++;
  }
};
