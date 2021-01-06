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

#include <base/bind.h>
#include <base/location.h>
#include <base/strings/stringprintf.h>
#include <cstdint>
#include <memory>

#include "device/include/interop.h"
#include "hci/controller.h"
#include "main/shim/controller.h"
#include "main/shim/dumpsys.h"
#include "main/shim/link_policy.h"
#include "main/shim/stack.h"
#include "osi/include/log.h"
#include "stack/btm/btm_int_types.h"
#include "stack/include/btm_api.h"
#include "stack/include/btm_api_types.h"
#include "stack/include/btm_ble_api_types.h"
#include "stack/include/hci_error_code.h"
#include "stack/include/hcidefs.h"

void btsnd_hcic_switch_role(const RawAddress& bd_addr,
                            uint8_t role);  // TODO remove

bt_status_t do_in_main_thread(const base::Location& from_here,
                              base::OnceClosure task);

void btm_cont_rswitch_from_handle(uint16_t hci_handle);
void btm_pm_proc_mode_change(tHCI_STATUS hci_status, uint16_t hci_handle,
                             tHCI_MODE mode, uint16_t interval);
void btm_sco_chk_pend_unpark(tHCI_STATUS hci_status, uint16_t hci_handle);
void l2c_OnHciModeChangeSendPendingPackets(RawAddress remote);
void process_ssr_event(tHCI_STATUS status, uint16_t handle,
                       UNUSED_ATTR uint16_t max_tx_lat, uint16_t max_rx_lat);
tACL_CONN* acl_get_connection_from_handle(uint16_t handle);

extern tBTM_CB btm_cb;

namespace {

tBTM_STATUS set_active_mode(tACL_CONN& p_acl) {
  bluetooth::shim::Stack::GetInstance()->LinkPolicy()->ExitSniffMode(
      p_acl.hci_handle);
  return BTM_SUCCESS;
}

tBTM_STATUS set_hold_mode(tACL_CONN& p_acl, uint16_t max, uint16_t min) {
  bluetooth::shim::Stack::GetInstance()->LinkPolicy()->HoldMode(
      p_acl.hci_handle, max, min);
  return BTM_SUCCESS;
}

tBTM_STATUS set_sniff_mode(tACL_CONN& p_acl, uint16_t max_interval,
                           uint16_t min_interval, uint16_t attempt,
                           uint16_t timeout) {
  bluetooth::shim::Stack::GetInstance()->LinkPolicy()->SniffMode(
      p_acl.hci_handle, max_interval, min_interval, attempt, timeout);
  return BTM_SUCCESS;
}

bool controller_supports_link_policy_mode(const tBTM_PM_MODE& mode,
                                          bool interop_check) {
  switch (mode) {
    case BTM_PM_MD_ACTIVE:  // Active mode is always supported
      break;
    case BTM_PM_MD_PARK:  // Park mode no longer supported
      return false;
    case BTM_PM_MD_SNIFF:
      if (!controller_get_interface()->supports_sniff_mode() || interop_check)
        return false;
      break;
    case BTM_PM_MD_HOLD:
      if (!controller_get_interface()->supports_hold_mode() || interop_check)
        return false;
      break;
    default:
      LOG_ERROR("Unknown mode:%u", mode);
      return false;
  }
  return true;
}

}  // namespace

bool bluetooth::shim::RegisterLinkPolicyClient(tBTM_PM_STATUS_CBACK* p_cb) {
  if (std::find(btm_cb.acl_cb_.link_policy.clients.begin(),
                btm_cb.acl_cb_.link_policy.clients.end(),
                p_cb) != btm_cb.acl_cb_.link_policy.clients.end()) {
    LOG_ERROR("Link policy client already registered");
    return false;
  }
  btm_cb.acl_cb_.link_policy.clients.push_back(p_cb);
  return true;
}

bool bluetooth::shim::UnregisterLinkPolicyClient(tBTM_PM_STATUS_CBACK* p_cb) {
  auto cb = std::find(btm_cb.acl_cb_.link_policy.clients.begin(),
                      btm_cb.acl_cb_.link_policy.clients.end(), p_cb);
  if (cb == btm_cb.acl_cb_.link_policy.clients.end()) {
    LOG_ERROR("Link policy client already unregistered");
    return false;
  }
  btm_cb.acl_cb_.link_policy.clients.erase(cb);
  return true;
}

tBTM_STATUS bluetooth::shim::BTM_SetPowerMode(tACL_CONN& p_acl,
                                              const tBTM_PM_PWR_MD& new_mode) {
  if (!controller_supports_link_policy_mode(
          new_mode.mode,
          interop_match_addr(INTEROP_DISABLE_SNIFF, &p_acl.remote_addr))) {
    return BTM_MODE_UNSUPPORTED;
  }

  if (p_acl.policy.Mode() == new_mode.mode) {
    LOG_INFO("Controller already in mode:%s[0x%02x]",
             power_mode_state_text(p_acl.policy.Mode()).c_str(),
             p_acl.policy.Mode());
  }

  if (p_acl.policy.mode.IsPending()) {
    LOG_INFO("Link policy mode is pending");
  }

  LOG_INFO("Switching mode from %s(0x%x) to %s(0x%x)",
           power_mode_state_text(p_acl.policy.Mode()).c_str(),
           p_acl.policy.Mode(), power_mode_state_text(new_mode.mode).c_str(),
           new_mode.mode);

  p_acl.policy.mode.pending_ = new_mode.mode;
  switch (new_mode.mode) {
    case BTM_PM_MD_ACTIVE:
      set_active_mode(p_acl);
      return BTM_SUCCESS;
      break;
    case BTM_PM_MD_SNIFF:
      set_sniff_mode(p_acl, new_mode.max, new_mode.min, new_mode.attempt,
                     new_mode.timeout);
      return BTM_SUCCESS;
      break;
    case BTM_PM_MD_HOLD:
      return set_hold_mode(p_acl, new_mode.max, new_mode.min);
      break;
  }
  return BTM_MODE_UNSUPPORTED;
}

static bool is_encryption_pause_supported(const tACL_CONN& p_acl) {
  CHECK(p_acl.peer_lmp_feature_valid[0])
      << "Checked before remote feature read has complete";
  return HCI_ATOMIC_ENCRYPT_SUPPORTED(p_acl.peer_lmp_feature_pages[0]) &&
         controller_get_interface()->supports_encryption_pause();
}

void bluetooth::shim::btm_pm_on_mode_change(tHCI_STATUS status, uint16_t handle,
                                            tHCI_MODE hci_mode,
                                            uint16_t interval) {
  tBTM_PM_MODE new_mode = HCI_TO_BTM_POWER_MODE(hci_mode);

  LOG_DEBUG(
      "For now pointing back again to legacy status:%s handle:0x%04x "
      "new_mode:%u interval:%u",
      hci_error_code_text(status).c_str(), handle, new_mode, interval);

  tACL_CONN* p_acl = acl_get_connection_from_handle(handle);
  if (p_acl == nullptr) {
    LOG_ERROR("Received mode change for unknown acl handle:0x%04x", handle);
    return;
  }

  tBTM_PM_MODE pending = p_acl->policy.mode.Pending();
  p_acl->policy.mode.pending_ = BTM_PM_MD_UNKNOWN;

  if (status == HCI_SUCCESS) {
    BTM_LogHistory(
        "Power", p_acl->remote_addr, "Mode change",
        base::StringPrintf("%s[0x%02x] ==> %s[0x%02x] pending:%s",
                           power_mode_state_text(p_acl->policy.Mode()).c_str(),
                           p_acl->policy.Mode(),
                           power_mode_state_text(new_mode).c_str(), new_mode,
                           power_mode_state_text(pending).c_str()));
    LOG_INFO("Power mode switched from %s[%hhu] to %s[%hhu] pending:%s",
             power_mode_state_text(p_acl->policy.Mode()).c_str(),
             p_acl->policy.Mode(), power_mode_state_text(new_mode).c_str(),
             new_mode, power_mode_state_text(pending).c_str());
    p_acl->policy.mode.mode_ = new_mode;

    if (new_mode == (BTM_PM_ST_ACTIVE) || new_mode == (BTM_PM_ST_SNIFF)) {
      l2c_OnHciModeChangeSendPendingPackets(p_acl->remote_addr);
    }

    /*check if sco disconnect  is waiting for the mode change */
    btm_sco_disc_chk_pend_for_modechange(handle);

    if (p_acl->is_switch_role_mode_change()) {
      if (p_acl->is_encrypted && !is_encryption_pause_supported(*p_acl)) {
        p_acl->set_encryption_off();
        p_acl->set_switch_role_encryption_off();
      } else {
        p_acl->set_switch_role_in_progress();
        p_acl->rs_disc_pending = BTM_SEC_RS_PENDING;
        bluetooth::legacy::hci::GetInterface().StartRoleSwitch(
            p_acl->remote_addr, HCI_ROLE_CENTRAL);
      }
    }
  }

  btm_sco_chk_pend_unpark(status, handle);
  // btm_pm_proc_mode_change(status, handle, new_mode, interval);

  for (auto client_callback : btm_cb.acl_cb_.link_policy.clients) {
    (*client_callback)(p_acl->remote_addr, new_mode, interval, status);
  }

  LOG_DEBUG(
      "Notified mode change registered clients cnt:%zu peer:%s "
      "status:%s",
      btm_cb.acl_cb_.link_policy.clients.size(),
      PRIVATE_ADDRESS(p_acl->remote_addr), hci_error_code_text(status).c_str());
}

tBTM_STATUS bluetooth::shim::BTM_SetSsrParams(tACL_CONN& p_acl,
                                              uint16_t max_lat,
                                              uint16_t min_rmt_to,
                                              uint16_t min_loc_to) {
  LOG_DEBUG("Sending gd power mode SSR Params");
  p_acl.policy.sniff_subrating.pending_ = true;
  bluetooth::shim::Stack::GetInstance()->LinkPolicy()->SniffSubrating(
      p_acl.hci_handle, max_lat, min_rmt_to, min_loc_to);
  return BTM_SUCCESS;
}

void bluetooth::shim::btm_pm_on_sniff_subrating(
    tHCI_STATUS status, uint16_t handle, uint16_t maximum_transmit_latency,
    UNUSED_ATTR uint16_t maximum_receive_latency,
    uint16_t minimum_remote_timeout, uint16_t minimum_local_timeout) {
  LOG_DEBUG("For now pointing back again to legacy");
  tACL_CONN* p_acl = acl_get_connection_from_handle(handle);
  if (p_acl == nullptr) {
    LOG_ERROR("Received mode change for unknown acl handle:0x%04x", handle);
    return;
  }

  p_acl->policy.sniff_subrating.pending_ = false;
  if (status == HCI_SUCCESS) {
    BTM_LogHistory(
        "Power", p_acl->remote_addr, "Sniff Subrating",
        base::StringPrintf(
            "max_xmit_latency:%.2fs remote_timeout:%.2fs local_timeout:%.2fs",
            ticks_to_seconds(maximum_transmit_latency),
            ticks_to_seconds(minimum_remote_timeout),
            ticks_to_seconds(minimum_local_timeout)));
  }

  const bool use_ssr =
      (p_acl->policy.mode.Interval() != maximum_receive_latency) ? true : false;

  for (auto client_callback : btm_cb.acl_cb_.link_policy.clients) {
    (*client_callback)(p_acl->remote_addr, BTM_PM_STS_SSR, (use_ssr) ? 1 : 0,
                       status);
  }

  LOG_DEBUG(
      "Notified sniff subrating registered clients cnt:%zu peer:%s use_ssr:%s "
      "status:%s",
      btm_cb.acl_cb_.link_policy.clients.size(),
      PRIVATE_ADDRESS(p_acl->remote_addr), logbool(use_ssr).c_str(),
      hci_error_code_text(status).c_str());
}
