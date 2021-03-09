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

#include <unordered_set>

#include "main/shim/dumpsys.h"
#include "osi/include/log.h"
#include "stack/acl/acl.h"
#include "types/raw_address.h"

void tACL_CONN::Reset() {
  memset(peer_le_features, 0, sizeof(peer_le_features));
  peer_le_features_valid = false;
  memset(peer_lmp_feature_pages, 0, sizeof(peer_lmp_feature_pages));
  memset(peer_lmp_feature_valid, 0, sizeof(peer_lmp_feature_valid));
  active_remote_addr = RawAddress::kEmpty;
  conn_addr = RawAddress::kEmpty;
  remote_addr = RawAddress::kEmpty;
  link_up_issued = false;
  transport = BT_TRANSPORT_INVALID;
  flush_timeout_in_ticks = 0;
  hci_handle = 0;
  link_super_tout = 0;
  pkt_types_mask = 0;
  active_remote_addr_type = BLE_ADDR_PUBLIC;
  conn_addr_type = BLE_ADDR_PUBLIC;
  disconnect_reason = 0;
  encrypt_state_ = BTM_ACL_ENCRYPT_STATE_IDLE;
  is_encrypted = false;
  link_role = HCI_ROLE_CENTRAL;
  switch_role_failed_attempts = 0;
  memset(&remote_version_info, 0, sizeof(remote_version_info));
  rs_disc_pending = BTM_SEC_RS_NOT_PENDING;
  switch_role_state_ = BTM_ACL_SWKEY_STATE_IDLE;
  sca = 0;
}

// When the local device initiates an le ACL disconnect the address
// should not be re-added to the acceptlist.
void tACL_CB::AddToIgnoreAutoConnectAfterDisconnect(const RawAddress& bd_addr) {
  if (!ignore_auto_connect_after_disconnect_set_.insert(bd_addr).second) {
    LOG_WARN(
        "Unexpectedly found device address already in ignore auto connect "
        "device:%s",
        PRIVATE_ADDRESS(bd_addr));
  }
}

// A check and clear mechanism used to determine if the address should be
// re-added to the acceptlist after an le ACL disconnect is received from a
// peer.
bool tACL_CB::CheckAndClearIgnoreAutoConnectAfterDisconnect(
    const RawAddress& bd_addr) {
  return (ignore_auto_connect_after_disconnect_set_.erase(bd_addr) > 0);
}

void tACL_CB::ClearAllIgnoreAutoConnectAfterDisconnect() {
  ignore_auto_connect_after_disconnect_set_.clear();
}
