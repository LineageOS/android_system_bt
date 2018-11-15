/******************************************************************************
 *
 *  Copyright 2018 The Android Open Source Project
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

#include "connection_manager.h"

#include <base/logging.h>
#include <map>
#include <set>

#include "stack/btm/btm_ble_bgconn.h"

struct tGATT_BG_CONN_DEV {
  // ids of clients doing background connection to given device
  std::set<tGATT_IF> doing_bg_conn;

  // TODO: keep clients doing direct connection here
};

namespace gatt {
namespace connection_manager {

namespace {
// Maps address to apps trying to connect to address
std::map<RawAddress, tGATT_BG_CONN_DEV> bgconn_dev;

bool anyone_connecting(
    const std::map<RawAddress, tGATT_BG_CONN_DEV>::iterator it) {
  return !it->second.doing_bg_conn.empty();
}

}  // namespace

/** Return ids of applications attempting to connect to device with given
 * address */
std::set<tGATT_IF> get_apps_connecting_to(const RawAddress& address) {
  auto it = bgconn_dev.find(address);
  return (it != bgconn_dev.end()) ? it->second.doing_bg_conn
                                  : std::set<tGATT_IF>();
}

/** Add a device to the background connection procedure. Returns true if device
 * was added succesfully, or was already in it, false otherwise */
bool background_connect_add(tGATT_IF gatt_if, const RawAddress& address) {
  auto it = bgconn_dev.find(address);
  if (it != bgconn_dev.end()) {
    // device already in the whitelist, just add interested app to the list
    if (!it->second.doing_bg_conn.insert(gatt_if).second) {
      LOG(INFO) << "device already in iniator white list";
    }

    return true;
  }
  // the device is not in the whitelist

  if (!BTM_WhiteListAdd(address)) return false;

  // create endtry for address, and insert gatt_if.
  bgconn_dev[address].doing_bg_conn.insert(gatt_if);
  return true;
}

/** Removes all registrations for background connection for given device.
 * Returns true if anything was removed, false otherwise */
bool background_connect_remove_unconditional(const RawAddress& address) {
  auto it = bgconn_dev.find(address);
  if (it == bgconn_dev.end()) return false;

  BTM_WhiteListRemove(address);
  bgconn_dev.erase(it);
  return true;
}

/** Remove device from the background connection procedure. Returns true if
 * device was on the list and was succesfully removed */
bool background_connect_remove(tGATT_IF gatt_if, const RawAddress& address) {
  auto it = bgconn_dev.find(address);
  if (it == bgconn_dev.end()) return false;

  if (!it->second.doing_bg_conn.erase(gatt_if)) return false;

  if (anyone_connecting(it)) return true;

  // no more apps interested - remove from whitelist and delete record
  BTM_WhiteListRemove(it->first);
  bgconn_dev.erase(it);
  return true;
}

/** Deregister all related background connetion device. */
void on_app_deregistered(tGATT_IF gatt_if) {
  auto it = bgconn_dev.begin();
  auto end = bgconn_dev.end();
  /* update the BG conn device list */
  while (it != end) {
    it->second.doing_bg_conn.erase(gatt_if);
    if (it->second.doing_bg_conn.size()) {
      it++;
      continue;
    }

    BTM_WhiteListRemove(it->first);
    it = bgconn_dev.erase(it);
  }
}

/** Reset bg device list. If called after controller reset, set |after_reset| to
 * true, as there is no need to wipe controller white list in this case. */
void reset(bool after_reset) {
  bgconn_dev.clear();
  if (!after_reset) BTM_WhiteListClear();
}

}  // namespace connection_manager
}  // namespace gatt