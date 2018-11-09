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
#include <list>
#include <set>

#include "stack/btm/btm_ble_bgconn.h"

struct tGATT_BG_CONN_DEV {
  std::set<tGATT_IF> gatt_if;
  RawAddress remote_bda;
};

namespace gatt {
namespace connection_manager {

namespace {
std::list<tGATT_BG_CONN_DEV> bgconn_dev;

std::list<tGATT_BG_CONN_DEV>::iterator gatt_find_bg_dev_it(
    const RawAddress& remote_bda) {
  auto& list = bgconn_dev;
  for (auto it = list.begin(); it != list.end(); it++) {
    if (it->remote_bda == remote_bda) {
      return it;
    }
  }
  return list.end();
}

}  // namespace

/** background connection device from the list. Returns pointer to the device
 * record, or nullptr if not found */
std::set<tGATT_IF> get_apps_connecting_to(const RawAddress& address) {
  for (tGATT_BG_CONN_DEV& dev : bgconn_dev)
    if (dev.remote_bda == address) return dev.gatt_if;

  return std::set<tGATT_IF>();
}

/** background connection device from the list. Returns pointer to the device
 * record, or nullptr if not found */
tGATT_BG_CONN_DEV* gatt_find_bg_dev(const RawAddress& remote_bda) {
  for (tGATT_BG_CONN_DEV& dev : bgconn_dev) {
    if (dev.remote_bda == remote_bda) {
      return &dev;
    }
  }
  return nullptr;
}

/** Add a device from the background connection list.  Returns true if device
 * added to the list, or already in list, false otherwise */
bool background_connect_add(tGATT_IF gatt_if, const RawAddress& bd_addr) {
  tGATT_BG_CONN_DEV* p_dev = gatt_find_bg_dev(bd_addr);
  if (p_dev) {
    // device already in the whitelist, just add interested app to the list
    if (!p_dev->gatt_if.insert(gatt_if).second) {
      LOG(ERROR) << "device already in iniator white list";
    }

    return true;
  }
  // the device is not in the whitelist

  if (!BTM_WhiteListAdd(bd_addr)) return false;

  bgconn_dev.emplace_back();
  tGATT_BG_CONN_DEV& dev = bgconn_dev.back();
  dev.remote_bda = bd_addr;
  dev.gatt_if.insert(gatt_if);
  return true;
}

/** Removes all registrations for background connection for given device.
 * Returns true if anything was removed, false otherwise */
bool background_connect_remove_unconditional(const RawAddress& bd_addr) {
  auto dev_it = gatt_find_bg_dev_it(bd_addr);
  if (dev_it == bgconn_dev.end()) return false;

  BTM_WhiteListRemove(dev_it->remote_bda);
  bgconn_dev.erase(dev_it);
  return true;
}

/** Remove device from the background connection device list or listening to
 * advertising list.  Returns true if device was on the list and was succesfully
 * removed */
bool background_connect_remove(tGATT_IF gatt_if, const RawAddress& bd_addr) {
  auto dev_it = gatt_find_bg_dev_it(bd_addr);
  if (dev_it == bgconn_dev.end()) return false;

  if (!dev_it->gatt_if.erase(gatt_if)) return false;

  if (!dev_it->gatt_if.empty()) return true;

  // no more apps interested - remove from whitelist and delete record
  BTM_WhiteListRemove(dev_it->remote_bda);
  bgconn_dev.erase(dev_it);
  return true;
}

/** deregister all related back ground connetion device. */
void on_app_deregistered(tGATT_IF gatt_if) {
  auto it = bgconn_dev.begin();
  auto end = bgconn_dev.end();
  /* update the BG conn device list */
  while (it != end) {
    it->gatt_if.erase(gatt_if);
    if (it->gatt_if.size()) {
      it++;
      continue;
    }

    BTM_WhiteListRemove(it->remote_bda);
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