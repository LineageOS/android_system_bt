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

#include <base/bind.h>
#include <base/callback.h>
#include <base/location.h>
#include <base/logging.h>
#include <map>
#include <memory>
#include <set>

#include "internal_include/bt_trace.h"
#include "osi/include/alarm.h"
#include "stack/btm/btm_ble_bgconn.h"

#define DIRECT_CONNECT_TIMEOUT (30 * 1000) /* 30 seconds */

struct closure_data {
  base::OnceClosure user_task;
  base::Location posted_from;
};

static void alarm_closure_cb(void* p) {
  closure_data* data = (closure_data*)p;
  VLOG(1) << "executing timer scheduled at %s" << data->posted_from.ToString();
  std::move(data->user_task).Run();
  delete data;
}

// Periodic alarms are not supported, because we clean up data in callback
void alarm_set_closure(const base::Location& posted_from, alarm_t* alarm,
                       uint64_t interval_ms, base::OnceClosure user_task) {
  closure_data* data = new closure_data;
  data->posted_from = posted_from;
  data->user_task = std::move(user_task);
  VLOG(1) << "scheduling timer %s" << data->posted_from.ToString();
  alarm_set_on_mloop(alarm, interval_ms, alarm_closure_cb, data);
}

using unique_alarm_ptr = std::unique_ptr<alarm_t, decltype(&alarm_free)>;

struct tGATT_BG_CONN_DEV {
  // ids of clients doing background connection to given device
  std::set<tGATT_IF> doing_bg_conn;

  // Apps trying to do direct connection.
  std::map<tGATT_IF, unique_alarm_ptr> doing_direct_conn;
};

namespace gatt {
namespace connection_manager {

namespace {
// Maps address to apps trying to connect to it
std::map<RawAddress, tGATT_BG_CONN_DEV> bgconn_dev;

bool anyone_connecting(
    const std::map<RawAddress, tGATT_BG_CONN_DEV>::iterator it) {
  return (!it->second.doing_bg_conn.empty() ||
          !it->second.doing_direct_conn.empty());
}

}  // namespace

/** background connection device from the list. Returns pointer to the device
 * record, or nullptr if not found */
std::set<tGATT_IF> get_apps_connecting_to(const RawAddress& address) {
  auto it = bgconn_dev.find(address);
  return (it != bgconn_dev.end()) ? it->second.doing_bg_conn
                                  : std::set<tGATT_IF>();
}

/** Add a device from the background connection list.  Returns true if device
 * added to the list, or already in list, false otherwise */
bool background_connect_add(tGATT_IF gatt_if, const RawAddress& address) {
  auto it = bgconn_dev.find(address);
  bool in_white_list = false;
  if (it != bgconn_dev.end()) {
    // device already in the whitelist, just add interested app to the list
    if (it->second.doing_bg_conn.count(gatt_if)) {
      LOG(INFO) << "App id=" << loghex(gatt_if)
                << "already doing background connection to " << address;
      return true;
    }

    // Already in white list ?
    if (anyone_connecting(it)) {
      in_white_list = true;
    }
  }

  if (!in_white_list) {
    // the device is not in the whitelist
    if (!BTM_WhiteListAdd(address)) return false;
  }

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

/** Remove device from the background connection device list or listening to
 * advertising list.  Returns true if device was on the list and was succesfully
 * removed */
bool background_connect_remove(tGATT_IF gatt_if, const RawAddress& address) {
  VLOG(2) << __func__;
  auto it = bgconn_dev.find(address);
  if (it == bgconn_dev.end()) return false;

  if (!it->second.doing_bg_conn.erase(gatt_if)) return false;

  if (anyone_connecting(it)) return true;

  // no more apps interested - remove from whitelist and delete record
  BTM_WhiteListRemove(address);
  bgconn_dev.erase(it);
  return true;
}

/** deregister all related background connetion device. */
void on_app_deregistered(tGATT_IF gatt_if) {
  auto it = bgconn_dev.begin();
  auto end = bgconn_dev.end();
  /* update the BG conn device list */
  while (it != end) {
    it->second.doing_bg_conn.erase(gatt_if);

    it->second.doing_direct_conn.erase(gatt_if);

    if (anyone_connecting(it)) {
      it++;
      continue;
    }

    BTM_WhiteListRemove(it->first);
    it = bgconn_dev.erase(it);
  }
}

void on_connection_complete(const RawAddress& address) {
  VLOG(2) << __func__;
  auto it = bgconn_dev.find(address);
  if (it == bgconn_dev.end()) return;

  while (!it->second.doing_direct_conn.empty()) {
    uint8_t gatt_if = it->second.doing_direct_conn.begin()->first;
    direct_connect_remove(gatt_if, address);
  }
}

/** Reset bg device list. If called after controller reset, set |after_reset| to
 * true, as there is no need to wipe controller white list in this case. */
void reset(bool after_reset) {
  bgconn_dev.clear();
  if (!after_reset) BTM_WhiteListClear();
}

void gatt_wl_direct_connect_timeout_cb(tGATT_IF gatt_if,
                                       const RawAddress& address) {
  // TODO: this would free the timer, from within the timer callback, which is
  // bad.
  direct_connect_remove(gatt_if, address);
}

/** Add a device to the direcgt connection list.  Returns true if device
 * added to the list, false otherwise */
bool direct_connect_add(tGATT_IF gatt_if, const RawAddress& address) {
  auto it = bgconn_dev.find(address);
  bool in_white_list = false;

  if (it != bgconn_dev.end()) {
    // app already trying to connect to this particular device
    if (it->second.doing_direct_conn.count(gatt_if)) {
      LOG(INFO) << "direct connect attempt from gatt_if=" << loghex(gatt_if)
                << " already in progress";
      return false;
    }

    // are we already in the white list ?
    if (anyone_connecting(it)) {
      in_white_list = true;
    }
  }

  bool params_changed = BTM_SetLeConnectionModeToFast();

  if (!in_white_list) {
    if (!BTM_WhiteListAdd(address)) {
      // if we can't add to white list, turn parameters back to slow.
      if (params_changed) BTM_SetLeConnectionModeToSlow();
      return false;
    }
  }

  // Setup a timer
  alarm_t* timeout = alarm_new("gatt_wl_conn_params_30s");
  alarm_set_closure(
      FROM_HERE, timeout, DIRECT_CONNECT_TIMEOUT,
      base::BindOnce(&gatt_wl_direct_connect_timeout_cb, gatt_if, address));

  bgconn_dev[address].doing_direct_conn.emplace(
      gatt_if, unique_alarm_ptr(timeout, &alarm_free));
  return true;
}

bool any_direct_connect_left() {
  for (const auto& tmp : bgconn_dev) {
    if (!tmp.second.doing_direct_conn.empty()) return true;
  }
  return false;
}

bool direct_connect_remove(tGATT_IF gatt_if, const RawAddress& address) {
  VLOG(2) << __func__ << ": "
          << "gatt_if: " << +gatt_if << ", address:" << address;
  auto it = bgconn_dev.find(address);
  if (it == bgconn_dev.end()) return false;

  auto app_it = it->second.doing_direct_conn.find(gatt_if);
  if (app_it == it->second.doing_direct_conn.end()) return false;

  // this will free the alarm
  it->second.doing_direct_conn.erase(app_it);

  // if we removed last direct connection, lower the scan parameters used for
  // connecting
  if (!any_direct_connect_left()) {
    BTM_SetLeConnectionModeToSlow();
  }

  if (anyone_connecting(it)) return true;

  // no more apps interested - remove from whitelist
  BTM_WhiteListRemove(address);
  bgconn_dev.erase(it);
  return true;
}

void dump(int fd) {
  dprintf(fd, "\ngatt::connection_manager state:\n");
  if (bgconn_dev.empty()) {
    dprintf(fd, "\n\tno Low Energy connection attempts\n");
    return;
  }

  dprintf(fd, "\n\tdevices attempting connection: %d\n",
          (int)bgconn_dev.size());
  for (const auto& entry : bgconn_dev) {
    dprintf(fd, "\n\t * %s: ", entry.first.ToString().c_str());

    if (!entry.second.doing_direct_conn.empty()) {
      dprintf(fd, "\n\t\tapps doing direct connect: ");
      for (const auto& id : entry.second.doing_direct_conn) {
        dprintf(fd, "%d, ", id.first);
      }
    }

    if (entry.second.doing_bg_conn.empty()) {
      dprintf(fd, "\n\t\tapps doing background connect: ");
      for (const auto& id : entry.second.doing_bg_conn) {
        dprintf(fd, "%d, ", id);
      }
    }
  }
}

}  // namespace connection_manager
}  // namespace gatt