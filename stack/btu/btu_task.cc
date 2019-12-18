/******************************************************************************
 *
 *  Copyright 1999-2012 Broadcom Corporation
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

#define LOG_TAG "bt_btu_task"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bta/sys/bta_sys.h"
#include "btcore/include/module.h"
#include "bte.h"
#include "btif/include/btif_common.h"
#include "common/message_loop_thread.h"
#include "common/once_timer.h"
#include "common/time_util.h"
#include "osi/include/osi.h"
#include "stack/btm/btm_int.h"
#include "stack/include/btu.h"
#include "stack/l2cap/l2c_int.h"

#include <base/bind.h>
#include <base/logging.h>
#include <base/run_loop.h>
#include <base/threading/thread.h>

#ifndef HWBINDER_TIMEOUT_MS
#define HWBINDER_TIMEOUT_MS 500
#endif

using bluetooth::common::MessageLoopThread;
using bluetooth::common::OnceTimer;

/* Define utils for HwBinder timer dumpsys */
typedef struct {
  uint64_t counter_5ms = 0;
  uint64_t counter_20ms = 0;
  uint64_t counter_50ms = 0;
  uint64_t counter_100ms = 0;
  uint64_t counter_250ms = 0;
  uint64_t counter_max_ms = 0;
  void addTime(uint64_t time) {
    if (time < 5) {
      counter_5ms++;
    } else if (time < 20) {
      counter_20ms++;
    } else if (time < 50) {
      counter_50ms++;
    } else if (time < 100) {
      counter_100ms++;
    } else if (time < 250) {
      counter_250ms++;
    } else {
      counter_max_ms++;
    }
  }
} hwbinder_timer_collector_t;

typedef struct {
  uint64_t start_time_ms;
  std::string from_here;
} hwbinder_timestamp_t;

std::map<std::string, hwbinder_timer_collector_t> timer_map;
hwbinder_timestamp_t hwbinder_timestamp;

/* Define BTU storage area */
uint8_t btu_trace_level = HCI_INITIAL_TRACE_LEVEL;

static MessageLoopThread main_thread("bt_main_thread");
static OnceTimer hwbinder_timer;

void btu_hci_msg_process(BT_HDR* p_msg) {
  /* Determine the input message type. */
  switch (p_msg->event & BT_EVT_MASK) {
    case BT_EVT_TO_BTU_HCI_ACL:
      /* All Acl Data goes to L2CAP */
      l2c_rcv_acl_data(p_msg);
      break;

    case BT_EVT_TO_BTU_L2C_SEG_XMIT:
      /* L2CAP segment transmit complete */
      l2c_link_segments_xmitted(p_msg);
      break;

    case BT_EVT_TO_BTU_HCI_SCO:
      btm_route_sco_data(p_msg);
      break;

    case BT_EVT_TO_BTU_HCI_EVT:
      btu_hcif_process_event((uint8_t)(p_msg->event & BT_SUB_EVT_MASK), p_msg);
      osi_free(p_msg);
      break;

    case BT_EVT_TO_BTU_HCI_CMD:
      btu_hcif_send_cmd((uint8_t)(p_msg->event & BT_SUB_EVT_MASK), p_msg);
      break;

    case BT_EVT_TO_BTU_HCI_ISO:
      // TODO: implement handler
      osi_free(p_msg);
      break;

    default:
      osi_free(p_msg);
      break;
  }
}

bluetooth::common::MessageLoopThread* get_main_thread() { return &main_thread; }

base::MessageLoop* get_main_message_loop() {
  return main_thread.message_loop();
}

bt_status_t do_in_main_thread(const base::Location& from_here,
                              base::OnceClosure task) {
  if (!main_thread.DoInThread(from_here, std::move(task))) {
    LOG(ERROR) << __func__ << ": failed from " << from_here.ToString();
    return BT_STATUS_FAIL;
  }
  return BT_STATUS_SUCCESS;
}

void hwbinder_timeout(const base::Location& from_here) {
  LOG(FATAL) << "HwBinder thread timeout at " << from_here.ToString();
}

void main_thread_hwbinder_timer_start(const base::Location& from_here) {
  if (hwbinder_timer.IsScheduled()) {
    LOG(FATAL) << __func__ << ": hwbinder_timer is already scheduled!";
  }
  if (!hwbinder_timer.Schedule(
          main_thread.GetWeakPtr(), from_here,
          base::Bind(&hwbinder_timeout, from_here),
          base::TimeDelta::FromMilliseconds(HWBINDER_TIMEOUT_MS))) {
    LOG(FATAL) << __func__ << ": failed from " << from_here.ToString();
  }

  hwbinder_timestamp.start_time_ms =
      bluetooth::common::time_get_os_boottime_ms();
  hwbinder_timestamp.from_here = from_here.ToString();
}

void main_thread_hwbinder_timer_stop() {
  if (!hwbinder_timer.IsScheduled()) {
    LOG(FATAL) << __func__ << ": hwbinder_timer is not scheduled!";
  }
  hwbinder_timer.CancelAndWait();

  uint64_t delta_time = bluetooth::common::time_get_os_boottime_ms() -
                        hwbinder_timestamp.start_time_ms;
  auto it = timer_map.find(hwbinder_timestamp.from_here);
  if (it == timer_map.end()) {
    hwbinder_timer_collector_t collector;
    collector.addTime(delta_time);
    timer_map.emplace(hwbinder_timestamp.from_here, collector);
  } else {
    it->second.addTime(delta_time);
  }
}

void stack_debug_hwbinder_thread_dump(int fd) {
  dprintf(fd, "\nHwBinder Thread Timer:\n");
  for (auto it = timer_map.begin(); it != timer_map.end(); it++) {
    dprintf(fd, "  %s:\n", it->first.c_str());
    std::stringstream ss;
    ss << "    Invoke Counts (5ms/20ms/50ms/100ms/250ms/Over 250ms) : "
       << std::to_string(it->second.counter_5ms) << " / "
       << std::to_string(it->second.counter_20ms) << " / "
       << std::to_string(it->second.counter_50ms) << " / "
       << std::to_string(it->second.counter_100ms) << " / "
       << std::to_string(it->second.counter_250ms) << " / "
       << std::to_string(it->second.counter_max_ms);
    dprintf(fd, "%s\n", ss.str().c_str());
  }
}

void btu_task_start_up(UNUSED_ATTR void* context) {
  LOG(INFO) << "Bluetooth chip preload is complete";

  /* Initialize the mandatory core stack control blocks
     (BTU, BTM, L2CAP, and SDP)
   */
  btu_init_core();

  /* Initialize any optional stack components */
  BTE_InitStack();

  bta_sys_init();

  /* Initialise platform trace levels at this point as BTE_InitStack() and
   * bta_sys_init()
   * reset the control blocks and preset the trace level with
   * XXX_INITIAL_TRACE_LEVEL
   */
  module_init(get_module(BTE_LOGMSG_MODULE));

  main_thread.StartUp();
  if (!main_thread.IsRunning()) {
    LOG(FATAL) << __func__ << ": unable to start btu message loop thread.";
  }
  if (!main_thread.EnableRealTimeScheduling()) {
    LOG(FATAL) << __func__ << ": unable to enable real time scheduling";
  }
  if (do_in_jni_thread(FROM_HERE, base::Bind(btif_init_ok, 0, nullptr)) !=
      BT_STATUS_SUCCESS) {
    LOG(FATAL) << __func__ << ": unable to continue starting Bluetooth";
  }
}

void btu_task_shut_down(UNUSED_ATTR void* context) {
  // Shutdown message loop on task completed
  main_thread.ShutDown();

  module_clean_up(get_module(BTE_LOGMSG_MODULE));

  bta_sys_free();
  btu_free_core();
}
