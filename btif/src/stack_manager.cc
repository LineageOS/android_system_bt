/******************************************************************************
 *
 *  Copyright 2014 Google, Inc.
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

#define LOG_TAG "bt_stack_manager"

#include "stack_manager.h"

#include <hardware/bluetooth.h>

#include "btcore/include/module.h"
#include "btcore/include/osi_module.h"
#include "btif_api.h"
#include "btif_common.h"
#include "common/message_loop_thread.h"
#include "device/include/controller.h"
#include "hci/include/btsnoop.h"
#include "main/shim/shim.h"
#include "osi/include/log.h"
#include "osi/include/osi.h"
#include "osi/include/semaphore.h"
#include "stack/include/acl_api.h"
#include "stack/include/btm_client_interface.h"
#include "stack/include/btu.h"

// Temp includes
#include "bt_utils.h"
#include "bta/sys/bta_sys.h"
#include "btif_config.h"
#include "btif_profile_queue.h"
#include "internal_include/bt_target.h"
#include "internal_include/bte.h"
#include "stack/btm/btm_int.h"
#include "stack/include/gatt_api.h"
#include "stack/include/l2c_api.h"
#include "stack/include/port_api.h"
#include "stack/sdp/sdpint.h"
#if (BNEP_INCLUDED == TRUE)
#include "stack/include/bnep_api.h"
#endif
#include "stack/include/gap_api.h"
#if (PAN_INCLUDED == TRUE)
#include "stack/include/pan_api.h"
#endif
#include "stack/include/a2dp_api.h"
#include "stack/include/avrc_api.h"
#if (HID_HOST_INCLUDED == TRUE)
#include "stack/include/hidh_api.h"
#endif
#include "stack/include/smp_api.h"
#include "bta_ar_api.h"
#include "bta/sys/bta_sys_int.h"
#include "bta_dm_int.h"
#include "btif/include/btif_pan.h"
#include "btif/include/btif_sock.h"
#include "device/include/interop.h"
#include "internal_include/stack_config.h"
#include "main/shim/controller.h"

void main_thread_shut_down();
void main_thread_start_up();
void BTA_dm_on_hw_on();
void BTA_dm_on_hw_off();

using bluetooth::common::MessageLoopThread;

static MessageLoopThread management_thread("bt_stack_manager_thread");

// If initialized, any of the bluetooth API functions can be called.
// (e.g. turning logging on and off, enabling/disabling the stack, etc)
static bool stack_is_initialized;
// If running, the stack is fully up and able to bluetooth.
static bool stack_is_running;

static void event_init_stack(void* context);
static void event_start_up_stack(void* context);
static void event_shut_down_stack(void* context);
static void event_clean_up_stack(void* context);

static void event_signal_stack_up(void* context);
static void event_signal_stack_down(void* context);

// Unvetted includes/imports, etc which should be removed or vetted in the
// future
static future_t* hack_future;
// End unvetted section

// Interface functions

static void init_stack() {
  // This is a synchronous process. Post it to the thread though, so
  // state modification only happens there. Using the thread to perform
  // all stack operations ensures that the operations are done serially
  // and do not overlap.
  semaphore_t* semaphore = semaphore_new(0);
  management_thread.DoInThread(FROM_HERE,
                               base::Bind(event_init_stack, semaphore));
  semaphore_wait(semaphore);
  semaphore_free(semaphore);
}

static void start_up_stack_async() {
  management_thread.DoInThread(FROM_HERE,
                               base::Bind(event_start_up_stack, nullptr));
}

static void shut_down_stack_async() {
  management_thread.DoInThread(FROM_HERE,
                               base::Bind(event_shut_down_stack, nullptr));
}

static void clean_up_stack() {
  // This is a synchronous process. Post it to the thread though, so
  // state modification only happens there.
  semaphore_t* semaphore = semaphore_new(0);
  management_thread.DoInThread(FROM_HERE,
                               base::Bind(event_clean_up_stack, semaphore));
  semaphore_wait(semaphore);
  semaphore_free(semaphore);
  management_thread.ShutDown();
}

static bool get_stack_is_running() { return stack_is_running; }

// Internal functions

// Synchronous function to initialize the stack
static void event_init_stack(void* context) {
  semaphore_t* semaphore = (semaphore_t*)context;

  LOG_INFO("%s is initializing the stack", __func__);

  if (stack_is_initialized) {
    LOG_INFO("%s found the stack already in initialized state", __func__);
  } else {
    module_management_start();

    module_init(get_module(OSI_MODULE));
    module_init(get_module(BT_UTILS_MODULE));
    if (bluetooth::shim::is_any_gd_enabled()) {
      module_start_up(get_module(GD_IDLE_MODULE));
    }
    module_init(get_module(BTIF_CONFIG_MODULE));
    btif_init_bluetooth();

    module_init(get_module(INTEROP_MODULE));
    bte_main_init();
    module_init(get_module(STACK_CONFIG_MODULE));

    // stack init is synchronous, so no waiting necessary here
    stack_is_initialized = true;
  }

  LOG_INFO("%s finished", __func__);

  if (semaphore) semaphore_post(semaphore);
}

static void ensure_stack_is_initialized() {
  if (!stack_is_initialized) {
    LOG_WARN("%s found the stack was uninitialized. Initializing now.",
             __func__);
    // No semaphore needed since we are calling it directly
    event_init_stack(nullptr);
  }
}

// Synchronous function to start up the stack
static void event_start_up_stack(UNUSED_ATTR void* context) {
  if (stack_is_running) {
    LOG_INFO("%s stack already brought up", __func__);
    return;
  }

  ensure_stack_is_initialized();

  LOG_INFO("%s is bringing up the stack", __func__);
  future_t* local_hack_future = future_new();
  hack_future = local_hack_future;

  if (bluetooth::shim::is_any_gd_enabled()) {
    LOG_INFO("%s Gd shim module enabled", __func__);
    module_shut_down(get_module(GD_IDLE_MODULE));
    module_start_up(get_module(GD_SHIM_MODULE));
    module_start_up(get_module(BTIF_CONFIG_MODULE));
  } else {
    module_start_up(get_module(BTIF_CONFIG_MODULE));
    module_start_up(get_module(BTSNOOP_MODULE));
    module_start_up(get_module(HCI_MODULE));
  }

  get_btm_client_interface().lifecycle.btm_init();
  l2c_init();
  sdp_init();
  gatt_init();
  SMP_Init();
  get_btm_client_interface().lifecycle.btm_ble_init();

  RFCOMM_Init();
#if (BNEP_INCLUDED == TRUE)
  BNEP_Init();
#if (PAN_INCLUDED == TRUE)
  PAN_Init();
#endif /* PAN */
#endif /* BNEP Included */
  A2DP_Init();
  AVRC_Init();
  GAP_Init();
#if (HID_HOST_INCLUDED == TRUE)
  HID_HostInit();
#endif

  bta_sys_init();
  bta_ar_init();
  module_init(get_module(BTE_LOGMSG_MODULE));

  main_thread_start_up();

  btif_init_ok();
  BTA_dm_init();
  bta_dm_enable(bte_dm_evt);

  bta_set_forward_hw_failures(true);
  btm_acl_device_down();
  BTM_db_reset();
  if (bluetooth::shim::is_gd_controller_enabled()) {
    CHECK(module_start_up(get_module(GD_CONTROLLER_MODULE)));
  } else {
    CHECK(module_start_up(get_module(CONTROLLER_MODULE)));
  }
  BTM_reset_complete();

  BTA_dm_on_hw_on();

  if (future_await(local_hack_future) != FUTURE_SUCCESS) {
    LOG_ERROR("%s failed to start up the stack", __func__);
    stack_is_running = true;  // So stack shutdown actually happens
    event_shut_down_stack(nullptr);
    return;
  }

  stack_is_running = true;
  LOG_INFO("%s finished", __func__);
  do_in_jni_thread(FROM_HERE, base::Bind(event_signal_stack_up, nullptr));
}

// Synchronous function to shut down the stack
static void event_shut_down_stack(UNUSED_ATTR void* context) {
  if (!stack_is_running) {
    LOG_INFO("%s stack is already brought down", __func__);
    return;
  }

  LOG_INFO("%s is bringing down the stack", __func__);
  future_t* local_hack_future = future_new();
  hack_future = local_hack_future;
  stack_is_running = false;

  do_in_main_thread(FROM_HERE, base::Bind(&btm_ble_multi_adv_cleanup));

  btif_dm_on_disable();
  btif_sock_cleanup();
  btif_pan_cleanup();

  do_in_main_thread(FROM_HERE, base::Bind(bta_dm_disable));

  future_await(local_hack_future);
  local_hack_future = future_new();
  hack_future = local_hack_future;

  bta_sys_disable();
  bta_set_forward_hw_failures(false);
  BTA_dm_on_hw_off();

  module_shut_down(get_module(BTIF_CONFIG_MODULE));

  future_await(local_hack_future);

  main_thread_shut_down();

  module_clean_up(get_module(BTE_LOGMSG_MODULE));

  gatt_free();
  l2c_free();
  sdp_free();
  get_btm_client_interface().lifecycle.btm_ble_free();
  get_btm_client_interface().lifecycle.btm_free();

  if (bluetooth::shim::is_any_gd_enabled()) {
    LOG_INFO("%s Gd shim module disabled", __func__);
    module_shut_down(get_module(GD_SHIM_MODULE));
    module_start_up(get_module(GD_IDLE_MODULE));
  } else {
    module_shut_down(get_module(HCI_MODULE));
    module_shut_down(get_module(BTSNOOP_MODULE));
  }

  module_shut_down(get_module(CONTROLLER_MODULE));  // Doesn't do any work, just
                                                    // puts it in a restartable
                                                    // state

  hack_future = future_new();
  do_in_jni_thread(FROM_HERE, base::Bind(event_signal_stack_down, nullptr));
  future_await(hack_future);
  LOG_INFO("%s finished", __func__);
}

static void ensure_stack_is_not_running() {
  if (stack_is_running) {
    LOG_WARN("%s found the stack was still running. Bringing it down now.",
             __func__);
    event_shut_down_stack(nullptr);
  }
}

// Synchronous function to clean up the stack
static void event_clean_up_stack(void* context) {
  if (!stack_is_initialized) {
    LOG_INFO("%s found the stack already in a clean state", __func__);
    goto cleanup;
  }

  ensure_stack_is_not_running();

  LOG_INFO("%s is cleaning up the stack", __func__);
  stack_is_initialized = false;

  btif_cleanup_bluetooth();

  module_clean_up(get_module(STACK_CONFIG_MODULE));
  module_clean_up(get_module(INTEROP_MODULE));

  module_clean_up(get_module(BTIF_CONFIG_MODULE));
  module_clean_up(get_module(BT_UTILS_MODULE));
  module_clean_up(get_module(OSI_MODULE));
  module_shut_down(get_module(GD_IDLE_MODULE));
  module_management_stop();
  LOG_INFO("%s finished", __func__);

cleanup:;
  semaphore_t* semaphore = (semaphore_t*)context;
  if (semaphore) semaphore_post(semaphore);
}

static void event_signal_stack_up(UNUSED_ATTR void* context) {
  // Notify BTIF connect queue that we've brought up the stack. It's
  // now time to dispatch all the pending profile connect requests.
  btif_queue_connect_next();
  invoke_adapter_state_changed_cb(BT_STATE_ON);
}

static void event_signal_stack_down(UNUSED_ATTR void* context) {
  invoke_adapter_state_changed_cb(BT_STATE_OFF);
  future_ready(stack_manager_get_hack_future(), FUTURE_SUCCESS);
}

static void ensure_manager_initialized() {
  if (management_thread.IsRunning()) return;

  management_thread.StartUp();
  if (!management_thread.IsRunning()) {
    LOG_ERROR("%s unable to start stack management thread", __func__);
    return;
  }
}

static const stack_manager_t interface = {init_stack, start_up_stack_async,
                                          shut_down_stack_async, clean_up_stack,
                                          get_stack_is_running};

const stack_manager_t* stack_manager_get_interface() {
  ensure_manager_initialized();
  return &interface;
}

future_t* stack_manager_get_hack_future() { return hack_future; }
