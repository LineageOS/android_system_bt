/******************************************************************************
 *
 *  Copyright 2000-2012 Broadcom Corporation
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

#define LOG_TAG "bt_task"

#include <base/logging.h>

#include "bt_target.h"
#include "btm_int.h"
#include "btu.h"
#include "common/message_loop_thread.h"
#include "device/include/controller.h"
#include "gatt_api.h"
#include "l2c_api.h"
#include "sdpint.h"

void btu_task_shut_down();

/*****************************************************************************
 *
 * Function         btu_free_core
 *
 * Description      Releases control block memory for each core component.
 *
 *
 * Returns          void
 *
 *****************************************************************************/
void btu_free_core() {
  /* Free the mandatory core stack components */
  gatt_free();

  l2c_free();

  sdp_free();

  btm_free();
}

void BTU_ShutDown() {
  btu_task_shut_down();
}
