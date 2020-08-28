/******************************************************************************
 *
 *  Copyright 2014 The Android Open Source Project
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
 *  Filename:      btif_mce.c
 *
 *  Description:   Message Access Profile (MCE role) Bluetooth Interface
 *
 *
 ******************************************************************************/

#define LOG_TAG "bt_btif_mce"

#include <stdlib.h>
#include <string.h>

#include <hardware/bluetooth.h>
#include <hardware/bt_mce.h>

#include "bt_types.h"
#include "bta_api.h"
#include "btif_common.h"
#include "btif_util.h"

/*****************************************************************************
 *  Static variables
 *****************************************************************************/

static bt_status_t init(btmce_callbacks_t* callbacks) {
  BTIF_TRACE_EVENT("%s", __func__);
  btif_enable_service(BTA_MAP_SERVICE_ID);
  return BT_STATUS_SUCCESS;
}

static bt_status_t get_remote_mas_instances(RawAddress* bd_addr) {
  return BT_STATUS_SUCCESS;
}

static const btmce_interface_t mce_if = {
    sizeof(btmce_interface_t), init, get_remote_mas_instances,
};

const btmce_interface_t* btif_mce_get_interface(void) {
  BTIF_TRACE_EVENT("%s", __func__);
  return &mce_if;
}
