/******************************************************************************
 *
 *  Copyright 2016 The Android Open Source Project
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

#pragma once

#include "stack/gatt/gatt_int.h"
#include "stack/include/btm_ble_api_types.h"
#include "types/raw_address.h"

struct tGATT_BG_CONN_DEV {
  std::unordered_set<tGATT_IF> gatt_if;
  RawAddress remote_bda;
};

/* for background connection */
extern bool gatt_add_bg_dev_list(tGATT_REG* p_reg, const RawAddress& bd_addr);
extern bool gatt_remove_bg_dev_from_list(tGATT_REG* p_reg,
                                         const RawAddress& bd_addr);
extern bool gatt_is_bg_dev_for_app(tGATT_BG_CONN_DEV* p_dev, tGATT_IF gatt_if);
extern uint8_t gatt_clear_bg_dev_for_addr(const RawAddress& bd_addr);
extern tGATT_BG_CONN_DEV* gatt_find_bg_dev(const RawAddress& remote_bda);
extern void gatt_deregister_bgdev_list(tGATT_IF gatt_if);
