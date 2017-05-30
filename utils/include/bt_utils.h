/******************************************************************************
 *
 *  Copyright (C) 2009-2012 Broadcom Corporation
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

#ifndef BT_UTILS_H
#define BT_UTILS_H

static const char BT_UTILS_MODULE[] = "bt_utils_module";

/*******************************************************************************
 *  Type definitions
 ******************************************************************************/

typedef enum {
  TASK_HIGH_MEDIA = 0,
  TASK_UIPC_READ,
  TASK_HIGH_MAX
} tHIGH_PRIORITY_TASK;

typedef enum {
    BT_SOC_DEFAULT = 0,
    BT_SOC_SMD = BT_SOC_DEFAULT,
    BT_SOC_AR3K,
    BT_SOC_ROME,
    BT_SOC_CHEROKEE,
    /* Add chipset type here */
    BT_SOC_RESERVED
} bt_soc_type;

/*******************************************************************************
 *  Functions
 ******************************************************************************/

void raise_priority_a2dp(tHIGH_PRIORITY_TASK high_task);
bt_soc_type get_soc_type();

#endif /* BT_UTILS_H */
