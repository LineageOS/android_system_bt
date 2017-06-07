/******************************************************************************
 *
 *  Copyright (C) 2012 Broadcom Corporation
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
 *  Filename:      bt_utils.cc
 *
 *  Description:   Miscellaneous helper functions
 *
 *
 ******************************************************************************/

#define LOG_TAG "bt_utils"

#include "bt_utils.h"

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <unistd.h>
#include <mutex>

#define A2DP_RT_PRIORITY 1
#ifndef OS_GENERIC
#include <cutils/sched_policy.h>
#endif

#include "bt_types.h"
#include "btcore/include/module.h"
#include "osi/include/compat.h"
#include "osi/include/log.h"
#include "osi/include/properties.h"

typedef struct {
  bt_soc_type soc_type;
  char* soc_name;
} soc_type_node;

static soc_type_node soc_type_entries[] = {
                           { BT_SOC_SMD , (char *)"smd" },
                           { BT_SOC_AR3K , (char *)"ath3k" },
                           { BT_SOC_ROME , (char *)"rome" },
                           { BT_SOC_CHEROKEE , (char *)"cherokee" },
                           { BT_SOC_RESERVED , (char *)"" }
                                       };

/*******************************************************************************
 *  Type definitions for callback functions
 ******************************************************************************/
static pthread_once_t g_DoSchedulingGroupOnce[TASK_HIGH_MAX];
static bool g_DoSchedulingGroup[TASK_HIGH_MAX];
static std::mutex gIdxLock;
static int g_TaskIdx;
static int g_TaskIDs[TASK_HIGH_MAX];
#define INVALID_TASK_ID (-1)
static bt_soc_type soc_type;
static void init_soc_type();

static future_t* init(void) {
  int i;

  for (i = 0; i < TASK_HIGH_MAX; i++) {
    g_DoSchedulingGroupOnce[i] = PTHREAD_ONCE_INIT;
    g_DoSchedulingGroup[i] = true;
    g_TaskIDs[i] = INVALID_TASK_ID;
  }

  init_soc_type();
  return NULL;
}

static future_t* clean_up(void) {
  return NULL;
}

EXPORT_SYMBOL extern const module_t bt_utils_module = {.name = BT_UTILS_MODULE,
                                                       .init = init,
                                                       .start_up = NULL,
                                                       .shut_down = NULL,
                                                       .clean_up = clean_up,
                                                       .dependencies = {NULL}};

/*****************************************************************************
 *
 * Function        check_do_scheduling_group
 *
 * Description     check if it is ok to change schedule group
 *
 * Returns         void
 *
 ******************************************************************************/
static void check_do_scheduling_group(void) {
  char buf[PROPERTY_VALUE_MAX];
  int len = osi_property_get("debug.sys.noschedgroups", buf, "");
  if (len > 0) {
    int temp;
    if (sscanf(buf, "%d", &temp) == 1) {
      g_DoSchedulingGroup[g_TaskIdx] = temp == 0;
    }
  }
}

/*****************************************************************************
 *
 * Function        raise_priority_a2dp
 *
 * Description     Raise task priority for A2DP streaming
 *
 * Returns         void
 *
 ******************************************************************************/
void raise_priority_a2dp(tHIGH_PRIORITY_TASK high_task) {
  int rc = 0;
  int tid = gettid();

  {
    std::lock_guard<std::mutex> lock(gIdxLock);
    g_TaskIdx = high_task;

// TODO(armansito): Remove this conditional check once we find a solution
// for system/core on non-Android platforms.
#if defined(OS_GENERIC)
    rc = -1;
#else   // !defined(OS_GENERIC)
    pthread_once(&g_DoSchedulingGroupOnce[g_TaskIdx],
                 check_do_scheduling_group);
    if (g_TaskIdx < TASK_HIGH_MAX && g_DoSchedulingGroup[g_TaskIdx]) {
      // set_sched_policy does not support tid == 0
      rc = set_sched_policy(tid, SP_AUDIO_SYS);
    }
#endif  // defined(OS_GENERIC)

    g_TaskIDs[high_task] = tid;
  }

  if (rc) {
    LOG_WARN(LOG_TAG, "failed to change sched policy, tid %d, err: %d", tid,
             errno);
  }

  // make A2DP threads use RT scheduling policy since they are part of the
  // audio pipeline
  {
    struct sched_param rt_params;
    rt_params.sched_priority = A2DP_RT_PRIORITY;

    const int rc = sched_setscheduler(tid, SCHED_FIFO, &rt_params);
    if (rc != 0) {
      LOG_ERROR(LOG_TAG,
                "%s unable to set SCHED_FIFO priority %d for tid %d, error %s",
                __func__, A2DP_RT_PRIORITY, tid, strerror(errno));
    }
  }
}

/*****************************************************************************
**
** Function        init_soc_type
**
** Description     Get Bluetooth SoC type from system setting and stores it
**                 in soc_type.
**
** Returns         void.
**
*******************************************************************************/
static void init_soc_type() {
  int ret = 0;
  char bt_soc_type[PROPERTY_VALUE_MAX];

  ALOGI("init_soc_type");

  soc_type = BT_SOC_DEFAULT;
  ret = property_get("qcom.bluetooth.soc", bt_soc_type, NULL);
  if (ret != 0) {
    int i;
    ALOGI("qcom.bluetooth.soc set to %s\n", bt_soc_type);
    for ( i = BT_SOC_AR3K ; i < BT_SOC_RESERVED ; i++ ) {
      char* soc_name = soc_type_entries[i].soc_name;
      if (!strcmp(bt_soc_type, soc_name)) {
        soc_type = soc_type_entries[i].soc_type;
        break;
      }
    }
  }
}

/*****************************************************************************
**
** Function        get_soc_type
**
** Description     This function is used to get the Bluetooth SoC type.
**
** Returns         bt_soc_type.
**
*******************************************************************************/
bt_soc_type get_soc_type() {
  return soc_type;
}
