/******************************************************************************
 *
 *  Copyright (C) 2016 Google Inc.
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

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#include "btcore/include/bdaddr.h"
#include "btif/include/btif_debug.h"
#include "btif/include/btif_debug_l2c.h"

#define NUM_UPDATE_REQUESTS 5
#define NUM_UPDATE_RESPONSES 5

#define INTERVAL_1_25_MS_MULTIPLIER 1.25f
#define TIMEOUT_10_MS_MULTIPLIER 10

typedef enum {
  BTIF_DEBUG_CONNECTION_UPDATE_REQUEST,
  BTIF_DEBUG_CONNECTION_UPDATE_RESPONSE,
} btif_debug_ble_conn_update_t;

/* Shared Connection update record for both request and response. */
typedef struct ble_conn_update_t {
  uint64_t timestamp_ms;
  bt_bdaddr_t bda;
  btif_debug_ble_conn_update_t type;
  uint8_t status;         /* Not populated for request. */
  uint16_t min_interval;  /* Not populated for response. */
  uint16_t max_interval;
  uint16_t latency;
  uint16_t timeout;
} ble_conn_update_t;

static int update_request_index;
static int update_response_index;
static ble_conn_update_t last_ble_conn_update_requests[NUM_UPDATE_REQUESTS];
static ble_conn_update_t last_ble_conn_update_responses[NUM_UPDATE_RESPONSES];

static int dump_connection_update(int fd, const ble_conn_update_t *update) {
  if (!update || update->timestamp_ms == 0) {
    return -1;
  }

  /* Format timestamp */
  const uint64_t msecs = update->timestamp_ms / 1000;
  const time_t secs = msecs / 1000;
  struct tm *ptm = localtime(&secs);
  char time_buf[20] = {0};
  strftime(time_buf, sizeof(time_buf), "%m-%d %H:%M:%S", ptm);
  snprintf(time_buf, sizeof(time_buf), "%s.%03u", time_buf,
      (uint16_t)(msecs % 1000));

  /* Format address */
  char addr_buf[18] = {0};
  bdaddr_to_string(&update->bda, addr_buf, sizeof(addr_buf));

  if (update->type == BTIF_DEBUG_CONNECTION_UPDATE_REQUEST) {
    dprintf(fd,
        "  %s %s min interval=%d (%.2fms) max interval=%d (%.2fms) "
        "latency parameter=%d timeout multiplier=%d (%dms)\n",
        time_buf, addr_buf, update->min_interval,
        (float)update->min_interval * INTERVAL_1_25_MS_MULTIPLIER,
        update->max_interval,
        (float)update->max_interval * INTERVAL_1_25_MS_MULTIPLIER,
        update->latency, update->timeout,
        update->timeout * TIMEOUT_10_MS_MULTIPLIER);
  } else {
    dprintf(fd,
        "  %s %s status=%d interval=%d (%.2fms) latency parameter=%d "
        "timeout multiplier=%d (%dms)\n", time_buf,
        addr_buf, update->status, update->max_interval,
        (float)update->max_interval * INTERVAL_1_25_MS_MULTIPLIER,
        update->latency, update->timeout,
        update->timeout * TIMEOUT_10_MS_MULTIPLIER);
  }

  return 0;
}

static void record_connection_update(bt_bdaddr_t bda, uint8_t status,
    uint16_t min_interval, uint16_t max_interval, uint16_t latency,
    uint16_t timeout, btif_debug_ble_conn_update_t type,
    ble_conn_update_t* update) {

  memcpy(&update->bda, &bda, sizeof(bt_bdaddr_t));
  update->type = type;
  update->timestamp_ms = btif_debug_ts();
  update->min_interval = min_interval;
  update->max_interval = max_interval;
  update->latency = latency;
  update->timeout = timeout;
  update->status = 0;
}

void btif_debug_ble_connection_update_request(bt_bdaddr_t bda,
    uint16_t min_interval, uint16_t max_interval, uint16_t slave_latency_param,
    uint16_t timeout_multiplier) {
  ble_conn_update_t *request =
      &last_ble_conn_update_requests[update_request_index];

  record_connection_update(bda, 0, min_interval, max_interval, slave_latency_param,
      timeout_multiplier, BTIF_DEBUG_CONNECTION_UPDATE_REQUEST, request);

  update_request_index = (update_request_index == NUM_UPDATE_REQUESTS - 1) ?
      0 : update_request_index + 1;
}

void btif_debug_ble_connection_update_response(bt_bdaddr_t bda, uint8_t status,
    uint16_t interval, uint16_t slave_latency_param,
    uint16_t timeout_multiplier) {
  ble_conn_update_t *response =
      &last_ble_conn_update_responses[update_response_index];

  record_connection_update(bda, status, 0, interval, slave_latency_param,
      timeout_multiplier, BTIF_DEBUG_CONNECTION_UPDATE_RESPONSE, response);

  update_response_index = (update_response_index == NUM_UPDATE_RESPONSES - 1) ?
      0 : update_response_index + 1;
}

void btif_debug_l2c_dump(int fd) {
  dprintf(fd, "\nLE Connection Parameter Updates:\n");

  int i;
  dprintf(fd, "  Last %d Request(s):\n", NUM_UPDATE_REQUESTS);
  for (i = 0; i < NUM_UPDATE_REQUESTS; ++i) {
    if (dump_connection_update(fd, &last_ble_conn_update_requests[i]) < 0 &&
        i == 0) {
      dprintf(fd, "  None\n");
      break;
    }
  }

  dprintf(fd, "\n  Last %d Response(s):\n", NUM_UPDATE_RESPONSES);
  for (i = 0; i < NUM_UPDATE_RESPONSES; ++i) {
    if (dump_connection_update(fd, &last_ble_conn_update_responses[i]) < 0 &&
        i == 0) {
      dprintf(fd, "  None\n");
      break;
    }
  }
}
