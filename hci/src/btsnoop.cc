/******************************************************************************
 *
 *  Copyright (C) 2014 Google, Inc.
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

#define LOG_TAG "bt_snoop"

#include <mutex>

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>

#include "bt_types.h"
#include "hci/include/btsnoop.h"
#include "hci/include/btsnoop_mem.h"
#include "hci_layer.h"
#include "osi/include/log.h"
#include "osi/include/time.h"
#include "stack_config.h"

typedef enum {
  kCommandPacket = 1,
  kAclPacket = 2,
  kScoPacket = 3,
  kEventPacket = 4
} packet_type_t;

// Epoch in microseconds since 01/01/0000.
static const uint64_t BTSNOOP_EPOCH_DELTA = 0x00dcddb30f2f8000ULL;

static const stack_config_t* stack_config;

static int logfile_fd = INVALID_FD;
static bool module_started;
static bool is_logging;
static bool logging_enabled_via_api;
static std::mutex btsnoop_mutex;

// TODO(zachoverflow): merge btsnoop and btsnoop_net together
void btsnoop_net_open();
void btsnoop_net_close();
void btsnoop_net_write(const void* data, size_t length);

static void btsnoop_write_packet(packet_type_t type, uint8_t* packet,
                                 bool is_received, uint64_t timestamp_us);
static void update_logging();

// Module lifecycle functions

static future_t* start_up(void) {
  module_started = true;
  update_logging();

  return NULL;
}

static future_t* shut_down(void) {
  module_started = false;
  update_logging();

  return NULL;
}

EXPORT_SYMBOL extern const module_t btsnoop_module = {
    .name = BTSNOOP_MODULE,
    .init = NULL,
    .start_up = start_up,
    .shut_down = shut_down,
    .clean_up = NULL,
    .dependencies = {STACK_CONFIG_MODULE, NULL}};

// Interface functions

static void set_api_wants_to_log(bool value) {
  logging_enabled_via_api = value;
  update_logging();
}

static void capture(const BT_HDR* buffer, bool is_received) {
  uint8_t* p = const_cast<uint8_t*>(buffer->data + buffer->offset);

  std::lock_guard<std::mutex> lock(btsnoop_mutex);
  uint64_t timestamp_us = time_gettimeofday_us();
  btsnoop_mem_capture(buffer, timestamp_us);

  if (logfile_fd == INVALID_FD) return;

  switch (buffer->event & MSG_EVT_MASK) {
    case MSG_HC_TO_STACK_HCI_EVT:
      btsnoop_write_packet(kEventPacket, p, false, timestamp_us);
      break;
    case MSG_HC_TO_STACK_HCI_ACL:
    case MSG_STACK_TO_HC_HCI_ACL:
      btsnoop_write_packet(kAclPacket, p, is_received, timestamp_us);
      break;
    case MSG_HC_TO_STACK_HCI_SCO:
    case MSG_STACK_TO_HC_HCI_SCO:
      btsnoop_write_packet(kScoPacket, p, is_received, timestamp_us);
      break;
    case MSG_STACK_TO_HC_HCI_CMD:
      btsnoop_write_packet(kCommandPacket, p, true, timestamp_us);
      break;
  }
}

static const btsnoop_t interface = {set_api_wants_to_log, capture};

const btsnoop_t* btsnoop_get_interface() {
  stack_config = stack_config_get_interface();
  return &interface;
}

// Internal functions

static void update_logging() {
  std::lock_guard<std::mutex> lock(btsnoop_mutex);

  bool should_log = module_started && (logging_enabled_via_api ||
                                       stack_config->get_btsnoop_turned_on());

  if (module_started && !should_log) {
    LOG_INFO(LOG_TAG, "Deleting snoop log if it exists");
    remove(stack_config->get_btsnoop_log_path());
  }

  if (should_log == is_logging) return;

  is_logging = should_log;
  if (should_log) {
    const char* log_path = stack_config->get_btsnoop_log_path();

    // Save the old log if configured to do so
    if (stack_config->get_btsnoop_should_save_last()) {
      char last_log_path[PATH_MAX];
      snprintf(last_log_path, PATH_MAX, "%s.%" PRIu64, log_path,
               time_gettimeofday_us());
      if (!rename(log_path, last_log_path) && errno != ENOENT)
        LOG_ERROR(LOG_TAG, "%s unable to rename '%s' to '%s': %s", __func__,
                  log_path, last_log_path, strerror(errno));
    }

    mode_t prevmask = umask(0);
    logfile_fd = open(log_path, O_WRONLY | O_CREAT | O_TRUNC,
                      S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH);
    if (logfile_fd == INVALID_FD) {
      LOG_ERROR(LOG_TAG, "%s unable to open '%s': %s", __func__, log_path,
                strerror(errno));
      is_logging = false;
      umask(prevmask);
      return;
    }
    umask(prevmask);

    write(logfile_fd, "btsnoop\0\0\0\0\1\0\0\x3\xea", 16);
    btsnoop_net_open();
  } else {
    if (logfile_fd != INVALID_FD) close(logfile_fd);

    logfile_fd = INVALID_FD;
    btsnoop_net_close();
  }
}

typedef struct {
  uint32_t length_original;
  uint32_t length_captured;
  uint32_t flags;
  uint32_t dropped_packets;
  uint64_t timestamp;
  uint8_t type;
} __attribute__((__packed__)) btsnoop_header_t;

static uint64_t htonll(uint64_t ll) {
  const uint32_t l = 1;
  if (*(reinterpret_cast<const uint8_t*>(&l)) == 1)
    return static_cast<uint64_t>(htonl(ll & 0xffffffff)) << 32 |
           htonl(ll >> 32);

  return ll;
}

static void btsnoop_write_packet(packet_type_t type, uint8_t* packet,
                                 bool is_received, uint64_t timestamp_us) {
  uint32_t length_he = 0;
  uint32_t flags = 0;

  switch (type) {
    case kCommandPacket:
      length_he = packet[2] + 4;
      flags = 2;
      break;
    case kAclPacket:
      length_he = (packet[3] << 8) + packet[2] + 5;
      flags = is_received;
      break;
    case kScoPacket:
      length_he = packet[2] + 4;
      flags = is_received;
      break;
    case kEventPacket:
      length_he = packet[1] + 3;
      flags = 3;
      break;
  }

  btsnoop_header_t header;
  header.length_original = htonl(length_he);
  header.length_captured = header.length_original;
  header.flags = htonl(flags);
  header.dropped_packets = 0;
  header.timestamp = htonll(timestamp_us + BTSNOOP_EPOCH_DELTA);
  header.type = type;

  btsnoop_net_write(&header, sizeof(btsnoop_header_t));
  btsnoop_net_write(packet, length_he - 1);

  if (logfile_fd != INVALID_FD) {
    iovec iov[] = {{&header, sizeof(btsnoop_header_t)},
                   {reinterpret_cast<void*>(packet), length_he - 1}};
    TEMP_FAILURE_RETRY(writev(logfile_fd, iov, 2));
  }
}
