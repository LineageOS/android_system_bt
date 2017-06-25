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

#include <base/logging.h>
#include <ctype.h>
#include <stdio.h>
#include <string.h>

#include "btcore/include/bdaddr.h"

bool bdaddr_is_empty(const RawAddress* addr) {
  CHECK(addr != NULL);

  uint8_t zero[sizeof(RawAddress)] = {0};
  return memcmp(addr, &zero, sizeof(RawAddress)) == 0;
}

const char* bdaddr_to_string(const RawAddress* addr, char* string,
                             size_t size) {
  CHECK(addr != NULL);
  CHECK(string != NULL);

  if (size < 18) return NULL;

  const uint8_t* ptr = addr->address;
  snprintf(string, size, "%02x:%02x:%02x:%02x:%02x:%02x", ptr[0], ptr[1],
           ptr[2], ptr[3], ptr[4], ptr[5]);
  return string;
}

bool string_is_bdaddr(const char* string) {
  CHECK(string != NULL);

  size_t len = strlen(string);
  if (len != 17) return false;

  for (size_t i = 0; i < len; ++i) {
    // Every 3rd char must be ':'.
    if (((i + 1) % 3) == 0 && string[i] != ':') return false;

    // All other chars must be a hex digit.
    if (((i + 1) % 3) != 0 && !isxdigit(string[i])) return false;
  }
  return true;
}

bool string_to_bdaddr(const char* string, RawAddress* addr) {
  CHECK(string != NULL);
  CHECK(addr != NULL);

  RawAddress new_addr;
  uint8_t* ptr = new_addr.address;
  bool ret = sscanf(string, "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
                    &ptr[0], &ptr[1], &ptr[2], &ptr[3], &ptr[4], &ptr[5]) == 6;

  if (ret) memcpy(addr, &new_addr, sizeof(RawAddress));

  return ret;
}
