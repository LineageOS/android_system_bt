/******************************************************************************
 *
 *  Copyright (C) 2015 Google, Inc.
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

#include <stdbool.h>

#include "btcore/include/bdaddr.h"

typedef enum {
  // Disable secure connections
  // This is for pre BT 4.1/2 devices that do not handle secure mode
  // very well.
  INTEROP_DISABLE_LE_SECURE_CONNECTIONS,

  // Some devices have proven problematic during the pairing process, often
  // requiring multiple retries to complete pairing. To avoid degrading the user
  // experience for those devices, automatically re-try pairing if page
  // timeouts are received during pairing.
  INTEROP_AUTO_RETRY_PAIRING,

  // Some HID devices have proven problematic behaviour if SDP is initiated more
  // while HID connection is in progress or if more than 1 SDP connection is created
  // with those HID devices rsulting in issues of connection failure with such devices.
  // To avoid degrading the user experience with those devices, sdp is not attempted
  // as part of pairing process from btif layer.
  INTEROP_DISABLE_SDP_AFTER_PAIRING,

  // Some HID pointing devices have proven problematic behaviour if pairing is initiated with
  // them, resulting in no response for authentication request and ultimately resulting
  // in connection failure.
  // To avoid degrading the user experience with those devices, authentication request
  // is not requested explictly.
  INTEROP_DISABLE_AUTH_FOR_HID_POINTING,
} interop_feature_t;

// Check if a given |addr| matches a known interoperability workaround as identified
// by the |interop_feature_t| enum. This API is used for simple address based lookups
// where more information is not available. No look-ups or random address resolution
// is performed on |addr|.
bool interop_addr_match(const interop_feature_t feature, const bt_bdaddr_t *addr);

// Check if a given |name| matches a known interoperability workaround as identified
// by the |interop_feature_t| enum. This API is used for simple name based lookups
// where more information is not available.
bool interop_name_match(const interop_feature_t feature, const char *addr);

// Check if a given |manufacturer| matches a known interoperability workaround as identified
// by the |interop_feature_t| enum. This API is used for simple name based lookups
// where more information is not available.
bool interop_manufacturer_match(const interop_feature_t feature, uint16_t manufacturer);

