/*
 * Copyright 2020 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include <cstdint>

/* BTM application return status codes */
enum : uint8_t {
  BTM_SUCCESS = 0,         /* 0  Command succeeded                 */
  BTM_CMD_STARTED,         /* 1  Command started OK.               */
  BTM_BUSY,                /* 2  Device busy with another command  */
  BTM_NO_RESOURCES,        /* 3  No resources to issue command     */
  BTM_MODE_UNSUPPORTED,    /* 4  Request for 1 or more unsupported modes */
  BTM_ILLEGAL_VALUE,       /* 5  Illegal parameter value           */
  BTM_WRONG_MODE,          /* 6  Device in wrong mode for request  */
  BTM_UNKNOWN_ADDR,        /* 7  Unknown remote BD address         */
  BTM_DEVICE_TIMEOUT,      /* 8  Device timeout                    */
  BTM_BAD_VALUE_RET,       /* 9  A bad value was received from HCI */
  BTM_ERR_PROCESSING,      /* 10 Generic error                     */
  BTM_NOT_AUTHORIZED,      /* 11 Authorization failed              */
  BTM_DEV_RESET,           /* 12 Device has been reset             */
  BTM_CMD_STORED,          /* 13 request is stored in control block */
  BTM_ILLEGAL_ACTION,      /* 14 state machine gets illegal command */
  BTM_DELAY_CHECK,         /* 15 delay the check on encryption */
  BTM_SCO_BAD_LENGTH,      /* 16 Bad SCO over HCI data length */
  BTM_SUCCESS_NO_SECURITY, /* 17 security passed, no security set  */
  BTM_FAILED_ON_SECURITY,  /* 18 security failed                   */
  BTM_REPEATED_ATTEMPTS,   /* 19 repeated attempts for LE security requests */
  BTM_MODE4_LEVEL4_NOT_SUPPORTED, /* 20 Secure Connections Only Mode can't be
                                     supported */
  BTM_DEV_BLACKLISTED             /* 21 The device is Blacklisted */
};

typedef uint8_t tBTM_STATUS;
