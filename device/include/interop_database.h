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

#include "device/include/interop.h"

typedef struct {
  bt_bdaddr_t addr;
  uint8_t len;
  interop_feature_t feature;
} interop_addr_t;

typedef struct {
  char *name;;
  interop_feature_t feature;
} interop_name_t;

typedef struct {
  uint16_t manufacturer;
  interop_feature_t feature;
} interop_manufacturer_t;

static const interop_addr_t interop_addr_database[] = {
  // Nexus Remote (Spike)
  // Note: May affect other Asus brand devices
  {{0x08, 0x62, 0x66,       0,0,0}, 3, INTEROP_DISABLE_LE_SECURE_CONNECTIONS},
  {{0x38, 0x2c, 0x4a, 0xc9,   0,0}, 4, INTEROP_DISABLE_LE_SECURE_CONNECTIONS},
  {{0x38, 0x2c, 0x4a, 0xe6,   0,0}, 4, INTEROP_DISABLE_LE_SECURE_CONNECTIONS},
  {{0x54, 0xa0, 0x50, 0xd9,   0,0}, 4, INTEROP_DISABLE_LE_SECURE_CONNECTIONS},
  {{0xac, 0x9e, 0x17,       0,0,0}, 3, INTEROP_DISABLE_LE_SECURE_CONNECTIONS},
  {{0xf0, 0x79, 0x59,       0,0,0}, 3, INTEROP_DISABLE_LE_SECURE_CONNECTIONS},

  // Polar Heart Rate Monitor
  {{0x00, 0x22, 0xd0,       0,0,0}, 3, INTEROP_DISABLE_LE_SECURE_CONNECTIONS},

  // Motorola Key Link
  {{0x1c, 0x96, 0x5a,       0,0,0}, 3, INTEROP_DISABLE_LE_SECURE_CONNECTIONS},

  // Dialog Keyboard/Mouse
  {{0x80, 0xea, 0xCa,       0,0,0}, 3, INTEROP_DISABLE_LE_SECURE_CONNECTIONS},
  // Xiaomi Mi Band
  {{0x88, 0x0f, 0x10,       0,0,0}, 3, INTEROP_DISABLE_LE_SECURE_CONNECTIONS},

  // BMW car kits (Harman/Becker)
  {{0x9c, 0xdf, 0x03,       0,0,0}, 3, INTEROP_AUTO_RETRY_PAIRING},

  // Apple Magic Mouse
  {{0x04, 0x0C, 0xCE,       0,0,0}, 3, INTEROP_DISABLE_SDP_AFTER_PAIRING},
  // Bluetooth Laser Travel Mouse
  {{0x00, 0x07, 0x61,       0,0,0}, 3, INTEROP_DISABLE_SDP_AFTER_PAIRING},
  // Microsoft Bluetooth Notebook Mouse 5000
  {{0x00, 0x1d, 0xd8,       0,0,0}, 3, INTEROP_DISABLE_SDP_AFTER_PAIRING},
  // Logitech MX Revolution Mouse
  {{0x00, 0x1f, 0x20,       0,0,0}, 3, INTEROP_DISABLE_SDP_AFTER_PAIRING},
  // Rapoo 6080 mouse
  {{0x6c, 0x5d, 0x63,       0,0,0}, 3, INTEROP_DISABLE_SDP_AFTER_PAIRING},
  // Microsoft Sculpt Touch Mouse
  {{0x28, 0x18, 0x78,       0,0,0}, 3, INTEROP_DISABLE_SDP_AFTER_PAIRING},

  // Targus BT Laser Notebook Mouse
  {{0x00, 0x12, 0xA1,       0,0,0}, 3, INTEROP_DISABLE_AUTH_FOR_HID_POINTING},

  // Fiat Carkit
  {{0x00, 0x14, 0x09,       0,0,0}, 3, INTEROP_INCREASE_AG_CONN_TIMEOUT},
};

static const interop_name_t interop_name_database[] = {
  // Apple Magic Mouse
  {"Apple Magic Mouse", INTEROP_DISABLE_SDP_AFTER_PAIRING},
  // Bluetooth Laser Travel Mouse
  {"Bluetooth Laser Travel Mouse", INTEROP_DISABLE_SDP_AFTER_PAIRING},
  // Microsoft Bluetooth Notebook Mouse 5000
  {"Microsoft Bluetooth Notebook Mouse 5000", INTEROP_DISABLE_SDP_AFTER_PAIRING},
  // Logitech MX Revolution Mouse
  {"Logitech MX Revolution Mouse", INTEROP_DISABLE_SDP_AFTER_PAIRING},
  // Microsoft Sculpt Touch Mouse
  {"Microsoft Sculpt Touch Mouse", INTEROP_DISABLE_SDP_AFTER_PAIRING},

  // Targus BT Laser Notebook Mouse
  {"Targus BT Laser Notebook Mouse", INTEROP_DISABLE_AUTH_FOR_HID_POINTING},
};

static const interop_manufacturer_t interop_manufctr_database[] = {
  // Apple Devices
  {76, INTEROP_DISABLE_SDP_AFTER_PAIRING},

  // Apple Devices
  {76, INTEROP_DISABLE_SNIFF_DURING_SCO},
};
