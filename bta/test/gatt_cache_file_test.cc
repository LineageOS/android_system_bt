/******************************************************************************
 *
 *  Copyright 2018 The Android Open Source Project
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

#include <gtest/gtest.h>

#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include "bta/include/bta_gatt_api.h"

using bluetooth::Uuid;

/* This test makes sure that cache element is properly encoded into file*/
TEST(GattCacheTest, nv_attr_service_to_binary_test) {
  tBTA_GATTC_NV_ATTR attr;

  /* make sure padding at end of union is cleared */
  memset(&attr, 0, sizeof(attr));

  attr = {
      .handle = 0x0001,
      .type = Uuid::FromString("2800"),
      .value = {.service = {.uuid = Uuid::FromString("1800"),
                            .e_handle = 0x001c}},
  };

  constexpr size_t len = sizeof(tBTA_GATTC_NV_ATTR);
  // clang-format off
  uint8_t binary_form[len] = {
      /*handle */ 0x01, 0x00,
      /* type*/ 0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 0x10, 0x00, 0x80, 0x00, 0x00, 0x80, 0x5F, 0x9B, 0x34, 0xFB,
      /* service uuid */ 0x00, 0x00, 0x18, 0x00, 0x00, 0x00, 0x10, 0x00, 0x80, 0x00, 0x00, 0x80, 0x5F, 0x9B, 0x34, 0xFB,
      /* end handle */ 0x1C, 0x00,
      /* cleared padding at end of union*/ 0x00, 0x00};
  // clang-format on

  // useful for debugging:
  // LOG(ERROR) << " " << base::HexEncode(&attr, len);
  EXPECT_EQ(memcmp(binary_form, &attr, len), 0);
}
