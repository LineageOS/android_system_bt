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

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <base/logging.h>
#include <base/strings/string_number_conversions.h>

#include "stack/include/smp_api.h"
#include "stack/smp/aes.h"

using ::testing::ElementsAreArray;

namespace {
constexpr int AES_128_KEY_BYTES = 16;
}

// BT Spec 5.0 | Vol 3, Part H D.1
TEST(AesCmacTest, bt_spec_test_d_1_test) {
  uint8_t k[] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};

  uint8_t m[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

  uint8_t aes_cmac_k_m[] = {0x7d, 0xf7, 0x6b, 0x0c, 0x1a, 0xb8, 0x99, 0xb3,
                            0x3e, 0x42, 0xf0, 0x47, 0xb9, 0x1b, 0x54, 0x6f};

  uint8_t output[16];
  aes_context ctx;
  aes_set_key(k, sizeof(k), &ctx);
  aes_encrypt(m, output, &ctx); /* outputs in byte 48 to byte 63 */

  EXPECT_THAT(output, ElementsAreArray(aes_cmac_k_m, AES_128_KEY_BYTES));

  // useful for debugging
  // LOG(INFO) << "k " << base::HexEncode(k, AES_128_KEY_BYTES);
  // LOG(INFO) << "m " << base::HexEncode(m, sizeof(m));
  // LOG(INFO) << "output " << base::HexEncode(output, AES_128_KEY_BYTES);
}

// BT Spec 5.0 | Vol 3, Part H D.1.1
TEST(AesCmacTest, bt_spec_example_d_1_1_test) {
  Octet16 k{0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};

  uint8_t aes_cmac_k_m[] = {0xbb, 0x1d, 0x69, 0x29, 0xe9, 0x59, 0x37, 0x28,
                            0x7f, 0xa3, 0x7d, 0x12, 0x9b, 0x75, 0x67, 0x46};

  // algorithm expect all input to be in little endian format, so reverse
  std::reverse(std::begin(k), std::end(k));
  std::reverse(std::begin(aes_cmac_k_m), std::end(aes_cmac_k_m));

  Octet16 output = aes_cmac(k, nullptr /* empty message */, 0);

  EXPECT_THAT(output, ElementsAreArray(aes_cmac_k_m, AES_128_KEY_BYTES));

  // useful for debugging
  // LOG(INFO) << "k " << base::HexEncode(k, AES_128_KEY_BYTES);
  // LOG(INFO) << "aes_cmac(k,nullptr) "
  //           << base::HexEncode(output, AES_128_KEY_BYTES);
}

// BT Spec 5.0 | Vol 3, Part H D.1.2
TEST(AesCmacTest, bt_spec_example_d_1_2_test) {
  Octet16 k{0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};

  uint8_t m[] = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
                 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a};

  uint8_t aes_cmac_k_m[] = {0x07, 0x0a, 0x16, 0xb4, 0x6b, 0x4d, 0x41, 0x44,
                            0xf7, 0x9b, 0xdd, 0x9d, 0xd0, 0x4a, 0x28, 0x7c};

  // algorithm expect all input to be in little endian format, so reverse
  std::reverse(std::begin(k), std::end(k));
  std::reverse(std::begin(m), std::end(m));
  std::reverse(std::begin(aes_cmac_k_m), std::end(aes_cmac_k_m));

  Octet16 output = aes_cmac(k, m, sizeof(m));

  EXPECT_THAT(output, ElementsAreArray(aes_cmac_k_m, AES_128_KEY_BYTES));

  // useful for debugging
  // LOG(INFO) << "k " << base::HexEncode(k, AES_128_KEY_BYTES);
  // LOG(INFO) << "m " << base::HexEncode(m, sizeof(m));
  // LOG(INFO) << "aes_cmac(k,m) "
  //           << base::HexEncode(output, AES_128_KEY_BYTES);
}

// BT Spec 5.0 | Vol 3, Part H D.1.3
TEST(AesCmacTest, bt_spec_example_d_1_3_test) {
  Octet16 k{0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};

  uint8_t m[] = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d,
                 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a, 0xae, 0x2d, 0x8a, 0x57,
                 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf,
                 0x8e, 0x51, 0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11};

  uint8_t aes_cmac_k_m[] = {0xdf, 0xa6, 0x67, 0x47, 0xde, 0x9a, 0xe6, 0x30,
                            0x30, 0xca, 0x32, 0x61, 0x14, 0x97, 0xc8, 0x27};

  // algorithm expect all input to be in little endian format, so reverse
  std::reverse(std::begin(k), std::end(k));
  std::reverse(std::begin(m), std::end(m));
  std::reverse(std::begin(aes_cmac_k_m), std::end(aes_cmac_k_m));

  Octet16 output = aes_cmac(k, m, sizeof(m));
  EXPECT_THAT(output, ElementsAreArray(aes_cmac_k_m, AES_128_KEY_BYTES));
}

// BT Spec 5.0 | Vol 3, Part H D.1.4
TEST(AesCmacTest, bt_spec_example_d_1_4_test) {
  Octet16 k{0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};

  uint8_t m[] = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d,
                 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a, 0xae, 0x2d, 0x8a, 0x57,
                 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf,
                 0x8e, 0x51, 0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
                 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef, 0xf6, 0x9f,
                 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b,
                 0xe6, 0x6c, 0x37, 0x10};

  uint8_t aes_cmac_k_m[] = {0x51, 0xf0, 0xbe, 0xbf, 0x7e, 0x3b, 0x9d, 0x92,
                            0xfc, 0x49, 0x74, 0x17, 0x79, 0x36, 0x3c, 0xfe};

  // algorithm expect all input to be in little endian format, so reverse
  std::reverse(std::begin(k), std::end(k));
  std::reverse(std::begin(m), std::end(m));
  std::reverse(std::begin(aes_cmac_k_m), std::end(aes_cmac_k_m));

  Octet16 output = aes_cmac(k, m, sizeof(m));

  EXPECT_THAT(output, ElementsAreArray(aes_cmac_k_m, AES_128_KEY_BYTES));
}
