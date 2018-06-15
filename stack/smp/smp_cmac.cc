/******************************************************************************
 *
 *  Copyright 2008-2012 Broadcom Corporation
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

/******************************************************************************
 *
 *  This file contains the implementation of the AES128 CMAC algorithm.
 *
 ******************************************************************************/

#include "bt_target.h"

#include <stdio.h>
#include <string.h>

#include "btm_ble_api.h"
#include "hcimsgs.h"
#include "smp_int.h"

typedef struct {
  uint8_t* text;
  uint16_t len;
  uint16_t round;
} tCMAC_CB;

tCMAC_CB cmac_cb;

/* Rb for AES-128 as block cipher, LSB as [0] */
Octet16 const_Rb{0x87, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

void print128(const Octet16& x, const uint8_t* key_name) {
#if (SMP_DEBUG == TRUE && SMP_DEBUG_VERBOSE == TRUE)
  uint8_t* p = (uint8_t*)x;
  uint8_t i;

  SMP_TRACE_WARNING("%s(MSB ~ LSB) = ", key_name);

  for (i = 0; i < 4; i++) {
    SMP_TRACE_WARNING("%02x %02x %02x %02x", p[OCTET16_LEN - i * 4 - 1],
                      p[OCTET16_LEN - i * 4 - 2], p[OCTET16_LEN - i * 4 - 3],
                      p[OCTET16_LEN - i * 4 - 4]);
  }
#endif
}

/** utility function to padding the given text to be a 128 bits data. The
 * parameter dest is input and output parameter, it must point to a
 * OCTET16_LEN memory space; where include length bytes valid data. */
static void padding(Octet16* dest, uint8_t length) {
  uint8_t i, *p = dest->data();
  /* original last block */
  for (i = length; i < OCTET16_LEN; i++)
    p[OCTET16_LEN - i - 1] = (i == length) ? 0x80 : 0;
}

/** utility function to left shift one bit for a 128 bits value. */
static void leftshift_onebit(uint8_t* input, uint8_t* output) {
  uint8_t i, overflow = 0, next_overflow = 0;
  SMP_TRACE_EVENT("leftshift_onebit ");
  /* input[0] is LSB */
  for (i = 0; i < OCTET16_LEN; i++) {
    next_overflow = (input[i] & 0x80) ? 1 : 0;
    output[i] = (input[i] << 1) | overflow;
    overflow = next_overflow;
  }
  return;
}

/** clean up function for AES_CMAC algorithm. */
static void cmac_aes_cleanup(void) {
  osi_free(cmac_cb.text);
  memset(&cmac_cb, 0, sizeof(tCMAC_CB));
}

/** This function is the calculation of block cipher using AES-128. */
static void cmac_aes_k_calculate(const Octet16& key, uint8_t* p_signature,
                                 uint16_t tlen) {
  Octet16 output;
  Octet16 x{0};  // zero initialized

  SMP_TRACE_EVENT("cmac_aes_k_calculate ");

  uint8_t i = 1;
  while (i <= cmac_cb.round) {
    /* Mi' := Mi (+) X  */
    smp_xor_128((Octet16*)&cmac_cb.text[(cmac_cb.round - i) * OCTET16_LEN], x);

    output = SMP_Encrypt(key, &cmac_cb.text[(cmac_cb.round - i) * OCTET16_LEN],
                         OCTET16_LEN);
    x = output;
    i++;
  }

  uint8_t* p_mac = output.data() + (OCTET16_LEN - tlen);
  memcpy(p_signature, p_mac, tlen);

  SMP_TRACE_DEBUG("tlen = %d p_mac = %d", tlen, p_mac);
  SMP_TRACE_DEBUG(
      "p_mac[0] = 0x%02x p_mac[1] = 0x%02x p_mac[2] = 0x%02x p_mac[3] = "
      "0x%02x",
      *p_mac, *(p_mac + 1), *(p_mac + 2), *(p_mac + 3));
  SMP_TRACE_DEBUG(
      "p_mac[4] = 0x%02x p_mac[5] = 0x%02x p_mac[6] = 0x%02x p_mac[7] = "
      "0x%02x",
      *(p_mac + 4), *(p_mac + 5), *(p_mac + 6), *(p_mac + 7));
}

/** This function proceeed to prepare the last block of message Mn depending on
 * the size of the message.
 */
static void cmac_prepare_last_block(const Octet16& k1, const Octet16& k2) {
  //    uint8_t     x[16] = {0};
  bool flag;

  SMP_TRACE_EVENT("cmac_prepare_last_block ");
  /* last block is a complete block set flag to 1 */
  flag = ((cmac_cb.len % OCTET16_LEN) == 0 && cmac_cb.len != 0) ? true : false;

  SMP_TRACE_WARNING("flag = %d round = %d", flag, cmac_cb.round);

  if (flag) { /* last block is complete block */
    smp_xor_128((Octet16*)&cmac_cb.text[0], k1);
  } else /* padding then xor with k2 */
  {
    padding((Octet16*)&cmac_cb.text[0], (uint8_t)(cmac_cb.len % 16));

    smp_xor_128((Octet16*)&cmac_cb.text[0], k2);
  }
}

/** This is the function to generate the two subkeys.
 * |key| is CMAC key, expect SRK when used by SMP.
 */
static void cmac_generate_subkey(const Octet16& key) {
  SMP_TRACE_EVENT(" cmac_generate_subkey");

  Octet16 zero{};
  Octet16 p = SMP_Encrypt(key, zero.data(), OCTET16_LEN);
  print128(p, (const uint8_t*)"K1 before shift");

  Octet16 k1, k2;
  uint8_t* pp = p.data();

  /* If MSB(L) = 0, then K1 = L << 1 */
  if ((pp[OCTET16_LEN - 1] & 0x80) != 0) {
    /* Else K1 = ( L << 1 ) (+) Rb */
    leftshift_onebit(pp, k1.data());
    smp_xor_128(&k1, const_Rb);
  } else {
    leftshift_onebit(pp, k1.data());
  }

  if ((k1[OCTET16_LEN - 1] & 0x80) != 0) {
    /* K2 =  (K1 << 1) (+) Rb */
    leftshift_onebit(k1.data(), k2.data());
    smp_xor_128(&k2, const_Rb);
  } else {
    /* If MSB(K1) = 0, then K2 = K1 << 1 */
    leftshift_onebit(k1.data(), k2.data());
  }

  print128(k1, (const uint8_t*)"K1");
  print128(k2, (const uint8_t*)"K2");

  cmac_prepare_last_block(k1, k2);
}
/*******************************************************************************
 *
 * Function         aes_cipher_msg_auth_code
 *
 * Description      This is the AES-CMAC Generation Function with tlen
 *                  implemented.
 *
 * Parameters       key - CMAC key in little endian order, expect SRK when used
 *                        by SMP.
 *                  input - text to be signed in little endian byte order.
 *                  length - length of the input in byte.
 *                  tlen - lenth of mac desired
 *                  p_signature - data pointer to where signed data to be
 *                                stored, tlen long.
 *
 ******************************************************************************/
void aes_cipher_msg_auth_code(const Octet16& key, const uint8_t* input,
                              uint16_t length, uint16_t tlen,
                              uint8_t* p_signature) {
  uint16_t len, diff;
  /* n is number of rounds */
  uint16_t n = (length + OCTET16_LEN - 1) / OCTET16_LEN;

  SMP_TRACE_EVENT("%s", __func__);

  if (n == 0) n = 1;
  len = n * OCTET16_LEN;

  SMP_TRACE_WARNING("AES128_CMAC started, allocate buffer size = %d", len);
  /* allocate a memory space of multiple of 16 bytes to hold text  */
  cmac_cb.text = (uint8_t*)osi_calloc(len);
  cmac_cb.round = n;
  diff = len - length;

  if (input != NULL && length > 0) {
    memcpy(&cmac_cb.text[diff], input, (int)length);
    cmac_cb.len = length;
  } else {
    cmac_cb.len = 0;
  }

  /* prepare calculation for subkey s and last block of data */
  cmac_generate_subkey(key);
  /* start calculation */
  cmac_aes_k_calculate(key, p_signature, tlen);

  /* clean up */
  cmac_aes_cleanup();
}
