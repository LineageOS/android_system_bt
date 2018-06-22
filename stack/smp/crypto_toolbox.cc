/*
 * Copyright (C) 2018 The Android Open Source Project
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

#include "bt_target.h"

#include "aes.h"
#include "bt_utils.h"
#include "p_256_ecc_pp.h"
#include "smp_int.h"

#include <algorithm>

#include <base/logging.h>
#include <base/strings/string_number_conversions.h>

using base::HexEncode;

Octet16 smp_calculate_h6(const Octet16& w, std::array<uint8_t, 4> keyid) {
  return aes_cmac(w, keyid.data(), keyid.size());
}

Octet16 smp_calculate_h7(const Octet16& salt, const Octet16& w) {
  return aes_cmac(salt, w.data(), w.size());
}

Octet16 smp_calculate_f4(uint8_t* u, uint8_t* v, const Octet16& x, uint8_t z) {
  constexpr size_t msg_len = BT_OCTET32_LEN /* U size */ +
                             BT_OCTET32_LEN /* V size */ + 1 /* Z size */;

  DVLOG(2) << "U=" << HexEncode(u, BT_OCTET32_LEN)
           << ", V=" << HexEncode(v, BT_OCTET32_LEN)
           << ", X=" << HexEncode(x.data(), x.size()) << " Z=" << loghex(z);

  uint8_t msg[msg_len];
  uint8_t* p = msg;
  UINT8_TO_STREAM(p, z);
  ARRAY_TO_STREAM(p, v, BT_OCTET32_LEN);
  ARRAY_TO_STREAM(p, u, BT_OCTET32_LEN);

  return aes_cmac(x, msg, msg_len);
}

/** helper for smp_calculate_f5 */
static Octet16 calculate_mac_key_or_ltk(const Octet16& t, uint8_t counter,
                                        uint8_t* key_id, const Octet16& n1,
                                        const Octet16& n2, uint8_t* a1,
                                        uint8_t* a2, uint8_t* length) {
  constexpr size_t msg_len = 1 /* Counter size */ + 4 /* keyID size */ +
                             OCTET16_LEN /* N1 size */ +
                             OCTET16_LEN /* N2 size */ + 7 /* A1 size*/ +
                             7 /* A2 size*/ + 2 /* Length size */;
  uint8_t msg[msg_len];
  uint8_t* p = msg;
  ARRAY_TO_STREAM(p, length, 2);
  ARRAY_TO_STREAM(p, a2, 7);
  ARRAY_TO_STREAM(p, a1, 7);
  ARRAY_TO_STREAM(p, n2.data(), OCTET16_LEN);
  ARRAY_TO_STREAM(p, n1.data(), OCTET16_LEN);
  ARRAY_TO_STREAM(p, key_id, 4);
  ARRAY_TO_STREAM(p, &counter, 1);

  return aes_cmac(t, msg, msg_len);
}

void smp_calculate_f5(uint8_t* w, const Octet16& n1, const Octet16& n2,
                      uint8_t* a1, uint8_t* a2, Octet16* mac_key,
                      Octet16* ltk) {
  DVLOG(2) << __func__ << "W=" << HexEncode(w, BT_OCTET32_LEN)
           << ", N1=" << HexEncode(n1.data(), n1.size())
           << ", N2=" << HexEncode(n2.data(), n2.size())
           << ", A1=" << HexEncode(a1, 7) << ", A2=" << HexEncode(a2, 7);

  const Octet16 salt{0xBE, 0x83, 0x60, 0x5A, 0xDB, 0x0B, 0x37, 0x60,
                     0x38, 0xA5, 0xF5, 0xAA, 0x91, 0x83, 0x88, 0x6C};
  Octet16 t = aes_cmac(salt, w, BT_OCTET32_LEN);

  DVLOG(2) << "T=" << HexEncode(t.data(), t.size());

  uint8_t key_id[4] = {0x65, 0x6c, 0x74, 0x62}; /* 0x62746c65 */
  uint8_t length[2] = {0x00, 0x01};             /* 0x0100 */

  *mac_key = calculate_mac_key_or_ltk(t, 0, key_id, n1, n2, a1, a2, length);

  *ltk = calculate_mac_key_or_ltk(t, 1, key_id, n1, n2, a1, a2, length);

  DVLOG(2) << "mac_key=" << HexEncode(mac_key->data(), mac_key->size());
  DVLOG(2) << "ltk=" << HexEncode(ltk->data(), ltk->size());
}

Octet16 smp_calculate_f6(const Octet16& w, const Octet16& n1, const Octet16& n2,
                         const Octet16& r, uint8_t* iocap, uint8_t* a1,
                         uint8_t* a2) {
  const uint8_t msg_len = OCTET16_LEN /* N1 size */ +
                          OCTET16_LEN /* N2 size */ + OCTET16_LEN /* R size */ +
                          3 /* IOcap size */ + 7 /* A1 size*/
                          + 7 /* A2 size*/;

  DVLOG(2) << __func__ << "W=" << HexEncode(w.data(), w.size())
           << ", N1=" << HexEncode(n1.data(), n1.size())
           << ", N2=" << HexEncode(n2.data(), n2.size())
           << ", R=" << HexEncode(r.data(), r.size())
           << ", IOcap=" << HexEncode(iocap, 3) << ", A1=" << HexEncode(a1, 7)
           << ", A2=" << HexEncode(a2, 7);

  std::array<uint8_t, msg_len> msg;
  auto it = msg.begin();
  it = std::copy(a2, a2 + 7, it);
  it = std::copy(a1, a1 + 7, it);
  it = std::copy(iocap, iocap + 3, it);
  it = std::copy(r.begin(), r.end(), it);
  it = std::copy(n2.begin(), n2.end(), it);
  it = std::copy(n1.begin(), n1.end(), it);

  return aes_cmac(w, msg.data(), msg.size());
}

uint32_t smp_calculate_g2(uint8_t* u, uint8_t* v, const Octet16& x,
                          const Octet16& y) {
  constexpr size_t msg_len = BT_OCTET32_LEN /* U size */ +
                             BT_OCTET32_LEN /* V size */
                             + OCTET16_LEN /* Y size */;

  DVLOG(2) << __func__ << "U=" << HexEncode(u, BT_OCTET32_LEN)
           << ", V=" << HexEncode(v, BT_OCTET32_LEN)
           << ", X=" << HexEncode(x.data(), x.size())
           << ", Y=" << HexEncode(y.data(), y.size());

  uint8_t msg[msg_len];
  uint8_t* p = msg;
  ARRAY_TO_STREAM(p, y.data(), OCTET16_LEN);
  ARRAY_TO_STREAM(p, v, BT_OCTET32_LEN);
  ARRAY_TO_STREAM(p, u, BT_OCTET32_LEN);

  Octet16 cmac = aes_cmac(x, msg, msg_len);

  /* vres = cmac mod 2**32 mod 10**6 */
  uint32_t vres;
  p = cmac.data();
  STREAM_TO_UINT32(vres, p);

  vres = vres % (BTM_MAX_PASSKEY_VAL + 1);
  return vres;
}

Octet16 smp_calculate_ltk_to_link_key(const Octet16& ltk, bool use_h7) {
  Octet16 ilk; /* intermidiate link key */
  if (use_h7) {
    constexpr Octet16 salt{0x31, 0x70, 0x6D, 0x74, 0x00, 0x00, 0x00, 0x00,
                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    ilk = smp_calculate_h7(salt, ltk);
  } else {
    /* "tmp1" mapping to extended ASCII, little endian*/
    constexpr std::array<uint8_t, 4> keyID_tmp1 = {0x31, 0x70, 0x6D, 0x74};
    ilk = smp_calculate_h6(ltk, keyID_tmp1);
  }

  /* "lebr" mapping to extended ASCII, little endian */
  constexpr std::array<uint8_t, 4> keyID_lebr = {0x72, 0x62, 0x65, 0x6c};
  return smp_calculate_h6(ilk, keyID_lebr);
}

Octet16 smp_calculate_link_key_to_ltk(const Octet16& link_key, bool use_h7) {
  Octet16 iltk; /* intermidiate long term key */
  if (use_h7) {
    constexpr Octet16 salt{0x32, 0x70, 0x6D, 0x74, 0x00, 0x00, 0x00, 0x00,
                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    iltk = smp_calculate_h7(salt, link_key);
  } else {
    /* "tmp2" mapping to extended ASCII, little endian */
    constexpr std::array<uint8_t, 4> keyID_tmp2 = {0x32, 0x70, 0x6D, 0x74};
    iltk = smp_calculate_h6(link_key, keyID_tmp2);
  }

  /* "brle" mapping to extended ASCII, little endian */
  constexpr std::array<uint8_t, 4> keyID_brle = {0x65, 0x6c, 0x72, 0x62};
  return smp_calculate_h6(iltk, keyID_brle);
}
