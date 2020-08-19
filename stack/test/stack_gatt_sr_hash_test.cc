/******************************************************************************
 *
 *  Copyright 2020 The Android Open Source Project
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

#include "crypto_toolbox/crypto_toolbox.h"
#include "stack/gatt/gatt_int.h"

using bluetooth::Uuid;

namespace {
  std::list<tGATT_SRV_LIST_ELEM> srv_elem_list;
}

/** copy from gatt_db.cc, remove unnecessary log */
tGATT_ATTR& allocate_attr_in_db(tGATT_SVC_DB& db, const Uuid& uuid,
                                       tGATT_PERM perm) {
  db.attr_list.emplace_back();
  tGATT_ATTR& attr = db.attr_list.back();
  attr.handle = db.next_handle++;
  attr.uuid = uuid;
  attr.permission = perm;
  return attr;
}

/** copy from gatt_db.cc, remove unnecessary log */
void gatts_init_service_db(tGATT_SVC_DB& db, const Uuid& service_uuid,
                           bool is_pri, uint16_t s_hdl, uint16_t num_handle) {
  db.attr_list.reserve(num_handle);

  /* update service database information */
  db.next_handle = s_hdl;
  db.end_handle = s_hdl + num_handle;

  /* add service declration record */
  Uuid uuid =
      Uuid::From16Bit(is_pri ? GATT_UUID_PRI_SERVICE : GATT_UUID_SEC_SERVICE);
  tGATT_ATTR& attr = allocate_attr_in_db(db, uuid, GATT_PERM_READ);
  attr.p_value.reset((tGATT_ATTR_VALUE*)(new Uuid));
  attr.p_value->uuid = service_uuid;
}

/** copy from gatt_db.cc, remove unnecessary log */
uint16_t gatts_add_included_service(tGATT_SVC_DB& db, uint16_t s_handle,
                                    uint16_t e_handle, const Uuid& service) {
  Uuid uuid = Uuid::From16Bit(GATT_UUID_INCLUDE_SERVICE);

  tGATT_ATTR& attr = allocate_attr_in_db(db, uuid, GATT_PERM_READ);

  attr.p_value.reset((tGATT_ATTR_VALUE*)(new tGATT_INCL_SRVC));
  attr.p_value->incl_handle.s_handle = s_handle;
  attr.p_value->incl_handle.e_handle = e_handle;
  attr.p_value->incl_handle.service_type = service;

  return attr.handle;
}

/** copy from gatt_db.cc, remove unnecessary log */
uint16_t gatts_add_characteristic(tGATT_SVC_DB& db, tGATT_PERM perm,
                                  tGATT_CHAR_PROP property,
                                  const Uuid& char_uuid) {
  Uuid uuid = Uuid::From16Bit(GATT_UUID_CHAR_DECLARE);

  tGATT_ATTR& char_decl = allocate_attr_in_db(db, uuid, GATT_PERM_READ);
  tGATT_ATTR& char_val = allocate_attr_in_db(db, char_uuid, perm);

  char_decl.p_value.reset((tGATT_ATTR_VALUE*)(new tGATT_CHAR_DECL));
  char_decl.p_value->char_decl.property = property;
  char_decl.p_value->char_decl.char_val_handle = char_val.handle;
  char_val.gatt_type = BTGATT_DB_CHARACTERISTIC;
  return char_val.handle;
}

/** copy from gatt_db.cc, remove unnecessary log */
uint16_t gatts_add_char_descr(tGATT_SVC_DB& db, tGATT_PERM perm,
                              const Uuid& descr_uuid) {
  /* Add characteristic descriptors */
  tGATT_ATTR& char_dscptr = allocate_attr_in_db(db, descr_uuid, perm);
  char_dscptr.gatt_type = BTGATT_DB_DESCRIPTOR;
  return char_dscptr.handle;
}

/** copy from gatt_utils.cc, used in gatt_sr_hash.cc */
uint8_t gatt_build_uuid_to_stream_len(const Uuid& uuid) {
  size_t len = uuid.GetShortestRepresentationSize();
  return len == Uuid::kNumBytes32 ? Uuid::kNumBytes128 : len;
}

/** copy from gatt_utils.cc, used in gatt_sr_hash.cc */
uint8_t gatt_build_uuid_to_stream(uint8_t** p_dst, const Uuid& uuid) {
  uint8_t* p = *p_dst;
  size_t len = uuid.GetShortestRepresentationSize();

  if (uuid.IsEmpty()) {
    return 0;
  }

  if (len == Uuid::kNumBytes16) {
    UINT16_TO_STREAM(p, uuid.As16Bit());
  } else if (len == Uuid::kNumBytes32) {
    /* always convert 32 bits into 128 bits */
    ARRAY_TO_STREAM(p, uuid.To128BitLE(), (int)Uuid::kNumBytes128);
    len = Uuid::kNumBytes128;
  } else if (len == Uuid::kNumBytes128) {
    ARRAY_TO_STREAM(p, uuid.To128BitLE(), (int)Uuid::kNumBytes128);
  }

  *p_dst = p;
  return len;
}

static void add_item_to_list(std::list<tGATT_SRV_LIST_ELEM>& srv_list_info,
                      tGATT_SVC_DB* db, bool is_primary) {
  srv_list_info.emplace_back();
  tGATT_SRV_LIST_ELEM& elem = srv_list_info.back();
  elem.p_db = db;
  elem.is_primary = is_primary;
}

// BT Spec 5.2, Vol 3, Part G, Appendix B
TEST(GattDatabaseTest, matchExampleInBtSpecV52) {
  tGATT_SVC_DB local_db[4];
  for (int i=0; i<4; i++) local_db[i] = tGATT_SVC_DB();
  std::list<tGATT_SRV_LIST_ELEM> srv_list_info;

  // 0x1800
  add_item_to_list(srv_list_info, &local_db[0], true);
  gatts_init_service_db(local_db[0], Uuid::From16Bit(0x1800), true, 0x0001, 5);
  gatts_add_characteristic(local_db[0],
    GATT_PERM_READ | GATT_PERM_WRITE,
    GATT_CHAR_PROP_BIT_READ | GATT_CHAR_PROP_BIT_WRITE,
    Uuid::From16Bit(0x2A00));
  gatts_add_characteristic(local_db[0], GATT_PERM_READ, GATT_CHAR_PROP_BIT_READ,
    Uuid::From16Bit(0x2A01));
  // 0x1801
  add_item_to_list(srv_list_info, &local_db[1], true);
  gatts_init_service_db(local_db[1], Uuid::From16Bit(0x1801), true, 0x0006, 8);
  gatts_add_characteristic(local_db[1], 0, GATT_CHAR_PROP_BIT_INDICATE,
    Uuid::From16Bit(0x2A05));
  gatts_add_char_descr(local_db[1], GATT_CHAR_PROP_BIT_READ, Uuid::From16Bit(0x2902));
  gatts_add_characteristic(local_db[1],
    GATT_PERM_READ | GATT_PERM_WRITE,
    GATT_CHAR_PROP_BIT_READ | GATT_CHAR_PROP_BIT_WRITE,
    Uuid::From16Bit(0x2B29));
  gatts_add_characteristic(local_db[1], GATT_PERM_READ, GATT_CHAR_PROP_BIT_READ,
    Uuid::From16Bit(0x2B2A));
  // 0x1808
  add_item_to_list(srv_list_info, &local_db[2], true);
  gatts_init_service_db(local_db[2], Uuid::From16Bit(0x1808), true, 0x000E, 6);
  gatts_add_included_service(local_db[2], 0x0014, 0x0016, Uuid::From16Bit(0x180F));
  gatts_add_characteristic(local_db[2], GATT_PERM_READ,
    GATT_CHAR_PROP_BIT_READ | GATT_CHAR_PROP_BIT_INDICATE | GATT_CHAR_PROP_BIT_EXT_PROP,
    Uuid::From16Bit(0x2A18));
  gatts_add_char_descr(local_db[2], 0x0000, Uuid::From16Bit(0x2902));
  gatts_add_char_descr(local_db[2], 0x0000, Uuid::From16Bit(0x2900));
  // 0x180F
  add_item_to_list(srv_list_info, &local_db[3], false);
  gatts_init_service_db(local_db[3], Uuid::From16Bit(0x180F), false, 0x0014, 3);
  gatts_add_characteristic(local_db[3], GATT_PERM_READ,  GATT_CHAR_PROP_BIT_READ,
    Uuid::From16Bit(0x2A19));

  Octet16 expected_hash{0xF1, 0xCA, 0x2D, 0x48, 0xEC, 0xF5, 0x8B, 0xAC,
                        0x8A, 0x88, 0x30, 0xBB, 0xB9, 0xFB, 0xA9, 0x90};
  std::reverse(expected_hash.begin(), expected_hash.end());

  Octet16 result_hash = gatts_calculate_database_hash(&srv_list_info);

  ASSERT_EQ(result_hash, expected_hash);
}
