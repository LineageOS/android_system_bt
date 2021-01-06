/******************************************************************************
 *
 *  Copyright 1999-2012 Broadcom Corporation
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
 *  This file contains functions for BLE address management.
 *
 ******************************************************************************/

#include <base/bind.h>
#include <string.h>

#include "bt_types.h"
#include "btu.h"
#include "device/include/controller.h"
#include "gap_api.h"
#include "hcimsgs.h"

#include "btm_ble_int.h"
#include "stack/btm/btm_dev.h"
#include "stack/crypto_toolbox/crypto_toolbox.h"
#include "stack/include/acl_api.h"

extern tBTM_CB btm_cb;

void btm_ble_set_random_address(const RawAddress& random_bda);

/* This function generates Resolvable Private Address (RPA) from Identity
 * Resolving Key |irk| and |random|*/
static RawAddress generate_rpa_from_irk_and_rand(const Octet16& irk,
                                                 BT_OCTET8 random) {
  random[2] &= (~BLE_RESOLVE_ADDR_MASK);
  random[2] |= BLE_RESOLVE_ADDR_MSB;

  RawAddress address;
  address.address[2] = random[0];
  address.address[1] = random[1];
  address.address[0] = random[2];

  /* encrypt with IRK */
  Octet16 p = crypto_toolbox::aes_128(irk, random, 3);

  /* set hash to be LSB of rpAddress */
  address.address[5] = p[0];
  address.address[4] = p[1];
  address.address[3] = p[2];
  return address;
}

static void btm_ble_refresh_raddr_timer_timeout(UNUSED_ATTR void* data) {
  if (btm_cb.ble_ctr_cb.addr_mgnt_cb.own_addr_type == BLE_ADDR_RANDOM) {
    /* refresh the random addr */
    btm_gen_resolvable_private_addr(base::Bind(&btm_gen_resolve_paddr_low));
  }
}

/** This function is called when random address for local controller was
 * generated */
void btm_gen_resolve_paddr_low(const RawAddress& address) {
  tBTM_LE_RANDOM_CB* p_cb = &btm_cb.ble_ctr_cb.addr_mgnt_cb;
  p_cb->private_addr = address;

  /* set it to controller */
  btm_ble_set_random_address(p_cb->private_addr);

  p_cb->own_addr_type = BLE_ADDR_RANDOM;

  /* start a periodical timer to refresh random addr */
  uint64_t interval_ms = btm_get_next_private_addrress_interval_ms();
#if (BTM_BLE_CONFORMANCE_TESTING == TRUE)
  interval_ms = btm_cb.ble_ctr_cb.rpa_tout * 1000;
#endif
  alarm_set_on_mloop(p_cb->refresh_raddr_timer, interval_ms,
                     btm_ble_refresh_raddr_timer_timeout, NULL);
}

/** This function generate a resolvable private address using local IRK */
void btm_gen_resolvable_private_addr(
    base::Callback<void(const RawAddress&)> cb) {
  /* generate 3B rand as BD LSB, SRK with it, get BD MSB */
  btsnd_hcic_ble_rand(base::Bind(
      [](base::Callback<void(const RawAddress&)> cb, BT_OCTET8 random) {
        const Octet16& irk = BTM_GetDeviceIDRoot();
        cb.Run(generate_rpa_from_irk_and_rand(irk, random));
      },
      std::move(cb)));
}

uint64_t btm_get_next_private_addrress_interval_ms() {
  /* 7 minutes minimum, 15 minutes maximum for random address refreshing */
  const uint64_t interval_min_ms = (7 * 60 * 1000);
  const uint64_t interval_random_part_max_ms = (8 * 60 * 1000);

  return interval_min_ms + std::rand() % interval_random_part_max_ms;
}

/*******************************************************************************
 *  Utility functions for Random address resolving
 ******************************************************************************/

/*******************************************************************************
 *
 * Function         btm_ble_init_pseudo_addr
 *
 * Description      This function is used to initialize pseudo address.
 *                  If pseudo address is not available, use dummy address
 *
 * Returns          true is updated; false otherwise.
 *
 ******************************************************************************/
bool btm_ble_init_pseudo_addr(tBTM_SEC_DEV_REC* p_dev_rec,
                              const RawAddress& new_pseudo_addr) {
  if (p_dev_rec->ble.pseudo_addr.IsEmpty()) {
    p_dev_rec->ble.pseudo_addr = new_pseudo_addr;
    return true;
  }

  return false;
}

/* Return true if given Resolvable Privae Address |rpa| matches Identity
 * Resolving Key |irk| */
static bool rpa_matches_irk(const RawAddress& rpa, const Octet16& irk) {
  /* use the 3 MSB of bd address as prand */
  uint8_t rand[3];
  rand[0] = rpa.address[2];
  rand[1] = rpa.address[1];
  rand[2] = rpa.address[0];

  /* generate X = E irk(R0, R1, R2) and R is random address 3 LSO */
  Octet16 x = crypto_toolbox::aes_128(irk, &rand[0], 3);

  rand[0] = rpa.address[5];
  rand[1] = rpa.address[4];
  rand[2] = rpa.address[3];

  if (memcmp(x.data(), &rand[0], 3) == 0) {
    // match
    return true;
  }
  // not a match
  return false;
}

/** This function checks if a RPA is resolvable by the device key.
 *  Returns true is resolvable; false otherwise.
 */
bool btm_ble_addr_resolvable(const RawAddress& rpa,
                             tBTM_SEC_DEV_REC* p_dev_rec) {
  if (!BTM_BLE_IS_RESOLVE_BDA(rpa)) return false;

  if ((p_dev_rec->device_type & BT_DEVICE_TYPE_BLE) &&
      (p_dev_rec->ble.key_type & BTM_LE_KEY_PID)) {
    BTM_TRACE_DEBUG("%s try to resolve", __func__);

    if (rpa_matches_irk(rpa, p_dev_rec->ble.keys.irk)) {
      btm_ble_init_pseudo_addr(p_dev_rec, rpa);
      return true;
    }
  }
  return false;
}

/** This function match the random address to the appointed device record,
 * starting from calculating IRK. If the record index exceeds the maximum record
 * number, matching failed and send a callback. */
static bool btm_ble_match_random_bda(void* data, void* context) {
  tBTM_SEC_DEV_REC* p_dev_rec = static_cast<tBTM_SEC_DEV_REC*>(data);
  RawAddress* random_bda = static_cast<RawAddress*>(context);

  if (!(p_dev_rec->device_type & BT_DEVICE_TYPE_BLE) ||
      !(p_dev_rec->ble.key_type & BTM_LE_KEY_PID))
    // Match fails preconditions
    return true;

  if (rpa_matches_irk(*random_bda, p_dev_rec->ble.keys.irk)) {
    // Matched
    return false;
  }

  // This item not a match, continue iteration
  return true;
}

/** This function is called to resolve a random address.
 * Returns pointer to the security record of the device whom a random address is
 * matched to.
 */
tBTM_SEC_DEV_REC* btm_ble_resolve_random_addr(const RawAddress& random_bda) {
  list_node_t* n = list_foreach(btm_cb.sec_dev_rec, btm_ble_match_random_bda,
                                (void*)&random_bda);
  return (n == nullptr) ? (nullptr)
                        : (static_cast<tBTM_SEC_DEV_REC*>(list_node(n)));
}

/*******************************************************************************
 *  address mapping between pseudo address and real connection address
 ******************************************************************************/
/** Find the security record whose LE identity address is matching */
static tBTM_SEC_DEV_REC* btm_find_dev_by_identity_addr(
    const RawAddress& bd_addr, uint8_t addr_type) {
  list_node_t* end = list_end(btm_cb.sec_dev_rec);
  for (list_node_t* node = list_begin(btm_cb.sec_dev_rec); node != end;
       node = list_next(node)) {
    tBTM_SEC_DEV_REC* p_dev_rec =
        static_cast<tBTM_SEC_DEV_REC*>(list_node(node));
    if (p_dev_rec->ble.identity_address_with_type.bda == bd_addr) {
      if ((p_dev_rec->ble.identity_address_with_type.type &
           (~BLE_ADDR_TYPE_ID_BIT)) != (addr_type & (~BLE_ADDR_TYPE_ID_BIT)))
        BTM_TRACE_WARNING(
            "%s find pseudo->random match with diff addr type: %d vs %d",
            __func__, p_dev_rec->ble.identity_address_with_type.type,
            addr_type);

      /* found the match */
      return p_dev_rec;
    }
  }

  return NULL;
}

/*******************************************************************************
 *
 * Function         btm_identity_addr_to_random_pseudo
 *
 * Description      This function map a static BD address to a pseudo random
 *                  address in security database.
 *
 ******************************************************************************/
bool btm_identity_addr_to_random_pseudo(RawAddress* bd_addr,
                                        uint8_t* p_addr_type, bool refresh) {
  tBTM_SEC_DEV_REC* p_dev_rec =
      btm_find_dev_by_identity_addr(*bd_addr, *p_addr_type);
  if (p_dev_rec == nullptr) {
    return false;
  }

  /* evt reported on static address, map static address to random pseudo */
  /* if RPA offloading is supported, or 4.2 controller, do RPA refresh */
  if (refresh &&
      controller_get_interface()->get_ble_resolving_list_max_size() != 0) {
    btm_ble_read_resolving_list_entry(p_dev_rec);
  }

  /* assign the original address to be the current report address */
  if (!btm_ble_init_pseudo_addr(p_dev_rec, *bd_addr)) {
    *bd_addr = p_dev_rec->ble.pseudo_addr;
  }

  *p_addr_type = p_dev_rec->ble.ble_addr_type;
  return true;
}

bool btm_identity_addr_to_random_pseudo_from_address_with_type(
    tBLE_BD_ADDR* address_with_type, bool refresh) {
  return btm_identity_addr_to_random_pseudo(
      &(address_with_type->bda), &(address_with_type->type), refresh);
}

/*******************************************************************************
 *
 * Function         btm_random_pseudo_to_identity_addr
 *
 * Description      This function map a random pseudo address to a public
 *                  address. random_pseudo is input and output parameter
 *
 ******************************************************************************/
bool btm_random_pseudo_to_identity_addr(RawAddress* random_pseudo,
                                        uint8_t* p_identity_addr_type) {
  tBTM_SEC_DEV_REC* p_dev_rec = btm_find_dev(*random_pseudo);

  if (p_dev_rec != NULL) {
    if (p_dev_rec->ble.in_controller_list & BTM_RESOLVING_LIST_BIT) {
      *p_identity_addr_type = p_dev_rec->ble.identity_address_with_type.type;
      *random_pseudo = p_dev_rec->ble.identity_address_with_type.bda;
      if (controller_get_interface()->supports_ble_privacy())
        *p_identity_addr_type |= BLE_ADDR_TYPE_ID_BIT;
      return true;
    }
  }
  return false;
}

/*******************************************************************************
 *
 * Function         btm_ble_refresh_peer_resolvable_private_addr
 *
 * Description      This function refresh the currently used resolvable remote
 *                  private address into security database and set active
 *                  connection address.
 *
 ******************************************************************************/
void btm_ble_refresh_peer_resolvable_private_addr(
    const RawAddress& pseudo_bda, const RawAddress& rpa,
    tBTM_SEC_BLE::tADDRESS_TYPE rra_type) {
  tBTM_SEC_DEV_REC* p_sec_rec = btm_find_dev(pseudo_bda);
  if (p_sec_rec == nullptr) {
    LOG_WARN("%s No matching known device in record", __func__);
    return;
  }

  p_sec_rec->ble.cur_rand_addr = rpa;

  if (rra_type == tBTM_SEC_BLE::BTM_BLE_ADDR_PSEUDO) {
    p_sec_rec->ble.active_addr_type = rpa.IsEmpty()
                                          ? tBTM_SEC_BLE::BTM_BLE_ADDR_STATIC
                                          : tBTM_SEC_BLE::BTM_BLE_ADDR_RRA;
  } else {
    p_sec_rec->ble.active_addr_type = rra_type;
  }

  /* connection refresh remote address */
  const auto& identity_address = p_sec_rec->ble.identity_address_with_type.bda;
  auto identity_address_type = p_sec_rec->ble.identity_address_with_type.type;

  if (!acl_refresh_remote_address(identity_address, identity_address_type,
                                  p_sec_rec->bd_addr, rra_type, rpa)) {
    // Try looking up the pseudo random address
    if (!acl_refresh_remote_address(identity_address, identity_address_type,
                                    p_sec_rec->ble.pseudo_addr, rra_type,
                                    rpa)) {
      LOG_ERROR("%s Unknown device to refresh remote device", __func__);
    }
  }
}
