/******************************************************************************
 *
 *  Copyright 2009-2012 Broadcom Corporation
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
#include <stdio.h>
#include <stdlib.h>

#include "bt_utils.h"
#include "bta_api.h"
#include "bta_dm_ci.h"
#include "bta_dm_co.h"
#include "bta_sys.h"
#include "bte_appl.h"
#include "btif_dm.h"
#include "btif_storage.h"
#include "osi/include/osi.h"

// tBTE_APPL_CFG.ble_io_cap is set to BTM_IO_CAP_UNKNOWN at structure
// initialization since btif_storage isn't ready yet for data to be fetched.
// This value is initialized properly during first use by fetching properly
// from btif_storage.
tBTE_APPL_CFG bte_appl_cfg = {
    BTA_LE_AUTH_REQ_SC_MITM_BOND,  // Authentication requirements
    BTM_IO_CAP_UNKNOWN, BTM_BLE_INITIATOR_KEY_SIZE, BTM_BLE_RESPONDER_KEY_SIZE,
    BTM_BLE_MAX_KEY_SIZE};

/*******************************************************************************
 *
 * Function         bta_dm_co_get_compress_memory
 *
 * Description      This callout function is executed by DM to get memory for
 compression

 * Parameters       id  -  BTA SYS ID
 *                  memory_p - memory return by callout
 *                  memory_size - memory size
 *
 * Returns          true for success, false for fail.
 *
 ******************************************************************************/
bool bta_dm_co_get_compress_memory(UNUSED_ATTR tBTA_SYS_ID id,
                                   UNUSED_ATTR uint8_t** memory_p,
                                   UNUSED_ATTR uint32_t* memory_size) {
  return true;
}

