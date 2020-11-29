/******************************************************************************
 *
 *  Copyright 2002-2012 Broadcom Corporation
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
 *  This file contains the definition of the btm control block.
 *
 ******************************************************************************/

#include <string.h>
#include "bt_target.h"
#include "bt_types.h"
#include "btm_int.h"
#include "stack_config.h"

/* Global BTM control block structure
*/
tBTM_CB btm_cb;

extern void btm_acl_init(void);
extern void btm_dev_init(void);
extern void btm_dev_free(void);
extern void btm_inq_db_init(void);
extern void btm_inq_db_free(void);
extern void btm_sco_init(void);
extern void wipe_secrets_and_remove(tBTM_SEC_DEV_REC* p_dev_rec);

/*******************************************************************************
 *
 * Function         btm_init
 *
 * Description      This function is called at BTM startup to allocate the
 *                  control block (if using dynamic memory), and initializes the
 *                  tracing level.  It then initializes the various components
 *                  of btm.
 *
 * Returns          void
 *
 ******************************************************************************/
void btm_init(void) {
  btm_cb.Init(stack_config_get_interface()->get_pts_secure_only_mode()
                  ? BTM_SEC_MODE_SC
                  : BTM_SEC_MODE_SP);

  /* Initialize BTM component structures */
  btm_inq_db_init(); /* Inquiry Database and Structures */
  btm_acl_init();    /* ACL Database and Structures */
  btm_sco_init(); /* SCO Database and Structures (If included) */

  btm_dev_init(); /* Device Manager Structures & HCI_Reset */
}

/** This function is called to free dynamic memory and system resource allocated by btm_init */
void btm_free(void) {
  btm_dev_free();
  btm_inq_db_free();

  btm_cb.Free();
}
