/******************************************************************************
 *
 *  Copyright (C) 2009-2013 Broadcom Corporation
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

#include <string.h>

#include "bt_target.h"
#include "bt_utils.h"
#include "gap_int.h"

tGAP_CB gap_cb;

/*******************************************************************************
 *
 * Function         GAP_Init
 *
 * Description      Initializes the control blocks used by GAP.
 *
 *                  This routine should not be called except once per
 *                      stack invocation.
 *
 * Returns          Nothing
 *
 ******************************************************************************/
void GAP_Init(void) {
  memset(&gap_cb, 0, sizeof(tGAP_CB));

  gap_conn_init();
  gap_attr_db_init();
}
