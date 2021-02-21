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
 *  This is the implementation for the audio/video registration module.
 *
 ******************************************************************************/

#include <cstdint>

#include "bta/ar/bta_ar_int.h"
#include "bta/sys/bta_sys.h"
#include "stack/include/avct_api.h"
#include "stack/include/avrc_api.h"

/* AV control block */
tBTA_AR_CB bta_ar_cb;

/*******************************************************************************
 *
 * Function         bta_ar_init
 *
 * Description      This function is called to register to AVDTP.
 *
 * Returns          void
 *
 ******************************************************************************/
void bta_ar_init(void) {
  /* initialize control block */
  memset(&bta_ar_cb, 0, sizeof(tBTA_AR_CB));
}

/*******************************************************************************
 *
 * Function         bta_ar_reg_avdt
 *
 * Description      This function is called to register to AVDTP.
 *
 * Returns          void
 *
 ******************************************************************************/
static void bta_ar_avdt_cback(uint8_t handle, const RawAddress& bd_addr,
                              uint8_t event, tAVDT_CTRL* p_data,
                              uint8_t scb_index) {
  /* route the AVDT registration callback to av or avk */
  if (bta_ar_cb.p_av_conn_cback)
    (*bta_ar_cb.p_av_conn_cback)(handle, bd_addr, event, p_data, scb_index);
}

/*******************************************************************************
 *
 * Function         bta_ar_reg_avdt
 *
 * Description      AR module registration to AVDT.
 *
 * Returns          void
 *
 ******************************************************************************/
void bta_ar_reg_avdt(AvdtpRcb* p_reg, tAVDT_CTRL_CBACK* p_cback) {
  bta_ar_cb.p_av_conn_cback = p_cback;
  if (bta_ar_cb.avdt_registered == 0) {
    AVDT_Register(p_reg, bta_ar_avdt_cback);
  } else {
    APPL_TRACE_WARNING("%s: doesn't register again (registered:%d)", __func__,
                       bta_ar_cb.avdt_registered);
  }
  bta_ar_cb.avdt_registered |= BTA_AR_AV_MASK;
}

/*******************************************************************************
 *
 * Function         bta_ar_dereg_avdt
 *
 * Description      This function is called to de-register from AVDTP.
 *
 * Returns          void
 *
 ******************************************************************************/
void bta_ar_dereg_avdt() {
  bta_ar_cb.p_av_conn_cback = NULL;
  bta_ar_cb.avdt_registered &= ~BTA_AR_AV_MASK;

  if (bta_ar_cb.avdt_registered == 0) AVDT_Deregister();
}

/*******************************************************************************
 *
 * Function         bta_ar_avdt_conn
 *
 * Description      This function is called to let ar know that some AVDTP
 *                  profile is connected for this sys_id.
 *                  If the other sys modules started a timer for PENDING_EVT,
 *                  the timer can be stopped now.
 *
 * Returns          void
 *
 ******************************************************************************/
void bta_ar_avdt_conn(tBTA_SYS_ID sys_id, const RawAddress& bd_addr,
                      uint8_t scb_index) {
}

/*******************************************************************************
 *
 * Function         bta_ar_reg_avct
 *
 * Description      This function is called to register to AVCTP.
 *
 * Returns          void
 *
 ******************************************************************************/
void bta_ar_reg_avct() {
  if (bta_ar_cb.avct_registered == 0) {
    AVCT_Register();
  }
  bta_ar_cb.avct_registered |= BTA_AR_AV_MASK;
}

/*******************************************************************************
 *
 * Function         bta_ar_dereg_avct
 *
 * Description      This function is called to deregister from AVCTP.
 *
 * Returns          void
 *
 ******************************************************************************/
void bta_ar_dereg_avct() {
  bta_ar_cb.avct_registered &= ~BTA_AR_AV_MASK;

  if (bta_ar_cb.avct_registered == 0) AVCT_Deregister();
}

/******************************************************************************
 *
 * Function         bta_ar_reg_avrc
 *
 * Description      This function is called to register an SDP record for AVRCP.
 *
 * Returns          void
 *
 *****************************************************************************/
void bta_ar_reg_avrc(uint16_t service_uuid, const char* service_name,
                     const char* provider_name, uint16_t categories,
                     bool browse_supported, uint16_t profile_version) {
  uint8_t mask = BTA_AR_AV_MASK;
  uint8_t temp[8], *p;

  if (!categories) return;

  if (service_uuid == UUID_SERVCLASS_AV_REM_CTRL_TARGET) {
    if (bta_ar_cb.sdp_tg_handle == 0) {
      bta_ar_cb.tg_registered = mask;
      bta_ar_cb.sdp_tg_handle = SDP_CreateRecord();
      AVRC_AddRecord(service_uuid, service_name, provider_name, categories,
                     bta_ar_cb.sdp_tg_handle, browse_supported,
                     profile_version, 0);
      bta_sys_add_uuid(service_uuid);
    }
    /* only one TG is allowed (first-come, first-served).
     * If sdp_tg_handle is non-0, ignore this request */
  } else if ((service_uuid == UUID_SERVCLASS_AV_REMOTE_CONTROL) ||
             (service_uuid == UUID_SERVCLASS_AV_REM_CTRL_CONTROL)) {
    bta_ar_cb.ct_categories[mask - 1] = categories;
    categories = bta_ar_cb.ct_categories[0] | bta_ar_cb.ct_categories[1];
    if (bta_ar_cb.sdp_ct_handle == 0) {
      bta_ar_cb.sdp_ct_handle = SDP_CreateRecord();
      AVRC_AddRecord(service_uuid, service_name, provider_name, categories,
                     bta_ar_cb.sdp_ct_handle, browse_supported,
                     profile_version, 0);
      bta_sys_add_uuid(service_uuid);
    } else {
      /* multiple CTs are allowed.
       * Change supported categories on the second one */
      p = temp;
      UINT16_TO_BE_STREAM(p, categories);
      SDP_AddAttribute(bta_ar_cb.sdp_ct_handle, ATTR_ID_SUPPORTED_FEATURES,
                       UINT_DESC_TYPE, (uint32_t)2, (uint8_t*)temp);
    }
  }
}

/******************************************************************************
 *
 * Function         bta_ar_dereg_avrc
 *
 * Description      This function is called to de-register/delete an SDP record
 *                  for AVRCP.
 *
 * Returns          void
 *
 *****************************************************************************/
void bta_ar_dereg_avrc(uint16_t service_uuid) {
  uint8_t mask = BTA_AR_AV_MASK;
  uint16_t categories = 0;
  uint8_t temp[8], *p;

  if (service_uuid == UUID_SERVCLASS_AV_REM_CTRL_TARGET) {
    if (bta_ar_cb.sdp_tg_handle && mask == bta_ar_cb.tg_registered) {
      bta_ar_cb.tg_registered = 0;
      SDP_DeleteRecord(bta_ar_cb.sdp_tg_handle);
      bta_ar_cb.sdp_tg_handle = 0;
      bta_sys_remove_uuid(service_uuid);
    }
  } else if (service_uuid == UUID_SERVCLASS_AV_REMOTE_CONTROL) {
    if (bta_ar_cb.sdp_ct_handle) {
      bta_ar_cb.ct_categories[mask - 1] = 0;
      categories = bta_ar_cb.ct_categories[0] | bta_ar_cb.ct_categories[1];
      if (!categories) {
        /* no CT is still registered - cleaup */
        SDP_DeleteRecord(bta_ar_cb.sdp_ct_handle);
        bta_ar_cb.sdp_ct_handle = 0;
        bta_sys_remove_uuid(service_uuid);
      } else {
        /* change supported categories to the remaning one */
        p = temp;
        UINT16_TO_BE_STREAM(p, categories);
        SDP_AddAttribute(bta_ar_cb.sdp_ct_handle, ATTR_ID_SUPPORTED_FEATURES,
                         UINT_DESC_TYPE, (uint32_t)2, (uint8_t*)temp);
      }
    }
  }
}
