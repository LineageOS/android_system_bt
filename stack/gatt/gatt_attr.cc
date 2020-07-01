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
 *  this file contains the main GATT server attributes access request
 *  handling functions.
 *
 ******************************************************************************/

#include "bt_target.h"
#include "bt_utils.h"

#include "gatt_api.h"
#include "gatt_int.h"
#include "osi/include/osi.h"

using base::StringPrintf;
using bluetooth::Uuid;

#define BLE_GATT_SVR_SUP_FEAT_EATT_BITMASK 0x01

#define BLE_GATT_CL_SUP_FEAT_CACHING_BITMASK 0x01
#define BLE_GATT_CL_SUP_FEAT_EATT_BITMASK 0x02

static void gatt_request_cback(uint16_t conn_id, uint32_t trans_id,
                               uint8_t op_code, tGATTS_DATA* p_data);
static void gatt_connect_cback(UNUSED_ATTR tGATT_IF gatt_if,
                               const RawAddress& bda, uint16_t conn_id,
                               bool connected, tGATT_DISCONN_REASON reason,
                               tBT_TRANSPORT transport);
static void gatt_disc_res_cback(uint16_t conn_id, tGATT_DISC_TYPE disc_type,
                                tGATT_DISC_RES* p_data);
static void gatt_disc_cmpl_cback(uint16_t conn_id, tGATT_DISC_TYPE disc_type,
                                 tGATT_STATUS status);
static void gatt_cl_op_cmpl_cback(UNUSED_ATTR uint16_t conn_id,
                                  UNUSED_ATTR tGATTC_OPTYPE op,
                                  UNUSED_ATTR tGATT_STATUS status,
                                  UNUSED_ATTR tGATT_CL_COMPLETE* p_data);

static void gatt_cl_start_config_ccc(tGATT_PROFILE_CLCB* p_clcb);

static tGATT_CBACK gatt_profile_cback = {gatt_connect_cback,
                                         gatt_cl_op_cmpl_cback,
                                         gatt_disc_res_cback,
                                         gatt_disc_cmpl_cback,
                                         gatt_request_cback,
                                         NULL,
                                         NULL,
                                         NULL,
                                         NULL};

/*******************************************************************************
 *
 * Function         gatt_profile_find_conn_id_by_bd_addr
 *
 * Description      Find the connection ID by remote address
 *
 * Returns          Connection ID
 *
 ******************************************************************************/
uint16_t gatt_profile_find_conn_id_by_bd_addr(const RawAddress& remote_bda) {
  uint16_t conn_id = GATT_INVALID_CONN_ID;
  GATT_GetConnIdIfConnected(gatt_cb.gatt_if, remote_bda, &conn_id,
                            BT_TRANSPORT_LE);
  if (conn_id == GATT_INVALID_CONN_ID)
    GATT_GetConnIdIfConnected(gatt_cb.gatt_if, remote_bda, &conn_id,
                              BT_TRANSPORT_BR_EDR);
  return conn_id;
}

/*******************************************************************************
 *
 * Function         gatt_profile_find_clcb_by_conn_id
 *
 * Description      find clcb by Connection ID
 *
 * Returns          Pointer to the found link conenction control block.
 *
 ******************************************************************************/
static tGATT_PROFILE_CLCB* gatt_profile_find_clcb_by_conn_id(uint16_t conn_id) {
  uint8_t i_clcb;
  tGATT_PROFILE_CLCB* p_clcb = NULL;

  for (i_clcb = 0, p_clcb = gatt_cb.profile_clcb; i_clcb < GATT_MAX_APPS;
       i_clcb++, p_clcb++) {
    if (p_clcb->in_use && p_clcb->conn_id == conn_id) return p_clcb;
  }

  return NULL;
}

/*******************************************************************************
 *
 * Function         gatt_profile_find_clcb_by_bd_addr
 *
 * Description      The function searches all LCBs with macthing bd address.
 *
 * Returns          Pointer to the found link conenction control block.
 *
 ******************************************************************************/
static tGATT_PROFILE_CLCB* gatt_profile_find_clcb_by_bd_addr(
    const RawAddress& bda, tBT_TRANSPORT transport) {
  uint8_t i_clcb;
  tGATT_PROFILE_CLCB* p_clcb = NULL;

  for (i_clcb = 0, p_clcb = gatt_cb.profile_clcb; i_clcb < GATT_MAX_APPS;
       i_clcb++, p_clcb++) {
    if (p_clcb->in_use && p_clcb->transport == transport && p_clcb->connected &&
        p_clcb->bda == bda)
      return p_clcb;
  }

  return NULL;
}

/*******************************************************************************
 *
 * Function         gatt_profile_clcb_alloc
 *
 * Description      The function allocates a GATT profile connection link
 *                  control block
 *
 * Returns          NULL if not found. Otherwise pointer to the connection link
 *                  block.
 *
 ******************************************************************************/
tGATT_PROFILE_CLCB* gatt_profile_clcb_alloc(uint16_t conn_id,
                                            const RawAddress& bda,
                                            tBT_TRANSPORT tranport) {
  uint8_t i_clcb = 0;
  tGATT_PROFILE_CLCB* p_clcb = NULL;

  for (i_clcb = 0, p_clcb = gatt_cb.profile_clcb; i_clcb < GATT_MAX_APPS;
       i_clcb++, p_clcb++) {
    if (!p_clcb->in_use) {
      p_clcb->in_use = true;
      p_clcb->conn_id = conn_id;
      p_clcb->connected = true;
      p_clcb->transport = tranport;
      p_clcb->bda = bda;
      break;
    }
  }
  if (i_clcb < GATT_MAX_APPS) return p_clcb;

  return NULL;
}

/*******************************************************************************
 *
 * Function         gatt_profile_clcb_dealloc
 *
 * Description      The function deallocates a GATT profile connection link
 *                  control block
 *
 * Returns          void
 *
 ******************************************************************************/
void gatt_profile_clcb_dealloc(tGATT_PROFILE_CLCB* p_clcb) {
  memset(p_clcb, 0, sizeof(tGATT_PROFILE_CLCB));
}

/** GAP Attributes Database Request callback */
tGATT_STATUS read_attr_value(uint16_t handle, tGATT_VALUE* p_value,
                             bool is_long) {
  uint8_t* p = p_value->value;

  if (handle == gatt_cb.handle_sr_supported_feat) {
    /* GATT_UUID_SERVER_SUP_FEAT*/
    if (is_long) return GATT_NOT_LONG;

    UINT8_TO_STREAM(p, gatt_cb.gatt_svr_supported_feat_mask);
    p_value->len = sizeof(gatt_cb.gatt_svr_supported_feat_mask);
    return GATT_SUCCESS;
  }

  if (handle == gatt_cb.handle_of_h_r) {
    /* GATT_UUID_GATT_SRV_CHGD */
    return GATT_READ_NOT_PERMIT;
  }

  return GATT_NOT_FOUND;
}

/** GAP Attributes Database Read/Read Blob Request process */
tGATT_STATUS proc_read_req(tGATTS_REQ_TYPE, tGATT_READ_REQ* p_data,
                           tGATTS_RSP* p_rsp) {
  if (p_data->is_long) p_rsp->attr_value.offset = p_data->offset;

  p_rsp->attr_value.handle = p_data->handle;

  return read_attr_value(p_data->handle, &p_rsp->attr_value, p_data->is_long);
}

/** GAP ATT server process a write request */
uint8_t proc_write_req(tGATTS_REQ_TYPE, tGATT_WRITE_REQ* p_data) {
  /* GATT_UUID_SERVER_SUP_FEAT*/
  if (p_data->handle == gatt_cb.handle_sr_supported_feat)
    return GATT_WRITE_NOT_PERMIT;

  /* GATT_UUID_GATT_SRV_CHGD */
  if (p_data->handle == gatt_cb.handle_of_h_r) return GATT_WRITE_NOT_PERMIT;

  return GATT_NOT_FOUND;
}

/*******************************************************************************
 *
 * Function         gatt_request_cback
 *
 * Description      GATT profile attribute access request callback.
 *
 * Returns          void.
 *
 ******************************************************************************/
static void gatt_request_cback(uint16_t conn_id, uint32_t trans_id,
                               tGATTS_REQ_TYPE type, tGATTS_DATA* p_data) {
  uint8_t status = GATT_INVALID_PDU;
  tGATTS_RSP rsp_msg;
  bool rsp_needed = true;

  memset(&rsp_msg, 0, sizeof(tGATTS_RSP));

  switch (type) {
    case GATTS_REQ_TYPE_READ_CHARACTERISTIC:
    case GATTS_REQ_TYPE_READ_DESCRIPTOR:
      status = proc_read_req(type, &p_data->read_req, &rsp_msg);
      break;

    case GATTS_REQ_TYPE_WRITE_CHARACTERISTIC:
    case GATTS_REQ_TYPE_WRITE_DESCRIPTOR:
    case GATTS_REQ_TYPE_WRITE_EXEC:
    case GATT_CMD_WRITE:
      if (!p_data->write_req.need_rsp) rsp_needed = false;

      status = proc_write_req(type, &p_data->write_req);
      break;

    case GATTS_REQ_TYPE_MTU:
      VLOG(1) << "Get MTU exchange new mtu size: " << +p_data->mtu;
      rsp_needed = false;
      break;

    default:
      VLOG(1) << "Unknown/unexpected LE GAP ATT request: " << loghex(type);
      break;
  }

  if (rsp_needed) GATTS_SendRsp(conn_id, trans_id, status, &rsp_msg);
}

/*******************************************************************************
 *
 * Function         gatt_connect_cback
 *
 * Description      Gatt profile connection callback.
 *
 * Returns          void
 *
 ******************************************************************************/
static void gatt_connect_cback(UNUSED_ATTR tGATT_IF gatt_if,
                               const RawAddress& bda, uint16_t conn_id,
                               bool connected, tGATT_DISCONN_REASON reason,
                               tBT_TRANSPORT transport) {
  VLOG(1) << __func__ << ": from " << bda << " connected: " << connected
          << ", conn_id: " << loghex(conn_id) << "reason: " << loghex(reason);

  tGATT_PROFILE_CLCB* p_clcb =
      gatt_profile_find_clcb_by_bd_addr(bda, transport);
  if (p_clcb == NULL) return;

  if (connected) {
    p_clcb->conn_id = conn_id;
    p_clcb->connected = true;

    if (p_clcb->ccc_stage == GATT_SVC_CHANGED_CONNECTING) {
      p_clcb->ccc_stage++;
      gatt_cl_start_config_ccc(p_clcb);
    }
  } else {
    gatt_profile_clcb_dealloc(p_clcb);
  }
}

/*******************************************************************************
 *
 * Function         gatt_profile_db_init
 *
 * Description      Initializa the GATT profile attribute database.
 *
 ******************************************************************************/
void gatt_profile_db_init(void) {
  uint16_t service_handle = 0;

  /* Fill our internal UUID with a fixed pattern 0x81 */
  std::array<uint8_t, Uuid::kNumBytes128> tmp;
  tmp.fill(0x81);

  /* Create a GATT profile service */
  gatt_cb.gatt_if = GATT_Register(Uuid::From128BitBE(tmp), &gatt_profile_cback);
  GATT_StartIf(gatt_cb.gatt_if);

  Uuid service_uuid = Uuid::From16Bit(UUID_SERVCLASS_GATT_SERVER);

  Uuid srv_changed_char_uuid = Uuid::From16Bit(GATT_UUID_GATT_SRV_CHGD);
  Uuid svr_sup_feat_uuid = Uuid::From16Bit(GATT_UUID_SERVER_SUP_FEAT);

  btgatt_db_element_t service[] = {
      {
          .uuid = service_uuid,
          .type = BTGATT_DB_PRIMARY_SERVICE,
      },
      {
          .uuid = srv_changed_char_uuid,
          .type = BTGATT_DB_CHARACTERISTIC,
          .properties = GATT_CHAR_PROP_BIT_INDICATE,
          .permissions = 0,
      },
      {
          .type = BTGATT_DB_CHARACTERISTIC,
          .uuid = svr_sup_feat_uuid,
          .properties = GATT_CHAR_PROP_BIT_READ,
          .permissions = GATT_PERM_READ,
      }};

  GATTS_AddService(gatt_cb.gatt_if, service,
                   sizeof(service) / sizeof(btgatt_db_element_t));

  service_handle = service[0].attribute_handle;
  gatt_cb.handle_of_h_r = service[1].attribute_handle;
  gatt_cb.handle_sr_supported_feat = service[2].attribute_handle;

  gatt_cb.gatt_svr_supported_feat_mask |= BLE_GATT_SVR_SUP_FEAT_EATT_BITMASK;
  gatt_cb.gatt_cl_supported_feat_mask |= BLE_GATT_CL_SUP_FEAT_EATT_BITMASK;

  VLOG(1) << __func__ << ": gatt_if=" << gatt_cb.gatt_if << " EATT supported";
}

/*******************************************************************************
 *
 * Function         gatt_disc_res_cback
 *
 * Description      Gatt profile discovery result callback
 *
 * Returns          void
 *
 ******************************************************************************/
static void gatt_disc_res_cback(uint16_t conn_id, tGATT_DISC_TYPE disc_type,
                                tGATT_DISC_RES* p_data) {
  tGATT_PROFILE_CLCB* p_clcb = gatt_profile_find_clcb_by_conn_id(conn_id);

  if (p_clcb == NULL) return;

  switch (disc_type) {
    case GATT_DISC_SRVC_BY_UUID: /* stage 1 */
      p_clcb->e_handle = p_data->value.group_value.e_handle;
      p_clcb->ccc_result++;
      break;

    case GATT_DISC_CHAR: /* stage 2 */
      p_clcb->s_handle = p_data->value.dclr_value.val_handle;
      p_clcb->ccc_result++;
      break;

    case GATT_DISC_CHAR_DSCPT: /* stage 3 */
      if (p_data->type == Uuid::From16Bit(GATT_UUID_CHAR_CLIENT_CONFIG)) {
        p_clcb->s_handle = p_data->handle;
        p_clcb->ccc_result++;
      }
      break;
  }
}

/*******************************************************************************
 *
 * Function         gatt_disc_cmpl_cback
 *
 * Description      Gatt profile discovery complete callback
 *
 * Returns          void
 *
 ******************************************************************************/
static void gatt_disc_cmpl_cback(uint16_t conn_id, tGATT_DISC_TYPE disc_type,
                                 tGATT_STATUS status) {
  tGATT_PROFILE_CLCB* p_clcb = gatt_profile_find_clcb_by_conn_id(conn_id);

  if (p_clcb == NULL) return;

  if (status != GATT_SUCCESS || p_clcb->ccc_result == 0) {
    LOG(WARNING) << __func__
                 << ": Unable to register for service changed indication";
    return;
  }

  p_clcb->ccc_result = 0;
  p_clcb->ccc_stage++;
  gatt_cl_start_config_ccc(p_clcb);
}

/*******************************************************************************
 *
 * Function         gatt_cl_op_cmpl_cback
 *
 * Description      Gatt profile client operation complete callback
 *
 * Returns          void
 *
 ******************************************************************************/
static void gatt_cl_op_cmpl_cback(UNUSED_ATTR uint16_t conn_id,
                                  UNUSED_ATTR tGATTC_OPTYPE op,
                                  UNUSED_ATTR tGATT_STATUS status,
                                  UNUSED_ATTR tGATT_CL_COMPLETE* p_data) {}

/*******************************************************************************
 *
 * Function         gatt_cl_start_config_ccc
 *
 * Description      Gatt profile start configure service change CCC
 *
 * Returns          void
 *
 ******************************************************************************/
static void gatt_cl_start_config_ccc(tGATT_PROFILE_CLCB* p_clcb) {

  VLOG(1) << __func__ << ": stage: " << +p_clcb->ccc_stage;

  switch (p_clcb->ccc_stage) {
    case GATT_SVC_CHANGED_SERVICE: /* discover GATT service */
      GATTC_Discover(p_clcb->conn_id, GATT_DISC_SRVC_BY_UUID, 0x0001, 0xffff,
                     Uuid::From16Bit(UUID_SERVCLASS_GATT_SERVER));
      break;

    case GATT_SVC_CHANGED_CHARACTERISTIC: /* discover service change char */
      GATTC_Discover(p_clcb->conn_id, GATT_DISC_CHAR, 0x0001, p_clcb->e_handle,
                     Uuid::From16Bit(GATT_UUID_GATT_SRV_CHGD));
      break;

    case GATT_SVC_CHANGED_DESCRIPTOR: /* discover service change ccc */
      GATTC_Discover(p_clcb->conn_id, GATT_DISC_CHAR_DSCPT, p_clcb->s_handle,
                     p_clcb->e_handle);
      break;

    case GATT_SVC_CHANGED_CONFIGURE_CCCD: /* write ccc */
    {
      tGATT_VALUE ccc_value;
      memset(&ccc_value, 0, sizeof(tGATT_VALUE));
      ccc_value.handle = p_clcb->s_handle;
      ccc_value.len = 2;
      ccc_value.value[0] = GATT_CLT_CONFIG_INDICATION;
      GATTC_Write(p_clcb->conn_id, GATT_WRITE, &ccc_value);
      break;
    }
  }
}

/*******************************************************************************
 *
 * Function         GATT_ConfigServiceChangeCCC
 *
 * Description      Configure service change indication on remote device
 *
 * Returns          none
 *
 ******************************************************************************/
void GATT_ConfigServiceChangeCCC(const RawAddress& remote_bda, bool enable,
                                 tBT_TRANSPORT transport) {
  tGATT_PROFILE_CLCB* p_clcb =
      gatt_profile_find_clcb_by_bd_addr(remote_bda, transport);

  if (p_clcb == NULL)
    p_clcb = gatt_profile_clcb_alloc(0, remote_bda, transport);

  if (p_clcb == NULL) return;

  if (GATT_GetConnIdIfConnected(gatt_cb.gatt_if, remote_bda, &p_clcb->conn_id,
                                transport)) {
    p_clcb->connected = true;
  }
  /* hold the link here */
  GATT_Connect(gatt_cb.gatt_if, remote_bda, true, transport, true);
  p_clcb->ccc_stage = GATT_SVC_CHANGED_CONNECTING;

  if (!p_clcb->connected) {
    /* wait for connection */
    return;
  }

  p_clcb->ccc_stage++;
  gatt_cl_start_config_ccc(p_clcb);
}
