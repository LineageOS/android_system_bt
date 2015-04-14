/******************************************************************************
 *
 *  Copyright (c) 2015, The Linux Foundation. All rights reserved.
 *  Not a Contribution
 *  Copyright (C) 2006-2013 Broadcom Corporation
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

#include "gki.h"
#include "avrc_api.h"
#include "avrc_defs.h"
#include "avrc_int.h"
#include "bt_utils.h"

/*****************************************************************************
**  Global data
*****************************************************************************/

#if (AVRC_METADATA_INCLUDED == TRUE)

/*******************************************************************************
**
** Function         avrc_pars_vendor_rsp
**
** Description      This function parses the vendor specific commands defined by
**                  Bluetooth SIG
**
** Returns          AVRC_STS_NO_ERROR, if the message in p_data is parsed successfully.
**                  Otherwise, the error code defined by AVRCP 1.4
**
*******************************************************************************/
static tAVRC_STS avrc_pars_vendor_rsp(tAVRC_MSG_VENDOR *p_msg, tAVRC_RESPONSE *p_result)
{
    tAVRC_STS  status = AVRC_STS_NO_ERROR;
    UINT8   *p;
    UINT16  len;
    UINT8 eventid=0;

    /* Check the vendor data */
    if (p_msg->vendor_len == 0)
        return AVRC_STS_NO_ERROR;
    if (p_msg->p_vendor_data == NULL)
        return AVRC_STS_INTERNAL_ERR;

    p = p_msg->p_vendor_data;
    BE_STREAM_TO_UINT8 (p_result->pdu, p);
    p++; /* skip the reserved/packe_type byte */
    BE_STREAM_TO_UINT16 (len, p);
    AVRC_TRACE_DEBUG("avrc_pars_vendor_rsp() ctype:0x%x pdu:0x%x, len:%d/0x%x", p_msg->hdr.ctype, p_result->pdu, len, len);
    if (p_msg->hdr.ctype == AVRC_RSP_REJ)
    {
        p_result->rsp.status = *p;
        return p_result->rsp.status;
    }

    switch (p_result->pdu)
    {
    /* case AVRC_PDU_REQUEST_CONTINUATION_RSP: 0x40 */
    /* case AVRC_PDU_ABORT_CONTINUATION_RSP:   0x41 */

#if (AVRC_ADV_CTRL_INCLUDED == TRUE)
    case AVRC_PDU_SET_ABSOLUTE_VOLUME:      /* 0x50 */
        if (len != 1)
            status = AVRC_STS_INTERNAL_ERR;
        else
        {
            BE_STREAM_TO_UINT8 (p_result->volume.volume, p);
        }
        break;
#endif /* (AVRC_ADV_CTRL_INCLUDED == TRUE) */

    case AVRC_PDU_REGISTER_NOTIFICATION:    /* 0x31 */
#if (AVRC_ADV_CTRL_INCLUDED == TRUE)
        BE_STREAM_TO_UINT8 (eventid, p);
        if(AVRC_EVT_VOLUME_CHANGE==eventid
            && (AVRC_RSP_CHANGED==p_msg->hdr.ctype || AVRC_RSP_INTERIM==p_msg->hdr.ctype
            || AVRC_RSP_REJ==p_msg->hdr.ctype || AVRC_RSP_NOT_IMPL==p_msg->hdr.ctype))
        {
            p_result->reg_notif.status=p_msg->hdr.ctype;
            p_result->reg_notif.event_id=eventid;
            BE_STREAM_TO_UINT8 (p_result->reg_notif.param.volume, p);
        }
        AVRC_TRACE_DEBUG("avrc_pars_vendor_rsp PDU reg notif response:event %x, volume %x",eventid,
            p_result->reg_notif.param.volume);
#endif /* (AVRC_ADV_CTRL_INCLUDED == TRUE) */
        break;
    default:
        status = AVRC_STS_BAD_CMD;
        break;
    }

    return status;
}
#if (AVRC_ADV_CTRL_INCLUDED == TRUE)
/*******************************************************************************
**
** Function         avrc_ctrl_pars_vendor_rsp
**
** Description      This function parses the vendor specific commands defined by
**                  Bluetooth SIG
**
** Returns          AVRC_STS_NO_ERROR, if the message in p_data is parsed successfully.
**                  Otherwise, the error code defined by AVRCP 1.4
**
*******************************************************************************/
static tAVRC_STS avrc_ctrl_pars_vendor_rsp(tAVRC_MSG_VENDOR *p_msg, tAVRC_RESPONSE *p_result, UINT8* p_buf, UINT16* buf_len)
{
    tAVRC_STS  status = AVRC_STS_NO_ERROR;
    UINT8   *p = p_msg->p_vendor_data;
    UINT16  len;
    UINT8   xx, yy;
    UINT8 eventid=0;

    BE_STREAM_TO_UINT8 (p_result->pdu, p);
    p++; /* skip the reserved/packe_type byte */
    BE_STREAM_TO_UINT16 (len, p);
    AVRC_TRACE_DEBUG("avrc_ctrl_pars_vendor_rsp() ctype:0x%x pdu:0x%x, len:%d",
                                         p_msg->hdr.ctype, p_result->pdu, len);
    if (p_msg->hdr.ctype == AVRC_RSP_REJ)
    {
        p_result->rsp.status = *p;
        return p_result->rsp.status;
    }

    switch (p_result->pdu)
    {
    /* case AVRC_PDU_REQUEST_CONTINUATION_RSP: 0x40 */
    /* case AVRC_PDU_ABORT_CONTINUATION_RSP:   0x41 */

     case AVRC_PDU_REGISTER_NOTIFICATION:    /* 0x31 */
        if (len <= 0)
        {
            buf_len = 0;
            break;
        }
        memcpy(p_buf,p,len);
        *buf_len = len;
        break;

    case AVRC_PDU_GET_CAPABILITIES:
        if (len == 0)
        {
            p_result->get_caps.count = 0;
            p_result->get_caps.capability_id = 0;
            break;
        }
        BE_STREAM_TO_UINT8(p_result->get_caps.capability_id,p);
        BE_STREAM_TO_UINT8(p_result->get_caps.count,p);
        AVRC_TRACE_DEBUG("AVRC_PDU_GET_CAPABILITIES cap id =%d, cap_count = %d "
                                     ,p_result->get_caps.capability_id,p_result->get_caps.count);
        if (p_result->get_caps.capability_id == AVRC_CAP_COMPANY_ID)
        {
            for(xx =0; ((xx<=p_result->get_caps.count) && (xx <AVRC_CAP_MAX_NUM_COMP_ID)); xx++)
            {
                BE_STREAM_TO_UINT24(p_result->get_caps.param.company_id[xx],p);
            }
        }
        else if (p_result->get_caps.capability_id == AVRC_CAP_EVENTS_SUPPORTED)
        {
            for(xx =0; ((xx<=p_result->get_caps.count) && (xx <AVRC_CAP_MAX_NUM_EVT_ID)); xx++)
            {
                BE_STREAM_TO_UINT8(p_result->get_caps.param.event_id[xx],p);
            }
        }
        break;
    case AVRC_PDU_LIST_PLAYER_APP_ATTR:
        if (len <= 0)
        {
            p_result->list_app_attr.num_attr = 0;
            break;
        }
        BE_STREAM_TO_UINT8(p_result->list_app_attr.num_attr,p);
        AVRC_TRACE_DEBUG("AVRC_PDU_LIST_PLAYER_APP_ATTR count = %d ",
                                           p_result->list_app_attr.num_attr);
        for(xx = 0; xx < p_result->list_app_attr.num_attr;xx++)
        {
            BE_STREAM_TO_UINT8(p_result->list_app_attr.attrs[xx],p);
        }
        break;
    case AVRC_PDU_LIST_PLAYER_APP_VALUES:
        if (len <= 0)
        {
            p_result->list_app_values.num_val = 0;
            break;
        }
        BE_STREAM_TO_UINT8(p_result->list_app_values.num_val,p);
        AVRC_TRACE_DEBUG("AVRC_PDU_LIST_PLAYER_APP_ATTR count = %d ",
                                          p_result->list_app_attr.num_attr);
        for(xx = 0; xx < p_result->list_app_values.num_val; xx++)
        {
            BE_STREAM_TO_UINT8(p_result->list_app_values.vals[xx],p);
        }
        break;
    case AVRC_PDU_GET_CUR_PLAYER_APP_VALUE:
    {
        tAVRC_APP_SETTING *app_sett;
        if (len <= 0)
        {
            p_result->get_cur_app_val.num_val = 0;
            break;
        }
        BE_STREAM_TO_UINT8(p_result->get_cur_app_val.num_val,p);
        app_sett =
            (tAVRC_APP_SETTING*)GKI_getbuf(p_result->get_cur_app_val.num_val*sizeof(tAVRC_APP_SETTING));
        AVRC_TRACE_DEBUG("AVRC_PDU_GET_CUR_PLAYER_APP_VALUE count = %d "
                                     ,p_result->get_cur_app_val.num_val);
        for (xx = 0; xx < p_result->get_cur_app_val.num_val; xx++)
        {
            BE_STREAM_TO_UINT8(app_sett[xx].attr_id,p);
            BE_STREAM_TO_UINT8(app_sett[xx].attr_val,p);
        }
        p_result->get_cur_app_val.p_vals = app_sett;
    }
        break;
    case AVRC_PDU_SET_PLAYER_APP_VALUE:
        /* nothing comes as part of this rsp */
        break;
    case AVRC_PDU_GET_ELEMENT_ATTR:
        if (len <= 0)
        {
            p_result->get_elem_attrs.num_attr = 0;
            break;
        }
        BE_STREAM_TO_UINT8(p_result->get_elem_attrs.num_attr,p);
        memcpy(p_buf,p,len-1); // 1 byte of len already read.
        *buf_len = len-1;
        break;
    case AVRC_PDU_GET_PLAY_STATUS:
        if (len <= 0)
        {
            buf_len = 0;
            break;
        }
        memcpy(p_buf,p,len);
        *buf_len = len;
        break;

    default:
        status = AVRC_STS_BAD_CMD;
        break;
    }

    return status;
}
#endif /* (AVRC_ADV_CTRL_INCLUDED == TRUE) */
/*******************************************************************************
**
** Function         AVRC_Ctrl_ParsResponse
**
** Description      This function is a parse response for AVRCP Controller.
**
** Returns          AVRC_STS_NO_ERROR, if the message in p_data is parsed successfully.
**                  Otherwise, the error code defined by AVRCP 1.4
**
*******************************************************************************/
tAVRC_STS AVRC_Ctrl_ParsResponse (tAVRC_MSG *p_msg, tAVRC_RESPONSE *p_result, UINT8 *p_buf, UINT16* buf_len)
{
    tAVRC_STS  status = AVRC_STS_INTERNAL_ERR;
    UINT16  id;

    if (p_msg && p_result)
    {
        switch (p_msg->hdr.opcode)
        {
        case AVRC_OP_VENDOR:     /*  0x00    Vendor-dependent commands */
            status = avrc_ctrl_pars_vendor_rsp(&p_msg->vendor, p_result, p_buf,buf_len);
            break;

        default:
            AVRC_TRACE_ERROR("AVRC_Ctrl_ParsResponse() unknown opcode:0x%x", p_msg->hdr.opcode);
            break;
        }
        p_result->rsp.opcode = p_msg->hdr.opcode;
        p_result->rsp.status = status;
    }
    return status;
}

/*******************************************************************************
**
** Function         AVRC_ParsResponse
**
** Description      This function is a superset of AVRC_ParsMetadata to parse the response.
**
** Returns          AVRC_STS_NO_ERROR, if the message in p_data is parsed successfully.
**                  Otherwise, the error code defined by AVRCP 1.4
**
*******************************************************************************/
tAVRC_STS AVRC_ParsResponse (tAVRC_MSG *p_msg, tAVRC_RESPONSE *p_result, UINT8 *p_buf, UINT16 buf_len)
{
    tAVRC_STS  status = AVRC_STS_INTERNAL_ERR;
    UINT16  id;
    UNUSED(p_buf);
    UNUSED(buf_len);

    if (p_msg && p_result)
    {
        switch (p_msg->hdr.opcode)
        {
        case AVRC_OP_VENDOR:     /*  0x00    Vendor-dependent commands */
            status = avrc_pars_vendor_rsp(&p_msg->vendor, p_result);
            break;

        case AVRC_OP_PASS_THRU:  /*  0x7C    panel subunit opcode */
            status = avrc_pars_pass_thru(&p_msg->pass, &id);
            if (status == AVRC_STS_NO_ERROR)
            {
                p_result->pdu = (UINT8)id;
            }
            break;

        default:
            AVRC_TRACE_ERROR("AVRC_ParsResponse() unknown opcode:0x%x", p_msg->hdr.opcode);
            break;
        }
        p_result->rsp.opcode = p_msg->hdr.opcode;
        p_result->rsp.status = status;
    }
    return status;
}
#endif /* (AVRC_METADATA_INCLUDED == TRUE) */
