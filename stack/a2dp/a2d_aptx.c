/******************************************************************************
    Copyright (c) 2016, The Linux Foundation. All rights reserved.

    Redistribution and use in source and binary forms, with or without
    modification, are permitted provided that the following conditions are
    met:
        * Redistributions of source code must retain the above copyright
          notice, this list of conditions and the following disclaimer.
        * Redistributions in binary form must reproduce the above
          copyright notice, this list of conditions and the following
          disclaimer in the documentation and/or other materials provided
          with the distribution.
        * Neither the name of The Linux Foundation nor the names of its
          contributors may be used to endorse or promote products derived
          from this software without specific prior written permission.

    THIS SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESS OR IMPLIED
    WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
    MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT
    ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS
    BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
    CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
    SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
    BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
    WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
    OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
    IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

 ******************************************************************************/

/******************************************************************************
 *
 *  Utility functions to help build and parse the aptX Codec Information
 *  Element and Media Payload.
 *
 ******************************************************************************/

#include "bt_target.h"

#include <string.h>
#include "bt_utils.h"
#include "a2d_api.h"
#include "a2d_int.h"
#include "a2d_aptx.h"
#include <utils/Log.h>

/******************************************************************************
**
** Function         A2D_BldAptxInfo
**
******************************************************************************/

UINT8 A2D_BldAptxInfo(UINT8 media_type, tA2D_APTX_CIE *p_ie, UINT8 *p_result)
{
    A2D_TRACE_API("A2D_BldAptxInfo - MediaType:%d", media_type);

    UINT8 status = 0;
    status = A2D_SUCCESS;
    *p_result++ = A2D_APTX_CODEC_LEN;
    *p_result++ = media_type;
    *p_result++ = A2D_NON_A2DP_MEDIA_CT;
    *p_result++ = (UINT8)(p_ie->vendorId & 0x000000FF);
    *p_result++ = (UINT8)(p_ie->vendorId & 0x0000FF00)>> 8;
    *p_result++ = (UINT8)(p_ie->vendorId & 0x00FF0000)>> 16;
    *p_result++ = (UINT8)(p_ie->vendorId & 0xFF000000)>> 24;
    *p_result++ = (UINT8)(p_ie->codecId & 0x00FF);
    *p_result++ = (UINT8)(p_ie->codecId & 0xFF00) >> 8;
    *p_result++ = p_ie->sampleRate | p_ie->channelMode;

    return status;
}
