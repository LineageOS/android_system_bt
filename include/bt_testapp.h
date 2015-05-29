/*
 * Copyright (c) 2013, The Linux Foundation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *        * Redistributions of source code must retain the above copyright
 *          notice, this list of conditions and the following disclaimer.
 *        * Redistributions in binary form must reproduce the above copyright
 *            notice, this list of conditions and the following disclaimer in the
 *            documentation and/or other materials provided with the distribution.
 *        * Neither the name of The Linux Foundation nor
 *            the names of its contributors may be used to endorse or promote
 *            products derived from this software without specific prior written
 *            permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NON-INFRINGEMENT ARE DISCLAIMED.    IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifdef TEST_APP_INTERFACE
#ifndef ANDROID_INCLUDE_BT_TESTAPP_H
#define ANDROID_INCLUDE_BT_TESTAPP_H
#include <stdio.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <ctype.h>
#include <fcntl.h>
#include <sys/prctl.h>
#include <linux/capability.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <private/android_filesystem_config.h>
#include <android/log.h>
#include <hardware/bluetooth.h>
#include "l2c_api.h"
#include "sdp_api.h"
#include "gatt_api.h"
#include "gap_api.h"
#include "mca_api.h"
#include <hardware/hardware.h>
#include "btm_api.h"

__BEGIN_DECLS

typedef void (tREMOTE_DEVICE_NAME_CB) (void *p1);

enum {
    SUCCESS,
    FAIL
};

typedef enum {
    DUMMY,
    ALL,
    SPP,
    FTP,
    OPP,
    MAP,
    PBAP,
    DUN,
    NOT_SUPPORTED,
}profileName;
typedef enum {
    TEST_APP_RFCOMM,
    TEST_APP_MCAP
} test_app_profile;

typedef struct
{
    size_t    size;
    void (*Init)(void);
    tMCA_HANDLE (*Register)(tMCA_REG *p_reg, tMCA_CTRL_CBACK *p_cback);
    void        (*Deregister)(tMCA_HANDLE handle);
    tMCA_RESULT (*CreateDep)(tMCA_HANDLE handle, tMCA_DEP *p_dep, tMCA_CS *p_cs);
    tMCA_RESULT (*DeleteDep)(tMCA_HANDLE handle, tMCA_DEP dep);
    tMCA_RESULT (*ConnectReq)(tMCA_HANDLE handle, BD_ADDR bd_addr,
                                          UINT16 ctrl_psm,
                                          UINT16 sec_mask);
    tMCA_RESULT (*DisconnectReq)(tMCA_CL mcl);
    tMCA_RESULT (*CreateMdl)(tMCA_CL mcl, tMCA_DEP dep, UINT16 data_psm,
                                         UINT16 mdl_id, UINT8 peer_dep_id,
                                         UINT8 cfg, const tMCA_CHNL_CFG *p_chnl_cfg);
    tMCA_RESULT (*CreateMdlRsp)(tMCA_CL mcl, tMCA_DEP dep,
                                            UINT16 mdl_id, UINT8 cfg, UINT8 rsp_code,
                                            const tMCA_CHNL_CFG *p_chnl_cfg);
    tMCA_RESULT (*CloseReq)(tMCA_DL mdl);
    tMCA_RESULT (*ReconnectMdl)(tMCA_CL mcl, tMCA_DEP dep, UINT16 data_psm,
                                            UINT16 mdl_id, const tMCA_CHNL_CFG *p_chnl_cfg);
    tMCA_RESULT (*ReconnectMdlRsp)(tMCA_CL mcl, tMCA_DEP dep,
                                               UINT16 mdl_id, UINT8 rsp_code,
                                               const tMCA_CHNL_CFG *p_chnl_cfg);
    tMCA_RESULT (*DataChnlCfg)(tMCA_CL mcl, const tMCA_CHNL_CFG *p_chnl_cfg);
    tMCA_RESULT (*Abort)(tMCA_CL mcl);
    tMCA_RESULT (*Delete)(tMCA_CL mcl, UINT16 mdl_id);
    tMCA_RESULT (*WriteReq)(tMCA_DL mdl, BT_HDR *p_pkt);
    UINT16 (*GetL2CapChannel) (tMCA_DL mdl);
}btmcap_interface_t;

/** Bluetooth RFC tool commands */
typedef enum {
    RFC_TEST_CLIENT =1,
    RFC_TEST_FRAME_ERROR,
    RFC_TEST_ROLE_SWITCH,
    RFC_TEST_SERVER,
    RFC_TEST_DISCON,
    RFC_TEST_CLIENT_TEST_MSC_DATA, //For PTS test case BV 21 and 22
    RFC_TEST_WRITE_DATA
}rfc_test_cmd_t;


typedef struct {
    bt_bdaddr_t bdadd;
    uint8_t     scn; //Server Channel Number
}bt_rfc_conn_t;

typedef struct {
    bt_bdaddr_t bdadd;
    uint8_t     role; //0x01 for master
}bt_role_sw;

typedef union {
    bt_rfc_conn_t  conn;
    uint8_t        server;
    bt_role_sw     role_switch;
}tRfcomm_test;

typedef struct {
    rfc_test_cmd_t param;
    tRfcomm_test   data;
}tRFC;

typedef struct {
    size_t          size;
    bt_status_t (*init)( tL2CAP_APPL_INFO* callbacks );
    void  (*rdut_rfcomm)( UINT8 server );
    void  (*rdut_rfcomm_test_interface)( tRFC *input);
    bt_status_t (*connect)( bt_bdaddr_t *bd_addr );
    void  (*cleanup)( void );
} btrfcomm_interface_t;

#endif

__END_DECLS

#endif /* ANDROID_INCLUDE_BT_TESTAPP_H */
