/******************************************************************************
 *
 *  Copyright (C) 1999-2012 Broadcom Corporation
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

#ifndef BTM_BLE_INT_TYPES_H
#define BTM_BLE_INT_TYPES_H

#include "osi/include/alarm.h"

#ifdef __cplusplus
extern "C" {
#endif

/* scanning enable status */
#define BTM_BLE_SCAN_ENABLE      0x01
#define BTM_BLE_SCAN_DISABLE     0x00

/* advertising enable status */
#define BTM_BLE_ADV_ENABLE     0x01
#define BTM_BLE_ADV_DISABLE    0x00

/* use the high 4 bits unused by inquiry mode */
#define BTM_BLE_SELECT_SCAN     0x20
#define BTM_BLE_NAME_REQUEST    0x40
#define BTM_BLE_OBSERVE         0x80

#define BTM_BLE_MAX_WL_ENTRY        1
#define BTM_BLE_AD_DATA_LEN         31

#define BTM_BLE_ENC_MASK    0x03

#define BTM_BLE_DUPLICATE_ENABLE        1
#define BTM_BLE_DUPLICATE_DISABLE       0

#define BTM_BLE_GAP_DISC_SCAN_INT      18         /* Interval(scan_int) = 11.25 ms= 0x0010 * 0.625 ms */
#define BTM_BLE_GAP_DISC_SCAN_WIN      18         /* scan_window = 11.25 ms= 0x0010 * 0.625 ms */
#define BTM_BLE_GAP_ADV_INT            512        /* Tgap(gen_disc) = 1.28 s= 512 * 0.625 ms */
#define BTM_BLE_GAP_LIM_TIMEOUT_MS     (180 * 1000) /* Tgap(lim_timeout) = 180s max */
#define BTM_BLE_LOW_LATENCY_SCAN_INT   8000       /* Interval(scan_int) = 5s= 8000 * 0.625 ms */
#define BTM_BLE_LOW_LATENCY_SCAN_WIN   8000       /* scan_window = 5s= 8000 * 0.625 ms */


#define BTM_BLE_GAP_ADV_FAST_INT_1         48         /* TGAP(adv_fast_interval1) = 30(used) ~ 60 ms  = 48 *0.625 */
#define BTM_BLE_GAP_ADV_FAST_INT_2         160         /* TGAP(adv_fast_interval2) = 100(used) ~ 150 ms = 160 * 0.625 ms */
#define BTM_BLE_GAP_ADV_SLOW_INT           2048         /* Tgap(adv_slow_interval) = 1.28 s= 512 * 0.625 ms */
#define BTM_BLE_GAP_ADV_DIR_MAX_INT        800         /* Tgap(dir_conn_adv_int_max) = 500 ms = 800 * 0.625 ms */
#define BTM_BLE_GAP_ADV_DIR_MIN_INT        400         /* Tgap(dir_conn_adv_int_min) = 250 ms = 400 * 0.625 ms */

#define BTM_BLE_GAP_FAST_ADV_TIMEOUT_MS    (30 * 1000)

#define BTM_BLE_SEC_REQ_ACT_NONE           0
#define BTM_BLE_SEC_REQ_ACT_ENCRYPT        1 /* encrypt the link using current key or key refresh */
#define BTM_BLE_SEC_REQ_ACT_PAIR           2
#define BTM_BLE_SEC_REQ_ACT_DISCARD        3 /* discard the sec request while encryption is started but not completed */
typedef UINT8   tBTM_BLE_SEC_REQ_ACT;

#define BLE_STATIC_PRIVATE_MSB_MASK          0x3f
#define BLE_RESOLVE_ADDR_MSB                 0x40   /*  most significant bit, bit7, bit6 is 01 to be resolvable random */
#define BLE_RESOLVE_ADDR_MASK                0xc0   /* bit 6, and bit7 */
#define BTM_BLE_IS_RESOLVE_BDA(x)           ((x[0] & BLE_RESOLVE_ADDR_MASK) == BLE_RESOLVE_ADDR_MSB)

#define BLE_PUBLIC_ADDR_MSB_MASK            0xC0
#define BLE_PUBLIC_ADDR_MSB                 0x80   /*  most significant bit, bit7, bit6 is 10 to be public address*/
#define BTM_IS_PUBLIC_BDA(x)               ((x[0]  & BLE_PUBLIC_ADDR_MSB) == BLE_PUBLIC_ADDR_MSB_MASK)

/* LE scan activity bit mask, continue with LE inquiry bits */
#define BTM_LE_SELECT_CONN_ACTIVE      0x40     /* selection connection is in progress */
#define BTM_LE_OBSERVE_ACTIVE          0x80     /* observe is in progress */

/* BLE scan activity mask checking */
#define BTM_BLE_IS_SCAN_ACTIVE(x)   ((x) & BTM_BLE_SCAN_ACTIVE_MASK)
#define BTM_BLE_IS_INQ_ACTIVE(x)   ((x) & BTM_BLE_INQUIRY_MASK)
#define BTM_BLE_IS_OBS_ACTIVE(x)   ((x) & BTM_LE_OBSERVE_ACTIVE)
#define BTM_BLE_IS_SEL_CONN_ACTIVE(x)   ((x) & BTM_LE_SELECT_CONN_ACTIVE)

/* BLE ADDR type ID bit */
#define BLE_ADDR_TYPE_ID_BIT 0x02

#define BTM_VSC_CHIP_CAPABILITY_L_VERSION 55
#define BTM_VSC_CHIP_CAPABILITY_M_VERSION 95

typedef struct
{
    UINT16              data_mask;
    UINT8               *p_flags;
    UINT8               ad_data[BTM_BLE_AD_DATA_LEN];
    UINT8               *p_pad;
}tBTM_BLE_LOCAL_ADV_DATA;

typedef struct
{
    UINT32          inq_count;          /* Used for determining if a response has already been      */
                                        /* received for the current inquiry operation. (We do not   */
                                        /* want to flood the caller with multiple responses from    */
                                        /* the same device.                                         */
    BOOLEAN         scan_rsp;
    tBLE_BD_ADDR    le_bda;
} tINQ_LE_BDADDR;

#define BTM_BLE_ADV_DATA_LEN_MAX        31
#define BTM_BLE_CACHE_ADV_DATA_MAX      62

#define BTM_BLE_ISVALID_PARAM(x, min, max)  (((x) >= (min) && (x) <= (max)) || ((x) == BTM_BLE_CONN_PARAM_UNDEF))

/* 15 minutes minimum for random address refreshing */
#define BTM_BLE_PRIVATE_ADDR_INT_MS     (15 * 60 * 1000)

typedef struct
{
    UINT16 discoverable_mode;
    UINT16 connectable_mode;
    UINT32 scan_window;
    UINT32 scan_interval;
    UINT8 scan_type; /* current scan type: active or passive */
    UINT8 scan_duplicate_filter; /* duplicate filter enabled for scan */
    UINT16 adv_interval_min;
    UINT16 adv_interval_max;
    tBTM_BLE_AFP afp; /* advertising filter policy */
    tBTM_BLE_SFP sfp; /* scanning filter policy */

    tBLE_ADDR_TYPE adv_addr_type;
    UINT8 evt_type;
    UINT8 adv_mode;
    tBLE_BD_ADDR direct_bda;
    tBTM_BLE_EVT directed_conn;
    BOOLEAN fast_adv_on;
    alarm_t *fast_adv_timer;

    UINT8 adv_len;
    UINT8 adv_data_cache[BTM_BLE_CACHE_ADV_DATA_MAX];

    /* inquiry BD addr database */
    UINT8 num_bd_entries;
    UINT8 max_bd_entries;
    tBTM_BLE_LOCAL_ADV_DATA adv_data;
    tBTM_BLE_ADV_CHNL_MAP adv_chnl_map;

    alarm_t *inquiry_timer;
    BOOLEAN scan_rsp;
    UINT8 state; /* Current state that the inquiry process is in */
    INT8 tx_power;
} tBTM_BLE_INQ_CB;


/* random address resolving complete callback */
typedef void (tBTM_BLE_RESOLVE_CBACK) (void * match_rec, void *p);

typedef void (tBTM_BLE_ADDR_CBACK) (BD_ADDR_PTR static_random, void *p);

/* random address management control block */
typedef struct
{
    tBLE_ADDR_TYPE              own_addr_type;         /* local device LE address type */
    BD_ADDR                     private_addr;
    BD_ADDR                     random_bda;
    BOOLEAN                     busy;
    tBTM_BLE_ADDR_CBACK         *p_generate_cback;
    void                        *p;
    alarm_t                     *refresh_raddr_timer;
} tBTM_LE_RANDOM_CB;

#define BTM_BLE_MAX_BG_CONN_DEV_NUM    10

typedef struct
{
    UINT16              min_conn_int;
    UINT16              max_conn_int;
    UINT16              slave_latency;
    UINT16              supervision_tout;

}tBTM_LE_CONN_PRAMS;


typedef struct
{
    BD_ADDR     bd_addr;
    UINT8       attr;
    BOOLEAN     is_connected;
    BOOLEAN     in_use;
}tBTM_LE_BG_CONN_DEV;

  /* white list using state as a bit mask */
#define BTM_BLE_WL_IDLE         0
#define BTM_BLE_WL_INIT         1
#define BTM_BLE_WL_SCAN         2
#define BTM_BLE_WL_ADV          4
typedef UINT8 tBTM_BLE_WL_STATE;

/* resolving list using state as a bit mask */
#define BTM_BLE_RL_IDLE         0
#define BTM_BLE_RL_INIT         1
#define BTM_BLE_RL_SCAN         2
#define BTM_BLE_RL_ADV          4
typedef UINT8 tBTM_BLE_RL_STATE;

/* BLE connection state */
#define BLE_CONN_IDLE    0
#define BLE_DIR_CONN     1
#define BLE_BG_CONN      2
#define BLE_CONN_CANCEL  3
typedef UINT8 tBTM_BLE_CONN_ST;

typedef struct
{
    void    *p_param;
}tBTM_BLE_CONN_REQ;

/* LE state request */
#define BTM_BLE_STATE_INVALID               0
#define BTM_BLE_STATE_CONN_ADV              1
#define BTM_BLE_STATE_INIT                  2
#define BTM_BLE_STATE_MASTER                3
#define BTM_BLE_STATE_SLAVE                 4
#define BTM_BLE_STATE_LO_DUTY_DIR_ADV       5
#define BTM_BLE_STATE_HI_DUTY_DIR_ADV       6
#define BTM_BLE_STATE_NON_CONN_ADV          7
#define BTM_BLE_STATE_PASSIVE_SCAN          8
#define BTM_BLE_STATE_ACTIVE_SCAN           9
#define BTM_BLE_STATE_SCAN_ADV              10
#define BTM_BLE_STATE_MAX                   11
typedef UINT8 tBTM_BLE_STATE;

#define BTM_BLE_STATE_CONN_ADV_BIT          0x0001
#define BTM_BLE_STATE_INIT_BIT              0x0002
#define BTM_BLE_STATE_MASTER_BIT            0x0004
#define BTM_BLE_STATE_SLAVE_BIT             0x0008
#define BTM_BLE_STATE_LO_DUTY_DIR_ADV_BIT   0x0010
#define BTM_BLE_STATE_HI_DUTY_DIR_ADV_BIT   0x0020
#define BTM_BLE_STATE_NON_CONN_ADV_BIT      0x0040
#define BTM_BLE_STATE_PASSIVE_SCAN_BIT      0x0080
#define BTM_BLE_STATE_ACTIVE_SCAN_BIT       0x0100
#define BTM_BLE_STATE_SCAN_ADV_BIT          0x0200
typedef UINT16 tBTM_BLE_STATE_MASK;

#define BTM_BLE_STATE_ALL_MASK              0x03ff
#define BTM_BLE_STATE_ALL_ADV_MASK          (BTM_BLE_STATE_CONN_ADV_BIT|BTM_BLE_STATE_LO_DUTY_DIR_ADV_BIT|BTM_BLE_STATE_HI_DUTY_DIR_ADV_BIT|BTM_BLE_STATE_SCAN_ADV_BIT)
#define BTM_BLE_STATE_ALL_SCAN_MASK         (BTM_BLE_STATE_PASSIVE_SCAN_BIT|BTM_BLE_STATE_ACTIVE_SCAN_BIT)
#define BTM_BLE_STATE_ALL_CONN_MASK         (BTM_BLE_STATE_MASTER_BIT|BTM_BLE_STATE_SLAVE_BIT)

#ifndef BTM_LE_RESOLVING_LIST_MAX
#define BTM_LE_RESOLVING_LIST_MAX     0x20
#endif

typedef struct
{
    BD_ADDR         *resolve_q_random_pseudo;
    UINT8           *resolve_q_action;
    UINT8           q_next;
    UINT8           q_pending;
} tBTM_BLE_RESOLVE_Q;

typedef struct
{
    BOOLEAN     in_use;
    BOOLEAN     to_add;
    BD_ADDR     bd_addr;
    UINT8       attr;
}tBTM_BLE_WL_OP;

/* BLE privacy mode */
#define BTM_PRIVACY_NONE    0              /* BLE no privacy */
#define BTM_PRIVACY_1_1     1              /* BLE privacy 1.1, do not support privacy 1.0 */
#define BTM_PRIVACY_1_2     2              /* BLE privacy 1.2 */
#define BTM_PRIVACY_MIXED   3              /* BLE privacy mixed mode, broadcom propietary mode */
typedef UINT8 tBTM_PRIVACY_MODE;

/* data length change event callback */
typedef void (tBTM_DATA_LENGTH_CHANGE_CBACK) (UINT16 max_tx_length, UINT16 max_rx_length);

/* Define BLE Device Management control structure
*/
typedef struct
{
    UINT8 scan_activity;         /* LE scan activity mask */

    /*****************************************************
    **      BLE Inquiry
    *****************************************************/
    tBTM_BLE_INQ_CB inq_var;

    /* observer callback and timer */
    tBTM_INQ_RESULTS_CB *p_obs_results_cb;
    tBTM_CMPL_CB *p_obs_cmpl_cb;
    alarm_t *observer_timer;

    /* background connection procedure cb value */
    tBTM_BLE_CONN_TYPE bg_conn_type;
    UINT32 scan_int;
    UINT32 scan_win;
    tBTM_BLE_SEL_CBACK *p_select_cback;

    /* white list information */
    UINT8 white_list_avail_size;
    tBTM_BLE_WL_STATE wl_state;

    fixed_queue_t *conn_pending_q;
    tBTM_BLE_CONN_ST conn_state;

    /* random address management control block */
    tBTM_LE_RANDOM_CB addr_mgnt_cb;

    BOOLEAN enabled;

#if BLE_PRIVACY_SPT == TRUE
    BOOLEAN mixed_mode; /* privacy 1.2 mixed mode is on or not */
    tBTM_PRIVACY_MODE privacy_mode; /* privacy mode */
    UINT8 resolving_list_avail_size; /* resolving list available size */
    tBTM_BLE_RESOLVE_Q resolving_list_pend_q; /* Resolving list queue */
    tBTM_BLE_RL_STATE suspended_rl_state; /* Suspended resolving list state */
    UINT8 *irk_list_mask; /* IRK list availability mask, up to max entry bits */
    tBTM_BLE_RL_STATE rl_state; /* Resolving list state */
#endif

    tBTM_BLE_WL_OP wl_op_q[BTM_BLE_MAX_BG_CONN_DEV_NUM];

    /* current BLE link state */
    tBTM_BLE_STATE_MASK cur_states; /* bit mask of tBTM_BLE_STATE */
    UINT8 link_count[2]; /* total link count master and slave*/
} tBTM_BLE_CB;

#ifdef __cplusplus
}
#endif

#endif // BTM_BLE_INT_TYPES_H
