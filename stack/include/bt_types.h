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

#ifndef BT_TYPES_H
#define BT_TYPES_H

#include <stdbool.h>
#include <stdint.h>
#ifdef __cplusplus
#include <string>
#endif  // __cplusplus

#ifndef FALSE
#define FALSE false
#endif

#ifndef TRUE
#define TRUE true
#endif

#ifdef __arm
#define PACKED __packed
#define INLINE __inline
#else
#define PACKED
#define INLINE
#endif

/* READ WELL !!
 *
 * This section defines global events. These are events that cross layers.
 * Any event that passes between layers MUST be one of these events. Tasks
 * can use their own events internally, but a FUNDAMENTAL design issue is
 * that global events MUST be one of these events defined below.
 *
 * The convention used is the the event name contains the layer that the
 * event is going to.
 */
#define BT_EVT_MASK 0xFF00
#define BT_SUB_EVT_MASK 0x00FF
/* To Bluetooth Upper Layers        */
/************************************/
/* L2CAP event */
#define BT_EVT_TO_BTU_L2C_EVT 0x0900
/* HCI Event                        */
#define BT_EVT_TO_BTU_HCI_EVT 0x1000
/* event from BR/EDR controller */
#define BT_EVT_TO_BTU_HCI_BR_EDR_EVT (0x0000 | BT_EVT_TO_BTU_HCI_EVT)
/* event from local AMP 1 controller */
#define BT_EVT_TO_BTU_HCI_AMP1_EVT (0x0001 | BT_EVT_TO_BTU_HCI_EVT)
/* event from local AMP 2 controller */
#define BT_EVT_TO_BTU_HCI_AMP2_EVT (0x0002 | BT_EVT_TO_BTU_HCI_EVT)
/* event from local AMP 3 controller */
#define BT_EVT_TO_BTU_HCI_AMP3_EVT (0x0003 | BT_EVT_TO_BTU_HCI_EVT)

/* ACL Data from HCI                */
#define BT_EVT_TO_BTU_HCI_ACL 0x1100
/* SCO Data from HCI                */
#define BT_EVT_TO_BTU_HCI_SCO 0x1200
/* HCI Transport Error              */
#define BT_EVT_TO_BTU_HCIT_ERR 0x1300

/* Serial Port Event                */
#define BT_EVT_TO_BTU_SP_EVT 0x1400
/* Serial Port Data                 */
#define BT_EVT_TO_BTU_SP_DATA 0x1500

/* HCI command from upper layer     */
#define BT_EVT_TO_BTU_HCI_CMD 0x1600

/* ISO Data from HCI                */
#define BT_EVT_TO_BTU_HCI_ISO 0x1700

/* L2CAP segment(s) transmitted     */
#define BT_EVT_TO_BTU_L2C_SEG_XMIT 0x1900

/* BlueStackTester event: incoming message from target */
#define BT_EVT_PROXY_INCOMING_MSG 0x1A00

/* Insight BTSIM event */
#define BT_EVT_BTSIM 0x1B00
/* Insight Script Engine event */
#define BT_EVT_BTISE 0x1C00

/* To LM                            */
/************************************/
/* HCI Command                      */
#define BT_EVT_TO_LM_HCI_CMD 0x2000
/* HCI ACL Data                     */
#define BT_EVT_TO_LM_HCI_ACL 0x2100
/* HCI SCO Data                     */
#define BT_EVT_TO_LM_HCI_SCO 0x2200
/* HCI Transport Error              */
#define BT_EVT_TO_LM_HCIT_ERR 0x2300
/* LC event                         */
#define BT_EVT_TO_LM_LC_EVT 0x2400
/* LC Received LMP command frame    */
#define BT_EVT_TO_LM_LC_LMP 0x2500
/* LC Received ACL data             */
#define BT_EVT_TO_LM_LC_ACL 0x2600
/* LC Received SCO data  (not used) */
#define BT_EVT_TO_LM_LC_SCO 0x2700
/* LMP data transmit complete       */
#define BT_EVT_TO_LM_LC_ACL_TX 0x2800
/* LMP Command transmit complete    */
#define BT_EVT_TO_LM_LC_LMPC_TX 0x2900
/* Data to be locally loopbacked    */
#define BT_EVT_TO_LM_LOCAL_ACL_LB 0x2a00
/* HCI ACL Data ack      (not used) */
#define BT_EVT_TO_LM_HCI_ACL_ACK 0x2b00
/* LM Diagnostics commands          */
#define BT_EVT_TO_LM_DIAG 0x2c00
/* HCI ISO Data                     */
#define BT_EVT_TO_LM_HCI_ISO 0x2d00

#define BT_EVT_TO_BTM_CMDS 0x2f00
#define BT_EVT_TO_BTM_PM_MDCHG_EVT (0x0001 | BT_EVT_TO_BTM_CMDS)

#define BT_EVT_TO_TCS_CMDS 0x3000

#define BT_EVT_TO_CTP_CMDS 0x3300

/* ftp events */
#define BT_EVT_TO_FTP_SRVR_CMDS 0x3600
#define BT_EVT_TO_FTP_CLNT_CMDS 0x3700

/* SIM Access Profile events */
#define BT_EVT_TO_BTU_SAP 0x3800

/* opp events */
#define BT_EVT_TO_OPP_SRVR_CMDS 0x3900
#define BT_EVT_TO_OPP_CLNT_CMDS 0x3a00

/* for NFC                          */
/************************************/
/* NCI Command, Notification or Data*/
#define BT_EVT_TO_NFC_NCI 0x4000
/* Initialization message */
#define BT_EVT_TO_NFC_INIT 0x4100
/* Low power */
#define BT_EVT_TO_NCI_LP 0x4200
/* Error notification to NFC Task */
#define BT_EVT_TO_NFC_ERR 0x4300

/* events to NFCC simulation (NCI packets) */
#define BT_EVT_TO_NFCCSIM_NCI 0x4a00

/* HCISU Events */

#define BT_EVT_HCISU 0x5000

#define BT_EVT_TO_HCISU_RECONFIG_EVT (0x0001 | BT_EVT_HCISU)
#define BT_EVT_TO_HCISU_UPDATE_BAUDRATE_EVT (0x0002 | BT_EVT_HCISU)
#define BT_EVT_TO_HCISU_LP_ENABLE_EVT (0x0003 | BT_EVT_HCISU)
#define BT_EVT_TO_HCISU_LP_DISABLE_EVT (0x0004 | BT_EVT_HCISU)
#define BT_EVT_TO_HCISU_LP_APP_SLEEPING_EVT (0x0005 | BT_EVT_HCISU)
#define BT_EVT_TO_HCISU_LP_ALLOW_BT_SLEEP_EVT (0x0006 | BT_EVT_HCISU)
#define BT_EVT_TO_HCISU_LP_WAKEUP_HOST_EVT (0x0007 | BT_EVT_HCISU)
#define BT_EVT_TO_HCISU_LP_RCV_H4IBSS_EVT (0x0008 | BT_EVT_HCISU)
#define BT_EVT_TO_HCISU_H5_RESET_EVT (0x0009 | BT_EVT_HCISU)
#define BT_EVT_HCISU_START_QUICK_TIMER (0x000a | BT_EVT_HCISU)

#define BT_EVT_DATA_TO_AMP_1 0x5100
#define BT_EVT_DATA_TO_AMP_15 0x5f00

/* HSP Events */

#define BT_EVT_BTU_HSP2 0x6000

#define BT_EVT_TO_BTU_HSP2_EVT (0x0001 | BT_EVT_BTU_HSP2)

/* BPP Events */
#define BT_EVT_TO_BPP_PR_CMDS 0x6100  /* Printer Events */
#define BT_EVT_TO_BPP_SND_CMDS 0x6200 /* BPP Sender Events */

/* BIP Events */
#define BT_EVT_TO_BIP_CMDS 0x6300

/* HCRP Events */

#define BT_EVT_BTU_HCRP 0x7000

#define BT_EVT_TO_BTU_HCRP_EVT (0x0001 | BT_EVT_BTU_HCRP)
#define BT_EVT_TO_BTU_HCRPM_EVT (0x0002 | BT_EVT_BTU_HCRP)

#define BT_EVT_BTU_HFP 0x8000
#define BT_EVT_TO_BTU_HFP_EVT (0x0001 | BT_EVT_BTU_HFP)

#define BT_EVT_BTU_IPC_EVT 0x9000
#define BT_EVT_BTU_IPC_LOGMSG_EVT (0x0000 | BT_EVT_BTU_IPC_EVT)
#define BT_EVT_BTU_IPC_ACL_EVT (0x0001 | BT_EVT_BTU_IPC_EVT)
#define BT_EVT_BTU_IPC_BTU_EVT (0x0002 | BT_EVT_BTU_IPC_EVT)
#define BT_EVT_BTU_IPC_L2C_EVT (0x0003 | BT_EVT_BTU_IPC_EVT)
#define BT_EVT_BTU_IPC_L2C_MSG_EVT (0x0004 | BT_EVT_BTU_IPC_EVT)
#define BT_EVT_BTU_IPC_BTM_EVT (0x0005 | BT_EVT_BTU_IPC_EVT)
#define BT_EVT_BTU_IPC_AVDT_EVT (0x0006 | BT_EVT_BTU_IPC_EVT)
#define BT_EVT_BTU_IPC_SLIP_EVT (0x0007 | BT_EVT_BTU_IPC_EVT)
#define BT_EVT_BTU_IPC_MGMT_EVT (0x0008 | BT_EVT_BTU_IPC_EVT)
#define BT_EVT_BTU_IPC_BTTRC_EVT (0x0009 | BT_EVT_BTU_IPC_EVT)
#define BT_EVT_BTU_IPC_BURST_EVT (0x000A | BT_EVT_BTU_IPC_EVT)

/* BTIF Events */
#define BT_EVT_BTIF 0xA000
#define BT_EVT_CONTEXT_SWITCH_EVT (0x0001 | BT_EVT_BTIF)

/* ISO Layer specific */
#define BT_ISO_HDR_CONTAINS_TS (0x0001)
#define BT_ISO_HDR_OFFSET_POINTS_DATA (0x0002)

/* Define the header of each buffer used in the Bluetooth stack.
 */
typedef struct {
  uint16_t event;
  uint16_t len;
  uint16_t offset;
  uint16_t layer_specific;
  uint8_t data[];
} BT_HDR;

#define BT_HDR_SIZE (sizeof(BT_HDR))

#define BT_PSM_SDP 0x0001
#define BT_PSM_RFCOMM 0x0003
#define BT_PSM_TCS 0x0005
#define BT_PSM_CTP 0x0007
#define BT_PSM_BNEP 0x000F
#define BT_PSM_HIDC 0x0011
#define BT_PSM_HIDI 0x0013
#define BT_PSM_UPNP 0x0015
#define BT_PSM_AVCTP 0x0017
#define BT_PSM_AVDTP 0x0019
#define BT_PSM_AVCTP_13 0x001B /* Advanced Control - Browsing */
#define BT_PSM_UDI_CP \
  0x001D /* Unrestricted Digital Information Profile C-Plane  */
#define BT_PSM_ATT 0x001F /* Attribute Protocol  */
#define BT_PSM_EATT 0x0027

/* These macros extract the HCI opcodes from a buffer
 */
#define HCI_GET_CMD_HDR_OPCODE(p)                    \
  (uint16_t)((*((uint8_t*)((p) + 1) + (p)->offset) + \
              (*((uint8_t*)((p) + 1) + (p)->offset + 1) << 8)))
#define HCI_GET_CMD_HDR_PARAM_LEN(p) \
  (uint8_t)(*((uint8_t*)((p) + 1) + (p)->offset + 2))

#define HCI_GET_EVT_HDR_OPCODE(p) \
  (uint8_t)(*((uint8_t*)((p) + 1) + (p)->offset))
#define HCI_GET_EVT_HDR_PARAM_LEN(p) \
  (uint8_t)(*((uint8_t*)((p) + 1) + (p)->offset + 1))

/*******************************************************************************
 * Macros to get and put bytes to and from a stream (Little Endian format).
 */
#define UINT64_TO_BE_STREAM(p, u64)  \
  {                                  \
    *(p)++ = (uint8_t)((u64) >> 56); \
    *(p)++ = (uint8_t)((u64) >> 48); \
    *(p)++ = (uint8_t)((u64) >> 40); \
    *(p)++ = (uint8_t)((u64) >> 32); \
    *(p)++ = (uint8_t)((u64) >> 24); \
    *(p)++ = (uint8_t)((u64) >> 16); \
    *(p)++ = (uint8_t)((u64) >> 8);  \
    *(p)++ = (uint8_t)(u64);         \
  }
#define UINT32_TO_STREAM(p, u32)     \
  {                                  \
    *(p)++ = (uint8_t)(u32);         \
    *(p)++ = (uint8_t)((u32) >> 8);  \
    *(p)++ = (uint8_t)((u32) >> 16); \
    *(p)++ = (uint8_t)((u32) >> 24); \
  }
#define UINT24_TO_STREAM(p, u24)     \
  {                                  \
    *(p)++ = (uint8_t)(u24);         \
    *(p)++ = (uint8_t)((u24) >> 8);  \
    *(p)++ = (uint8_t)((u24) >> 16); \
  }
#define UINT16_TO_STREAM(p, u16)    \
  {                                 \
    *(p)++ = (uint8_t)(u16);        \
    *(p)++ = (uint8_t)((u16) >> 8); \
  }
#define UINT8_TO_STREAM(p, u8) \
  { *(p)++ = (uint8_t)(u8); }
#define INT8_TO_STREAM(p, u8) \
  { *(p)++ = (int8_t)(u8); }
#define ARRAY32_TO_STREAM(p, a)                                     \
  {                                                                 \
    int ijk;                                                        \
    for (ijk = 0; ijk < 32; ijk++) *(p)++ = (uint8_t)(a)[31 - ijk]; \
  }
#define ARRAY16_TO_STREAM(p, a)                                     \
  {                                                                 \
    int ijk;                                                        \
    for (ijk = 0; ijk < 16; ijk++) *(p)++ = (uint8_t)(a)[15 - ijk]; \
  }
#define ARRAY8_TO_STREAM(p, a)                                    \
  {                                                               \
    int ijk;                                                      \
    for (ijk = 0; ijk < 8; ijk++) *(p)++ = (uint8_t)(a)[7 - ijk]; \
  }
#define LAP_TO_STREAM(p, a)                     \
  {                                             \
    int ijk;                                    \
    for (ijk = 0; ijk < LAP_LEN; ijk++)         \
      *(p)++ = (uint8_t)(a)[LAP_LEN - 1 - ijk]; \
  }
#define DEVCLASS_TO_STREAM(p, a)                      \
  {                                                   \
    int ijk;                                          \
    for (ijk = 0; ijk < DEV_CLASS_LEN; ijk++)         \
      *(p)++ = (uint8_t)(a)[DEV_CLASS_LEN - 1 - ijk]; \
  }
#define ARRAY_TO_STREAM(p, a, len)                                \
  {                                                               \
    int ijk;                                                      \
    for (ijk = 0; ijk < (len); ijk++) *(p)++ = (uint8_t)(a)[ijk]; \
  }
#define REVERSE_ARRAY_TO_STREAM(p, a, len)                                  \
  {                                                                         \
    int ijk;                                                                \
    for (ijk = 0; ijk < (len); ijk++) *(p)++ = (uint8_t)(a)[(len)-1 - ijk]; \
  }

#define STREAM_TO_INT8(u8, p)   \
  {                             \
    (u8) = (*((int8_t*)(p)));   \
    (p) += 1;                   \
  }
#define STREAM_TO_UINT8(u8, p) \
  {                            \
    (u8) = (uint8_t)(*(p));    \
    (p) += 1;                  \
  }
#define STREAM_TO_UINT16(u16, p)                                  \
  {                                                               \
    (u16) = ((uint16_t)(*(p)) + (((uint16_t)(*((p) + 1))) << 8)); \
    (p) += 2;                                                     \
  }
#define STREAM_TO_UINT24(u32, p)                                      \
  {                                                                   \
    (u32) = (((uint32_t)(*(p))) + ((((uint32_t)(*((p) + 1)))) << 8) + \
             ((((uint32_t)(*((p) + 2)))) << 16));                     \
    (p) += 3;                                                         \
  }
#define STREAM_TO_UINT32(u32, p)                                      \
  {                                                                   \
    (u32) = (((uint32_t)(*(p))) + ((((uint32_t)(*((p) + 1)))) << 8) + \
             ((((uint32_t)(*((p) + 2)))) << 16) +                     \
             ((((uint32_t)(*((p) + 3)))) << 24));                     \
    (p) += 4;                                                         \
  }
#define STREAM_TO_UINT64(u64, p)                                      \
  {                                                                   \
    (u64) = (((uint64_t)(*(p))) + ((((uint64_t)(*((p) + 1)))) << 8) + \
             ((((uint64_t)(*((p) + 2)))) << 16) +                     \
             ((((uint64_t)(*((p) + 3)))) << 24) +                     \
             ((((uint64_t)(*((p) + 4)))) << 32) +                     \
             ((((uint64_t)(*((p) + 5)))) << 40) +                     \
             ((((uint64_t)(*((p) + 6)))) << 48) +                     \
             ((((uint64_t)(*((p) + 7)))) << 56));                     \
    (p) += 8;                                                         \
  }
#define STREAM_TO_ARRAY32(a, p)                     \
  {                                                 \
    int ijk;                                        \
    uint8_t* _pa = (uint8_t*)(a) + 31;              \
    for (ijk = 0; ijk < 32; ijk++) *_pa-- = *(p)++; \
  }
#define STREAM_TO_ARRAY16(a, p)                     \
  {                                                 \
    int ijk;                                        \
    uint8_t* _pa = (uint8_t*)(a) + 15;              \
    for (ijk = 0; ijk < 16; ijk++) *_pa-- = *(p)++; \
  }
#define STREAM_TO_ARRAY8(a, p)                     \
  {                                                \
    int ijk;                                       \
    uint8_t* _pa = (uint8_t*)(a) + 7;              \
    for (ijk = 0; ijk < 8; ijk++) *_pa-- = *(p)++; \
  }
#define STREAM_TO_DEVCLASS(a, p)                               \
  {                                                            \
    int ijk;                                                   \
    uint8_t* _pa = (uint8_t*)(a) + DEV_CLASS_LEN - 1;          \
    for (ijk = 0; ijk < DEV_CLASS_LEN; ijk++) *_pa-- = *(p)++; \
  }
#define STREAM_TO_LAP(a, p)                               \
  {                                                       \
    int ijk;                                              \
    uint8_t* plap = (uint8_t*)(a) + LAP_LEN - 1;          \
    for (ijk = 0; ijk < LAP_LEN; ijk++) *plap-- = *(p)++; \
  }
#define STREAM_TO_ARRAY(a, p, len)                                   \
  {                                                                  \
    int ijk;                                                         \
    for (ijk = 0; ijk < (len); ijk++) ((uint8_t*)(a))[ijk] = *(p)++; \
  }
#define REVERSE_STREAM_TO_ARRAY(a, p, len)             \
  {                                                    \
    int ijk;                                           \
    uint8_t* _pa = (uint8_t*)(a) + (len)-1;            \
    for (ijk = 0; ijk < (len); ijk++) *_pa-- = *(p)++; \
  }

#define STREAM_SKIP_UINT8(p) \
  do {                       \
    (p) += 1;                \
  } while (0)
#define STREAM_SKIP_UINT16(p) \
  do {                        \
    (p) += 2;                 \
  } while (0)
#define STREAM_SKIP_UINT32(p) \
  do {                        \
    (p) += 4;                 \
  } while (0)

/*******************************************************************************
 * Macros to get and put bytes to and from a field (Little Endian format).
 * These are the same as to stream, except the pointer is not incremented.
 */
#define UINT32_TO_FIELD(p, u32)                    \
  {                                                \
    *(uint8_t*)(p) = (uint8_t)(u32);               \
    *((uint8_t*)(p) + 1) = (uint8_t)((u32) >> 8);  \
    *((uint8_t*)(p) + 2) = (uint8_t)((u32) >> 16); \
    *((uint8_t*)(p) + 3) = (uint8_t)((u32) >> 24); \
  }
#define UINT24_TO_FIELD(p, u24)                    \
  {                                                \
    *(uint8_t*)(p) = (uint8_t)(u24);               \
    *((uint8_t*)(p) + 1) = (uint8_t)((u24) >> 8);  \
    *((uint8_t*)(p) + 2) = (uint8_t)((u24) >> 16); \
  }
#define UINT16_TO_FIELD(p, u16)                   \
  {                                               \
    *(uint8_t*)(p) = (uint8_t)(u16);              \
    *((uint8_t*)(p) + 1) = (uint8_t)((u16) >> 8); \
  }
#define UINT8_TO_FIELD(p, u8) \
  { *(uint8_t*)(p) = (uint8_t)(u8); }

/*******************************************************************************
 * Macros to get and put bytes to and from a stream (Big Endian format)
 */
#define UINT32_TO_BE_STREAM(p, u32)  \
  {                                  \
    *(p)++ = (uint8_t)((u32) >> 24); \
    *(p)++ = (uint8_t)((u32) >> 16); \
    *(p)++ = (uint8_t)((u32) >> 8);  \
    *(p)++ = (uint8_t)(u32);         \
  }
#define UINT24_TO_BE_STREAM(p, u24)  \
  {                                  \
    *(p)++ = (uint8_t)((u24) >> 16); \
    *(p)++ = (uint8_t)((u24) >> 8);  \
    *(p)++ = (uint8_t)(u24);         \
  }
#define UINT16_TO_BE_STREAM(p, u16) \
  {                                 \
    *(p)++ = (uint8_t)((u16) >> 8); \
    *(p)++ = (uint8_t)(u16);        \
  }
#define UINT8_TO_BE_STREAM(p, u8) \
  { *(p)++ = (uint8_t)(u8); }
#define ARRAY_TO_BE_STREAM(p, a, len)                             \
  {                                                               \
    int ijk;                                                      \
    for (ijk = 0; ijk < (len); ijk++) *(p)++ = (uint8_t)(a)[ijk]; \
  }
#define ARRAY_TO_BE_STREAM_REVERSE(p, a, len)                               \
  {                                                                         \
    int ijk;                                                                \
    for (ijk = 0; ijk < (len); ijk++) *(p)++ = (uint8_t)(a)[(len)-ijk - 1]; \
  }

#define BE_STREAM_TO_UINT8(u8, p) \
  {                               \
    (u8) = (uint8_t)(*(p));       \
    (p) += 1;                     \
  }
#define BE_STREAM_TO_UINT16(u16, p)                                       \
  {                                                                       \
    (u16) = (uint16_t)(((uint16_t)(*(p)) << 8) + (uint16_t)(*((p) + 1))); \
    (p) += 2;                                                             \
  }
#define BE_STREAM_TO_UINT24(u32, p)                                     \
  {                                                                     \
    (u32) = (((uint32_t)(*((p) + 2))) + ((uint32_t)(*((p) + 1)) << 8) + \
             ((uint32_t)(*(p)) << 16));                                 \
    (p) += 3;                                                           \
  }
#define BE_STREAM_TO_UINT32(u32, p)                                      \
  {                                                                      \
    (u32) = ((uint32_t)(*((p) + 3)) + ((uint32_t)(*((p) + 2)) << 8) +    \
             ((uint32_t)(*((p) + 1)) << 16) + ((uint32_t)(*(p)) << 24)); \
    (p) += 4;                                                            \
  }
#define BE_STREAM_TO_UINT64(u64, p)                                            \
  {                                                                            \
    (u64) = ((uint64_t)(*((p) + 7)) + ((uint64_t)(*((p) + 6)) << 8) +          \
             ((uint64_t)(*((p) + 5)) << 16) + ((uint64_t)(*((p) + 4)) << 24) + \
             ((uint64_t)(*((p) + 3)) << 32) + ((uint64_t)(*((p) + 2)) << 40) + \
             ((uint64_t)(*((p) + 1)) << 48) + ((uint64_t)(*(p)) << 56));       \
    (p) += 8;                                                                  \
  }
#define BE_STREAM_TO_ARRAY(p, a, len)                                \
  {                                                                  \
    int ijk;                                                         \
    for (ijk = 0; ijk < (len); ijk++) ((uint8_t*)(a))[ijk] = *(p)++; \
  }

/*******************************************************************************
 * Macros to get and put bytes to and from a field (Big Endian format).
 * These are the same as to stream, except the pointer is not incremented.
 */
#define UINT32_TO_BE_FIELD(p, u32)                 \
  {                                                \
    *(uint8_t*)(p) = (uint8_t)((u32) >> 24);       \
    *((uint8_t*)(p) + 1) = (uint8_t)((u32) >> 16); \
    *((uint8_t*)(p) + 2) = (uint8_t)((u32) >> 8);  \
    *((uint8_t*)(p) + 3) = (uint8_t)(u32);         \
  }
#define UINT24_TO_BE_FIELD(p, u24)                \
  {                                               \
    *(uint8_t*)(p) = (uint8_t)((u24) >> 16);      \
    *((uint8_t*)(p) + 1) = (uint8_t)((u24) >> 8); \
    *((uint8_t*)(p) + 2) = (uint8_t)(u24);        \
  }
#define UINT16_TO_BE_FIELD(p, u16)          \
  {                                         \
    *(uint8_t*)(p) = (uint8_t)((u16) >> 8); \
    *((uint8_t*)(p) + 1) = (uint8_t)(u16);  \
  }
#define UINT8_TO_BE_FIELD(p, u8) \
  { *(uint8_t*)(p) = (uint8_t)(u8); }

/* Common Bluetooth field definitions */
#define BD_ADDR_LEN 6 /* Device address length */

#ifdef __cplusplus
#include <bluetooth/uuid.h>
#include <include/hardware/bluetooth.h>

inline void BDADDR_TO_STREAM(uint8_t*& p, const RawAddress& a) {
  for (int ijk = 0; ijk < BD_ADDR_LEN; ijk++)
    *(p)++ = (uint8_t)(a.address)[BD_ADDR_LEN - 1 - ijk];
}

inline void STREAM_TO_BDADDR(RawAddress& a, uint8_t*& p) {
  uint8_t* pbda = (uint8_t*)(a.address) + BD_ADDR_LEN - 1;
  for (int ijk = 0; ijk < BD_ADDR_LEN; ijk++) *pbda-- = *(p)++;
}

#endif

#define BT_OCTET8_LEN 8
typedef uint8_t BT_OCTET8[BT_OCTET8_LEN]; /* octet array: size 16 */

/* Some C files include this header file */
#ifdef __cplusplus

#include <array>

constexpr int OCTET16_LEN = 16;
typedef std::array<uint8_t, OCTET16_LEN> Octet16;

constexpr int LINK_KEY_LEN = OCTET16_LEN;
typedef Octet16 LinkKey; /* Link Key */

/* Sample LTK from BT Spec 5.1 | Vol 6, Part C 1
 * 0x4C68384139F574D836BCF34E9DFB01BF */
constexpr Octet16 SAMPLE_LTK = {0xbf, 0x01, 0xfb, 0x9d, 0x4e, 0xf3, 0xbc, 0x36,
                                0xd8, 0x74, 0xf5, 0x39, 0x41, 0x38, 0x68, 0x4c};
inline bool is_sample_ltk(const Octet16& ltk) { return ltk == SAMPLE_LTK; }

#endif

#define PIN_CODE_LEN 16
typedef uint8_t PIN_CODE[PIN_CODE_LEN]; /* Pin Code (upto 128 bits) MSB is 0 */

#define BT_OCTET32_LEN 32
typedef uint8_t BT_OCTET32[BT_OCTET32_LEN]; /* octet array: size 32 */

#define DEV_CLASS_LEN 3
typedef uint8_t DEV_CLASS[DEV_CLASS_LEN]; /* Device class */

#define EXT_INQ_RESP_LEN 3
typedef uint8_t EXT_INQ_RESP[EXT_INQ_RESP_LEN]; /* Extended Inquiry Response */

#define BD_NAME_LEN 248
typedef uint8_t BD_NAME[BD_NAME_LEN + 1]; /* Device name */

#define BD_FEATURES_LEN 8
typedef uint8_t
    BD_FEATURES[BD_FEATURES_LEN]; /* LMP features supported by device */

#ifdef __cplusplus
// Bit order [0]:0-7 [1]:8-15 ... [7]:56-63
inline std::string bd_features_text(BD_FEATURES features) {
  uint8_t len = BD_FEATURES_LEN;
  char buf[255];
  char* pbuf = buf;
  uint8_t* b = features;
  while (len--) {
    pbuf += sprintf(pbuf, "0x%02x ", *b++);
  }
  return std::string(buf);
}
#endif  // __cplusplus

#define BT_EVENT_MASK_LEN 8
typedef uint8_t BT_EVENT_MASK[BT_EVENT_MASK_LEN]; /* Event Mask */

#define LAP_LEN 3
typedef uint8_t LAP[LAP_LEN];     /* IAC as passed to Inquiry (LAP) */
typedef uint8_t INQ_LAP[LAP_LEN]; /* IAC as passed to Inquiry (LAP) */

#define COF_LEN 12
typedef uint8_t COF[COF_LEN]; /* ciphering offset number */

typedef struct {
  uint8_t qos_flags;          /* TBD */
  uint8_t service_type;       /* see below */
  uint32_t token_rate;        /* bytes/second */
  uint32_t token_bucket_size; /* bytes */
  uint32_t peak_bandwidth;    /* bytes/second */
  uint32_t latency;           /* microseconds */
  uint32_t delay_variation;   /* microseconds */
} FLOW_SPEC;

/* Values for service_type */
#define SVC_TYPE_BEST_EFFORT 1
#define SVC_TYPE_GUARANTEED 2

#define BT_1SEC_TIMEOUT_MS (1 * 1000) /* 1 second */

#define BT_EIR_FLAGS_TYPE 0x01
#define BT_EIR_MORE_16BITS_UUID_TYPE 0x02
#define BT_EIR_COMPLETE_16BITS_UUID_TYPE 0x03
#define BT_EIR_MORE_32BITS_UUID_TYPE 0x04
#define BT_EIR_COMPLETE_32BITS_UUID_TYPE 0x05
#define BT_EIR_MORE_128BITS_UUID_TYPE 0x06
#define BT_EIR_COMPLETE_128BITS_UUID_TYPE 0x07
#define BT_EIR_SHORTENED_LOCAL_NAME_TYPE 0x08
#define BT_EIR_COMPLETE_LOCAL_NAME_TYPE 0x09
#define BT_EIR_TX_POWER_LEVEL_TYPE 0x0A
#define BT_EIR_OOB_BD_ADDR_TYPE 0x0C
#define BT_EIR_OOB_COD_TYPE 0x0D
#define BT_EIR_OOB_SSP_HASH_C_TYPE 0x0E
#define BT_EIR_OOB_SSP_RAND_R_TYPE 0x0F
#define BT_EIR_SERVICE_DATA_TYPE 0x16
#define BT_EIR_SERVICE_DATA_16BITS_UUID_TYPE 0x16
#define BT_EIR_SERVICE_DATA_32BITS_UUID_TYPE 0x20
#define BT_EIR_SERVICE_DATA_128BITS_UUID_TYPE 0x21
#define BT_EIR_MANUFACTURER_SPECIFIC_TYPE 0xFF

/* We will not allocate a PSM in the reserved range to 3rd party apps
 */
#define BRCM_RESERVED_PSM_START 0x5AE1
#define BRCM_RESERVED_PSM_END 0x5AFF

/*****************************************************************************
 *                          Low Energy definitions
 *
 * Address types
 */
#define BLE_ADDR_PUBLIC 0x00
#define BLE_ADDR_RANDOM 0x01
#define BLE_ADDR_PUBLIC_ID 0x02
#define BLE_ADDR_RANDOM_ID 0x03
#define BLE_ADDR_ANONYMOUS 0xFF
typedef uint8_t tBLE_ADDR_TYPE;
#ifdef __cplusplus
inline std::string AddressTypeText(tBLE_ADDR_TYPE type) {
  switch (type) {
    case BLE_ADDR_PUBLIC:
      return std::string("public");
    case BLE_ADDR_RANDOM:
      return std::string("random");
    case BLE_ADDR_PUBLIC_ID:
      return std::string("public identity");
    case BLE_ADDR_RANDOM_ID:
      return std::string("random identity");
    case BLE_ADDR_ANONYMOUS:
      return std::string("anonymous");
    default:
      return std::string("unknown");
  }
}
#endif  // __cplusplus

/* BLE ADDR type ID bit */
#define BLE_ADDR_TYPE_ID_BIT 0x02

#ifdef __cplusplus
constexpr uint8_t kBleAddressPublicDevice = BLE_ADDR_PUBLIC;
constexpr uint8_t kBleAddressRandomDevice = BLE_ADDR_RANDOM;
constexpr uint8_t kBleAddressIdentityBit = BLE_ADDR_TYPE_ID_BIT;
constexpr uint8_t kBleAddressPublicIdentity =
    kBleAddressIdentityBit | kBleAddressPublicDevice;
constexpr uint8_t kBleAddressRandomIdentity =
    kBleAddressIdentityBit | kBleAddressRandomDevice;

constexpr uint8_t kResolvableAddressMask = 0xc0;
constexpr uint8_t kResolvableAddressMsb = 0x40;

struct tBLE_BD_ADDR {
  tBLE_ADDR_TYPE type;
  RawAddress bda;
  bool AddressEquals(const RawAddress& other) const { return other == bda; }
  bool IsPublicDeviceType() const { return type == kBleAddressPublicDevice; }
  bool IsRandomDeviceType() const { return type == kBleAddressRandomDevice; }
  bool IsPublicIdentityType() const {
    return type == kBleAddressPublicIdentity;
  }
  bool lsRandomIdentityType() const {
    return type == kBleAddressRandomIdentity;
  }
  bool IsAddressResolvable() const {
    return ((bda.address)[0] & kResolvableAddressMask) == kResolvableAddressMsb;
  }
  bool IsPublic() const { return type & 0x01; }
  bool IsResolvablePrivateAddress() const {
    return IsAddressResolvable() && IsRandomDeviceType();
  }
  bool IsIdentityType() const {
    return IsPublicIdentityType() || lsRandomIdentityType();
  }
  bool TypeWithoutIdentityEquals(const tBLE_ADDR_TYPE other) const {
    return (other & ~kBleAddressIdentityBit) ==
           (type & ~kBleAddressIdentityBit);
  }
};
#endif

/* Device Types
 */
enum : uint8_t {
  BT_DEVICE_TYPE_BREDR = (1 << 0),
  BT_DEVICE_TYPE_BLE = (1 << 1),
  BT_DEVICE_TYPE_DUMO = BT_DEVICE_TYPE_BREDR | BT_DEVICE_TYPE_BLE,
};
typedef uint8_t tBT_DEVICE_TYPE;
#ifdef __cplusplus
inline std::string DeviceTypeText(tBT_DEVICE_TYPE type) {
  switch (type) {
    case BT_DEVICE_TYPE_BREDR:
      return std::string("BR_EDR");
    case BT_DEVICE_TYPE_BLE:
      return std::string("BLE");
    case BT_DEVICE_TYPE_DUMO:
      return std::string("BR_EDR and BLE");
    default:
      return std::string("Unknown");
  }
}
#endif  // __cplusplus

/*****************************************************************************/

/* Define trace levels */
#define BT_TRACE_LEVEL_NONE 0    /* No trace messages to be generated    */
#define BT_TRACE_LEVEL_ERROR 1   /* Error condition trace messages       */
#define BT_TRACE_LEVEL_WARNING 2 /* Warning condition trace messages     */
#define BT_TRACE_LEVEL_API 3     /* API traces                           */
#define BT_TRACE_LEVEL_EVENT 4   /* Debug messages for events            */
#define BT_TRACE_LEVEL_DEBUG 5   /* Full debug messages                  */
#define BT_TRACE_LEVEL_VERBOSE 6 /* Verbose debug messages               */

#define TRACE_CTRL_GENERAL 0x00000000

#define TRACE_LAYER_MASK 0x00ff0000
#define TRACE_GET_LAYER(x) ((((uint32_t)(x)) & TRACE_LAYER_MASK) >> 16)

#define TRACE_LAYER_NONE 0x00000000
#define TRACE_LAYER_HCI 0x00070000
#define TRACE_LAYER_L2CAP 0x00080000
#define TRACE_LAYER_RFCOMM 0x00090000
#define TRACE_LAYER_SDP 0x000a0000
#define TRACE_LAYER_BTM 0x000d0000
#define TRACE_LAYER_BNEP 0x001b0000
#define TRACE_LAYER_PAN 0x001c0000
#define TRACE_LAYER_HID 0x001e0000
#define TRACE_LAYER_AVP 0x00200000
#define TRACE_LAYER_A2DP 0x00210000
#define TRACE_LAYER_SMP 0x00260000

#define TRACE_LAYER_MAX_NUM 0x0031

#define TRACE_ORG_MASK 0x0000ff00
#define TRACE_GET_ORG(x) ((((uint32_t)(x)) & TRACE_ORG_MASK) >> 8)

#define TRACE_ORG_STACK 0x00000000
#define TRACE_ORG_APPL 0x00000500
#define TRACE_ORG_USER_SCR 0x00000800

#define TRACE_TYPE_MASK 0x000000ff
#define TRACE_GET_TYPE(x) (((uint32_t)(x)) & TRACE_TYPE_MASK)

#define TRACE_TYPE_ERROR 0x00000000
#define TRACE_TYPE_WARNING 0x00000001
#define TRACE_TYPE_API 0x00000002
#define TRACE_TYPE_EVENT 0x00000003
#define TRACE_TYPE_DEBUG 0x00000004

#define TCS_PSM_INTERCOM 5
#define TCS_PSM_CORDLESS 7
#define BT_PSM_BNEP 0x000F
/* Define PSMs HID uses */
#define HID_PSM_CONTROL 0x0011
#define HID_PSM_INTERRUPT 0x0013

#endif
