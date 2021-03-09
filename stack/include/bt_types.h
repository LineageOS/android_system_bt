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
/* HCI Event                        */
#define BT_EVT_TO_BTU_HCI_EVT 0x1000
/* ACL Data from HCI                */
#define BT_EVT_TO_BTU_HCI_ACL 0x1100
/* SCO Data from HCI                */
#define BT_EVT_TO_BTU_HCI_SCO 0x1200
/* HCI Transport Error              */
#define BT_EVT_TO_BTU_HCIT_ERR 0x1300

/* Serial Port Data                 */
#define BT_EVT_TO_BTU_SP_DATA 0x1500

/* HCI command from upper layer     */
#define BT_EVT_TO_BTU_HCI_CMD 0x1600

/* ISO Data from HCI                */
#define BT_EVT_TO_BTU_HCI_ISO 0x1700

/* L2CAP segment(s) transmitted     */
#define BT_EVT_TO_BTU_L2C_SEG_XMIT 0x1900

/* To LM                            */
/************************************/
/* HCI Command                      */
#define BT_EVT_TO_LM_HCI_CMD 0x2000
/* HCI ACL Data                     */
#define BT_EVT_TO_LM_HCI_ACL 0x2100
/* HCI SCO Data                     */
#define BT_EVT_TO_LM_HCI_SCO 0x2200
/* HCI ISO Data                     */
#define BT_EVT_TO_LM_HCI_ISO 0x2d00

#define BT_EVT_HCISU 0x5000

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

typedef struct {
  uint16_t event;
  uint16_t len;
  uint16_t offset;
  uint16_t layer_specific;
  // Note: Removal of flexible array member with no specified size.
  // This struct may be embedded in any position within other structs
  // and will not trigger various flexible member compilation issues.
} BT_HDR_RIGID;

#define BT_HDR_SIZE (sizeof(BT_HDR))

enum {
  BT_PSM_SDP = 0x0001,
  BT_PSM_RFCOMM = 0x0003,
  BT_PSM_TCS = 0x0005,
  BT_PSM_CTP = 0x0007,
  BT_PSM_BNEP = 0x000F,
  BT_PSM_HIDC = 0x0011,
  HID_PSM_CONTROL = 0x0011,
  BT_PSM_HIDI = 0x0013,
  HID_PSM_INTERRUPT = 0x0013,
  BT_PSM_UPNP = 0x0015,
  BT_PSM_AVCTP = 0x0017,
  BT_PSM_AVDTP = 0x0019,
  BT_PSM_AVCTP_13 = 0x001B, /* Advanced Control - Browsing */
  BT_PSM_UDI_CP =
      0x001D,          /* Unrestricted Digital Information Profile C-Plane  */
  BT_PSM_ATT = 0x001F, /* Attribute Protocol  */
  BT_PSM_EATT = 0x0027,
  /* We will not allocate a PSM in the reserved range to 3rd party apps
   */
  BRCM_RESERVED_PSM_START = 0x5AE1,
  BRCM_RESERVED_PSM_END = 0x5AFF,
};

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
inline std::string bd_features_text(const BD_FEATURES& features) {
  uint8_t len = BD_FEATURES_LEN;
  char buf[255];
  char* pbuf = buf;
  const uint8_t* b = features;
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

/* Device Types
 */
enum {
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

#endif
