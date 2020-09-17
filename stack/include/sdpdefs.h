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

/******************************************************************************
 *
 *  This file contains the definitions for the SDP API
 *
 ******************************************************************************/

#ifndef SDP_DEFS_H
#define SDP_DEFS_H

/* Define the service attribute IDs.
*/
#define ATTR_ID_SERVICE_RECORD_HDL 0x0000
#define ATTR_ID_SERVICE_CLASS_ID_LIST 0x0001
#define ATTR_ID_SERVICE_ID 0x0003
#define ATTR_ID_PROTOCOL_DESC_LIST 0x0004
#define ATTR_ID_BROWSE_GROUP_LIST 0x0005
#define ATTR_ID_LANGUAGE_BASE_ATTR_ID_LIST 0x0006
#define ATTR_ID_BT_PROFILE_DESC_LIST 0x0009
#define ATTR_ID_DOCUMENTATION_URL 0x000A
#define ATTR_ID_CLIENT_EXE_URL 0x000B
#define ATTR_ID_ADDITION_PROTO_DESC_LISTS 0x000D

#define LANGUAGE_BASE_ID 0x0100
#define ATTR_ID_SERVICE_NAME (LANGUAGE_BASE_ID + 0x0000)
#define ATTR_ID_SERVICE_DESCRIPTION (LANGUAGE_BASE_ID + 0x0001)
#define ATTR_ID_PROVIDER_NAME (LANGUAGE_BASE_ID + 0x0002)

/* Device Identification (DI)
*/
#define ATTR_ID_SPECIFICATION_ID 0x0200
#define ATTR_ID_VENDOR_ID 0x0201
#define ATTR_ID_PRODUCT_ID 0x0202
#define ATTR_ID_PRODUCT_VERSION 0x0203
#define ATTR_ID_PRIMARY_RECORD 0x0204
#define ATTR_ID_VENDOR_ID_SOURCE 0x0205

#define BLUETOOTH_DI_SPECIFICATION 0x0103 /* 1.3 */
#define DI_VENDOR_ID_SOURCE_BTSIG 0x0001
#define DI_VENDOR_ID_SOURCE_USBIF 0x0002

#define ATTR_ID_GOEP_L2CAP_PSM 0x0200

#define ATTR_ID_NETWORK 0x0301
#define ATTR_ID_FAX_CLASS_1_SUPPORT 0x0302
#define ATTR_ID_REMOTE_AUDIO_VOLUME_CONTROL 0x0302
#define ATTR_ID_SUPPORTED_FORMATS_LIST 0x0303
#define ATTR_ID_SUPPORTED_FEATURES 0x0311         /* HFP, BIP */
#define ATTR_ID_SUPPORTED_REPOSITORIES 0x0314  /* Phone book access Profile */
#define ATTR_ID_MAS_INSTANCE_ID 0x0315         /* MAP profile */
#define ATTR_ID_SUPPORTED_MSG_TYPE 0x0316      /* MAP profile */
#define ATTR_ID_MAP_SUPPORTED_FEATURES 0x0317  /* MAP profile */
#define ATTR_ID_PBAP_SUPPORTED_FEATURES 0x0317 /* PBAP profile */

/* These values are for the PAN profile */
#define ATTR_ID_SECURITY_DESCRIPTION 0x030A
#define ATTR_ID_NET_ACCESS_TYPE 0x030B
#define ATTR_ID_MAX_NET_ACCESS_RATE 0x030C

/* These values are for HID profile */
#define ATTR_ID_HID_DEVICE_RELNUM 0x0200
#define ATTR_ID_HID_PARSER_VERSION 0x0201
#define ATTR_ID_HID_DEVICE_SUBCLASS 0x0202
#define ATTR_ID_HID_COUNTRY_CODE 0x0203
#define ATTR_ID_HID_VIRTUAL_CABLE 0x0204
#define ATTR_ID_HID_RECONNECT_INITIATE 0x0205
#define ATTR_ID_HID_DESCRIPTOR_LIST 0x0206
#define ATTR_ID_HID_LANGUAGE_ID_BASE 0x0207
#define ATTR_ID_HID_SDP_DISABLE 0x0208
#define ATTR_ID_HID_BATTERY_POWER 0x0209
#define ATTR_ID_HID_REMOTE_WAKE 0x020A
#define ATTR_ID_HID_PROFILE_VERSION 0x020B
#define ATTR_ID_HID_LINK_SUPERVISION_TO 0x020C
#define ATTR_ID_HID_NORMALLY_CONNECTABLE 0x020D
#define ATTR_ID_HID_BOOT_DEVICE 0x020E
#define ATTR_ID_HID_SSR_HOST_MAX_LAT 0x020F
#define ATTR_ID_HID_SSR_HOST_MIN_TOUT 0x0210

/* Define common 16-bit protocol UUIDs
*/
#define UUID_PROTOCOL_RFCOMM 0x0003
#define UUID_PROTOCOL_OBEX 0x0008
#define UUID_PROTOCOL_BNEP 0x000F
#define UUID_PROTOCOL_HIDP 0x0011
#define UUID_PROTOCOL_AVCTP 0x0017
#define UUID_PROTOCOL_AVDTP 0x0019
#define UUID_PROTOCOL_L2CAP 0x0100
#define UUID_PROTOCOL_ATT 0x0007

/* Define common 16-bit service class UUIDs
*/
#define UUID_SERVCLASS_SERVICE_DISCOVERY_SERVER 0X1000
#define UUID_SERVCLASS_BROWSE_GROUP_DESCRIPTOR 0X1001
#define UUID_SERVCLASS_PUBLIC_BROWSE_GROUP 0X1002
#define UUID_SERVCLASS_SERIAL_PORT 0X1101
#define UUID_SERVCLASS_LAN_ACCESS_USING_PPP 0X1102
#define UUID_SERVCLASS_DIALUP_NETWORKING 0X1103
#define UUID_SERVCLASS_IRMC_SYNC 0X1104
#define UUID_SERVCLASS_OBEX_OBJECT_PUSH 0X1105
#define UUID_SERVCLASS_OBEX_FILE_TRANSFER 0X1106
#define UUID_SERVCLASS_IRMC_SYNC_COMMAND 0X1107
#define UUID_SERVCLASS_HEADSET 0X1108
#define UUID_SERVCLASS_CORDLESS_TELEPHONY 0X1109
#define UUID_SERVCLASS_AUDIO_SOURCE 0X110A
#define UUID_SERVCLASS_AUDIO_SINK 0X110B
/* Audio/Video Control profile */
#define UUID_SERVCLASS_AV_REM_CTRL_TARGET 0X110C
/* Advanced Audio Distribution profile */
#define UUID_SERVCLASS_ADV_AUDIO_DISTRIBUTION 0X110D
/* Audio/Video Control profile */
#define UUID_SERVCLASS_AV_REMOTE_CONTROL 0X110E
/* Audio/Video Control profile */
#define UUID_SERVCLASS_AV_REM_CTRL_CONTROL 0X110F
#define UUID_SERVCLASS_INTERCOM 0X1110
#define UUID_SERVCLASS_FAX 0X1111
#define UUID_SERVCLASS_HEADSET_AUDIO_GATEWAY 0X1112
#define UUID_SERVCLASS_WAP 0X1113
#define UUID_SERVCLASS_WAP_CLIENT 0X1114
#define UUID_SERVCLASS_PANU 0X1115                    /* PAN profile */
#define UUID_SERVCLASS_NAP 0X1116                     /* PAN profile */
#define UUID_SERVCLASS_GN 0X1117                      /* PAN profile */
#define UUID_SERVCLASS_DIRECT_PRINTING 0X1118         /* BPP profile */
#define UUID_SERVCLASS_REFERENCE_PRINTING 0X1119      /* BPP profile */
#define UUID_SERVCLASS_IMAGING 0X111A                 /* Imaging profile */
#define UUID_SERVCLASS_IMAGING_RESPONDER 0X111B       /* Imaging profile */
#define UUID_SERVCLASS_IMAGING_AUTO_ARCHIVE 0X111C    /* Imaging profile */
#define UUID_SERVCLASS_IMAGING_REF_OBJECTS 0X111D     /* Imaging profile */
#define UUID_SERVCLASS_HF_HANDSFREE 0X111E            /* Handsfree profile */
#define UUID_SERVCLASS_AG_HANDSFREE 0X111F            /* Handsfree profile */
#define UUID_SERVCLASS_DIR_PRT_REF_OBJ_SERVICE 0X1120 /* BPP profile */
#define UUID_SERVCLASS_REFLECTED_UI 0X1121            /* BPP profile */
#define UUID_SERVCLASS_BASIC_PRINTING 0X1122          /* BPP profile */
#define UUID_SERVCLASS_PRINTING_STATUS 0X1123         /* BPP profile */
#define UUID_SERVCLASS_HUMAN_INTERFACE 0X1124         /* HID profile */
#define UUID_SERVCLASS_CABLE_REPLACEMENT 0X1125       /* HCRP profile */
#define UUID_SERVCLASS_HCRP_PRINT 0X1126              /* HCRP profile */
#define UUID_SERVCLASS_HCRP_SCAN 0X1127               /* HCRP profile */
/* CAPI Message Transport Protocol*/
#define UUID_SERVCLASS_COMMON_ISDN_ACCESS 0X1128
/* Video Conferencing profile */
#define UUID_SERVCLASS_VIDEO_CONFERENCING_GW 0X1129
/* Unrestricted Digital Information profile */
#define UUID_SERVCLASS_UDI_MT 0X112A
/* Unrestricted Digital Information profile */
#define UUID_SERVCLASS_UDI_TA 0X112B
#define UUID_SERVCLASS_VCP 0X112C      /* Video Conferencing profile */
#define UUID_SERVCLASS_SAP 0X112D      /* SIM Access profile */
#define UUID_SERVCLASS_PBAP_PCE 0X112E /* Phonebook Access - PCE */
#define UUID_SERVCLASS_PBAP_PSE 0X112F /* Phonebook Access - PSE */
#define UUID_SERVCLASS_PHONE_ACCESS 0x1130
#define UUID_SERVCLASS_HEADSET_HS 0x1131      /* Headset - HS, from HSP v1.2 */
#define UUID_SERVCLASS_PNP_INFORMATION 0X1200 /* Device Identification */
#define UUID_SERVCLASS_GENERIC_NETWORKING 0X1201
#define UUID_SERVCLASS_GENERIC_FILETRANSFER 0X1202
#define UUID_SERVCLASS_GENERIC_AUDIO 0X1203
#define UUID_SERVCLASS_GENERIC_TELEPHONY 0X1204
#define UUID_SERVCLASS_UPNP_SERVICE 0X1205       /* UPNP_Service [ESDP] */
#define UUID_SERVCLASS_UPNP_IP_SERVICE 0X1206    /* UPNP_IP_Service [ESDP] */
#define UUID_SERVCLASS_ESDP_UPNP_IP_PAN 0X1300   /* UPNP_IP_PAN [ESDP] */
#define UUID_SERVCLASS_ESDP_UPNP_IP_LAP 0X1301   /* UPNP_IP_LAP [ESDP] */
#define UUID_SERVCLASS_ESDP_UPNP_IP_L2CAP 0X1302 /* UPNP_L2CAP [ESDP] */

/* Video Distribution Profile (VDP) */
#define UUID_SERVCLASS_VIDEO_SOURCE 0X1303
#define UUID_SERVCLASS_VIDEO_SINK 0X1304
#define UUID_SERVCLASS_VIDEO_DISTRIBUTION 0X1305

#define UUID_SERVCLASS_HDP_PROFILE 0X1400    /* Health Device profile (HDP) */
#define UUID_SERVCLASS_HDP_SOURCE 0X1401     /* Health Device profile (HDP) */
#define UUID_SERVCLASS_HDP_SINK 0X1402       /* Health Device profile (HDP) */
#define UUID_SERVCLASS_MAP_PROFILE 0X1134    /* MAP profile */
#define UUID_SERVCLASS_MESSAGE_ACCESS 0X1132 /* Message Access Service */
#define UUID_SERVCLASS_MESSAGE_NOTIFICATION \
  0X1133 /* Message Notification Service */

#define UUID_SERVCLASS_GAP_SERVER 0x1800
#define UUID_SERVCLASS_GATT_SERVER 0x1801
#define UUID_SERVCLASS_DEVICE_INFO 0x180A     /* device info service */
#define UUID_SERVCLASS_LE_HID 0x1812     /*  HID over LE */
#define UUID_SERVCLASS_SCAN_PARAM 0x1813 /* Scan Parameter service */

#define UUID_CODEC_CVSD 0x0001 /* CVSD */
#define UUID_CODEC_MSBC 0x0002 /* mSBC */

/* Define all the 'Descriptor Type' values.
*/
#define UINT_DESC_TYPE 1
#define TWO_COMP_INT_DESC_TYPE 2
#define UUID_DESC_TYPE 3
#define TEXT_STR_DESC_TYPE 4
#define BOOLEAN_DESC_TYPE 5
#define DATA_ELE_SEQ_DESC_TYPE 6
#define DATA_ELE_ALT_DESC_TYPE 7
#define URL_DESC_TYPE 8

/* Define all the "Descriptor Size" values.
*/
#define SIZE_ONE_BYTE 0
#define SIZE_TWO_BYTES 1
#define SIZE_FOUR_BYTES 2
#define SIZE_EIGHT_BYTES 3
#define SIZE_SIXTEEN_BYTES 4
#define SIZE_IN_NEXT_BYTE 5
#define SIZE_IN_NEXT_WORD 6
#define SIZE_IN_NEXT_LONG 7

/* Language Encoding Constants */
#define LANG_ID_CODE_ENGLISH ((uint16_t)0x656e)     /* "en" */
#define LANG_ID_CHAR_ENCODE_UTF8 ((uint16_t)0x006a) /* UTF-8 */

/* Constants used for display purposes only.  These define overlapping attribute
 * values */
#define ATTR_ID_DATA_STORES_OR_NETWORK 0x0301

#endif
