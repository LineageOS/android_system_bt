/******************************************************************************
 *
 *  Copyright 2014 Google, Inc.
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

#pragma once

// 2 bytes for opcode, 1 byte for parameter length (Volume 2, Part E, 5.4.1)
#define HCI_COMMAND_PREAMBLE_SIZE 3
// 2 bytes for handle, 2 bytes for data length (Volume 2, Part E, 5.4.2)
#define HCI_ACL_PREAMBLE_SIZE 4
// 2 bytes for handle, 1 byte for data length (Volume 2, Part E, 5.4.3)
#define HCI_SCO_PREAMBLE_SIZE 3
// 1 byte for event code, 1 byte for parameter length (Volume 2, Part E, 5.4.4)
#define HCI_EVENT_PREAMBLE_SIZE 2

// ISO
// 2 bytes for handle, 2 bytes for data length (Volume 2, Part E, 5.4.5)
#define HCI_ISO_PREAMBLE_SIZE 4

#define HCI_ISO_BF_FIRST_FRAGMENTED_PACKET (0)
#define HCI_ISO_BF_CONTINUATION_FRAGMENT_PACKET (1)
#define HCI_ISO_BF_COMPLETE_PACKET (2)
#define HCI_ISO_BF_LAST_FRAGMENT_PACKET (3)

#define HCI_ISO_HEADER_TIMESTAMP_SIZE (4)
#define HCI_ISO_HEADER_ISO_LEN_SIZE (2)
#define HCI_ISO_HEADER_PACKET_SEQ_SIZE (2)

#define HCI_ISO_HEADER_LEN_WITHOUT_TS \
  (HCI_ISO_HEADER_ISO_LEN_SIZE + HCI_ISO_HEADER_PACKET_SEQ_SIZE)
#define HCI_ISO_HEADER_LEN_WITH_TS \
  (HCI_ISO_HEADER_LEN_WITHOUT_TS + HCI_ISO_HEADER_TIMESTAMP_SIZE)

#define HCI_ISO_SET_CONTINUATION_FLAG(handle) \
  (((handle)&0x4FFF) | (0x0001 << 12))
#define HCI_ISO_SET_COMPLETE_FLAG(handle) (((handle)&0x4FFF) | (0x0002 << 12))
#define HCI_ISO_SET_END_FRAG_FLAG(handle) (((handle)&0x4FFF) | (0x0003 << 12))
#define HCI_ISO_SET_TIMESTAMP_FLAG(handle) (((handle)&0x3FFF) | (0x0001 << 14))

#define HCI_ISO_GET_TS_FLAG(handle) (((handle) >> 14) & 0x0001)
#define HCI_ISO_GET_PACKET_STATUS_FLAGS(iso_sdu_length) \
  (iso_sdu_length & 0xC000)

#define HCI_ISO_SDU_LENGTH_MASK 0x0FFF
