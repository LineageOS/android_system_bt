/******************************************************************************
 *
 *  Copyright (C) 2017 Google, Inc.
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
#define LOG_TAG "l2cap_assemble"

#include "l2cap_packet.h"

#include <algorithm>

#include "osi/include/log.h"

namespace test_vendor_lib {

const int kL2capHeaderLength = 4;
const uint16_t kSduTxSeqBits = 0x007e;
const int kSduStandardHeaderLength = 6;
const int kSduFirstHeaderLength = 8;

std::unique_ptr<L2capPacket> L2capPacket::assemble(
    const std::vector<L2capSdu>& sdu_packets) {
  std::unique_ptr<L2capPacket> built_l2cap_packet(new L2capPacket());
  uint16_t l2cap_payload_length = 0;
  uint16_t first_packet_channel_id = 0;
  uint16_t total_expected_l2cap_length;
  uint8_t txseq_start;

  if (sdu_packets.size() == 0) {
    return nullptr;
  }
  if (sdu_packets.size() == 1 && !L2capSdu::is_complete_l2cap(sdu_packets[0])) {
    return nullptr;
  }

  first_packet_channel_id = sdu_packets[0].get_channel_id();

  built_l2cap_packet->l2cap_packet_.resize(kL2capHeaderLength);

  for (size_t i = 0; i < sdu_packets.size(); i++) {
    uint16_t payload_length = sdu_packets[i].get_payload_length();

    // TODO(jruthe): Remove these checks when ACL packets have been
    // implemented. Once those are done, that will be the only way to create
    // L2capSdu objects and these checks will be moved there instead.
    //
    // Check the integrity of the packet length, if it is zero, it is invalid.
    // The maximum size of a single, partial L2CAP payload is 1016 bytes.
    if ((payload_length <= 0) ||
        (payload_length != sdu_packets[i].get_vector_size() - 4)) {
      return nullptr;
    }

    uint16_t fcs_check = sdu_packets[i].get_fcs();

    if (sdu_packets[i].calculate_fcs() != fcs_check) {
      return nullptr;
    }

    uint16_t controls = sdu_packets[i].get_controls();

    if (sdu_packets[i].get_channel_id() != first_packet_channel_id) {
      return nullptr;
    }

    if (i == 0) txseq_start = controls & kSduTxSeqBits;

    // Bluetooth Specification version 4.2 volume 3 part A 3.3.2:
    // If there is only a single SDU, the first two bits of the control must be
    // set to 00b, representing an unsegmented SDU. If the SDU is segmented,
    // there is a begin and an end. The first segment must have the first two
    // control bits set to 01b and the ending segment must have them set to 10b.
    // Meanwhile all segments in between the start and end must have the bits
    // set to 11b.
    uint16_t starting_index;
    uint8_t txseq = controls & kSduTxSeqBits;
    if (sdu_packets.size() > 1 && i == 0 &&
        !L2capSdu::is_starting_sdu(sdu_packets[i])) {
      return nullptr;
    }
    if (i != 0 && L2capSdu::is_starting_sdu(sdu_packets[i])) {
      return nullptr;
    }
    if (txseq != (txseq_start + (static_cast<uint8_t>(i) << 1))) {
      return nullptr;
    }
    if (sdu_packets.size() > 1 && i == sdu_packets.size() - 1 &&
        !L2capSdu::is_ending_sdu(sdu_packets[i])) {
      return nullptr;
    }

    // Subtract the control and fcs from every SDU payload length.
    l2cap_payload_length += (payload_length - 4);

    if (L2capSdu::is_starting_sdu(sdu_packets[i])) {
      starting_index = kSduFirstHeaderLength;
      total_expected_l2cap_length = sdu_packets[i].get_total_l2cap_length();

      // Subtract the additional two bytes from the first packet of a segmented
      // SDU.
      l2cap_payload_length -= 2;
    } else {
      starting_index = kSduStandardHeaderLength;
    }

    auto payload_begin = sdu_packets[i].get_payload_begin(starting_index);
    auto payload_end = sdu_packets[i].get_payload_end();

    built_l2cap_packet->l2cap_packet_.insert(
        built_l2cap_packet->l2cap_packet_.end(), payload_begin, payload_end);
  }

  if (l2cap_payload_length != total_expected_l2cap_length &&
      sdu_packets.size() > 1) {
    return nullptr;
  }

  built_l2cap_packet->l2cap_packet_[0] = l2cap_payload_length & 0xff;
  built_l2cap_packet->l2cap_packet_[1] = (l2cap_payload_length & 0xff00) >> 8;
  built_l2cap_packet->l2cap_packet_[2] = first_packet_channel_id & 0xff;
  built_l2cap_packet->l2cap_packet_[3] =
      (first_packet_channel_id & 0xff00) >> 8;

  return built_l2cap_packet;
}  // Assemble

std::vector<uint8_t> L2capPacket::get_l2cap_payload() const {
  std::vector<uint8_t> payload_sub_vector;
  payload_sub_vector.clear();

  auto begin_payload_iter = get_l2cap_payload_begin();
  payload_sub_vector.insert(payload_sub_vector.end(), begin_payload_iter,
                            l2cap_packet_.end());

  return payload_sub_vector;
}

uint16_t L2capPacket::get_l2cap_cid() const {
  return ((l2cap_packet_[3] << 8) | l2cap_packet_[2]);
}

}  // namespace test_vendor_lib
