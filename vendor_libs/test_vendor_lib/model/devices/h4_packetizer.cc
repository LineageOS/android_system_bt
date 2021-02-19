//
// Copyright 2017 The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

#include "h4_packetizer.h"

#include <cerrno>

#include <dlfcn.h>
#include <fcntl.h>
#include <sys/uio.h>
#include <unistd.h>

#include "os/log.h"

namespace test_vendor_lib {
size_t H4Packetizer::HciGetPacketLengthForType(PacketType type,
                                               const uint8_t* preamble) const {
  static const size_t
      packet_length_offset[static_cast<size_t>(PacketType::ISO) + 1] = {
          0,
          H4Packetizer::COMMAND_LENGTH_OFFSET,
          H4Packetizer::ACL_LENGTH_OFFSET,
          H4Packetizer::SCO_LENGTH_OFFSET,
          H4Packetizer::EVENT_LENGTH_OFFSET,
          H4Packetizer::ISO_LENGTH_OFFSET,
      };

  size_t offset = packet_length_offset[static_cast<size_t>(type)];
  size_t size = preamble[offset];
  if (type == PacketType::ACL) {
    size |= ((size_t)preamble[offset + 1]) << 8u;
  }
  if (type == PacketType::ISO) {
    size |= ((size_t)preamble[offset + 1] & 0x0fu) << 8u;
  }
  return size;
}

H4Packetizer::H4Packetizer(int fd, PacketReadCallback command_cb,
                           PacketReadCallback event_cb,
                           PacketReadCallback acl_cb, PacketReadCallback sco_cb,
                           PacketReadCallback iso_cb,
                           ClientDisconnectCallback disconnect_cb)
    : uart_fd_(fd),
      command_cb_(std::move(command_cb)),
      event_cb_(std::move(event_cb)),
      acl_cb_(std::move(acl_cb)),
      sco_cb_(std::move(sco_cb)),
      iso_cb_(std::move(iso_cb)),
      disconnect_cb_(std::move(disconnect_cb)) {}

size_t H4Packetizer::Send(uint8_t type, const uint8_t* data, size_t length) {
  struct iovec iov[] = {{&type, sizeof(type)}, {const_cast<uint8_t*>(data), length}};
  ssize_t ret = 0;
  do {
    ret = TEMP_FAILURE_RETRY(writev(uart_fd_, iov, sizeof(iov) / sizeof(iov[0])));
  } while (-1 == ret && EAGAIN == errno);

  if (ret == -1) {
    LOG_ERROR("Error writing to UART (%s)", strerror(errno));
  } else if (ret < static_cast<ssize_t>(length + 1)) {
    LOG_ERROR("%d / %d bytes written - something went wrong...",
              static_cast<int>(ret), static_cast<int>(length + 1));
  }
  return ret;
}

void H4Packetizer::OnPacketReady() {
  switch (hci_packet_type_) {
    case PacketType::COMMAND:
      command_cb_(packet_);
      break;
    case PacketType::ACL:
      acl_cb_(packet_);
      break;
    case PacketType::SCO:
      sco_cb_(packet_);
      break;
    case PacketType::EVENT:
      event_cb_(packet_);
      break;
    case PacketType::ISO:
      iso_cb_(packet_);
      break;
    default:
      LOG_ALWAYS_FATAL("Unimplemented packet type %d",
                       static_cast<int>(hci_packet_type_));
  }
  // Get ready for the next type byte.
  hci_packet_type_ = PacketType::UNKNOWN;
}

void H4Packetizer::OnDataReady(int fd) {
  if (disconnected_) return;
  ssize_t bytes_to_read = 0;
  uint8_t* buffer_pointer = nullptr;

  static const size_t preamble_size[static_cast<size_t>(PacketType::ISO) + 1] =
      {
          0,
          H4Packetizer::COMMAND_PREAMBLE_SIZE,
          H4Packetizer::ACL_PREAMBLE_SIZE,
          H4Packetizer::SCO_PREAMBLE_SIZE,
          H4Packetizer::EVENT_PREAMBLE_SIZE,
          H4Packetizer::ISO_PREAMBLE_SIZE,
      };
  switch (state_) {
    case HCI_TYPE:
      bytes_to_read = 1;
      buffer_pointer = &packet_type_;
      break;
    case HCI_PREAMBLE:
    case HCI_PAYLOAD:
      bytes_to_read = packet_.size() - bytes_read_;
      buffer_pointer = packet_.data() + bytes_read_;
      break;
  }

  ssize_t bytes_read =
      TEMP_FAILURE_RETRY(read(fd, buffer_pointer, bytes_to_read));
  if (bytes_read == 0) {
    LOG_INFO("remote disconnected!");
    disconnected_ = true;
    disconnect_cb_();
    return;
  } else if (bytes_read < 0) {
    if (errno == EAGAIN) {
      // No data, try again later.
      return;
    } else if (errno == ECONNRESET) {
      // They probably rejected our packet
      disconnected_ = true;
      disconnect_cb_();
      return;
    } else {
      LOG_ALWAYS_FATAL(
          "Read error in %s: %s",
          state_ == HCI_TYPE
              ? "HCI_TYPE"
              : state_ == HCI_PREAMBLE ? "HCI_PREAMBLE" : "HCI_PAYLOAD",
          strerror(errno));
    }
  } else if (bytes_read > bytes_to_read) {
    LOG_ALWAYS_FATAL("More bytes read (%u) than expected (%u)!",
                     static_cast<int>(bytes_read),
                     static_cast<int>(bytes_to_read));
  }

  switch (state_) {
    case HCI_TYPE:
      hci_packet_type_ = static_cast<PacketType>(packet_type_);
      if (hci_packet_type_ != PacketType::ACL &&
          hci_packet_type_ != PacketType::SCO &&
          hci_packet_type_ != PacketType::COMMAND &&
          hci_packet_type_ != PacketType::EVENT &&
          hci_packet_type_ != PacketType::ISO) {
        LOG_ALWAYS_FATAL("Unimplemented packet type %hhd", packet_type_);
      }
      state_ = HCI_PREAMBLE;
      bytes_read_ = 0;
      packet_.resize(preamble_size[static_cast<size_t>(hci_packet_type_)]);
      break;
    case HCI_PREAMBLE:
      bytes_read_ += bytes_read;
      if (bytes_read_ == packet_.size()) {
        size_t payload_size =
            HciGetPacketLengthForType(hci_packet_type_, packet_.data());
        if (payload_size == 0) {
          OnPacketReady();
          state_ = HCI_TYPE;
        } else {
          packet_.resize(packet_.size() + payload_size);
          state_ = HCI_PAYLOAD;
        }
      }
      break;
    case HCI_PAYLOAD:
      bytes_read_ += bytes_read;
      if (bytes_read_ == packet_.size()) {
        OnPacketReady();
        state_ = HCI_TYPE;
      }
      break;
  }
}

}  // namespace test_vendor_lib
