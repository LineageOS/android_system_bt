/*
 * Copyright 2018 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "link_layer_socket_device.h"

#include <unistd.h>

#include "packets/packet_view.h"
#include "packets/view.h"

using std::vector;

namespace test_vendor_lib {

LinkLayerSocketDevice::LinkLayerSocketDevice(int socket_fd, Phy::Type phy_type)
    : socket_(socket_fd), phy_type_(phy_type) {}

void LinkLayerSocketDevice::TimerTick() {
  if (bytes_left_ == 0) {
    size_t size_bytes = sizeof(uint32_t);
    received_ = std::make_shared<std::vector<uint8_t>>(size_bytes);
    size_t bytes_received = socket_.TryReceive(size_bytes, received_->data());
    if (bytes_received == 0) {
      return;
    }
    ASSERT_LOG(bytes_received == size_bytes, "bytes_received == %d",
               static_cast<int>(bytes_received));
    packets::PacketView<true> size({packets::View(received_, 0, size_bytes)});
    bytes_left_ = size.begin().extract<uint32_t>();
    received_->resize(size_bytes + bytes_left_);
    offset_ = size_bytes;
  }
  size_t bytes_received = socket_.TryReceive(bytes_left_, received_->data() + offset_);
  if (bytes_received == 0) {
    return;
  }
  bytes_left_ -= bytes_received;
  offset_ += bytes_received;
  if (bytes_left_ == 0) {
    bluetooth::packet::PacketView<bluetooth::packet::kLittleEndian> packet_view(
        received_);
    auto packet = model::packets::LinkLayerPacketView::Create(packet_view);
    ASSERT(packet.IsValid());
    SendLinkLayerPacket(packet, phy_type_);
    offset_ = 0;
    received_.reset();
  }
}

void LinkLayerSocketDevice::IncomingPacket(
    model::packets::LinkLayerPacketView packet) {
  std::shared_ptr<std::vector<uint8_t>> payload_bytes =
      std::make_shared<std::vector<uint8_t>>(packet.begin(), packet.end());
  packets::PacketView<true> packet_view(payload_bytes);

  socket_.TrySend(packet_view);
}

}  // namespace test_vendor_lib
