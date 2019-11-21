/*
 * Copyright 2019 The Android Open Source Project
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
#include <cstring>
#include <memory>

#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

#include "packet/base_packet_builder.h"
#include "packet/bit_inserter.h"
#include "packet/iterator.h"
#include "packet/packet_builder.h"
#include "packet/packet_struct.h"
#include "packet/packet_view.h"
#include "packet/parser/checksum_type_checker.h"
#include "packet/parser/custom_type_checker.h"

namespace py = pybind11;

namespace bluetooth {

namespace hci {
void define_hci_packets_submodule(py::module&);
}
namespace l2cap {
void define_l2cap_packets_submodule(py::module&);
}
namespace security {
void define_smp_packets_submodule(py::module&);
}

namespace packet {

using ::bluetooth::packet::BasePacketBuilder;
using ::bluetooth::packet::BaseStruct;
using ::bluetooth::packet::BitInserter;
using ::bluetooth::packet::CustomTypeChecker;
using ::bluetooth::packet::Iterator;
using ::bluetooth::packet::kLittleEndian;
using ::bluetooth::packet::PacketBuilder;
using ::bluetooth::packet::PacketStruct;
using ::bluetooth::packet::PacketView;
using ::bluetooth::packet::parser::ChecksumTypeChecker;

PYBIND11_MODULE(bluetooth_packets_python3, m) {
  py::class_<BasePacketBuilder>(m, "BasePacketBuilder");
  py::class_<PacketBuilder<kLittleEndian>, BasePacketBuilder>(m, "PacketBuilderLittleEndian");
  py::class_<PacketBuilder<!kLittleEndian>, BasePacketBuilder>(m, "PacketBuilderBigEndian");
  py::class_<BaseStruct>(m, "BaseStruct");
  py::class_<PacketStruct<kLittleEndian>, BaseStruct>(m, "PacketStructLittleEndian");
  py::class_<PacketStruct<!kLittleEndian>, BaseStruct>(m, "PacketStructBigEndian");
  py::class_<Iterator<kLittleEndian>>(m, "IteratorLittleEndian");
  py::class_<Iterator<!kLittleEndian>>(m, "IteratorBigEndian");
  py::class_<PacketView<kLittleEndian>>(m, "PacketViewLittleEndian").def(py::init([](std::vector<uint8_t> bytes) {
    // Make a copy
    auto bytes_shared = std::make_shared<std::vector<uint8_t>>(bytes);
    return std::make_unique<PacketView<kLittleEndian>>(bytes_shared);
  }));
  py::class_<PacketView<!kLittleEndian>>(m, "PacketViewBigEndian").def(py::init([](std::vector<uint8_t> bytes) {
    // Make a copy
    auto bytes_shared = std::make_shared<std::vector<uint8_t>>(bytes);
    return std::make_unique<PacketView<!kLittleEndian>>(bytes_shared);
  }));

  bluetooth::hci::define_hci_packets_submodule(m);
  bluetooth::l2cap::define_l2cap_packets_submodule(m);
  bluetooth::security::define_smp_packets_submodule(m);
}

}  // namespace packet
}  // namespace bluetooth
