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

#include <filesystem>
#include <fstream>
#include <iostream>
#include "declarations.h"

void generate_rust_packet_preamble(std::ostream& s) {
  s <<
      R"(
use bytes::{Bytes, BytesMut};
use num_derive::{FromPrimitive, ToPrimitive};
use num_traits::{FromPrimitive, ToPrimitive};
use std::convert::TryInto;
use thiserror::Error;
use std::sync::Arc;

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
  #[error("Packet parsing failed")]
  InvalidPacketError
}

pub struct Address {
  pub addr: [u8; 6],
}

pub struct ClassOfDevice {
  pub cod: [u8; 3],
}
)";
}

bool generate_rust_source_one_file(
    const Declarations& decls,
    const std::filesystem::path& input_file,
    const std::filesystem::path& include_dir,
    const std::filesystem::path& out_dir,
    __attribute__((unused)) const std::string& root_namespace) {
  auto gen_relative_path = input_file.lexically_relative(include_dir).parent_path();

  auto input_filename = input_file.filename().string().substr(0, input_file.filename().string().find(".pdl"));
  auto gen_path = out_dir / gen_relative_path;

  std::filesystem::create_directories(gen_path);

  auto gen_file = gen_path / (input_filename + ".rs");

  std::cout << "generating " << gen_file << std::endl;

  std::ofstream out_file;
  out_file.open(gen_file);
  if (!out_file.is_open()) {
    std::cerr << "can't open " << gen_file << std::endl;
    return false;
  }

  out_file << "// @generated rust packets from " << input_file.filename().string() << "\n\n";

  generate_rust_packet_preamble(out_file);
  if (input_filename == "hci_packets") {
    out_file << "pub trait CommandExpectations { "
             << "type ResponseType;"
             << "fn _to_response_type(pkt: EventPacket) -> Self::ResponseType;"
             << "}";

    for (const auto& packet_def : decls.packet_defs_queue_) {
      auto packet = packet_def.second;
      if (!packet->HasAncestorNamed("Command")) {
        continue;
      }
      auto constraint = packet->parent_constraints_.find("op_code");
      if (constraint == packet->parent_constraints_.end()) {
        continue;
      }
      auto opcode = std::get<std::string>(constraint->second);
      for (const auto& other_packet_def : decls.packet_defs_queue_) {
        auto other_packet = other_packet_def.second;
        bool command_status = other_packet->HasAncestorNamed("CommandStatus");
        bool command_complete = other_packet->HasAncestorNamed("CommandComplete");
        if (!command_status && !command_complete) {
          continue;
        }
        auto other_constraint = other_packet->parent_constraints_.find("command_op_code");
        if (other_constraint == other_packet->parent_constraints_.end()) {
          continue;
        }

        auto other_opcode = std::get<std::string>(other_constraint->second);
        if (opcode == other_opcode) {
          packet->complement_ = other_packet;
          break;
        }
      }
    }

    EnumDef* opcode = nullptr;
    EnumDef* opcode_index = nullptr;
    for (const auto& e : decls.type_defs_queue_) {
      if (e.second->GetDefinitionType() == TypeDef::Type::ENUM) {
        auto* enum_def = dynamic_cast<EnumDef*>(e.second);
        if (enum_def->name_ == "OpCode") {
          opcode = enum_def;
        } else if (enum_def->name_ == "OpCodeIndex") {
          opcode_index = enum_def;
        }
      }
    }

    if (opcode_index != nullptr && opcode != nullptr) {
      opcode_index->try_from_enum_ = opcode;
      out_file << "use std::convert::TryFrom;";
    }
  }

  for (const auto& e : decls.type_defs_queue_) {
    if (e.second->GetDefinitionType() == TypeDef::Type::ENUM) {
      const auto* enum_def = dynamic_cast<const EnumDef*>(e.second);
      EnumGen gen(*enum_def);
      gen.GenRustDef(out_file);
      out_file << "\n\n";
    }
  }

  for (auto& s : decls.type_defs_queue_) {
    if (s.second->GetDefinitionType() == TypeDef::Type::STRUCT) {
      const auto* struct_def = dynamic_cast<const StructDef*>(s.second);
      struct_def->GenRustDef(out_file);
      out_file << "\n\n";
    }
  }

  for (const auto& packet_def : decls.packet_defs_queue_) {
    if (packet_def.second->name_.rfind("LeGetVendorCapabilitiesComplete", 0) == 0) {
      continue;
    }
    packet_def.second->GenRustDef(out_file);
    out_file << "\n\n";
  }

  out_file.close();
  return true;
}
