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

#include <errno.h>
#include <unistd.h>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <queue>
#include <regex>
#include <sstream>
#include <vector>

#include "declarations.h"
#include "struct_parser_generator.h"

#include "language_y.h"

void yylex_init(void**);
void yylex_destroy(void*);
void yyset_debug(int, void*);
void yyset_in(FILE*, void*);

namespace {

const std::string kBluetoothTopNamespace = "bluetooth";

void parse_namespace(std::filesystem::path input_file_relative_path, std::vector<std::string>& token) {
  std::filesystem::path gen_namespace = kBluetoothTopNamespace / input_file_relative_path;
  std::string gen_namespace_str = gen_namespace;
  std::regex path_tokenizer("/");
  auto it = std::sregex_token_iterator(gen_namespace_str.cbegin(), gen_namespace_str.cend(), path_tokenizer, -1);
  std::sregex_token_iterator it_end;
  for (; it != it_end; ++it) {
    token.push_back(it->str());
  }
}

void generate_namespace_open(const std::vector<std::string>& token, std::ostream& output) {
  for (auto it = token.begin(); it != token.end(); ++it) {
    output << "namespace " << *it << " {" << std::endl;
  }
}

void generate_namespace_close(const std::vector<std::string>& token, std::ostream& output) {
  for (auto it = token.rbegin(); it != token.rend(); ++it) {
    output << "}  //namespace " << *it << std::endl;
  }
}

bool parse_one_file(std::filesystem::path input_file, std::filesystem::path include_dir,
                    std::filesystem::path out_dir) {
  auto gen_relative_path = input_file.lexically_relative(include_dir).parent_path();

  auto input_filename = input_file.filename().string().substr(0, input_file.filename().string().find(".pdl"));
  auto gen_path = out_dir / gen_relative_path;

  std::filesystem::create_directories(gen_path);

  auto gen_file = gen_path / (input_filename + ".h");

  void* scanner;
  yylex_init(&scanner);

  FILE* in_file = fopen(input_file.string().c_str(), "r");
  if (in_file == nullptr) {
    std::cerr << "can't open " << input_file << ": " << strerror(errno) << std::endl;
    return false;
  }

  yyset_in(in_file, scanner);

  std::ofstream out_file;
  out_file.open(gen_file);
  if (!out_file.is_open()) {
    std::cerr << "can't open " << gen_file << std::endl;
    return false;
  }

  Declarations decls;
  int ret = yy::parser(scanner, &decls).parse();

  yylex_destroy(scanner);

  if (ret != 0) {
    std::cerr << "yylex parsing failed: returned " << ret << std::endl;
    return false;
  }

  out_file << "\n\n";
  out_file << "#pragma once\n";
  out_file << "\n\n";
  out_file << "#include <stdint.h>\n";
  out_file << "#include <string>\n";
  out_file << "#include <functional>\n";
  out_file << "\n\n";
  out_file << "#include \"os/log.h\"\n";
  out_file << "#include \"packet/base_packet_builder.h\"\n";
  out_file << "#include \"packet/bit_inserter.h\"\n";
  out_file << "#include \"packet/iterator.h\"\n";
  out_file << "#include \"packet/packet_builder.h\"\n";
  out_file << "#include \"packet/packet_struct.h\"\n";
  out_file << "#include \"packet/packet_view.h\"\n";
  out_file << "#include \"packet/parser/checksum_type_checker.h\"\n";
  out_file << "#include \"packet/parser/custom_type_checker.h\"\n";
  out_file << "\n\n";

  for (const auto& c : decls.type_defs_queue_) {
    if (c.second->GetDefinitionType() == TypeDef::Type::CUSTOM ||
        c.second->GetDefinitionType() == TypeDef::Type::CHECKSUM) {
      ((CustomFieldDef*)c.second)->GenInclude(out_file);
    }
  }
  out_file << "\n\n";

  std::vector<std::string> namespace_list;
  parse_namespace(gen_relative_path, namespace_list);
  generate_namespace_open(namespace_list, out_file);
  out_file << "\n\n";

  for (const auto& c : decls.type_defs_queue_) {
    if (c.second->GetDefinitionType() == TypeDef::Type::CUSTOM ||
        c.second->GetDefinitionType() == TypeDef::Type::CHECKSUM) {
      ((CustomFieldDef*)c.second)->GenUsing(out_file);
    }
  }
  out_file << "\n\n";

  out_file << "using ::bluetooth::packet::BasePacketBuilder;";
  out_file << "using ::bluetooth::packet::BitInserter;";
  out_file << "using ::bluetooth::packet::CustomTypeChecker;";
  out_file << "using ::bluetooth::packet::Iterator;";
  out_file << "using ::bluetooth::packet::kLittleEndian;";
  out_file << "using ::bluetooth::packet::PacketBuilder;";
  out_file << "using ::bluetooth::packet::PacketStruct;";
  out_file << "using ::bluetooth::packet::PacketView;";
  out_file << "using ::bluetooth::packet::parser::ChecksumTypeChecker;";
  out_file << "\n\n";

  for (const auto& e : decls.type_defs_queue_) {
    if (e.second->GetDefinitionType() == TypeDef::Type::ENUM) {
      EnumGen gen(*(EnumDef*)e.second);
      gen.GenDefinition(out_file);
      out_file << "\n\n";
    }
  }
  for (const auto& e : decls.type_defs_queue_) {
    if (e.second->GetDefinitionType() == TypeDef::Type::ENUM) {
      EnumGen gen(*(EnumDef*)e.second);
      gen.GenLogging(out_file);
      out_file << "\n\n";
    }
  }
  for (const auto& ch : decls.type_defs_queue_) {
    if (ch.second->GetDefinitionType() == TypeDef::Type::CHECKSUM) {
      ((ChecksumDef*)ch.second)->GenChecksumCheck(out_file);
    }
  }
  out_file << "\n/* Done ChecksumChecks */\n";

  for (const auto& c : decls.type_defs_queue_) {
    if (c.second->GetDefinitionType() == TypeDef::Type::CUSTOM && c.second->size_ == -1 /* Variable Size */) {
      ((CustomFieldDef*)c.second)->GenCustomFieldCheck(out_file, decls.is_little_endian);
    }
  }
  out_file << "\n";

  for (auto& s : decls.type_defs_queue_) {
    if (s.second->GetDefinitionType() == TypeDef::Type::STRUCT) {
      ((StructDef*)s.second)->SetEndianness(decls.is_little_endian);
      ((StructDef*)s.second)->GenDefinition(out_file);
      out_file << "\n";
    }
  }

  {
    StructParserGenerator spg(decls);
    spg.Generate(out_file);
    out_file << "\n\n";
  }

  for (size_t i = 0; i < decls.packet_defs_queue_.size(); i++) {
    decls.packet_defs_queue_[i].second.SetEndianness(decls.is_little_endian);
    decls.packet_defs_queue_[i].second.GenParserDefinition(out_file);
    out_file << "\n\n";
  }

  for (const auto p : decls.packet_defs_queue_) {
    p.second.GenBuilderDefinition(out_file);
    out_file << "\n\n";
  }

  generate_namespace_close(namespace_list, out_file);

  out_file.close();
  fclose(in_file);

  return true;
}

}  // namespace

// TODO(b/141583809): stop leaks
extern "C" const char* __asan_default_options() {
  return "detect_leaks=0";
}

int main(int argc, const char** argv) {
  std::filesystem::path out_dir;
  std::filesystem::path include_dir;
  std::queue<std::filesystem::path> input_files;
  const std::string arg_out = "--out=";
  const std::string arg_include = "--include=";

  for (int i = 1; i < argc; i++) {
    std::string arg = argv[i];
    if (arg.find(arg_out) == 0) {
      auto out_path = std::filesystem::path(arg.substr(arg_out.size()));
      out_dir = std::filesystem::current_path() / std::filesystem::path(arg.substr(arg_out.size()));
    } else if (arg.find(arg_include) == 0) {
      auto include_path = std::filesystem::path(arg.substr(arg_out.size()));
      include_dir = std::filesystem::current_path() / std::filesystem::path(arg.substr(arg_include.size()));
    } else {
      input_files.emplace(std::filesystem::current_path() / std::filesystem::path(arg));
    }
  }
  if (out_dir == std::filesystem::path() || include_dir == std::filesystem::path()) {
    std::cerr << "Usage: bt-packetgen --out=OUT --include=INCLUDE input_files..." << std::endl;
    return 1;
  }

  while (!input_files.empty()) {
    if (!parse_one_file(input_files.front(), include_dir, out_dir)) {
      std::cerr << "Didn't parse " << input_files.front() << " correctly" << std::endl;
      return 2;
    }
    input_files.pop();
  }

  return 0;
}
