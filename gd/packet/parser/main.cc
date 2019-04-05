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

#include <unistd.h>
#include <iostream>
#include <sstream>
#include <vector>

#include "declarations.h"

#include "language_y.h"

void yylex_init(void**);
void yylex_destroy(void*);
void yyset_debug(int, void*);

int main() {
  void* scanner;
  yylex_init(&scanner);

  Declarations decls;
  int ret = yy::parser(scanner, &decls).parse();

  yylex_destroy(scanner);

  if (ret != 0) return ret;

  std::cout << "\n\n";
  std::cout << "#include <stdint.h>\n";
  std::cout << "#include <string>\n";
  std::cout << "\n\n";
  std::cout << "#include \"os/log.h\"\n";
  std::cout << "#include \"packet/base_packet_builder.h\"\n";
  std::cout << "#include \"packet/bit_inserter.h\"\n";
  std::cout << "#include \"packet/packet_builder.h\"\n";
  std::cout << "#include \"packet/packet_view.h\"\n";
  std::cout << "\n\n";
  std::cout << "using bluetooth::packet::BasePacketBuilder;";
  std::cout << "using bluetooth::packet::BitInserter;";
  std::cout << "using bluetooth::packet::kLittleEndian;";
  std::cout << "using bluetooth::packet::PacketBuilder;";
  std::cout << "using bluetooth::packet::PacketView;";
  std::cout << "\n\n";

  for (const auto& e : decls.enum_defs_queue_) {
    EnumGen gen(e.second);
    gen.GenDefinition(std::cout);
    std::cout << "\n\n";
  }
  for (const auto& e : decls.enum_defs_queue_) {
    EnumGen gen(e.second);
    gen.GenLogging(std::cout);
    std::cout << "\n\n";
  }

  for (size_t i = 0; i < decls.packet_defs_queue_.size(); i++) {
    decls.packet_defs_queue_[i].second.SetEndianness(decls.is_little_endian);
    decls.packet_defs_queue_[i].second.GenParserDefinition(std::cout);
    std::cout << "\n\n";
  }

  for (const auto p : decls.packet_defs_queue_) {
    p.second.GenBuilderDefinition(std::cout);
    std::cout << "\n\n";
  }
}
