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

  for (const auto& e : decls.type_defs_queue_) {
    if (e.second->GetDefinitionType() == TypeDef::Type::ENUM) {
      const auto* enum_def = dynamic_cast<const EnumDef*>(e.second);
      EnumGen gen(*enum_def);
      gen.GenRustDef(out_file);
      out_file << "\n\n";
    }
  }

  out_file.close();
  return true;
}
