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
#include "declarations.h"

bool generate_rust_source_one_file(
    __attribute__((unused)) const Declarations& decls,
    __attribute__((unused)) const std::filesystem::path& input_file,
    __attribute__((unused)) const std::filesystem::path& include_dir,
    __attribute__((unused)) const std::filesystem::path& out_dir,
    __attribute__((unused)) const std::string& root_namespace) {
  // TODO do fun things
  return true;
}
