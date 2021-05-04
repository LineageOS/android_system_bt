/*
 * Copyright 2021 The Android Open Source Project
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

/*
 * Generated mock file from original source file
 *   Functions generated:18
 *
 *  mockcify.pl ver 0.2
 */

#include <cstdint>
#include <functional>
#include <map>
#include <string>

extern std::map<std::string, int> mock_function_count_map;

// Original included files, if any
// NOTE: Since this is a mock file with mock definitions some number of
//       include files may not be required.  The include-what-you-use
//       still applies, but crafting proper inclusion is out of scope
//       for this effort.  This compilation unit may compile as-is, or
//       may need attention to prune the inclusion set.

// Mock include file to share data between tests and mock
#include "test/mock/mock_btif_config.h"

// Mocked compile conditionals, if any
#ifndef UNUSED_ATTR
#define UNUSED_ATTR
#endif

// Mocked internal structures, if any

namespace test {
namespace mock {
namespace btif_config {

// Function state capture and return values, if needed
struct btif_get_device_type btif_get_device_type;
struct btif_get_address_type btif_get_address_type;
struct btif_config_exist btif_config_exist;
struct btif_config_get_int btif_config_get_int;
struct btif_config_set_int btif_config_set_int;
struct btif_config_get_uint64 btif_config_get_uint64;
struct btif_config_set_uint64 btif_config_set_uint64;
struct btif_config_get_str btif_config_get_str;
struct btif_config_set_str btif_config_set_str;
struct btif_config_get_bin btif_config_get_bin;
struct btif_config_get_bin_length btif_config_get_bin_length;
struct btif_config_set_bin btif_config_set_bin;
struct btif_config_get_paired_devices btif_config_get_paired_devices;
struct btif_config_remove btif_config_remove;
struct btif_config_save btif_config_save;
struct btif_config_flush btif_config_flush;
struct btif_config_clear btif_config_clear;
struct btif_debug_config_dump btif_debug_config_dump;

}  // namespace btif_config
}  // namespace mock
}  // namespace test

// Mocked functions, if any
bool btif_get_device_type(const RawAddress& bda, int* p_device_type) {
  mock_function_count_map[__func__]++;
  return test::mock::btif_config::btif_get_device_type(bda, p_device_type);
}
bool btif_get_address_type(const RawAddress& bda, tBLE_ADDR_TYPE* p_addr_type) {
  mock_function_count_map[__func__]++;
  return test::mock::btif_config::btif_get_address_type(bda, p_addr_type);
}
bool btif_config_exist(const std::string& section, const std::string& key) {
  mock_function_count_map[__func__]++;
  return test::mock::btif_config::btif_config_exist(section, key);
}
bool btif_config_get_int(const std::string& section, const std::string& key,
                         int* value) {
  mock_function_count_map[__func__]++;
  return test::mock::btif_config::btif_config_get_int(section, key, value);
}
bool btif_config_set_int(const std::string& section, const std::string& key,
                         int value) {
  mock_function_count_map[__func__]++;
  return test::mock::btif_config::btif_config_set_int(section, key, value);
}
bool btif_config_get_uint64(const std::string& section, const std::string& key,
                            uint64_t* value) {
  mock_function_count_map[__func__]++;
  return test::mock::btif_config::btif_config_get_uint64(section, key, value);
}
bool btif_config_set_uint64(const std::string& section, const std::string& key,
                            uint64_t value) {
  mock_function_count_map[__func__]++;
  return test::mock::btif_config::btif_config_set_uint64(section, key, value);
}
bool btif_config_get_str(const std::string& section, const std::string& key,
                         char* value, int* size_bytes) {
  mock_function_count_map[__func__]++;
  return test::mock::btif_config::btif_config_get_str(section, key, value,
                                                      size_bytes);
}
bool btif_config_set_str(const std::string& section, const std::string& key,
                         const std::string& value) {
  mock_function_count_map[__func__]++;
  return test::mock::btif_config::btif_config_set_str(section, key, value);
}
bool btif_config_get_bin(const std::string& section, const std::string& key,
                         uint8_t* value, size_t* length) {
  mock_function_count_map[__func__]++;
  return test::mock::btif_config::btif_config_get_bin(section, key, value,
                                                      length);
}
size_t btif_config_get_bin_length(const std::string& section,
                                  const std::string& key) {
  mock_function_count_map[__func__]++;
  return test::mock::btif_config::btif_config_get_bin_length(section, key);
}
bool btif_config_set_bin(const std::string& section, const std::string& key,
                         const uint8_t* value, size_t length) {
  mock_function_count_map[__func__]++;
  return test::mock::btif_config::btif_config_set_bin(section, key, value,
                                                      length);
}
std::vector<RawAddress> btif_config_get_paired_devices() {
  mock_function_count_map[__func__]++;
  return test::mock::btif_config::btif_config_get_paired_devices();
}
bool btif_config_remove(const std::string& section, const std::string& key) {
  mock_function_count_map[__func__]++;
  return test::mock::btif_config::btif_config_remove(section, key);
}
void btif_config_save(void) {
  mock_function_count_map[__func__]++;
  test::mock::btif_config::btif_config_save();
}
void btif_config_flush(void) {
  mock_function_count_map[__func__]++;
  test::mock::btif_config::btif_config_flush();
}
bool btif_config_clear(void) {
  mock_function_count_map[__func__]++;
  return test::mock::btif_config::btif_config_clear();
}
void btif_debug_config_dump(int fd) {
  mock_function_count_map[__func__]++;
  test::mock::btif_config::btif_debug_config_dump(fd);
}

// END mockcify generation
