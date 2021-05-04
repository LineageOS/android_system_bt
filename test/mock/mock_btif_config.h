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

#include <map>
#include <string>

extern std::map<std::string, int> mock_function_count_map;

// Original included files, if any
// NOTE: Since this is a mock file with mock definitions some number of
//       include files may not be required.  The include-what-you-use
//       still applies, but crafting proper inclusion is out of scope
//       for this effort.  This compilation unit may compile as-is, or
//       may need attention to prune the inclusion set.

#include "btif/include/btif_config.h"

// Mocked compile conditionals, if any
#ifndef UNUSED_ATTR
#define UNUSED_ATTR
#endif

namespace test {
namespace mock {
namespace btif_config {

// Shared state between mocked functions and tests
// Name: btif_get_device_type
// Params: const RawAddress& bda, int* p_device_type
// Returns: bool
struct btif_get_device_type {
  std::function<bool(const RawAddress& bda, int* p_device_type)> body{
      [](const RawAddress& bda, int* p_device_type) { return false; }};
  bool operator()(const RawAddress& bda, int* p_device_type) {
    return body(bda, p_device_type);
  };
};
extern struct btif_get_device_type btif_get_device_type;
// Name: btif_get_address_type
// Params: const RawAddress& bda, tBLE_ADDR_TYPE* p_addr_type
// Returns: bool
struct btif_get_address_type {
  std::function<bool(const RawAddress& bda, tBLE_ADDR_TYPE* p_addr_type)> body{
      [](const RawAddress& bda, tBLE_ADDR_TYPE* p_addr_type) { return false; }};
  bool operator()(const RawAddress& bda, tBLE_ADDR_TYPE* p_addr_type) {
    return body(bda, p_addr_type);
  };
};
extern struct btif_get_address_type btif_get_address_type;
// Name: btif_config_exist
// Params: const std::string& section, const std::string& key
// Returns: bool
struct btif_config_exist {
  std::function<bool(const std::string& section, const std::string& key)> body{
      [](const std::string& section, const std::string& key) { return false; }};
  bool operator()(const std::string& section, const std::string& key) {
    return body(section, key);
  };
};
extern struct btif_config_exist btif_config_exist;
// Name: btif_config_get_int
// Params: const std::string& section, const std::string& key, int* value
// Returns: bool
struct btif_config_get_int {
  std::function<bool(const std::string& section, const std::string& key,
                     int* value)>
      body{[](const std::string& section, const std::string& key, int* value) {
        return false;
      }};
  bool operator()(const std::string& section, const std::string& key,
                  int* value) {
    return body(section, key, value);
  };
};
extern struct btif_config_get_int btif_config_get_int;
// Name: btif_config_set_int
// Params: const std::string& section, const std::string& key, int value
// Returns: bool
struct btif_config_set_int {
  std::function<bool(const std::string& section, const std::string& key,
                     int value)>
      body{[](const std::string& section, const std::string& key, int value) {
        return false;
      }};
  bool operator()(const std::string& section, const std::string& key,
                  int value) {
    return body(section, key, value);
  };
};
extern struct btif_config_set_int btif_config_set_int;
// Name: btif_config_get_uint64
// Params: const std::string& section, const std::string& key, uint64_t* value
// Returns: bool
struct btif_config_get_uint64 {
  std::function<bool(const std::string& section, const std::string& key,
                     uint64_t* value)>
      body{[](const std::string& section, const std::string& key,
              uint64_t* value) { return false; }};
  bool operator()(const std::string& section, const std::string& key,
                  uint64_t* value) {
    return body(section, key, value);
  };
};
extern struct btif_config_get_uint64 btif_config_get_uint64;
// Name: btif_config_set_uint64
// Params: const std::string& section, const std::string& key, uint64_t value
// Returns: bool
struct btif_config_set_uint64 {
  std::function<bool(const std::string& section, const std::string& key,
                     uint64_t value)>
      body{[](const std::string& section, const std::string& key,
              uint64_t value) { return false; }};
  bool operator()(const std::string& section, const std::string& key,
                  uint64_t value) {
    return body(section, key, value);
  };
};
extern struct btif_config_set_uint64 btif_config_set_uint64;
// Name: btif_config_get_str
// Params: const std::string& section, const std::string& key, char* value, int*
// size_bytes Returns: bool
struct btif_config_get_str {
  std::function<bool(const std::string& section, const std::string& key,
                     char* value, int* size_bytes)>
      body{[](const std::string& section, const std::string& key, char* value,
              int* size_bytes) { return false; }};
  bool operator()(const std::string& section, const std::string& key,
                  char* value, int* size_bytes) {
    return body(section, key, value, size_bytes);
  };
};
extern struct btif_config_get_str btif_config_get_str;
// Name: btif_config_set_str
// Params: const std::string& section, const std::string& key, const
// std::string& value Returns: bool
struct btif_config_set_str {
  std::function<bool(const std::string& section, const std::string& key,
                     const std::string& value)>
      body{[](const std::string& section, const std::string& key,
              const std::string& value) { return false; }};
  bool operator()(const std::string& section, const std::string& key,
                  const std::string& value) {
    return body(section, key, value);
  };
};
extern struct btif_config_set_str btif_config_set_str;
// Name: btif_config_get_bin
// Params: const std::string& section, const std::string& key, uint8_t* value,
// size_t* length Returns: bool
struct btif_config_get_bin {
  std::function<bool(const std::string& section, const std::string& key,
                     uint8_t* value, size_t* length)>
      body{[](const std::string& section, const std::string& key,
              uint8_t* value, size_t* length) { return false; }};
  bool operator()(const std::string& section, const std::string& key,
                  uint8_t* value, size_t* length) {
    return body(section, key, value, length);
  };
};
extern struct btif_config_get_bin btif_config_get_bin;
// Name: btif_config_get_bin_length
// Params: const std::string& section, const std::string& key
// Returns: size_t
struct btif_config_get_bin_length {
  std::function<size_t(const std::string& section, const std::string& key)>
      body{
          [](const std::string& section, const std::string& key) { return 0; }};
  size_t operator()(const std::string& section, const std::string& key) {
    return body(section, key);
  };
};
extern struct btif_config_get_bin_length btif_config_get_bin_length;
// Name: btif_config_set_bin
// Params: const std::string& section, const std::string& key, const uint8_t*
// value, size_t length Returns: bool
struct btif_config_set_bin {
  std::function<bool(const std::string& section, const std::string& key,
                     const uint8_t* value, size_t length)>
      body{[](const std::string& section, const std::string& key,
              const uint8_t* value, size_t length) { return false; }};
  bool operator()(const std::string& section, const std::string& key,
                  const uint8_t* value, size_t length) {
    return body(section, key, value, length);
  };
};
extern struct btif_config_set_bin btif_config_set_bin;
// Name: btif_config_get_paired_devices
// Params:
// Returns: std::vector<RawAddress>
struct btif_config_get_paired_devices {
  std::vector<RawAddress> raw_addresses;
  std::function<std::vector<RawAddress>()> body{
      [this]() { return raw_addresses; }};
  std::vector<RawAddress> operator()() { return body(); };
};
extern struct btif_config_get_paired_devices btif_config_get_paired_devices;
// Name: btif_config_remove
// Params: const std::string& section, const std::string& key
// Returns: bool
struct btif_config_remove {
  std::function<bool(const std::string& section, const std::string& key)> body{
      [](const std::string& section, const std::string& key) { return false; }};
  bool operator()(const std::string& section, const std::string& key) {
    return body(section, key);
  };
};
extern struct btif_config_remove btif_config_remove;
// Name: btif_config_save
// Params: void
// Returns: void
struct btif_config_save {
  std::function<void(void)> body{[](void) {}};
  void operator()(void) { body(); };
};
extern struct btif_config_save btif_config_save;
// Name: btif_config_flush
// Params: void
// Returns: void
struct btif_config_flush {
  std::function<void(void)> body{[](void) {}};
  void operator()(void) { body(); };
};
extern struct btif_config_flush btif_config_flush;
// Name: btif_config_clear
// Params: void
// Returns: bool
struct btif_config_clear {
  std::function<bool(void)> body{[](void) { return false; }};
  bool operator()(void) { return body(); };
};
extern struct btif_config_clear btif_config_clear;
// Name: btif_debug_config_dump
// Params: int fd
// Returns: void
struct btif_debug_config_dump {
  std::function<void(int fd)> body{[](int fd) {}};
  void operator()(int fd) { body(fd); };
};
extern struct btif_debug_config_dump btif_debug_config_dump;

}  // namespace btif_config
}  // namespace mock
}  // namespace test

// END mockcify generation
