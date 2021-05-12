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
 *   Functions generated:3
 *
 *  mockcify.pl ver 0.2
 */

#include <cstdint>
#include <functional>
#include <map>
#include <string>

extern std::map<std::string, int> mock_function_count_map;

// Mock include file to share data between tests and mock
#include "test/mock/mock_main_bte.h"

// Mocked compile conditionals, if any
#ifndef UNUSED_ATTR
#define UNUSED_ATTR
#endif

// Mocked internal structures, if any

namespace test {
namespace mock {
namespace main_bte {

// Function state capture and return values, if needed
struct post_to_main_message_loop post_to_main_message_loop;
struct bte_main_init bte_main_init;
struct bte_main_hci_send bte_main_hci_send;

}  // namespace main_bte
}  // namespace mock
}  // namespace test

// Mocked functions, if any
void post_to_main_message_loop(const base::Location& from_here, BT_HDR* p_msg) {
  mock_function_count_map[__func__]++;
  test::mock::main_bte::post_to_main_message_loop(from_here, p_msg);
}
void bte_main_init(void) {
  mock_function_count_map[__func__]++;
  test::mock::main_bte::bte_main_init();
}
void bte_main_hci_send(BT_HDR* p_msg, uint16_t event) {
  mock_function_count_map[__func__]++;
  test::mock::main_bte::bte_main_hci_send(p_msg, event);
}

// END mockcify generation
