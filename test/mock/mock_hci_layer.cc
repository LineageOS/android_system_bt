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
 *   Functions generated:13
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

// Mock include file to share data between tests and mock
#include "test/mock/mock_hci_layer.h"

// Mocked compile conditionals, if any
#ifndef UNUSED_ATTR
#define UNUSED_ATTR
#endif

// Mocked internal structures, if any
typedef struct {
} waiting_command_t;

namespace test {
namespace mock {
namespace hci_layer {

// Function state capture and return values, if needed
struct initialization_complete initialization_complete;
struct hci_event_received hci_event_received;
struct acl_event_received acl_event_received;
struct sco_data_received sco_data_received;
struct iso_data_received iso_data_received;
struct hal_service_died hal_service_died;
struct process_command_credits process_command_credits;
struct hci_is_root_inflammation_event_received
    hci_is_root_inflammation_event_received;
struct handle_root_inflammation_event handle_root_inflammation_event;
struct hci_layer_cleanup_interface hci_layer_cleanup_interface;
struct hci_layer_get_interface hci_layer_get_interface;
struct hci_layer_get_test_interface hci_layer_get_test_interface;

}  // namespace hci_layer
}  // namespace mock
}  // namespace test

// Mocked functions, if any
void initialization_complete() {
  mock_function_count_map[__func__]++;
  test::mock::hci_layer::initialization_complete();
}
void hci_event_received(const base::Location& from_here, BT_HDR* packet) {
  mock_function_count_map[__func__]++;
  test::mock::hci_layer::hci_event_received(from_here, packet);
}
void acl_event_received(BT_HDR* packet) {
  mock_function_count_map[__func__]++;
  test::mock::hci_layer::acl_event_received(packet);
}
void sco_data_received(BT_HDR* packet) {
  mock_function_count_map[__func__]++;
  test::mock::hci_layer::sco_data_received(packet);
}
void iso_data_received(BT_HDR* packet) {
  mock_function_count_map[__func__]++;
  test::mock::hci_layer::iso_data_received(packet);
}
void hal_service_died() {
  mock_function_count_map[__func__]++;
  test::mock::hci_layer::hal_service_died();
}
void process_command_credits(int credits) {
  mock_function_count_map[__func__]++;
  test::mock::hci_layer::process_command_credits(credits);
}
bool hci_is_root_inflammation_event_received() {
  mock_function_count_map[__func__]++;
  return test::mock::hci_layer::hci_is_root_inflammation_event_received();
}
void handle_root_inflammation_event() {
  mock_function_count_map[__func__]++;
  test::mock::hci_layer::handle_root_inflammation_event();
}
void hci_layer_cleanup_interface() {
  mock_function_count_map[__func__]++;
  test::mock::hci_layer::hci_layer_cleanup_interface();
}
const hci_t* hci_layer_get_interface() {
  mock_function_count_map[__func__]++;
  return test::mock::hci_layer::hci_layer_get_interface();
}
const hci_t* hci_layer_get_test_interface(
    const allocator_t* buffer_allocator_interface,
    const btsnoop_t* btsnoop_interface,
    const packet_fragmenter_t* packet_fragmenter_interface) {
  mock_function_count_map[__func__]++;
  return test::mock::hci_layer::hci_layer_get_test_interface(
      buffer_allocator_interface, btsnoop_interface,
      packet_fragmenter_interface);
}

// END mockcify generation
