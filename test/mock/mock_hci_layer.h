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

#include "hci/include/hci_layer.h"

// Mocked compile conditionals, if any
#ifndef UNUSED_ATTR
#define UNUSED_ATTR
#endif

namespace test {
namespace mock {
namespace hci_layer {

// Shared state between mocked functions and tests
// Name: initialization_complete
// Params:
// Returns: void
struct initialization_complete {
  std::function<void()> body{[]() {}};
  void operator()() { body(); };
};
extern struct initialization_complete initialization_complete;
// Name: hci_event_received
// Params: const base::Location& from_here, BT_HDR* packet
// Returns: void
struct hci_event_received {
  std::function<void(const base::Location& from_here, BT_HDR* packet)> body{
      [](const base::Location& from_here, BT_HDR* packet) {}};
  void operator()(const base::Location& from_here, BT_HDR* packet) {
    body(from_here, packet);
  };
};
extern struct hci_event_received hci_event_received;
// Name: acl_event_received
// Params: BT_HDR* packet
// Returns: void
struct acl_event_received {
  std::function<void(BT_HDR* packet)> body{[](BT_HDR* packet) {}};
  void operator()(BT_HDR* packet) { body(packet); };
};
extern struct acl_event_received acl_event_received;
// Name: sco_data_received
// Params: BT_HDR* packet
// Returns: void
struct sco_data_received {
  std::function<void(BT_HDR* packet)> body{[](BT_HDR* packet) {}};
  void operator()(BT_HDR* packet) { body(packet); };
};
extern struct sco_data_received sco_data_received;
// Name: iso_data_received
// Params: BT_HDR* packet
// Returns: void
struct iso_data_received {
  std::function<void(BT_HDR* packet)> body{[](BT_HDR* packet) {}};
  void operator()(BT_HDR* packet) { body(packet); };
};
extern struct iso_data_received iso_data_received;
// Name: hal_service_died
// Params:
// Returns: void
struct hal_service_died {
  std::function<void()> body{[]() {}};
  void operator()() { body(); };
};
extern struct hal_service_died hal_service_died;
// Name: process_command_credits
// Params: int credits
// Returns: void
struct process_command_credits {
  std::function<void(int credits)> body{[](int credits) {}};
  void operator()(int credits) { body(credits); };
};
extern struct process_command_credits process_command_credits;
// Name: hci_is_root_inflammation_event_received
// Params:
// Returns: bool
struct hci_is_root_inflammation_event_received {
  std::function<bool()> body{[]() { return false; }};
  bool operator()() { return body(); };
};
extern struct hci_is_root_inflammation_event_received
    hci_is_root_inflammation_event_received;
// Name: handle_root_inflammation_event
// Params:
// Returns: void
struct handle_root_inflammation_event {
  std::function<void()> body{[]() {}};
  void operator()() { body(); };
};
extern struct handle_root_inflammation_event handle_root_inflammation_event;
// Name: hci_layer_cleanup_interface
// Params:
// Returns: void
struct hci_layer_cleanup_interface {
  std::function<void()> body{[]() {}};
  void operator()() { body(); };
};
extern struct hci_layer_cleanup_interface hci_layer_cleanup_interface;
// Name: hci_layer_get_interface
// Params:
// Returns: const hci_t*
struct hci_layer_get_interface {
  hci_t* hci;
  std::function<const hci_t*()> body{[this]() { return hci; }};
  const hci_t* operator()() { return body(); };
};
extern struct hci_layer_get_interface hci_layer_get_interface;
// Name: hci_layer_get_test_interface
// Params:  const allocator_t* buffer_allocator_interface, const btsnoop_t*
// btsnoop_interface, const packet_fragmenter_t* packet_fragmenter_interface
// Returns: const hci_t*
struct hci_layer_get_test_interface {
  std::function<const hci_t*(
      const allocator_t* buffer_allocator_interface,
      const btsnoop_t* btsnoop_interface,
      const packet_fragmenter_t* packet_fragmenter_interface)>
      body{[](const allocator_t* buffer_allocator_interface,
              const btsnoop_t* btsnoop_interface,
              const packet_fragmenter_t* packet_fragmenter_interface) {
        return nullptr;
      }};
  const hci_t* operator()(
      const allocator_t* buffer_allocator_interface,
      const btsnoop_t* btsnoop_interface,
      const packet_fragmenter_t* packet_fragmenter_interface) {
    return body(buffer_allocator_interface, btsnoop_interface,
                packet_fragmenter_interface);
  };
};
extern struct hci_layer_get_test_interface hci_layer_get_test_interface;

}  // namespace hci_layer
}  // namespace mock
}  // namespace test

// END mockcify generation
