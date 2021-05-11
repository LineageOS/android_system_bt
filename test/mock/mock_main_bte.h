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

// Original included files, if any
// NOTE: Since this is a mock file with mock definitions some number of
//       include files may not be required.  The include-what-you-use
//       still applies, but crafting proper inclusion is out of scope
//       for this effort.  This compilation unit may compile as-is, or
//       may need attention to prune the inclusion set.
#include <base/logging.h>
#include <hardware/bluetooth.h>
#include "bt_common.h"
#include "btcore/include/module.h"
#include "bte.h"
#include "btif/include/btif_config.h"
#include "btu.h"
#include "device/include/interop.h"
#include "hci/include/btsnoop.h"
#include "hci/include/hci_layer.h"
#include "main/shim/hci_layer.h"
#include "main/shim/shim.h"
#include "osi/include/log.h"
#include "osi/include/osi.h"
#include "stack_config.h"

// Mocked compile conditionals, if any
#ifndef UNUSED_ATTR
#define UNUSED_ATTR
#endif

namespace test {
namespace mock {
namespace main_bte {

// Shared state between mocked functions and tests
// Name: post_to_main_message_loop
// Params: const base::Location& from_here, BT_HDR* p_msg
// Returns: void
struct post_to_main_message_loop {
  std::function<void(const base::Location& from_here, BT_HDR* p_msg)> body{
      [](const base::Location& from_here, BT_HDR* p_msg) {}};
  void operator()(const base::Location& from_here, BT_HDR* p_msg) {
    body(from_here, p_msg);
  };
};
extern struct post_to_main_message_loop post_to_main_message_loop;
// Name: bte_main_init
// Params: void
// Returns: void
struct bte_main_init {
  std::function<void(void)> body{[](void) {}};
  void operator()(void) { body(); };
};
extern struct bte_main_init bte_main_init;
// Name: bte_main_hci_send
// Params: BT_HDR* p_msg, uint16_t event
// Returns: void
struct bte_main_hci_send {
  std::function<void(BT_HDR* p_msg, uint16_t event)> body{
      [](BT_HDR* p_msg, uint16_t event) {}};
  void operator()(BT_HDR* p_msg, uint16_t event) { body(p_msg, event); };
};
extern struct bte_main_hci_send bte_main_hci_send;

}  // namespace main_bte
}  // namespace mock
}  // namespace test

// END mockcify generation
