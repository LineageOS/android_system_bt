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
 *   Functions generated:5
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
#include <frameworks/proto_logging/stats/enums/bluetooth/enums.pb.h>
#include <frameworks/proto_logging/stats/enums/bluetooth/hci/enums.pb.h>
#include "common/metrics.h"
#include "main/shim/metrics_api.h"
#include "main/shim/shim.h"
#include "stack/include/stack_metrics_logging.h"
#include "types/raw_address.h"

// Mocked compile conditionals, if any
#ifndef UNUSED_ATTR
#define UNUSED_ATTR
#endif

namespace test {
namespace mock {
namespace stack_metrics_logging {

// Shared state between mocked functions and tests
// Name: log_classic_pairing_event
// Params: const RawAddress& address, uint16_t handle, uint32_t hci_cmd,
// uint16_t hci_event, uint16_t cmd_status, uint16_t reason_code, int64_t
// event_value Returns: void
struct log_classic_pairing_event {
  std::function<void(const RawAddress& address, uint16_t handle,
                     uint32_t hci_cmd, uint16_t hci_event, uint16_t cmd_status,
                     uint16_t reason_code, int64_t event_value)>
      body{[](const RawAddress& address, uint16_t handle, uint32_t hci_cmd,
              uint16_t hci_event, uint16_t cmd_status, uint16_t reason_code,
              int64_t event_value) {}};
  void operator()(const RawAddress& address, uint16_t handle, uint32_t hci_cmd,
                  uint16_t hci_event, uint16_t cmd_status, uint16_t reason_code,
                  int64_t event_value) {
    body(address, handle, hci_cmd, hci_event, cmd_status, reason_code,
         event_value);
  };
};
extern struct log_classic_pairing_event log_classic_pairing_event;
// Name: log_link_layer_connection_event
// Params:  const RawAddress* address, uint32_t connection_handle,
// android::bluetooth::DirectionEnum direction, uint16_t link_type, uint32_t
// hci_cmd, uint16_t hci_event, uint16_t hci_ble_event, uint16_t cmd_status,
// uint16_t reason_code Returns: void
struct log_link_layer_connection_event {
  std::function<void(const RawAddress* address, uint32_t connection_handle,
                     android::bluetooth::DirectionEnum direction,
                     uint16_t link_type, uint32_t hci_cmd, uint16_t hci_event,
                     uint16_t hci_ble_event, uint16_t cmd_status,
                     uint16_t reason_code)>
      body{[](const RawAddress* address, uint32_t connection_handle,
              android::bluetooth::DirectionEnum direction, uint16_t link_type,
              uint32_t hci_cmd, uint16_t hci_event, uint16_t hci_ble_event,
              uint16_t cmd_status, uint16_t reason_code) {}};
  void operator()(const RawAddress* address, uint32_t connection_handle,
                  android::bluetooth::DirectionEnum direction,
                  uint16_t link_type, uint32_t hci_cmd, uint16_t hci_event,
                  uint16_t hci_ble_event, uint16_t cmd_status,
                  uint16_t reason_code) {
    body(address, connection_handle, direction, link_type, hci_cmd, hci_event,
         hci_ble_event, cmd_status, reason_code);
  };
};
extern struct log_link_layer_connection_event log_link_layer_connection_event;
// Name: log_smp_pairing_event
// Params: const RawAddress& address, uint8_t smp_cmd,
// android::bluetooth::DirectionEnum direction, uint8_t smp_fail_reason Returns:
// void
struct log_smp_pairing_event {
  std::function<void(const RawAddress& address, uint8_t smp_cmd,
                     android::bluetooth::DirectionEnum direction,
                     uint8_t smp_fail_reason)>
      body{[](const RawAddress& address, uint8_t smp_cmd,
              android::bluetooth::DirectionEnum direction,
              uint8_t smp_fail_reason) {}};
  void operator()(const RawAddress& address, uint8_t smp_cmd,
                  android::bluetooth::DirectionEnum direction,
                  uint8_t smp_fail_reason) {
    body(address, smp_cmd, direction, smp_fail_reason);
  };
};
extern struct log_smp_pairing_event log_smp_pairing_event;
// Name: log_sdp_attribute
// Params: const RawAddress& address, uint16_t protocol_uuid, uint16_t
// attribute_id, size_t attribute_size, const char* attribute_value Returns:
// void
struct log_sdp_attribute {
  std::function<void(const RawAddress& address, uint16_t protocol_uuid,
                     uint16_t attribute_id, size_t attribute_size,
                     const char* attribute_value)>
      body{[](const RawAddress& address, uint16_t protocol_uuid,
              uint16_t attribute_id, size_t attribute_size,
              const char* attribute_value) {}};
  void operator()(const RawAddress& address, uint16_t protocol_uuid,
                  uint16_t attribute_id, size_t attribute_size,
                  const char* attribute_value) {
    body(address, protocol_uuid, attribute_id, attribute_size, attribute_value);
  };
};
extern struct log_sdp_attribute log_sdp_attribute;
// Name: log_manufacturer_info
// Params: const RawAddress& address, android::bluetooth::DeviceInfoSrcEnum
// source_type, const std::string& source_name, const std::string& manufacturer,
// const std::string& model, const std::string& hardware_version, const
// std::string& software_version Returns: void
struct log_manufacturer_info {
  std::function<void(const RawAddress& address,
                     android::bluetooth::DeviceInfoSrcEnum source_type,
                     const std::string& source_name,
                     const std::string& manufacturer, const std::string& model,
                     const std::string& hardware_version,
                     const std::string& software_version)>
      body{[](const RawAddress& address,
              android::bluetooth::DeviceInfoSrcEnum source_type,
              const std::string& source_name, const std::string& manufacturer,
              const std::string& model, const std::string& hardware_version,
              const std::string& software_version) {}};
  void operator()(const RawAddress& address,
                  android::bluetooth::DeviceInfoSrcEnum source_type,
                  const std::string& source_name,
                  const std::string& manufacturer, const std::string& model,
                  const std::string& hardware_version,
                  const std::string& software_version) {
    body(address, source_type, source_name, manufacturer, model,
         hardware_version, software_version);
  };
};
extern struct log_manufacturer_info log_manufacturer_info;

}  // namespace stack_metrics_logging
}  // namespace mock
}  // namespace test

// END mockcify generation