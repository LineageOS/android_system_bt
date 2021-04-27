/*
 * Copyright 2021 HIMSA II K/S - www.himsa.com.
 * Represented by EHIMA - www.ehima.com
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

#pragma once

#include <cstdint>
#include <unordered_set>
#include <vector>

#include "bta/include/bta_gatt_api.h"
#include "bta/vc/types.h"
#include "include/hardware/bt_vc.h"
#include "types/raw_address.h"

namespace bluetooth {
namespace vc {
namespace internal {

class VolumeControlDevice {
 public:
  RawAddress address;
  /* This is true only during first connection to profile, until we store the
   * device
   */
  bool first_connection;

  /* we are making active attempt to connect to this device, 'direct connect'.
   * This is true only during initial phase of first connection. */
  bool connecting_actively;

  bool service_changed_rcvd;

  uint8_t volume;
  uint8_t change_counter;
  bool mute;
  uint8_t flags;

  uint16_t connection_id;

  /* Volume Control Service */
  uint16_t volume_state_handle;
  uint16_t volume_state_ccc_handle;
  uint16_t volume_control_point_handle;
  uint16_t volume_flags_handle;
  uint16_t volume_flags_ccc_handle;

  bool device_ready; /* Set when device read server status and registgered for
                        notifications */

  VolumeControlDevice(const RawAddress& address, bool first_connection)
      : address(address),
        first_connection(first_connection),
        connecting_actively(first_connection),
        service_changed_rcvd(false),
        volume(0),
        change_counter(0),
        mute(false),
        flags(0),
        connection_id(GATT_INVALID_CONN_ID),
        volume_state_handle(0),
        volume_state_ccc_handle(0),
        volume_control_point_handle(0),
        volume_flags_handle(0),
        volume_flags_ccc_handle(0),
        device_ready(false) {}

  ~VolumeControlDevice() = default;

  inline std::string ToString() { return address.ToString(); }

  void DebugDump(int fd) { dprintf(fd, "%s\n", this->ToString().c_str()); }

  bool IsConnected() { return connection_id != GATT_INVALID_CONN_ID; }

  void Disconnect(tGATT_IF gatt_if);

  bool UpdateHandles(void);

  void ResetHandles(void);

  bool HasHandles(void) { return GATT_HANDLE_IS_VALID(volume_state_handle); }

  void ControlPointOperation(uint8_t opcode, const std::vector<uint8_t>* arg,
                             GATT_WRITE_OP_CB cb, void* cb_data);
  bool IsEncryptionEnabled();

  bool EnableEncryption(tBTM_SEC_CALLBACK* callback);

  bool EnqueueInitialRequests(tGATT_IF gatt_if, GATT_READ_OP_CB chrc_read_cb,
                              GATT_WRITE_OP_CB cccd_write_cb);
  void EnqueueRemainingRequests(tGATT_IF gatt_if, GATT_READ_OP_CB chrc_read_cb,
                                GATT_WRITE_OP_CB cccd_write_cb);
  bool VerifyReady(uint16_t handle);

 private:
  /*
   * This is used to track the pending GATT operation handles. Once the list is
   * empty the device is assumed ready and connected. We are doing it because we
   * want to make sure all the required characteristics and descritors are
   * available on server side.
   */
  std::unordered_set<uint16_t> handles_pending;

  uint16_t find_ccc_handle(uint16_t chrc_handle);
  bool set_volume_control_service_handles(const gatt::Service& service);
  bool subscribe_for_notifications(tGATT_IF gatt_if, uint16_t handle,
                                   uint16_t ccc_handle, GATT_WRITE_OP_CB cb);
};

class VolumeControlDevices {
 public:
  void Add(const RawAddress& address, bool first_connection) {
    if (FindByAddress(address) != nullptr) return;

    devices_.emplace_back(address, first_connection);
  }

  void Remove(const RawAddress& address) {
    for (auto it = devices_.begin(); it != devices_.end(); it++) {
      if (it->address == address) {
        it = devices_.erase(it);
        break;
      }
    }
  }

  VolumeControlDevice* FindByAddress(const RawAddress& address) {
    auto iter = std::find_if(devices_.begin(), devices_.end(),
                             [&address](const VolumeControlDevice& device) {
                               return device.address == address;
                             });

    return (iter == devices_.end()) ? nullptr : &(*iter);
  }

  VolumeControlDevice* FindByConnId(uint16_t connection_id) {
    auto iter =
        std::find_if(devices_.begin(), devices_.end(),
                     [&connection_id](const VolumeControlDevice& device) {
                       return device.connection_id == connection_id;
                     });

    return (iter == devices_.end()) ? nullptr : &(*iter);
  }

  size_t Size() { return (devices_.size()); }

  void Clear() { devices_.clear(); }

  void DebugDump(int fd) {
    for (auto& device : devices_) {
      device.DebugDump(fd);
    }
  }

  void Disconnect(tGATT_IF gatt_if) {
    for (auto& device : devices_) {
      device.Disconnect(gatt_if);
    }
  }

  void ControlPointOperation(std::vector<RawAddress>& devices, uint8_t opcode,
                             const std::vector<uint8_t>* arg,
                             GATT_WRITE_OP_CB cb, void* cb_data) {
    for (auto& addr : devices) {
      VolumeControlDevice* device = FindByAddress(addr);
      if (device && device->IsConnected())
        device->ControlPointOperation(opcode, arg, cb, cb_data);
    }
  }

 private:
  std::vector<VolumeControlDevice> devices_;
};

}  // namespace internal
}  // namespace vc
}  // namespace bluetooth
