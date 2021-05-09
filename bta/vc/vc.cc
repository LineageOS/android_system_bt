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

#include <base/bind.h>
#include <base/bind_helpers.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <hardware/bt_vc.h>

#include <string>
#include <vector>

#include "bta_gatt_api.h"
#include "bta_gatt_queue.h"
#include "bta_vc_api.h"
#include "btif_storage.h"
#include "devices.h"

using base::Closure;
using bluetooth::Uuid;
using bluetooth::vc::ConnectionState;
using namespace bluetooth::vc::internal;

namespace {
class VolumeControlImpl;
VolumeControlImpl* instance;

/**
 * Overview:
 *
 * This is Volume Control Implementation class which realize Volume Control
 * Profile (VCP)
 *
 * Each connected peer device supporting Volume Control Service (VCS) is on the
 * list of devices (volume_control_devices_).
 *
 * Once all the mandatory characteristis for all the services are discovered,
 * Fluoride calls ON_CONNECTED callback.
 *
 * It is assumed that whenever application changes general audio options in this
 * profile e.g. Volume up/down, mute/unmute etc, profile configures all the
 * devices which are active Le Audio devices.
 *
 *
 */
class VolumeControlImpl : public VolumeControl {
 public:
  ~VolumeControlImpl() override = default;

  VolumeControlImpl(bluetooth::vc::VolumeControlCallbacks* callbacks)
      : gatt_if_(0), callbacks_(callbacks) {
    BTA_GATTC_AppRegister(
        gattc_callback_static,
        base::Bind([](uint8_t client_id, uint8_t status) {
          if (status != GATT_SUCCESS) {
            LOG(ERROR) << "Can't start Volume Control profile - no gatt "
                          "clients left!";
            return;
          }
          instance->gatt_if_ = client_id;
        }),
        true);
  }

  void Connect(const RawAddress& address) override {
    LOG(INFO) << __func__ << " " << address;

    auto device = volume_control_devices_.FindByAddress(address);
    if (!device) {
      volume_control_devices_.Add(address, true);
    } else {
      device->connecting_actively = true;
    }

    BTA_GATTC_Open(gatt_if_, address, true, false);
  }

  void AddFromStorage(const RawAddress& address, bool auto_connect) {
    LOG(INFO) << __func__ << " " << address
              << ", auto_connect=" << auto_connect;

    if (auto_connect) {
      volume_control_devices_.Add(address, false);

      /* Add device into BG connection to accept remote initiated connection */
      BTA_GATTC_Open(gatt_if_, address, false, false);
    }
  }

  void OnGattConnected(tGATT_STATUS status, uint16_t connection_id,
                       tGATT_IF /*client_if*/, RawAddress address,
                       tBT_TRANSPORT /*transport*/, uint16_t /*mtu*/) {
    LOG(INFO) << __func__ << ": address=" << address
              << ", connection_id=" << connection_id;

    VolumeControlDevice* device =
        volume_control_devices_.FindByAddress(address);
    if (!device) {
      LOG(ERROR) << __func__ << "Skipping unknown device, address=" << address;
      return;
    }

    if (status != GATT_SUCCESS) {
      LOG(INFO) << "Failed to connect to Volume Control device";
      device_cleanup_helper(device, device->connecting_actively);
      return;
    }

    device->connection_id = connection_id;

    if (device->IsEncryptionEnabled()) {
      OnEncryptionComplete(address, BTM_SUCCESS);
      return;
    }

    if (!device->EnableEncryption(enc_callback_static)) {
      device_cleanup_helper(device, device->connecting_actively);
    }
  }

  void OnEncryptionComplete(const RawAddress& address, uint8_t success) {
    VolumeControlDevice* device =
        volume_control_devices_.FindByAddress(address);
    if (!device) {
      LOG(ERROR) << __func__ << "Skipping unknown device" << address;
      return;
    }

    if (success != BTM_SUCCESS) {
      LOG(ERROR) << "encryption failed "
                 << "status: " << int{success};
      // If the encryption failed, do not remove the device.
      // Disconnect only, since the Android will try to re-enable encryption
      // after disconnection
      device->Disconnect(gatt_if_);
      if (device->connecting_actively)
        callbacks_->OnConnectionState(ConnectionState::DISCONNECTED,
                                      device->address);
      return;
    }

    LOG(INFO) << __func__ << " " << address << "status: " << success;

    if (device->HasHandles()) {
      device->EnqueueInitialRequests(gatt_if_, chrc_read_callback_static,
                                     OnGattWriteCccStatic);

    } else {
      device->first_connection = true;
      BTA_GATTC_ServiceSearchRequest(device->connection_id,
                                     &kVolumeControlUuid);
    }
  }

  void OnServiceChangeEvent(const RawAddress& address) {
    VolumeControlDevice* device =
        volume_control_devices_.FindByAddress(address);
    if (!device) {
      LOG(ERROR) << __func__ << "Skipping unknown device" << address;
      return;
    }
    LOG(INFO) << __func__ << ": address=" << address;
    device->first_connection = true;
    device->service_changed_rcvd = true;
    BtaGattQueue::Clean(device->connection_id);
  }

  void OnServiceDiscDoneEvent(const RawAddress& address) {
    VolumeControlDevice* device =
        volume_control_devices_.FindByAddress(address);
    if (!device) {
      LOG(ERROR) << __func__ << "Skipping unknown device" << address;
      return;
    }

    if (device->service_changed_rcvd)
      BTA_GATTC_ServiceSearchRequest(device->connection_id,
                                     &kVolumeControlUuid);
  }

  void OnServiceSearchComplete(uint16_t connection_id, tGATT_STATUS status) {
    VolumeControlDevice* device =
        volume_control_devices_.FindByConnId(connection_id);
    if (!device) {
      LOG(ERROR) << __func__ << "Skipping unknown device, connection_id="
                 << loghex(connection_id);
      return;
    }

    /* Known device, nothing to do */
    if (!device->first_connection) return;

    if (status != GATT_SUCCESS) {
      /* close connection and report service discovery complete with error */
      LOG(ERROR) << "Service discovery failed";
      device_cleanup_helper(device, device->first_connection);
      return;
    }

    bool success = device->UpdateHandles();
    if (!success) {
      LOG(ERROR) << "Incomplete service database";
      device_cleanup_helper(device, true);
      return;
    }

    device->EnqueueInitialRequests(gatt_if_, chrc_read_callback_static,
                                   OnGattWriteCccStatic);
  }

  void OnCharacteristicValueChanged(uint16_t conn_id, tGATT_STATUS status,
                                    uint16_t handle, uint16_t len,
                                    uint8_t* value, void* /* data */) {
    VolumeControlDevice* device = volume_control_devices_.FindByConnId(conn_id);
    if (!device) {
      LOG(INFO) << __func__ << ": unknown conn_id=" << loghex(conn_id);
      return;
    }

    if (status != GATT_SUCCESS) {
      LOG(INFO) << __func__ << ": status=" << static_cast<int>(status);
      return;
    }

    if (handle == device->volume_state_handle) {
      OnVolumeControlStateChanged(device, len, value);
      verify_device_ready(device, handle);
      return;
    }
    if (handle == device->volume_flags_handle) {
      OnVolumeControlFlagsChanged(device, len, value);
      verify_device_ready(device, handle);
      return;
    }

    LOG(ERROR) << __func__ << ": unknown handle=" << loghex(handle);
  }

  void OnNotificationEvent(uint16_t conn_id, uint16_t handle, uint16_t len,
                           uint8_t* value) {
    LOG(INFO) << __func__ << ": handle=" << loghex(handle);
    OnCharacteristicValueChanged(conn_id, GATT_SUCCESS, handle, len, value,
                                 nullptr);
  }

  void VolumeControlReadCommon(uint16_t conn_id, uint16_t handle) {
    BtaGattQueue::ReadCharacteristic(conn_id, handle, chrc_read_callback_static,
                                     nullptr);
  }

  void OnVolumeControlStateChanged(VolumeControlDevice* device, uint16_t len,
                                   uint8_t* value) {
    if (len != 3) {
      LOG(INFO) << __func__ << ": malformed len=" << loghex(len);
      return;
    }

    uint8_t* pp = value;
    STREAM_TO_UINT8(device->volume, pp);
    STREAM_TO_UINT8(device->mute, pp);
    STREAM_TO_UINT8(device->change_counter, pp);

    LOG(INFO) << __func__ << " " << base::HexEncode(value, len);
    LOG(INFO) << __func__ << "volume " << loghex(device->volume) << "mute"
              << loghex(device->mute) << "change_counter"
              << loghex(device->change_counter);

    if (!device->device_ready) return;

    callbacks_->OnVolumeStateChanged(device->address, device->volume,
                                     device->mute);
  }

  void OnVolumeControlFlagsChanged(VolumeControlDevice* device, uint16_t len,
                                   uint8_t* value) {
    device->flags = *value;

    LOG(INFO) << __func__ << " " << base::HexEncode(value, len);
    LOG(INFO) << __func__ << "flags " << loghex(device->flags);
  }

  void OnGattWriteCcc(uint16_t connection_id, tGATT_STATUS status,
                      uint16_t handle, void* /*data*/) {
    VolumeControlDevice* device =
        volume_control_devices_.FindByConnId(connection_id);
    if (!device) {
      LOG(INFO) << __func__
                << "unknown connection_id=" << loghex(connection_id);
      BtaGattQueue::Clean(connection_id);
      return;
    }

    if (status != GATT_SUCCESS) {
      LOG(ERROR) << __func__
                 << "Failed to register for notification: " << loghex(handle)
                 << " status: " << status;
      device_cleanup_helper(device, true);
      return;
    }

    LOG(INFO) << __func__
              << "Successfully register for indications: " << loghex(handle);

    verify_device_ready(device, handle);
  }

  static void OnGattWriteCccStatic(uint16_t connection_id, tGATT_STATUS status,
                                   uint16_t handle, void* data) {
    if (!instance) {
      LOG(ERROR) << __func__ << "No instance=" << handle;
      return;
    }

    instance->OnGattWriteCcc(connection_id, status, handle, data);
  }

  void Dump(int fd) { volume_control_devices_.DebugDump(fd); }

  void Disconnect(const RawAddress& address) override {
    VolumeControlDevice* device =
        volume_control_devices_.FindByAddress(address);
    if (!device) {
      LOG(INFO) << "Device not connected to profile" << address;
      return;
    }

    LOG(INFO) << __func__ << ": " << address;
    LOG(INFO) << "GAP_EVT_CONN_CLOSED: " << device->address;
    device_cleanup_helper(device, true);
  }

  void OnGattDisconnected(uint16_t connection_id, tGATT_IF /*client_if*/,
                          RawAddress remote_bda,
                          tGATT_DISCONN_REASON /*reason*/) {
    VolumeControlDevice* device =
        volume_control_devices_.FindByConnId(connection_id);
    if (!device) {
      LOG(ERROR) << __func__
                 << " Skipping unknown device disconnect, connection_id="
                 << loghex(connection_id);
      return;
    }

    // If we get here, it means, device has not been exlicitly disconnected.
    bool device_ready = device->device_ready;

    device_cleanup_helper(device, device->connecting_actively);

    if (device_ready) {
      volume_control_devices_.Add(remote_bda, true);

      /* Add device into BG connection to accept remote initiated connection */
      BTA_GATTC_Open(gatt_if_, remote_bda, false, false);
    }
  }

  void OnWriteControlResponse(uint16_t connection_id, tGATT_STATUS status,
                              uint16_t handle, void* /*data*/) {
    VolumeControlDevice* device =
        volume_control_devices_.FindByConnId(connection_id);
    if (!device) {
      LOG(ERROR) << __func__
                 << "Skipping unknown device disconnect, connection_id="
                 << loghex(connection_id);
      return;
    }

    LOG(INFO) << "Write response handle: " << loghex(handle)
              << " status: " << loghex((int)(status));
  }

  void SetVolume(std::variant<RawAddress, int> addr_or_group_id,
                 uint8_t volume) override {
    LOG(INFO) << __func__ << "vol: " << +volume;

    if (std::holds_alternative<RawAddress>(addr_or_group_id)) {
      std::vector<RawAddress> devices = {
          std::get<RawAddress>(addr_or_group_id)};
      std::vector<uint8_t> arg({volume});
      devices_control_point_helper(devices,
                                   kControlPointOpcodeSetAbsoluteVolume, &arg);
      return;
    }

    /* TODO implement handling group request */
  }

  void CleanUp() {
    LOG(INFO) << __func__;
    volume_control_devices_.Disconnect(gatt_if_);
    volume_control_devices_.Clear();
    BTA_GATTC_AppDeregister(gatt_if_);
  }

 private:
  tGATT_IF gatt_if_;
  bluetooth::vc::VolumeControlCallbacks* callbacks_;
  VolumeControlDevices volume_control_devices_;

  void verify_device_ready(VolumeControlDevice* device, uint16_t handle) {
    if (device->device_ready) return;

    // VerifyReady sets the device_ready flag if all remaining GATT operations
    // are completed
    if (device->VerifyReady(handle)) {
      LOG(INFO) << __func__ << "Outstanding reads completed ";

      callbacks_->OnConnectionState(ConnectionState::CONNECTED,
                                    device->address);

      device->connecting_actively = true;

      device->first_connection = false;

      // once profile connected we can notify current states
      callbacks_->OnVolumeStateChanged(device->address, device->volume,
                                       device->mute);

      device->EnqueueRemainingRequests(gatt_if_, chrc_read_callback_static,
                                       OnGattWriteCccStatic);
    }
  }

  void device_cleanup_helper(VolumeControlDevice* device, bool notify) {
    device->Disconnect(gatt_if_);
    if (notify)
      callbacks_->OnConnectionState(ConnectionState::DISCONNECTED,
                                    device->address);
    volume_control_devices_.Remove(device->address);
  }

  void devices_control_point_helper(std::vector<RawAddress>& devices,
                                    uint8_t opcode,
                                    const std::vector<uint8_t>* arg) {
    volume_control_devices_.ControlPointOperation(
        devices, opcode, arg,
        [](uint16_t connection_id, tGATT_STATUS status, uint16_t handle,
           void* data) {
          if (instance)
            instance->OnWriteControlResponse(connection_id, status, handle,
                                             data);
        },
        nullptr);
  }

  void gattc_callback(tBTA_GATTC_EVT event, tBTA_GATTC* p_data) {
    LOG(INFO) << __func__ << " event = " << static_cast<int>(event);

    if (p_data == nullptr) return;

    switch (event) {
      case BTA_GATTC_OPEN_EVT: {
        tBTA_GATTC_OPEN& o = p_data->open;
        OnGattConnected(o.status, o.conn_id, o.client_if, o.remote_bda,
                        o.transport, o.mtu);

      } break;

      case BTA_GATTC_CLOSE_EVT: {
        tBTA_GATTC_CLOSE& c = p_data->close;
        OnGattDisconnected(c.conn_id, c.client_if, c.remote_bda, c.reason);
      } break;

      case BTA_GATTC_SEARCH_CMPL_EVT:
        OnServiceSearchComplete(p_data->search_cmpl.conn_id,
                                p_data->search_cmpl.status);
        break;

      case BTA_GATTC_NOTIF_EVT: {
        tBTA_GATTC_NOTIFY& n = p_data->notify;
        if (!n.is_notify || n.len > GATT_MAX_ATTR_LEN) {
          LOG(ERROR) << __func__ << ": rejected BTA_GATTC_NOTIF_EVT. is_notify="
                     << n.is_notify << ", len=" << static_cast<int>(n.len);
          break;
        }
        OnNotificationEvent(n.conn_id, n.handle, n.len, n.value);
      } break;

      case BTA_GATTC_ENC_CMPL_CB_EVT:
        OnEncryptionComplete(p_data->enc_cmpl.remote_bda, true);
        break;

      case BTA_GATTC_SRVC_CHG_EVT:
        OnServiceChangeEvent(p_data->remote_bda);
        break;

      case BTA_GATTC_SRVC_DISC_DONE_EVT:
        OnServiceDiscDoneEvent(p_data->remote_bda);
        break;

      default:
        break;
    }
  }

  static void gattc_callback_static(tBTA_GATTC_EVT event, tBTA_GATTC* p_data) {
    if (instance) instance->gattc_callback(event, p_data);
  }

  static void enc_callback_static(const RawAddress* address, tBT_TRANSPORT,
                                  void*, tBTM_STATUS status) {
    if (instance) instance->OnEncryptionComplete(*address, status);
  }

  static void chrc_read_callback_static(uint16_t conn_id, tGATT_STATUS status,
                                        uint16_t handle, uint16_t len,
                                        uint8_t* value, void* data) {
    if (instance)
      instance->OnCharacteristicValueChanged(conn_id, status, handle, len,
                                             value, data);
  }
};
}  // namespace

void VolumeControl::Initialize(
    bluetooth::vc::VolumeControlCallbacks* callbacks) {
  if (instance) {
    LOG(ERROR) << "Already initialized!";
    return;
  }

  instance = new VolumeControlImpl(callbacks);
}

bool VolumeControl::IsVolumeControlRunning() { return instance; }

VolumeControl* VolumeControl::Get(void) {
  CHECK(instance);
  return instance;
};

void VolumeControl::AddFromStorage(const RawAddress& address,
                                   bool auto_connect) {
  if (!instance) {
    LOG(ERROR) << "Not initialized yet";
    return;
  }

  instance->AddFromStorage(address, auto_connect);
};

void VolumeControl::CleanUp() {
  if (!instance) {
    LOG(ERROR) << "not initialized!";
    return;
  }

  VolumeControlImpl* ptr = instance;
  instance = nullptr;

  ptr->CleanUp();

  delete ptr;
};

void VolumeControl::DebugDump(int fd) {
  dprintf(fd, "Volume Control Manager:\n");
  if (instance) instance->Dump(fd);
  dprintf(fd, "\n");
}
