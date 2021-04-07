/*
 * Copyright 2020 HIMSA II K/S - www.himsa.com.
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

#include <map>
#include <vector>

#include "bta_gatt_api.h"
#include "bta_gatt_queue.h"
#include "devices.h"
#include "gatt_api.h"
#include "stack/btm/btm_sec.h"

using namespace bluetooth::vc::internal;

void VolumeControlDevice::Disconnect(tGATT_IF gatt_if) {
  LOG(INFO) << __func__ << ": " << this->ToString();

  if (IsConnected()) {
    if (volume_state_handle != 0)
      BTA_GATTC_DeregisterForNotifications(gatt_if, address,
                                           volume_state_handle);

    if (volume_flags_handle != 0)
      BTA_GATTC_DeregisterForNotifications(gatt_if, address,
                                           volume_flags_handle);

    BtaGattQueue::Clean(connection_id);
    BTA_GATTC_Close(connection_id);
    connection_id = GATT_INVALID_CONN_ID;
  } else {
    BTA_GATTC_CancelOpen(gatt_if, address, false);
  }

  device_ready = false;
  handles_pending.clear();
}

/*
 * Find the handle for the client characteristics configuration of a given
 * characteristics
 */
uint16_t VolumeControlDevice::find_ccc_handle(uint16_t chrc_handle) {
  const gatt::Characteristic* p_char =
      BTA_GATTC_GetCharacteristic(connection_id, chrc_handle);
  if (!p_char) {
    LOG(WARNING) << __func__ << ": no such handle=" << loghex(chrc_handle);
    return 0;
  }

  for (const gatt::Descriptor& desc : p_char->descriptors) {
    if (desc.uuid == Uuid::From16Bit(GATT_UUID_CHAR_CLIENT_CONFIG))
      return desc.handle;
  }

  return 0;
}

bool VolumeControlDevice::set_volume_control_service_handles(
    const gatt::Service& service) {
  uint16_t state_handle = 0, state_ccc_handle = 0, control_point_handle = 0,
           flags_handle = 0, flags_ccc_handle = 0;

  for (const gatt::Characteristic& chrc : service.characteristics) {
    if (chrc.uuid == kVolumeControlStateUuid) {
      state_handle = chrc.value_handle;
      state_ccc_handle = find_ccc_handle(chrc.value_handle);
    } else if (chrc.uuid == kVolumeControlPointUuid) {
      control_point_handle = chrc.value_handle;
    } else if (chrc.uuid == kVolumeFlagsUuid) {
      flags_handle = chrc.value_handle;
      flags_ccc_handle = find_ccc_handle(chrc.value_handle);
    } else {
      LOG(WARNING) << __func__ << ": unknown characteristic=" << chrc.uuid;
    }
  }

  // Validate service handles
  if (GATT_HANDLE_IS_VALID(state_handle) &&
      GATT_HANDLE_IS_VALID(state_ccc_handle) &&
      GATT_HANDLE_IS_VALID(control_point_handle) &&
      GATT_HANDLE_IS_VALID(flags_handle)
      /* volume_flags_ccc_handle is optional */) {
    volume_state_handle = state_handle;
    volume_state_ccc_handle = state_ccc_handle;
    volume_control_point_handle = control_point_handle;
    volume_flags_handle = flags_handle;
    volume_flags_ccc_handle = flags_ccc_handle;
    return true;
  }

  return false;
}

bool VolumeControlDevice::UpdateHandles(void) {
  ResetHandles();

  bool vcs_found = false;
  const std::list<gatt::Service>* services =
      BTA_GATTC_GetServices(connection_id);
  if (services == nullptr) {
    LOG(ERROR) << "No services found";
    return false;
  }

  for (auto const& service : *services) {
    if (service.uuid == kVolumeControlUuid) {
      LOG(INFO) << "Found VCS, handle=" << loghex(service.handle);
      vcs_found = set_volume_control_service_handles(service);
      if (!vcs_found) break;
    }
  }

  return vcs_found;
}

void VolumeControlDevice::ResetHandles(void) {
  device_ready = false;

  // the handles are not valid, so discard pending GATT operations
  BtaGattQueue::Clean(connection_id);

  volume_state_handle = 0;
  volume_state_ccc_handle = 0;
  volume_control_point_handle = 0;
  volume_flags_handle = 0;
  volume_flags_ccc_handle = 0;
}

void VolumeControlDevice::ControlPointOperation(uint8_t opcode,
                                                const std::vector<uint8_t>* arg,
                                                GATT_WRITE_OP_CB cb,
                                                void* cb_data) {
  std::vector<uint8_t> set_value({opcode, change_counter});
  if (arg != nullptr)
    set_value.insert(set_value.end(), (*arg).begin(), (*arg).end());

  BtaGattQueue::WriteCharacteristic(connection_id, volume_control_point_handle,
                                    set_value, GATT_WRITE, cb, cb_data);
}

bool VolumeControlDevice::subscribe_for_notifications(tGATT_IF gatt_if,
                                                      uint16_t handle,
                                                      uint16_t ccc_handle,
                                                      GATT_WRITE_OP_CB cb) {
  tGATT_STATUS status =
      BTA_GATTC_RegisterForNotifications(gatt_if, address, handle);
  if (status != GATT_SUCCESS) {
    LOG(ERROR) << __func__ << ": failed, status=" << loghex(+status);
    return false;
  }

  std::vector<uint8_t> value(2);
  uint8_t* ptr = value.data();
  UINT16_TO_STREAM(ptr, GATT_CHAR_CLIENT_CONFIG_NOTIFICATION);
  BtaGattQueue::WriteDescriptor(connection_id, ccc_handle, std::move(value),
                                GATT_WRITE, cb, nullptr);

  return true;
}

/**
 * Enqueue GATT requests that are required by the Volume Control to be
 * functional. This includes State characteristics read and subscription.
 * Those characteristics contain the change counter needed to send any request
 * via Control Point. Once completed successfully, the device can be stored
 * and reported as connected. In each case we subscribe first to be sure we do
 * not miss any value change.
 */
bool VolumeControlDevice::EnqueueInitialRequests(
    tGATT_IF gatt_if, GATT_READ_OP_CB chrc_read_cb,
    GATT_WRITE_OP_CB cccd_write_cb) {
  handles_pending.clear();
  handles_pending.insert(volume_state_handle);
  handles_pending.insert(volume_state_ccc_handle);
  if (!subscribe_for_notifications(gatt_if, volume_state_handle,
                                   volume_state_ccc_handle, cccd_write_cb)) {
    return false;
  }

  BtaGattQueue::ReadCharacteristic(connection_id, volume_state_handle,
                                   chrc_read_cb, nullptr);

  return true;
}

/**
 * Enqueue the remaining requests. Those are not so crucial and can be done
 * once Volume Control instance indicates it's readiness to profile.
 * This includes characteristics read and subscription.
 * In each case we subscribe first to be sure we do not miss any value change.
 */
void VolumeControlDevice::EnqueueRemainingRequests(
    tGATT_IF gatt_if, GATT_READ_OP_CB chrc_read_cb,
    GATT_WRITE_OP_CB cccd_write_cb) {
  std::map<uint16_t, uint16_t> handle_pairs{
      {volume_flags_handle, volume_flags_ccc_handle},
  };

  for (auto const& handles : handle_pairs) {
    if (GATT_HANDLE_IS_VALID(handles.second)) {
      subscribe_for_notifications(gatt_if, handles.first, handles.second,
                                  cccd_write_cb);
    }

    BtaGattQueue::ReadCharacteristic(connection_id, handles.first, chrc_read_cb,
                                     nullptr);
  }
}

bool VolumeControlDevice::VerifyReady(uint16_t handle) {
  handles_pending.erase(handle);
  device_ready = handles_pending.size() == 0;
  return device_ready;
}

bool VolumeControlDevice::IsEncryptionEnabled() {
  uint8_t sec_flag = 0;
  bool device_found =
      BTM_GetSecurityFlagsByTransport(address, &sec_flag, BT_TRANSPORT_LE);
  LOG(INFO) << __func__ << ": found=" << static_cast<int>(device_found)
            << " sec_flag=" << loghex(sec_flag);
  return device_found && (sec_flag & BTM_SEC_FLAG_ENCRYPTED);
}

bool VolumeControlDevice::EnableEncryption(tBTM_SEC_CALLBACK* callback) {
  int result = BTM_SetEncryption(address, BT_TRANSPORT_LE, callback, nullptr,
                                 BTM_BLE_SEC_ENCRYPT);
  LOG(INFO) << __func__ << ": result=" << +result;
  // TODO: should we care about the result??
  return true;
}
