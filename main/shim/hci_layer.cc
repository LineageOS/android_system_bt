/*
 * Copyright 2019 The Android Open Source Project
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

#define LOG_TAG "bt_gd_hci"

#include <base/bind.h>
#include <frameworks/base/core/proto/android/bluetooth/hci/enums.pb.h>
#include <algorithm>
#include <cstdint>

#include "btcore/include/module.h"
#include "main/shim/hci_layer.h"
#include "main/shim/shim.h"
#include "osi/include/allocator.h"
#include "osi/include/future.h"
#include "stack/include/bt_types.h"

/**
 * Callback data wrapped as opaque token bundled with the command
 * transmit request to the Gd layer.
 *
 * Upon completion a token for a corresponding command transmit.
 * request is returned from the Gd layer.
 */
using CommandCallbackData = struct {
  void* context;
  command_complete_cb complete_callback;
  command_status_cb status_callback;
};

constexpr size_t kBtHdrSize = sizeof(BT_HDR);
constexpr size_t kCommandLengthSize = sizeof(uint8_t);
constexpr size_t kCommandOpcodeSize = sizeof(uint16_t);

static hci_t interface;
static base::Callback<void(const base::Location&, BT_HDR*)> send_data_upwards;

static future_t* hci_module_shut_down(void);
static future_t* hci_module_start_up(void);

static void OnCommandComplete(uint16_t command_op_code,
                              std::vector<const uint8_t> data,
                              const void* token) {
  BT_HDR* response = static_cast<BT_HDR*>(osi_calloc(data.size() + kBtHdrSize));
  std::copy(data.begin(), data.end(), response->data);
  response->len = data.size();

  const CommandCallbackData* command_callback_data =
      static_cast<const CommandCallbackData*>(token);
  CHECK(command_callback_data->complete_callback != nullptr);

  command_callback_data->complete_callback(response,
                                           command_callback_data->context);
  delete command_callback_data;
}

static void OnCommandStatus(uint16_t command_op_code,
                            std::vector<const uint8_t> data, const void* token,
                            uint8_t status) {
  BT_HDR* response = static_cast<BT_HDR*>(osi_calloc(data.size() + kBtHdrSize));
  std::copy(data.begin(), data.end(), response->data);
  response->len = data.size();

  const CommandCallbackData* command_callback_data =
      static_cast<const CommandCallbackData*>(token);
  CHECK(command_callback_data->status_callback != nullptr);

  command_callback_data->status_callback(status, response,
                                         command_callback_data->context);
  delete command_callback_data;
}

EXPORT_SYMBOL extern const module_t gd_hci_module = {
    .name = GD_HCI_MODULE,
    .init = nullptr,
    .start_up = hci_module_start_up,
    .shut_down = hci_module_shut_down,
    .clean_up = nullptr,
    .dependencies = {GD_SHIM_MODULE, nullptr}};

static future_t* hci_module_start_up(void) {
  bluetooth::shim::GetHciLayer()->RegisterCommandComplete(OnCommandComplete);
  bluetooth::shim::GetHciLayer()->RegisterCommandStatus(OnCommandStatus);
  return nullptr;
}

static future_t* hci_module_shut_down(void) {
  bluetooth::shim::GetHciLayer()->UnregisterCommandComplete();
  bluetooth::shim::GetHciLayer()->UnregisterCommandStatus();
  return nullptr;
}

static void set_data_cb(
    base::Callback<void(const base::Location&, BT_HDR*)> send_data_cb) {
  send_data_upwards = std::move(send_data_cb);
}

static void transmit_command(BT_HDR* command,
                             command_complete_cb complete_callback,
                             command_status_cb status_callback, void* context) {
  CHECK(command != nullptr);
  uint8_t* data = command->data + command->offset;
  size_t len = command->len;
  CHECK(len >= (kCommandOpcodeSize + kCommandLengthSize));

  // little endian command opcode
  uint16_t command_op_code = (data[1] << 8 | data[0]);
  // Gd stack API requires opcode specification and calculates length, so
  // no need to provide opcode or length here.
  data += (kCommandOpcodeSize + kCommandLengthSize);
  len -= (kCommandOpcodeSize + kCommandLengthSize);

  const CommandCallbackData* command_callback_data = new CommandCallbackData{
      context,
      complete_callback,
      status_callback,
  };
  bluetooth::shim::GetHciLayer()->TransmitCommand(
      command_op_code, const_cast<const uint8_t*>(data), len,
      static_cast<const void*>(command_callback_data));
}

const hci_t* bluetooth::shim::hci_layer_get_interface() {
  static bool loaded = false;
  if (!loaded) {
    loaded = true;
    interface.set_data_cb = set_data_cb;
    interface.transmit_command = transmit_command;
    interface.transmit_command_futured = nullptr;
    interface.transmit_downward = nullptr;
  }
  return &interface;
}
