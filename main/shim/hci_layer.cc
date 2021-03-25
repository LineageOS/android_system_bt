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

#define LOG_TAG "bt_shim_hci"

#include "hci/hci_layer.h"

#include <base/bind.h>

#include <algorithm>
#include <cstdint>

#include "callbacks/callbacks.h"
#include "gd/common/init_flags.h"
#include "hci/hci_packets.h"
#include "hci/include/packet_fragmenter.h"
#include "hci/le_acl_connection_interface.h"
#include "main/shim/hci_layer.h"
#include "main/shim/shim.h"
#include "main/shim/stack.h"
#include "osi/include/allocator.h"
#include "osi/include/future.h"
#include "packet/raw_builder.h"
#include "src/hci.rs.h"
#include "stack/include/bt_types.h"

/**
 * Callback data wrapped as opaque token bundled with the command
 * transmit request to the Gd layer.
 *
 * Upon completion a token for a corresponding command transmit.
 * request is returned from the Gd layer.
 */
using CommandCallbackData = struct { void* context; };

constexpr size_t kBtHdrSize = sizeof(BT_HDR);
constexpr size_t kCommandLengthSize = sizeof(uint8_t);
constexpr size_t kCommandOpcodeSize = sizeof(uint16_t);

static base::Callback<void(const base::Location&, BT_HDR*)> send_data_upwards;
static const packet_fragmenter_t* packet_fragmenter;

namespace {
bool is_valid_event_code(uint8_t event_code_raw) {
  auto event_code = static_cast<bluetooth::hci::EventCode>(event_code_raw);
  switch (event_code) {
    case bluetooth::hci::EventCode::INQUIRY_COMPLETE:
    case bluetooth::hci::EventCode::INQUIRY_RESULT:
    case bluetooth::hci::EventCode::CONNECTION_COMPLETE:
    case bluetooth::hci::EventCode::CONNECTION_REQUEST:
    case bluetooth::hci::EventCode::DISCONNECTION_COMPLETE:
    case bluetooth::hci::EventCode::AUTHENTICATION_COMPLETE:
    case bluetooth::hci::EventCode::REMOTE_NAME_REQUEST_COMPLETE:
    case bluetooth::hci::EventCode::ENCRYPTION_CHANGE:
    case bluetooth::hci::EventCode::CHANGE_CONNECTION_LINK_KEY_COMPLETE:
    case bluetooth::hci::EventCode::CENTRAL_LINK_KEY_COMPLETE:
    case bluetooth::hci::EventCode::READ_REMOTE_SUPPORTED_FEATURES_COMPLETE:
    case bluetooth::hci::EventCode::READ_REMOTE_VERSION_INFORMATION_COMPLETE:
    case bluetooth::hci::EventCode::QOS_SETUP_COMPLETE:
    case bluetooth::hci::EventCode::COMMAND_COMPLETE:
    case bluetooth::hci::EventCode::COMMAND_STATUS:
    case bluetooth::hci::EventCode::HARDWARE_ERROR:
    case bluetooth::hci::EventCode::FLUSH_OCCURRED:
    case bluetooth::hci::EventCode::ROLE_CHANGE:
    case bluetooth::hci::EventCode::NUMBER_OF_COMPLETED_PACKETS:
    case bluetooth::hci::EventCode::MODE_CHANGE:
    case bluetooth::hci::EventCode::RETURN_LINK_KEYS:
    case bluetooth::hci::EventCode::PIN_CODE_REQUEST:
    case bluetooth::hci::EventCode::LINK_KEY_REQUEST:
    case bluetooth::hci::EventCode::LINK_KEY_NOTIFICATION:
    case bluetooth::hci::EventCode::LOOPBACK_COMMAND:
    case bluetooth::hci::EventCode::DATA_BUFFER_OVERFLOW:
    case bluetooth::hci::EventCode::MAX_SLOTS_CHANGE:
    case bluetooth::hci::EventCode::READ_CLOCK_OFFSET_COMPLETE:
    case bluetooth::hci::EventCode::CONNECTION_PACKET_TYPE_CHANGED:
    case bluetooth::hci::EventCode::QOS_VIOLATION:
    case bluetooth::hci::EventCode::PAGE_SCAN_REPETITION_MODE_CHANGE:
    case bluetooth::hci::EventCode::FLOW_SPECIFICATION_COMPLETE:
    case bluetooth::hci::EventCode::INQUIRY_RESULT_WITH_RSSI:
    case bluetooth::hci::EventCode::READ_REMOTE_EXTENDED_FEATURES_COMPLETE:
    case bluetooth::hci::EventCode::SYNCHRONOUS_CONNECTION_COMPLETE:
    case bluetooth::hci::EventCode::SYNCHRONOUS_CONNECTION_CHANGED:
    case bluetooth::hci::EventCode::SNIFF_SUBRATING:
    case bluetooth::hci::EventCode::EXTENDED_INQUIRY_RESULT:
    case bluetooth::hci::EventCode::ENCRYPTION_KEY_REFRESH_COMPLETE:
    case bluetooth::hci::EventCode::IO_CAPABILITY_REQUEST:
    case bluetooth::hci::EventCode::IO_CAPABILITY_RESPONSE:
    case bluetooth::hci::EventCode::USER_CONFIRMATION_REQUEST:
    case bluetooth::hci::EventCode::USER_PASSKEY_REQUEST:
    case bluetooth::hci::EventCode::REMOTE_OOB_DATA_REQUEST:
    case bluetooth::hci::EventCode::SIMPLE_PAIRING_COMPLETE:
    case bluetooth::hci::EventCode::LINK_SUPERVISION_TIMEOUT_CHANGED:
    case bluetooth::hci::EventCode::ENHANCED_FLUSH_COMPLETE:
    case bluetooth::hci::EventCode::USER_PASSKEY_NOTIFICATION:
    case bluetooth::hci::EventCode::KEYPRESS_NOTIFICATION:
    case bluetooth::hci::EventCode::REMOTE_HOST_SUPPORTED_FEATURES_NOTIFICATION:
    case bluetooth::hci::EventCode::NUMBER_OF_COMPLETED_DATA_BLOCKS:
    case bluetooth::hci::EventCode::VENDOR_SPECIFIC:
      return true;
    case bluetooth::hci::EventCode::LE_META_EVENT:  // Private to hci
      return false;
  }
  return false;
};

bool is_valid_subevent_code(uint8_t subevent_code_raw) {
  auto subevent_code =
      static_cast<bluetooth::hci::SubeventCode>(subevent_code_raw);
  switch (subevent_code) {
    case bluetooth::hci::SubeventCode::CONNECTION_COMPLETE:
    case bluetooth::hci::SubeventCode::CONNECTION_UPDATE_COMPLETE:
    case bluetooth::hci::SubeventCode::DATA_LENGTH_CHANGE:
    case bluetooth::hci::SubeventCode::ENHANCED_CONNECTION_COMPLETE:
    case bluetooth::hci::SubeventCode::PHY_UPDATE_COMPLETE:
    case bluetooth::hci::SubeventCode::READ_REMOTE_FEATURES_COMPLETE:
    case bluetooth::hci::SubeventCode::REMOTE_CONNECTION_PARAMETER_REQUEST:
    case bluetooth::hci::SubeventCode::READ_LOCAL_P256_PUBLIC_KEY_COMPLETE:
    case bluetooth::hci::SubeventCode::GENERATE_DHKEY_COMPLETE:
    case bluetooth::hci::SubeventCode::DIRECTED_ADVERTISING_REPORT:
    case bluetooth::hci::SubeventCode::EXTENDED_ADVERTISING_REPORT:
    case bluetooth::hci::SubeventCode::PERIODIC_ADVERTISING_SYNC_ESTABLISHED:
    case bluetooth::hci::SubeventCode::PERIODIC_ADVERTISING_REPORT:
    case bluetooth::hci::SubeventCode::PERIODIC_ADVERTISING_SYNC_LOST:
    case bluetooth::hci::SubeventCode::SCAN_TIMEOUT:
    case bluetooth::hci::SubeventCode::ADVERTISING_SET_TERMINATED:
    case bluetooth::hci::SubeventCode::SCAN_REQUEST_RECEIVED:
    case bluetooth::hci::SubeventCode::CHANNEL_SELECTION_ALGORITHM:
    case bluetooth::hci::SubeventCode::CONNECTIONLESS_IQ_REPORT:
    case bluetooth::hci::SubeventCode::CONNECTION_IQ_REPORT:
    case bluetooth::hci::SubeventCode::CTE_REQUEST_FAILED:
    case bluetooth::hci::SubeventCode::
        PERIODIC_ADVERTISING_SYNC_TRANSFER_RECEIVED:
    case bluetooth::hci::SubeventCode::CIS_ESTABLISHED:
    case bluetooth::hci::SubeventCode::CIS_REQUEST:
    case bluetooth::hci::SubeventCode::CREATE_BIG_COMPLETE:
    case bluetooth::hci::SubeventCode::TERMINATE_BIG_COMPLETE:
    case bluetooth::hci::SubeventCode::BIG_SYNC_ESTABLISHED:
    case bluetooth::hci::SubeventCode::BIG_SYNC_LOST:
    case bluetooth::hci::SubeventCode::REQUEST_PEER_SCA_COMPLETE:
    case bluetooth::hci::SubeventCode::PATH_LOSS_THRESHOLD:
    case bluetooth::hci::SubeventCode::TRANSMIT_POWER_REPORTING:
    case bluetooth::hci::SubeventCode::BIG_INFO_ADVERTISING_REPORT:
    case bluetooth::hci::SubeventCode::ADVERTISING_REPORT:
    case bluetooth::hci::SubeventCode::LONG_TERM_KEY_REQUEST:
      return true;
    default:
      return false;
  }
}

bool is_valid_vendor_specific_event(uint8_t vse_code_raw) {
  auto vse_code = static_cast<bluetooth::hci::VseSubeventCode>(vse_code_raw);
  switch (vse_code) {
    case bluetooth::hci::VseSubeventCode::BQR_EVENT:
    case bluetooth::hci::VseSubeventCode::BLE_THRESHOLD:
    case bluetooth::hci::VseSubeventCode::BLE_TRACKING:
    case bluetooth::hci::VseSubeventCode::DEBUG_INFO:
      return true;
    default:
      return false;
  }
}

static bool event_already_registered_in_hci_layer(
    bluetooth::hci::EventCode event_code) {
  switch (event_code) {
    case bluetooth::hci::EventCode::COMMAND_COMPLETE:
    case bluetooth::hci::EventCode::COMMAND_STATUS:
    case bluetooth::hci::EventCode::PAGE_SCAN_REPETITION_MODE_CHANGE:
    case bluetooth::hci::EventCode::MAX_SLOTS_CHANGE:
    case bluetooth::hci::EventCode::VENDOR_SPECIFIC:
      return bluetooth::shim::is_gd_hci_enabled();
    case bluetooth::hci::EventCode::DISCONNECTION_COMPLETE:
    case bluetooth::hci::EventCode::READ_REMOTE_VERSION_INFORMATION_COMPLETE:
    case bluetooth::hci::EventCode::LE_META_EVENT:
      return bluetooth::shim::is_gd_acl_enabled() ||
             bluetooth::shim::is_gd_l2cap_enabled();
    default:
      return false;
  }
}

static bool event_already_registered_in_controller_layer(
    bluetooth::hci::EventCode event_code) {
  switch (event_code) {
    case bluetooth::hci::EventCode::NUMBER_OF_COMPLETED_PACKETS:
      return bluetooth::shim::is_gd_acl_enabled() ||
             bluetooth::shim::is_gd_l2cap_enabled();
    default:
      return false;
  }
}

static bool event_already_registered_in_acl_layer(
    bluetooth::hci::EventCode event_code) {
  for (auto event : bluetooth::hci::AclConnectionEvents) {
    if (event == event_code) {
      return bluetooth::shim::is_gd_acl_enabled() ||
             bluetooth::shim::is_gd_l2cap_enabled();
    }
  }
  return false;
}

static bool subevent_already_registered_in_le_hci_layer(
    bluetooth::hci::SubeventCode subevent_code) {
  switch (subevent_code) {
    case bluetooth::hci::SubeventCode::CONNECTION_COMPLETE:
    case bluetooth::hci::SubeventCode::CONNECTION_UPDATE_COMPLETE:
    case bluetooth::hci::SubeventCode::DATA_LENGTH_CHANGE:
    case bluetooth::hci::SubeventCode::ENHANCED_CONNECTION_COMPLETE:
    case bluetooth::hci::SubeventCode::PHY_UPDATE_COMPLETE:
    case bluetooth::hci::SubeventCode::REMOTE_CONNECTION_PARAMETER_REQUEST:
      return bluetooth::shim::is_gd_acl_enabled() ||
             bluetooth::shim::is_gd_l2cap_enabled() ||
             bluetooth::shim::is_gd_advertising_enabled() ||
             bluetooth::shim::is_gd_scanning_enabled();
    case bluetooth::hci::SubeventCode::ADVERTISING_SET_TERMINATED:
    case bluetooth::hci::SubeventCode::SCAN_REQUEST_RECEIVED:
      return bluetooth::shim::is_gd_acl_enabled() ||
             bluetooth::shim::is_gd_l2cap_enabled() ||
             bluetooth::shim::is_gd_advertising_enabled();
    case bluetooth::hci::SubeventCode::SCAN_TIMEOUT:
    case bluetooth::hci::SubeventCode::ADVERTISING_REPORT:
    case bluetooth::hci::SubeventCode::DIRECTED_ADVERTISING_REPORT:
    case bluetooth::hci::SubeventCode::EXTENDED_ADVERTISING_REPORT:
    case bluetooth::hci::SubeventCode::PERIODIC_ADVERTISING_REPORT:
    case bluetooth::hci::SubeventCode::PERIODIC_ADVERTISING_SYNC_ESTABLISHED:
    case bluetooth::hci::SubeventCode::PERIODIC_ADVERTISING_SYNC_LOST:
      return bluetooth::shim::is_gd_scanning_enabled();
    case bluetooth::hci::SubeventCode::READ_REMOTE_FEATURES_COMPLETE:
    case bluetooth::hci::SubeventCode::READ_LOCAL_P256_PUBLIC_KEY_COMPLETE:
    case bluetooth::hci::SubeventCode::GENERATE_DHKEY_COMPLETE:
    case bluetooth::hci::SubeventCode::CHANNEL_SELECTION_ALGORITHM:
    case bluetooth::hci::SubeventCode::CONNECTIONLESS_IQ_REPORT:
    case bluetooth::hci::SubeventCode::CONNECTION_IQ_REPORT:
    case bluetooth::hci::SubeventCode::CTE_REQUEST_FAILED:
    case bluetooth::hci::SubeventCode::
        PERIODIC_ADVERTISING_SYNC_TRANSFER_RECEIVED:
    case bluetooth::hci::SubeventCode::CIS_ESTABLISHED:
    case bluetooth::hci::SubeventCode::CIS_REQUEST:
    case bluetooth::hci::SubeventCode::CREATE_BIG_COMPLETE:
    case bluetooth::hci::SubeventCode::TERMINATE_BIG_COMPLETE:
    case bluetooth::hci::SubeventCode::BIG_SYNC_ESTABLISHED:
    case bluetooth::hci::SubeventCode::BIG_SYNC_LOST:
    case bluetooth::hci::SubeventCode::REQUEST_PEER_SCA_COMPLETE:
    case bluetooth::hci::SubeventCode::PATH_LOSS_THRESHOLD:
    case bluetooth::hci::SubeventCode::TRANSMIT_POWER_REPORTING:
    case bluetooth::hci::SubeventCode::BIG_INFO_ADVERTISING_REPORT:
    case bluetooth::hci::SubeventCode::LONG_TERM_KEY_REQUEST:
    default:
      return false;
  }
}

static bool event_already_registered_in_le_advertising_manager(
    bluetooth::hci::EventCode event_code) {
  for (auto event : bluetooth::hci::AclConnectionEvents) {
    if (event == event_code) {
      return bluetooth::shim::is_gd_advertising_enabled();
    }
  }
  return false;
}

static bool event_already_registered_in_le_scanning_manager(
    bluetooth::hci::EventCode event_code) {
  for (auto event : bluetooth::hci::AclConnectionEvents) {
    if (event == event_code) {
      return bluetooth::shim::is_gd_scanning_enabled();
    }
  }
  return false;
}

class OsiObject {
 public:
  OsiObject(void* ptr) : ptr_(ptr) {}
  ~OsiObject() {
    if (ptr_ != nullptr) {
      osi_free(ptr_);
    }
  }
  void* Release() {
    void* ptr = ptr_;
    ptr_ = nullptr;
    return ptr;
  }

 private:
  void* ptr_;
};

}  // namespace

namespace cpp {
bluetooth::common::BidiQueueEnd<bluetooth::hci::AclBuilder,
                                bluetooth::hci::AclView>* hci_queue_end =
    nullptr;
static bluetooth::os::EnqueueBuffer<bluetooth::hci::AclBuilder>* pending_data =
    nullptr;

static std::unique_ptr<bluetooth::packet::RawBuilder> MakeUniquePacket(
    const uint8_t* data, size_t len) {
  bluetooth::packet::RawBuilder builder;
  std::vector<uint8_t> bytes(data, data + len);

  auto payload = std::make_unique<bluetooth::packet::RawBuilder>();
  payload->AddOctets(bytes);

  return payload;
}

static BT_HDR* WrapPacketAndCopy(
    uint16_t event,
    bluetooth::hci::PacketView<bluetooth::hci::kLittleEndian>* data) {
  size_t packet_size = data->size() + kBtHdrSize;
  BT_HDR* packet = reinterpret_cast<BT_HDR*>(osi_malloc(packet_size));
  packet->offset = 0;
  packet->len = data->size();
  packet->layer_specific = 0;
  packet->event = event;
  std::copy(data->begin(), data->end(), packet->data);
  return packet;
}

static void event_callback(bluetooth::hci::EventView event_packet_view) {
  if (!send_data_upwards) {
    return;
  }
  send_data_upwards.Run(FROM_HERE, WrapPacketAndCopy(MSG_HC_TO_STACK_HCI_EVT,
                                                     &event_packet_view));
}

static void subevent_callback(
    bluetooth::hci::LeMetaEventView le_meta_event_view) {
  if (!send_data_upwards) {
    return;
  }
  send_data_upwards.Run(FROM_HERE, WrapPacketAndCopy(MSG_HC_TO_STACK_HCI_EVT,
                                                     &le_meta_event_view));
}

static void vendor_specific_event_callback(
    bluetooth::hci::VendorSpecificEventView vendor_specific_event_view) {
  if (!send_data_upwards) {
    return;
  }
  send_data_upwards.Run(
      FROM_HERE,
      WrapPacketAndCopy(MSG_HC_TO_STACK_HCI_EVT, &vendor_specific_event_view));
}

void OnTransmitPacketCommandComplete(command_complete_cb complete_callback,
                                     void* context,
                                     bluetooth::hci::CommandCompleteView view) {
  LOG_DEBUG("Received cmd complete for %s",
            bluetooth::hci::OpCodeText(view.GetCommandOpCode()).c_str());
  std::vector<const uint8_t> data(view.begin(), view.end());
  BT_HDR* response = WrapPacketAndCopy(MSG_HC_TO_STACK_HCI_EVT, &view);
  complete_callback(response, context);
}

void OnTransmitPacketStatus(command_status_cb status_callback, void* context,
                            std::unique_ptr<OsiObject> command,
                            bluetooth::hci::CommandStatusView view) {
  LOG_DEBUG("Received cmd status %s for %s",
            bluetooth::hci::ErrorCodeText(view.GetStatus()).c_str(),
            bluetooth::hci::OpCodeText(view.GetCommandOpCode()).c_str());
  uint8_t status = static_cast<uint8_t>(view.GetStatus());
  status_callback(status, static_cast<BT_HDR*>(command->Release()), context);
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

  auto op_code = static_cast<const bluetooth::hci::OpCode>(command_op_code);

  auto payload = MakeUniquePacket(data, len);
  auto packet =
      bluetooth::hci::CommandBuilder::Create(op_code, std::move(payload));

  LOG_DEBUG("Sending command %s", bluetooth::hci::OpCodeText(op_code).c_str());

  if (bluetooth::hci::Checker::IsCommandStatusOpcode(op_code)) {
    auto command_unique = std::make_unique<OsiObject>(command);
    bluetooth::shim::GetHciLayer()->EnqueueCommand(
        std::move(packet), bluetooth::shim::GetGdShimHandler()->BindOnce(
                               OnTransmitPacketStatus, status_callback, context,
                               std::move(command_unique)));
  } else {
    bluetooth::shim::GetHciLayer()->EnqueueCommand(
        std::move(packet),
        bluetooth::shim::GetGdShimHandler()->BindOnce(
            OnTransmitPacketCommandComplete, complete_callback, context));
    osi_free(command);
  }
}

static void transmit_fragment(uint8_t* stream, size_t length) {
  uint16_t handle_with_flags;
  STREAM_TO_UINT16(handle_with_flags, stream);
  auto pb_flag = static_cast<bluetooth::hci::PacketBoundaryFlag>(
      handle_with_flags >> 12 & 0b11);
  auto bc_flag =
      static_cast<bluetooth::hci::BroadcastFlag>(handle_with_flags >> 14);
  uint16_t handle = handle_with_flags & 0xEFF;
  length -= 2;
  // skip data total length
  stream += 2;
  length -= 2;
  auto payload = MakeUniquePacket(stream, length);
  auto acl_packet = bluetooth::hci::AclBuilder::Create(handle, pb_flag, bc_flag,
                                                       std::move(payload));
  pending_data->Enqueue(std::move(acl_packet),
                        bluetooth::shim::GetGdShimHandler());
}

static void register_event(bluetooth::hci::EventCode event_code) {
  auto handler = bluetooth::shim::GetGdShimHandler();
  bluetooth::shim::GetHciLayer()->RegisterEventHandler(
      event_code, handler->Bind(event_callback));
}

static void register_le_event(bluetooth::hci::SubeventCode subevent_code) {
  auto handler = bluetooth::shim::GetGdShimHandler();
  bluetooth::shim::GetHciLayer()->RegisterLeEventHandler(
      subevent_code, handler->Bind(subevent_callback));
}

static void register_vendor_specific_event(
    bluetooth::hci::VseSubeventCode vse_code) {
  auto handler = bluetooth::shim::GetGdShimHandler();
  bluetooth::shim::GetHciLayer()->RegisterVendorSpecificEventHandler(
      vse_code, handler->Bind(vendor_specific_event_callback));
}

static void acl_data_callback() {
  if (hci_queue_end == nullptr) {
    return;
  }
  auto packet = hci_queue_end->TryDequeue();
  ASSERT(packet != nullptr);
  if (!packet->IsValid()) {
    LOG_INFO("Dropping invalid packet of size %zu", packet->size());
    return;
  }
  if (!send_data_upwards) {
    return;
  }
  auto data = WrapPacketAndCopy(MSG_HC_TO_STACK_HCI_ACL, packet.get());
  packet_fragmenter->reassemble_and_dispatch(data);
}

static void register_for_acl() {
  hci_queue_end = bluetooth::shim::GetHciLayer()->GetAclQueueEnd();

  // if gd advertising/scanning enabled, hci_queue_end will be register in
  // AclManager::impl::Start
  if (!bluetooth::shim::is_gd_advertising_enabled() &&
      !bluetooth::shim::is_gd_scanning_enabled() &&
      !bluetooth::shim::is_gd_l2cap_enabled()) {
    hci_queue_end->RegisterDequeue(bluetooth::shim::GetGdShimHandler(),
                                   bluetooth::common::Bind(acl_data_callback));
  }

  pending_data = new bluetooth::os::EnqueueBuffer<bluetooth::hci::AclBuilder>(
      hci_queue_end);
}

static void on_shutting_down() {
  if (pending_data != nullptr) {
    pending_data->Clear();
    delete pending_data;
    pending_data = nullptr;
  }
  if (hci_queue_end != nullptr) {
    if (!bluetooth::shim::is_gd_advertising_enabled() &&
        !bluetooth::shim::is_gd_l2cap_enabled()) {
      hci_queue_end->UnregisterDequeue();
    }
    for (uint8_t event_code_raw = 0; event_code_raw < 0xFF; event_code_raw++) {
      if (!is_valid_event_code(event_code_raw)) {
        continue;
      }
      auto event_code = static_cast<bluetooth::hci::EventCode>(event_code_raw);
      if (event_already_registered_in_hci_layer(event_code)) {
        continue;
      } else if (event_already_registered_in_le_advertising_manager(
                     event_code)) {
        continue;
      } else if (event_already_registered_in_le_scanning_manager(event_code)) {
        continue;
      }
      bluetooth::shim::GetHciLayer()->UnregisterEventHandler(event_code);
    }
    hci_queue_end = nullptr;
  }
}

}  // namespace cpp

using bluetooth::common::Bind;
using bluetooth::common::BindOnce;
using bluetooth::common::Unretained;

namespace rust {

using bluetooth::shim::rust::u8SliceCallback;
using bluetooth::shim::rust::u8SliceOnceCallback;

static BT_HDR* WrapRustPacketAndCopy(uint16_t event,
                                     ::rust::Slice<uint8_t>* data) {
  size_t packet_size = data->length() + kBtHdrSize;
  BT_HDR* packet = reinterpret_cast<BT_HDR*>(osi_malloc(packet_size));
  packet->offset = 0;
  packet->len = data->length();
  packet->layer_specific = 0;
  packet->event = event;
  std::copy(data->data(), data->data() + data->length(), packet->data);
  return packet;
}

static void on_acl(::rust::Slice<uint8_t> data) {
  if (!send_data_upwards) {
    return;
  }
  auto legacy_data = WrapRustPacketAndCopy(MSG_HC_TO_STACK_HCI_ACL, &data);
  packet_fragmenter->reassemble_and_dispatch(legacy_data);
}

static void on_event(::rust::Slice<uint8_t> data) {
  if (!send_data_upwards) {
    return;
  }
  send_data_upwards.Run(FROM_HERE,
                        WrapRustPacketAndCopy(MSG_HC_TO_STACK_HCI_EVT, &data));
}

void OnRustTransmitPacketCommandComplete(command_complete_cb complete_callback,
                                         void* context,
                                         ::rust::Slice<uint8_t> data) {
  BT_HDR* response = WrapRustPacketAndCopy(MSG_HC_TO_STACK_HCI_EVT, &data);
  complete_callback(response, context);
}

void OnRustTransmitPacketStatus(command_status_cb status_callback,
                                void* context,
                                std::unique_ptr<OsiObject> command,
                                ::rust::Slice<uint8_t> data) {
  ASSERT(data.length() >= 3);
  uint8_t status = data.data()[2];
  status_callback(status, static_cast<BT_HDR*>(command->Release()), context);
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
  auto op_code = static_cast<const bluetooth::hci::OpCode>(command_op_code);

  LOG_DEBUG("Sending command %s", bluetooth::hci::OpCodeText(op_code).c_str());

  if (bluetooth::hci::Checker::IsCommandStatusOpcode(op_code)) {
    auto command_unique = std::make_unique<OsiObject>(command);
    bluetooth::shim::rust::hci_send_command(
        **bluetooth::shim::Stack::Stack::GetInstance()->GetRustHci(),
        ::rust::Slice(data, len),
        std::make_unique<u8SliceOnceCallback>(
            BindOnce(OnRustTransmitPacketStatus, status_callback, context,
                     std::move(command_unique))));
  } else {
    bluetooth::shim::rust::hci_send_command(
        **bluetooth::shim::Stack::Stack::GetInstance()->GetRustHci(),
        ::rust::Slice(data, len),
        std::make_unique<u8SliceOnceCallback>(BindOnce(
            OnRustTransmitPacketCommandComplete, complete_callback, context)));
    osi_free(command);
  }
}

static void transmit_fragment(uint8_t* stream, size_t length) {
  bluetooth::shim::rust::hci_send_acl(
      **bluetooth::shim::Stack::Stack::GetInstance()->GetRustHci(),
      ::rust::Slice(stream, length));
}

static void register_event(bluetooth::hci::EventCode event_code) {
  bluetooth::shim::rust::hci_register_event(
      **bluetooth::shim::Stack::GetInstance()->GetRustHci(),
      static_cast<uint8_t>(event_code));
}

static void register_le_event(bluetooth::hci::SubeventCode subevent_code) {
  bluetooth::shim::rust::hci_register_le_event(
      **bluetooth::shim::Stack::Stack::GetInstance()->GetRustHci(),
      static_cast<uint8_t>(subevent_code));
}

static void hci_on_reset_complete() {
  bluetooth::shim::rust::hci_set_evt_callback(
      **bluetooth::shim::Stack::GetInstance()->GetRustHci(),
      std::make_unique<u8SliceCallback>(Bind(rust::on_event)));
  bluetooth::shim::rust::hci_set_le_evt_callback(
      **bluetooth::shim::Stack::GetInstance()->GetRustHci(),
      std::make_unique<u8SliceCallback>(Bind(rust::on_event)));
}

static void register_for_acl() {
  bluetooth::shim::rust::hci_set_acl_callback(
      **bluetooth::shim::Stack::GetInstance()->GetRustHci(),
      std::make_unique<u8SliceCallback>(Bind(rust::on_acl)));
}

static void on_shutting_down() {}

}  // namespace rust

static void set_data_cb(
    base::Callback<void(const base::Location&, BT_HDR*)> send_data_cb) {
  send_data_upwards = std::move(send_data_cb);
}

static void transmit_command(BT_HDR* command,
                             command_complete_cb complete_callback,
                             command_status_cb status_callback, void* context) {
  if (bluetooth::common::init_flags::gd_rust_is_enabled()) {
    rust::transmit_command(command, complete_callback, status_callback,
                           context);
  } else {
    cpp::transmit_command(command, complete_callback, status_callback, context);
  }
}

static void command_complete_callback(BT_HDR* response, void* context) {
  auto future = static_cast<future_t*>(context);
  future_ready(future, response);
}

static void command_status_callback(uint8_t status, BT_HDR* command,
                                    void* context) {
  LOG_ALWAYS_FATAL(
      "transmit_command_futured should only send command complete opcode");
}

static future_t* transmit_command_futured(BT_HDR* command) {
  future_t* future = future_new();
  transmit_command(command, command_complete_callback, command_status_callback,
                   future);
  return future;
}

static void transmit_fragment(BT_HDR* packet, bool send_transmit_finished) {
  // HCI command packets are freed on a different thread when the matching
  // event is received. Check packet->event before sending to avoid a race.
  bool free_after_transmit =
      (packet->event & MSG_EVT_MASK) != MSG_STACK_TO_HC_HCI_CMD &&
      send_transmit_finished;

  uint8_t* stream = packet->data + packet->offset;
  size_t length = packet->len;
  if (bluetooth::common::init_flags::gd_rust_is_enabled()) {
    rust::transmit_fragment(stream, length);
  } else {
    cpp::transmit_fragment(stream, length);
  }
  if (free_after_transmit) {
    osi_free(packet);
  }
}
static void dispatch_reassembled(BT_HDR* packet) {
  // Events should already have been dispatched before this point
  CHECK((packet->event & MSG_EVT_MASK) != MSG_HC_TO_STACK_HCI_EVT);
  CHECK(!send_data_upwards.is_null());
  send_data_upwards.Run(FROM_HERE, packet);
}
static void fragmenter_transmit_finished(BT_HDR* packet,
                                         bool all_fragments_sent) {
  if (all_fragments_sent) {
    osi_free(packet);
  } else {
    // This is kind of a weird case, since we're dispatching a partially sent
    // packet up to a higher layer.
    // TODO(zachoverflow): rework upper layer so this isn't necessary.
    send_data_upwards.Run(FROM_HERE, packet);
  }
}

static const packet_fragmenter_callbacks_t packet_fragmenter_callbacks = {
    transmit_fragment, dispatch_reassembled, fragmenter_transmit_finished};

static void transmit_downward(uint16_t type, void* raw_data) {
  if (bluetooth::common::init_flags::gd_rust_is_enabled()) {
    packet_fragmenter->fragment_and_dispatch(static_cast<BT_HDR*>(raw_data));
  } else {
    bluetooth::shim::GetGdShimHandler()->Call(
        packet_fragmenter->fragment_and_dispatch,
        static_cast<BT_HDR*>(raw_data));
  }
}

static hci_t interface = {.set_data_cb = set_data_cb,
                          .transmit_command = transmit_command,
                          .transmit_command_futured = transmit_command_futured,
                          .transmit_downward = transmit_downward};

const hci_t* bluetooth::shim::hci_layer_get_interface() {
  packet_fragmenter = packet_fragmenter_get_interface();
  packet_fragmenter->init(&packet_fragmenter_callbacks);
  return &interface;
}

void bluetooth::shim::hci_on_reset_complete() {
  ASSERT(send_data_upwards);
  if (bluetooth::common::init_flags::gd_rust_is_enabled()) {
    ::rust::hci_on_reset_complete();
  }

  for (uint8_t event_code_raw = 0; event_code_raw < 0xFF; event_code_raw++) {
    if (!is_valid_event_code(event_code_raw)) {
      continue;
    }
    auto event_code = static_cast<bluetooth::hci::EventCode>(event_code_raw);
    if (event_already_registered_in_acl_layer(event_code)) {
      continue;
    } else if (event_already_registered_in_controller_layer(event_code)) {
      continue;
    } else if (event_already_registered_in_hci_layer(event_code)) {
      continue;
    } else if (event_already_registered_in_le_advertising_manager(event_code)) {
      continue;
    } else if (event_already_registered_in_le_scanning_manager(event_code)) {
      continue;
    }

    if (bluetooth::common::init_flags::gd_rust_is_enabled()) {
      ::rust::register_event(event_code);
    } else {
      cpp::register_event(event_code);
    }
  }

  for (uint8_t subevent_code_raw = 0; subevent_code_raw < 0xFF;
       subevent_code_raw++) {
    if (!is_valid_subevent_code(subevent_code_raw)) {
      continue;
    }
    auto subevent_code =
        static_cast<bluetooth::hci::SubeventCode>(subevent_code_raw);
    if (subevent_already_registered_in_le_hci_layer(subevent_code)) {
      continue;
    }

    if (bluetooth::common::init_flags::gd_rust_is_enabled()) {
      ::rust::register_le_event(subevent_code);
    } else {
      cpp::register_le_event(subevent_code);
    }
  }

  for (uint8_t vse_code_raw = 0; vse_code_raw < 0xFF; vse_code_raw++) {
    if (!is_valid_vendor_specific_event(vse_code_raw)) {
      continue;
    }
    auto vse_code = static_cast<bluetooth::hci::VseSubeventCode>(vse_code_raw);
    if (bluetooth::common::init_flags::gd_rust_is_enabled()) {
      // TODO(b/183057550): Need Rust HCI implementation for VSE
      // ::rust::register_vendor_specific_event(vse_code_raw);
    } else {
      cpp::register_vendor_specific_event(vse_code);
    }
  }

  if (bluetooth::shim::is_gd_acl_enabled()) {
    return;
  }

  if (bluetooth::common::init_flags::gd_rust_is_enabled()) {
    ::rust::register_for_acl();
  } else {
    cpp::register_for_acl();
  }
}

void bluetooth::shim::hci_on_shutting_down() {
  if (bluetooth::common::init_flags::gd_rust_is_enabled()) {
    ::rust::on_shutting_down();
  } else {
    cpp::on_shutting_down();
  }
}
