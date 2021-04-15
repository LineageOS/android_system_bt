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
#include <frameworks/proto_logging/stats/enums/bluetooth/enums.pb.h>
#include <frameworks/proto_logging/stats/enums/bluetooth/hci/enums.pb.h>

#include "hci/hci_metrics_logging.h"
#include "os/metrics.h"

namespace bluetooth {
namespace hci {

void log_link_layer_connection_hci_event(std::unique_ptr<CommandView>& command_view, EventView event_view) {
  ASSERT(event_view.IsValid());
  EventCode event_code = event_view.GetEventCode();
  switch (event_code) {
    case EventCode::COMMAND_COMPLETE: {
      ASSERT(command_view->IsValid());
      log_link_layer_connection_command_complete(event_view, command_view);
      break;
    }
    case EventCode::COMMAND_STATUS: {
      ASSERT(command_view->IsValid());
      CommandStatusView response_view = CommandStatusView::Create(event_view);
      ASSERT(response_view.IsValid());
      log_link_layer_connection_command_status(command_view, response_view.GetStatus());
      break;
    }
    case EventCode::LE_META_EVENT: {
      LeMetaEventView le_meta_event_view = LeMetaEventView::Create(event_view);
      ASSERT(le_meta_event_view.IsValid());
      log_link_layer_connection_event_le_meta(le_meta_event_view);
      break;
    }
    default:
      log_link_layer_connection_other_hci_event(event_view);
  }
}
void log_link_layer_connection_command_status(std::unique_ptr<CommandView>& command_view, ErrorCode status) {
  // get op_code
  ASSERT(command_view->IsValid());
  OpCode op_code = command_view->GetOpCode();

  // init parameters to log
  Address address = Address::kEmpty;
  uint32_t connection_handle = bluetooth::os::kUnknownConnectionHandle;
  uint16_t reason = static_cast<uint16_t>(ErrorCode::UNKNOWN_HCI_COMMAND);
  static uint16_t kUnknownBleEvt = android::bluetooth::hci::BLE_EVT_UNKNOWN;
  uint16_t event_code = android::bluetooth::hci::EVT_COMMAND_STATUS;
  android::bluetooth::DirectionEnum direction = android::bluetooth::DIRECTION_UNKNOWN;
  uint16_t link_type = android::bluetooth::LINK_TYPE_UNKNOWN;

  // get ConnectionManagementCommandView
  ConnectionManagementCommandView connection_management_command_view =
      ConnectionManagementCommandView::Create(AclCommandView::Create(*command_view));
  ASSERT(connection_management_command_view.IsValid());
  switch (op_code) {
    case OpCode::CREATE_CONNECTION: {
      auto create_connection_view = CreateConnectionView::Create(std::move(connection_management_command_view));
      ASSERT(create_connection_view.IsValid());
      address = create_connection_view.GetBdAddr();
      direction = android::bluetooth::DIRECTION_OUTGOING;
      link_type = android::bluetooth::LINK_TYPE_ACL;
      break;
    }
    case OpCode::CREATE_CONNECTION_CANCEL: {
      auto create_connection_cancel_view =
          CreateConnectionCancelView::Create(std::move(connection_management_command_view));
      ASSERT(create_connection_cancel_view.IsValid());
      address = create_connection_cancel_view.GetBdAddr();
      direction = android::bluetooth::DIRECTION_OUTGOING;
      link_type = android::bluetooth::LINK_TYPE_ACL;
      break;
    }
    case OpCode::DISCONNECT: {
      auto disconnect_view = DisconnectView::Create(std::move(connection_management_command_view));
      ASSERT(disconnect_view.IsValid());
      connection_handle = disconnect_view.GetConnectionHandle();
      reason = static_cast<uint16_t>(disconnect_view.GetReason());
      break;
    }
    case OpCode::SETUP_SYNCHRONOUS_CONNECTION: {
      auto setup_synchronous_connection_view = SetupSynchronousConnectionView::Create(
          ScoConnectionCommandView::Create(std::move(connection_management_command_view)));
      ASSERT(setup_synchronous_connection_view.IsValid());
      connection_handle = setup_synchronous_connection_view.GetConnectionHandle();
      direction = android::bluetooth::DIRECTION_OUTGOING;
      break;
    }
    case OpCode::ENHANCED_SETUP_SYNCHRONOUS_CONNECTION: {
      auto enhanced_setup_synchronous_connection_view = EnhancedSetupSynchronousConnectionView::Create(
          ScoConnectionCommandView::Create(std::move(connection_management_command_view)));
      ASSERT(enhanced_setup_synchronous_connection_view.IsValid());
      connection_handle = enhanced_setup_synchronous_connection_view.GetConnectionHandle();
      direction = android::bluetooth::DIRECTION_OUTGOING;
      break;
    }
    case OpCode::ACCEPT_CONNECTION_REQUEST: {
      auto accept_connection_request_view =
          AcceptConnectionRequestView::Create(std::move(connection_management_command_view));
      ASSERT(accept_connection_request_view.IsValid());
      address = accept_connection_request_view.GetBdAddr();
      direction = android::bluetooth::DIRECTION_INCOMING;
      break;
    }
    case OpCode::ACCEPT_SYNCHRONOUS_CONNECTION: {
      auto accept_synchronous_connection_view = AcceptSynchronousConnectionView::Create(
          ScoConnectionCommandView::Create(std::move(connection_management_command_view)));
      ASSERT(accept_synchronous_connection_view.IsValid());
      address = accept_synchronous_connection_view.GetBdAddr();
      direction = android::bluetooth::DIRECTION_INCOMING;
      break;
    }
    case OpCode::ENHANCED_ACCEPT_SYNCHRONOUS_CONNECTION: {
      auto enhanced_accept_synchronous_connection_view = EnhancedAcceptSynchronousConnectionView::Create(
          ScoConnectionCommandView::Create(std::move(connection_management_command_view)));
      ASSERT(enhanced_accept_synchronous_connection_view.IsValid());
      address = enhanced_accept_synchronous_connection_view.GetBdAddr();
      direction = android::bluetooth::DIRECTION_INCOMING;
      break;
    }
    case OpCode::REJECT_CONNECTION_REQUEST: {
      auto reject_connection_request_view =
          RejectConnectionRequestView::Create(std::move(connection_management_command_view));
      ASSERT(reject_connection_request_view.IsValid());
      address = reject_connection_request_view.GetBdAddr();
      reason = static_cast<uint16_t>(reject_connection_request_view.GetReason());
      direction = android::bluetooth::DIRECTION_INCOMING;
      break;
    }
    case OpCode::REJECT_SYNCHRONOUS_CONNECTION: {
      auto reject_synchronous_connection_view = RejectSynchronousConnectionView::Create(
          ScoConnectionCommandView::Create(std::move(connection_management_command_view)));
      ASSERT(reject_synchronous_connection_view.IsValid());
      address = reject_synchronous_connection_view.GetBdAddr();
      reason = static_cast<uint16_t>(reject_synchronous_connection_view.GetReason());
      direction = android::bluetooth::DIRECTION_INCOMING;
      break;
    }
    case OpCode::LE_CREATE_CONNECTION: {
      auto le_create_connection_view = LeCreateConnectionView::Create(
          LeConnectionManagementCommandView::Create(std::move(connection_management_command_view)));
      ASSERT(le_create_connection_view.IsValid());
      uint8_t initiator_filter_policy = static_cast<uint8_t>(le_create_connection_view.GetInitiatorFilterPolicy());
      if (initiator_filter_policy != 0x00 && status == ErrorCode::SUCCESS) {
        return;
      }
      address = le_create_connection_view.GetPeerAddress();
      direction = android::bluetooth::DIRECTION_INCOMING;
      link_type = android::bluetooth::LINK_TYPE_ACL;
      break;
    }
    case OpCode::LE_EXTENDED_CREATE_CONNECTION: {
      auto le_extended_create_connection_view = LeExtendedCreateConnectionView::Create(
          LeConnectionManagementCommandView::Create(std::move(connection_management_command_view)));
      ASSERT(le_extended_create_connection_view.IsValid());
      uint8_t initiator_filter_policy =
          static_cast<uint8_t>(le_extended_create_connection_view.GetInitiatorFilterPolicy());
      if (initiator_filter_policy != 0x00 && status == ErrorCode::SUCCESS) {
        return;
      }
      address = le_extended_create_connection_view.GetPeerAddress();
      direction = android::bluetooth::DIRECTION_OUTGOING;
      link_type = android::bluetooth::LINK_TYPE_ACL;
      break;
    }
    case OpCode::LE_CREATE_CONNECTION_CANCEL: {
      auto le_create_connection_cancel_view = LeCreateConnectionCancelView::Create(
          LeConnectionManagementCommandView::Create(std::move(connection_management_command_view)));
      ASSERT(le_create_connection_cancel_view.IsValid());
      if (status == ErrorCode::SUCCESS) {
        return;
      }
      direction = android::bluetooth::DIRECTION_OUTGOING;
      link_type = android::bluetooth::LINK_TYPE_ACL;
      break;
    }
    case OpCode::LE_CLEAR_CONNECT_LIST: {
      auto le_clear_connect_list_view = LeClearConnectListView::Create(
          LeConnectionManagementCommandView::Create(std::move(connection_management_command_view)));
      ASSERT(le_clear_connect_list_view.IsValid());
      direction = android::bluetooth::DIRECTION_INCOMING;
      link_type = android::bluetooth::LINK_TYPE_ACL;
      break;
    }
    case OpCode::LE_ADD_DEVICE_TO_CONNECT_LIST: {
      auto le_add_device_to_connect_list_view = LeAddDeviceToConnectListView::Create(
          LeConnectionManagementCommandView::Create(std::move(connection_management_command_view)));
      ASSERT(le_add_device_to_connect_list_view.IsValid());
      address = le_add_device_to_connect_list_view.GetAddress();
      direction = android::bluetooth::DIRECTION_INCOMING;
      link_type = android::bluetooth::LINK_TYPE_ACL;
      break;
    }
    case OpCode::LE_REMOVE_DEVICE_FROM_CONNECT_LIST: {
      auto le_remove_device_from_connect_list_view = LeRemoveDeviceFromConnectListView::Create(
          LeConnectionManagementCommandView::Create(std::move(connection_management_command_view)));
      ASSERT(le_remove_device_from_connect_list_view.IsValid());
      address = le_remove_device_from_connect_list_view.GetAddress();
      direction = android::bluetooth::DIRECTION_INCOMING;
      link_type = android::bluetooth::LINK_TYPE_ACL;
      break;
    }
    default:
      return;
  }
  os::LogMetricLinkLayerConnectionEvent(
      &address,
      connection_handle,
      direction,
      link_type,
      static_cast<uint32_t>(op_code),
      static_cast<uint16_t>(event_code),
      kUnknownBleEvt,
      static_cast<uint16_t>(status),
      static_cast<uint16_t>(reason));
}

void log_link_layer_connection_command_complete(EventView event_view, std::unique_ptr<CommandView>& command_view) {
  CommandCompleteView command_complete_view = CommandCompleteView::Create(std::move(event_view));
  ASSERT(command_complete_view.IsValid());
  OpCode op_code = command_complete_view.GetCommandOpCode();

  // init parameters to log
  Address address = Address::kEmpty;
  uint32_t connection_handle = bluetooth::os::kUnknownConnectionHandle;
  ErrorCode status = ErrorCode::UNKNOWN_HCI_COMMAND;
  ErrorCode reason = ErrorCode::UNKNOWN_HCI_COMMAND;
  static uint16_t kUnknownBleEvt = android::bluetooth::hci::BLE_EVT_UNKNOWN;
  uint16_t event_code = android::bluetooth::hci::EVT_COMMAND_COMPLETE;
  android::bluetooth::DirectionEnum direction = android::bluetooth::DIRECTION_UNKNOWN;
  uint16_t link_type = android::bluetooth::LINK_TYPE_UNKNOWN;

  // get ConnectionManagementCommandView
  ConnectionManagementCommandView connection_management_command_view =
      ConnectionManagementCommandView::Create(AclCommandView::Create(*command_view));
  ASSERT(connection_management_command_view.IsValid());

  switch (op_code) {
    case OpCode::LE_CLEAR_CONNECT_LIST: {
      auto le_clear_connect_list_view = LeClearConnectListView::Create(
          LeConnectionManagementCommandView::Create(std::move(connection_management_command_view)));
      ASSERT(le_clear_connect_list_view.IsValid());
      direction = android::bluetooth::DIRECTION_INCOMING;
      link_type = android::bluetooth::LINK_TYPE_ACL;
      break;
    }
    case OpCode::LE_ADD_DEVICE_TO_CONNECT_LIST: {
      auto le_add_device_to_connect_list_view = LeAddDeviceToConnectListView::Create(
          LeConnectionManagementCommandView::Create(std::move(connection_management_command_view)));
      ASSERT(le_add_device_to_connect_list_view.IsValid());
      address = le_add_device_to_connect_list_view.GetAddress();
      direction = android::bluetooth::DIRECTION_INCOMING;
      link_type = android::bluetooth::LINK_TYPE_ACL;
      break;
    }
    case OpCode::LE_REMOVE_DEVICE_FROM_CONNECT_LIST: {
      auto le_remove_device_from_connect_list_view = LeRemoveDeviceFromConnectListView::Create(
          LeConnectionManagementCommandView::Create(std::move(connection_management_command_view)));
      ASSERT(le_remove_device_from_connect_list_view.IsValid());
      address = le_remove_device_from_connect_list_view.GetAddress();
      direction = android::bluetooth::DIRECTION_INCOMING;
      link_type = android::bluetooth::LINK_TYPE_ACL;
      break;
    }
    case OpCode::CREATE_CONNECTION_CANCEL: {
      auto create_connection_cancel_complete_view =
          CreateConnectionCancelCompleteView::Create(std::move(command_complete_view));
      ASSERT(create_connection_cancel_complete_view.IsValid());
      address = create_connection_cancel_complete_view.GetBdAddr();
      direction = android::bluetooth::DIRECTION_OUTGOING;
      link_type = android::bluetooth::LINK_TYPE_ACL;
      status = create_connection_cancel_complete_view.GetStatus();
      break;
    }
    case OpCode::LE_CREATE_CONNECTION_CANCEL: {
      auto le_create_connection_cancel_complete_view =
          LeCreateConnectionCancelCompleteView::Create(std::move(command_complete_view));
      ASSERT(le_create_connection_cancel_complete_view.IsValid());
      direction = android::bluetooth::DIRECTION_OUTGOING;
      link_type = android::bluetooth::LINK_TYPE_ACL;
      status = le_create_connection_cancel_complete_view.GetStatus();
      break;
    }
    default:
      return;
  }
  os::LogMetricLinkLayerConnectionEvent(
      &address,
      connection_handle,
      direction,
      link_type,
      static_cast<uint32_t>(op_code),
      static_cast<uint16_t>(event_code),
      kUnknownBleEvt,
      static_cast<uint16_t>(status),
      static_cast<uint16_t>(reason));
}

void log_link_layer_connection_other_hci_event(EventView packet) {
  EventCode event_code = packet.GetEventCode();
  Address address = Address::kEmpty;
  uint32_t connection_handle = bluetooth::os::kUnknownConnectionHandle;
  android::bluetooth::DirectionEnum direction = android::bluetooth::DIRECTION_UNKNOWN;
  uint16_t link_type = android::bluetooth::LINK_TYPE_UNKNOWN;
  ErrorCode status = ErrorCode::UNKNOWN_HCI_COMMAND;
  ErrorCode reason = ErrorCode::UNKNOWN_HCI_COMMAND;
  uint32_t cmd = android::bluetooth::hci::CMD_UNKNOWN;
  switch (event_code) {
    case EventCode::CONNECTION_COMPLETE: {
      auto connection_complete_view = ConnectionCompleteView::Create(std::move(packet));
      ASSERT(connection_complete_view.IsValid());
      address = connection_complete_view.GetBdAddr();
      connection_handle = connection_complete_view.GetConnectionHandle();
      link_type = static_cast<uint16_t>(connection_complete_view.GetLinkType());
      status = connection_complete_view.GetStatus();
      break;
    }
    case EventCode::CONNECTION_REQUEST: {
      auto connection_request_view = ConnectionRequestView::Create(std::move(packet));
      ASSERT(connection_request_view.IsValid());
      address = connection_request_view.GetBdAddr();
      link_type = static_cast<uint16_t>(connection_request_view.GetLinkType());
      direction = android::bluetooth::DIRECTION_INCOMING;
      break;
    }
    case EventCode::DISCONNECTION_COMPLETE: {
      auto disconnection_complete_view = DisconnectionCompleteView::Create(std::move(packet));
      ASSERT(disconnection_complete_view.IsValid());
      status = disconnection_complete_view.GetStatus();
      connection_handle = disconnection_complete_view.GetConnectionHandle();
      reason = disconnection_complete_view.GetReason();
      break;
    }
    case EventCode::SYNCHRONOUS_CONNECTION_COMPLETE: {
      auto synchronous_connection_complete_view = SynchronousConnectionCompleteView::Create(std::move(packet));
      ASSERT(synchronous_connection_complete_view.IsValid());
      connection_handle = synchronous_connection_complete_view.GetConnectionHandle();
      address = synchronous_connection_complete_view.GetBdAddr();
      link_type = static_cast<uint16_t>(synchronous_connection_complete_view.GetLinkType());
      status = synchronous_connection_complete_view.GetStatus();
      break;
    }
    case EventCode::SYNCHRONOUS_CONNECTION_CHANGED: {
      auto synchronous_connection_changed_view = SynchronousConnectionChangedView::Create(std::move(packet));
      ASSERT(synchronous_connection_changed_view.IsValid());
      status = synchronous_connection_changed_view.GetStatus();
      connection_handle = synchronous_connection_changed_view.GetConnectionHandle();
      break;
    }
    default:
      return;
  }
  os::LogMetricLinkLayerConnectionEvent(
      &address,
      connection_handle,
      direction,
      link_type,
      static_cast<uint32_t>(cmd),
      static_cast<uint16_t>(event_code),
      android::bluetooth::hci::BLE_EVT_UNKNOWN,
      static_cast<uint16_t>(status),
      static_cast<uint16_t>(reason));
}

void log_link_layer_connection_event_le_meta(LeMetaEventView le_meta_event_view) {
  SubeventCode leEvt = le_meta_event_view.GetSubeventCode();
  auto le_connection_complete_view = LeConnectionCompleteView::Create(std::move(le_meta_event_view));
  if (!le_connection_complete_view.IsValid()) {
    // function is called for all le meta events. Only need to process le connection complete.
    return;
  }
  ASSERT(le_connection_complete_view.IsValid());
  // init parameters to log
  EventCode event_code = EventCode::LE_META_EVENT;
  Address address = le_connection_complete_view.GetPeerAddress();
  uint32_t connection_handle = le_connection_complete_view.GetConnectionHandle();
  android::bluetooth::DirectionEnum direction = android::bluetooth::DIRECTION_UNKNOWN;
  uint16_t link_type = android::bluetooth::LINK_TYPE_ACL;
  ErrorCode status = le_connection_complete_view.GetStatus();
  ErrorCode reason = ErrorCode::UNKNOWN_HCI_COMMAND;
  uint32_t cmd = android::bluetooth::hci::CMD_UNKNOWN;

  os::LogMetricLinkLayerConnectionEvent(
      &address,
      connection_handle,
      direction,
      link_type,
      static_cast<uint32_t>(cmd),
      static_cast<uint16_t>(event_code),
      static_cast<uint16_t>(leEvt),
      static_cast<uint16_t>(status),
      static_cast<uint16_t>(reason));
}
}  // namespace hci
}  // namespace bluetooth