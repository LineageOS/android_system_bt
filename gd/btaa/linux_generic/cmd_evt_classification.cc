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

#include "btaa/cmd_evt_classification.h"

namespace bluetooth {
namespace activity_attribution {

CmdEvtActivityClassification lookup_cmd(hci::OpCode opcode) {
  CmdEvtActivityClassification classification = {};
  switch (opcode) {
    case hci::OpCode::INQUIRY:
    case hci::OpCode::INQUIRY_CANCEL:
    case hci::OpCode::PERIODIC_INQUIRY_MODE:
    case hci::OpCode::EXIT_PERIODIC_INQUIRY_MODE:
      classification = {.activity = Activity::SCAN, .connection_handle_pos = 0, .address_pos = 0};
      break;

    case hci::OpCode::CREATE_CONNECTION:
    case hci::OpCode::CREATE_CONNECTION_CANCEL:
    case hci::OpCode::ACCEPT_CONNECTION_REQUEST:
    case hci::OpCode::LINK_KEY_REQUEST_REPLY:
    case hci::OpCode::LINK_KEY_REQUEST_NEGATIVE_REPLY:
    case hci::OpCode::PIN_CODE_REQUEST_REPLY:
    case hci::OpCode::PIN_CODE_REQUEST_NEGATIVE_REPLY:
    case hci::OpCode::REJECT_CONNECTION_REQUEST:
    case hci::OpCode::REMOTE_NAME_REQUEST:
    case hci::OpCode::REMOTE_NAME_REQUEST_CANCEL:
    case hci::OpCode::ACCEPT_SYNCHRONOUS_CONNECTION:
    case hci::OpCode::REJECT_SYNCHRONOUS_CONNECTION:
    case hci::OpCode::IO_CAPABILITY_REQUEST_REPLY:
    case hci::OpCode::USER_CONFIRMATION_REQUEST_REPLY:
    case hci::OpCode::USER_CONFIRMATION_REQUEST_NEGATIVE_REPLY:
    case hci::OpCode::USER_PASSKEY_REQUEST_REPLY:
    case hci::OpCode::USER_PASSKEY_REQUEST_NEGATIVE_REPLY:
    case hci::OpCode::REMOTE_OOB_DATA_REQUEST_REPLY:
    case hci::OpCode::REMOTE_OOB_DATA_REQUEST_NEGATIVE_REPLY:
    case hci::OpCode::IO_CAPABILITY_REQUEST_NEGATIVE_REPLY:
    case hci::OpCode::ENHANCED_ACCEPT_SYNCHRONOUS_CONNECTION:
    case hci::OpCode::REMOTE_OOB_EXTENDED_DATA_REQUEST_REPLY:
    case hci::OpCode::SWITCH_ROLE:
    case hci::OpCode::READ_STORED_LINK_KEY:
      classification = {.activity = Activity::CONNECT, .connection_handle_pos = 0, .address_pos = 3};
      break;

    case hci::OpCode::CENTRAL_LINK_KEY:
    case hci::OpCode::READ_DEFAULT_LINK_POLICY_SETTINGS:
    case hci::OpCode::WRITE_DEFAULT_LINK_POLICY_SETTINGS:
    case hci::OpCode::WRITE_SCAN_ENABLE:
    case hci::OpCode::READ_PAGE_SCAN_ACTIVITY:
    case hci::OpCode::WRITE_PAGE_SCAN_ACTIVITY:
    case hci::OpCode::READ_PAGE_SCAN_TYPE:
    case hci::OpCode::WRITE_PAGE_SCAN_TYPE:
    case hci::OpCode::READ_SIMPLE_PAIRING_MODE:
    case hci::OpCode::WRITE_SIMPLE_PAIRING_MODE:
    case hci::OpCode::READ_SCAN_ENABLE:
    case hci::OpCode::LE_CREATE_CONNECTION_CANCEL:
    case hci::OpCode::LE_READ_CONNECT_LIST_SIZE:
    case hci::OpCode::LE_CLEAR_CONNECT_LIST:
    case hci::OpCode::SEND_KEYPRESS_NOTIFICATION:
    case hci::OpCode::LE_CLEAR_RESOLVING_LIST:
    case hci::OpCode::LE_READ_RESOLVING_LIST_SIZE:
    case hci::OpCode::LE_SET_HOST_CHANNEL_CLASSIFICATION:
      classification = {.activity = Activity::CONNECT, .connection_handle_pos = 0, .address_pos = 0};
      break;

    case hci::OpCode::DISCONNECT:
    case hci::OpCode::CHANGE_CONNECTION_PACKET_TYPE:
    case hci::OpCode::AUTHENTICATION_REQUESTED:
    case hci::OpCode::SET_CONNECTION_ENCRYPTION:
    case hci::OpCode::CHANGE_CONNECTION_LINK_KEY:
    case hci::OpCode::READ_REMOTE_SUPPORTED_FEATURES:
    case hci::OpCode::READ_REMOTE_EXTENDED_FEATURES:
    case hci::OpCode::READ_REMOTE_VERSION_INFORMATION:
    case hci::OpCode::READ_CLOCK_OFFSET:
    case hci::OpCode::READ_LMP_HANDLE:
    case hci::OpCode::SETUP_SYNCHRONOUS_CONNECTION:
    case hci::OpCode::ENHANCED_SETUP_SYNCHRONOUS_CONNECTION:
    case hci::OpCode::HOLD_MODE:
    case hci::OpCode::SNIFF_MODE:
    case hci::OpCode::EXIT_SNIFF_MODE:
    case hci::OpCode::QOS_SETUP:
    case hci::OpCode::ROLE_DISCOVERY:
    case hci::OpCode::READ_LINK_POLICY_SETTINGS:
    case hci::OpCode::WRITE_LINK_POLICY_SETTINGS:
    case hci::OpCode::FLOW_SPECIFICATION:
    case hci::OpCode::SNIFF_SUBRATING:
    case hci::OpCode::FLUSH:
    case hci::OpCode::READ_AUTOMATIC_FLUSH_TIMEOUT:
    case hci::OpCode::WRITE_AUTOMATIC_FLUSH_TIMEOUT:
    case hci::OpCode::READ_LINK_SUPERVISION_TIMEOUT:
    case hci::OpCode::WRITE_LINK_SUPERVISION_TIMEOUT:
    case hci::OpCode::REFRESH_ENCRYPTION_KEY:
    case hci::OpCode::READ_FAILED_CONTACT_COUNTER:
    case hci::OpCode::RESET_FAILED_CONTACT_COUNTER:
    case hci::OpCode::READ_LINK_QUALITY:
    case hci::OpCode::READ_RSSI:
    case hci::OpCode::READ_AFH_CHANNEL_MAP:
    case hci::OpCode::READ_CLOCK:
    case hci::OpCode::READ_ENCRYPTION_KEY_SIZE:
    // READ_LOOPBACK_MODE = 0x1801,
    // WRITE_LOOPBACK_MODE = 0x1802,
    // ENABLE_DEVICE_UNDER_TEST_MODE = 0x1803,
    // WRITE_SIMPLE_PAIRING_DEBUG_MODE = 0x1804,
    // WRITE_SECURE_CONNECTIONS_TEST_MODE = 0x180a,
    case hci::OpCode::ENHANCED_FLUSH:
    case hci::OpCode::LE_CONNECTION_UPDATE:
    case hci::OpCode::LE_START_ENCRYPTION:
    case hci::OpCode::LE_LONG_TERM_KEY_REQUEST_REPLY:
    case hci::OpCode::LE_LONG_TERM_KEY_REQUEST_NEGATIVE_REPLY:
    case hci::OpCode::LE_READ_PHY:
    case hci::OpCode::LE_SET_PHY:
    case hci::OpCode::LE_READ_REMOTE_FEATURES:
    case hci::OpCode::LE_REMOTE_CONNECTION_PARAMETER_REQUEST_REPLY:
    case hci::OpCode::LE_REMOTE_CONNECTION_PARAMETER_REQUEST_NEGATIVE_REPLY:
    case hci::OpCode::LE_SET_DATA_LENGTH:
      classification = {.activity = Activity::CONNECT, .connection_handle_pos = 3, .address_pos = 0};
      break;

    case hci::OpCode::SET_EVENT_MASK:
    case hci::OpCode::RESET:
    case hci::OpCode::SET_EVENT_FILTER:
    case hci::OpCode::READ_PIN_TYPE:
    case hci::OpCode::WRITE_PIN_TYPE:
    case hci::OpCode::WRITE_LOCAL_NAME:
    case hci::OpCode::READ_LOCAL_NAME:
    case hci::OpCode::READ_CONNECTION_ACCEPT_TIMEOUT:
    case hci::OpCode::WRITE_CONNECTION_ACCEPT_TIMEOUT:
    case hci::OpCode::READ_PAGE_TIMEOUT:
    case hci::OpCode::WRITE_PAGE_TIMEOUT:
    case hci::OpCode::READ_AUTHENTICATION_ENABLE:
    case hci::OpCode::WRITE_AUTHENTICATION_ENABLE:
    case hci::OpCode::READ_CLASS_OF_DEVICE:
    case hci::OpCode::WRITE_CLASS_OF_DEVICE:
    case hci::OpCode::READ_VOICE_SETTING:
    case hci::OpCode::WRITE_VOICE_SETTING:
    case hci::OpCode::READ_NUM_BROADCAST_RETRANSMITS:
    case hci::OpCode::WRITE_NUM_BROADCAST_RETRANSMITS:
    case hci::OpCode::READ_HOLD_MODE_ACTIVITY:
    case hci::OpCode::WRITE_HOLD_MODE_ACTIVITY:
    case hci::OpCode::READ_SYNCHRONOUS_FLOW_CONTROL_ENABLE:
    case hci::OpCode::WRITE_SYNCHRONOUS_FLOW_CONTROL_ENABLE:
    case hci::OpCode::SET_CONTROLLER_TO_HOST_FLOW_CONTROL:
    case hci::OpCode::HOST_BUFFER_SIZE:
    case hci::OpCode::HOST_NUM_COMPLETED_PACKETS:
    case hci::OpCode::READ_NUMBER_OF_SUPPORTED_IAC:
    case hci::OpCode::READ_CURRENT_IAC_LAP:
    case hci::OpCode::WRITE_CURRENT_IAC_LAP:
    case hci::OpCode::SET_AFH_HOST_CHANNEL_CLASSIFICATION:
    case hci::OpCode::READ_AFH_CHANNEL_ASSESSMENT_MODE:
    case hci::OpCode::WRITE_AFH_CHANNEL_ASSESSMENT_MODE:
    case hci::OpCode::READ_LE_HOST_SUPPORT:
    case hci::OpCode::WRITE_LE_HOST_SUPPORT:
    case hci::OpCode::READ_SECURE_CONNECTIONS_HOST_SUPPORT:
    case hci::OpCode::WRITE_SECURE_CONNECTIONS_HOST_SUPPORT:
    case hci::OpCode::READ_LOCAL_OOB_EXTENDED_DATA:
    case hci::OpCode::SET_ECOSYSTEM_BASE_INTERVAL:
    case hci::OpCode::CONFIGURE_DATA_PATH:
    case hci::OpCode::READ_LOCAL_VERSION_INFORMATION:
    case hci::OpCode::READ_LOCAL_SUPPORTED_COMMANDS:
    case hci::OpCode::READ_LOCAL_SUPPORTED_FEATURES:
    case hci::OpCode::READ_LOCAL_EXTENDED_FEATURES:
    case hci::OpCode::READ_BUFFER_SIZE:
    case hci::OpCode::READ_BD_ADDR:
    case hci::OpCode::READ_DATA_BLOCK_SIZE:
    case hci::OpCode::READ_LOCAL_SUPPORTED_CODECS_V1:
    case hci::OpCode::READ_LOCAL_SUPPORTED_CODECS_V2:
    case hci::OpCode::READ_LOCAL_SUPPORTED_CODEC_CAPABILITIES:
    case hci::OpCode::READ_LOCAL_SUPPORTED_CONTROLLER_DELAY:
    case hci::OpCode::READ_LOCAL_OOB_DATA:
    case hci::OpCode::LE_GENERATE_DHKEY_COMMAND:
    case hci::OpCode::LE_MODIFY_SLEEP_CLOCK_ACCURACY:
    case hci::OpCode::LE_READ_BUFFER_SIZE_V2:
    case hci::OpCode::LE_READ_SUGGESTED_DEFAULT_DATA_LENGTH:
    case hci::OpCode::LE_WRITE_SUGGESTED_DEFAULT_DATA_LENGTH:
    case hci::OpCode::LE_READ_LOCAL_P_256_PUBLIC_KEY_COMMAND:
    case hci::OpCode::LE_GENERATE_DHKEY_COMMAND_V1:
    case hci::OpCode::LE_SET_EVENT_MASK:
    case hci::OpCode::LE_READ_BUFFER_SIZE_V1:
    case hci::OpCode::LE_READ_LOCAL_SUPPORTED_FEATURES:
    case hci::OpCode::LE_SET_RANDOM_ADDRESS:
    case hci::OpCode::LE_READ_TRANSMIT_POWER:
    case hci::OpCode::LE_READ_RF_PATH_COMPENSATION_POWER:
    case hci::OpCode::LE_WRITE_RF_PATH_COMPENSATION_POWER:
    case hci::OpCode::LE_SET_DEFAULT_PHY:
    case hci::OpCode::LE_ENCRYPT:
    case hci::OpCode::LE_RAND:
    case hci::OpCode::LE_SET_ADDRESS_RESOLUTION_ENABLE:
    case hci::OpCode::LE_SET_RESOLVABLE_PRIVATE_ADDRESS_TIMEOUT:
    case hci::OpCode::LE_READ_MAXIMUM_DATA_LENGTH:
    case hci::OpCode::LE_READ_SUPPORTED_STATES:
      classification = {.activity = Activity::CONTROL, .connection_handle_pos = 0, .address_pos = 0};
      break;

    case hci::OpCode::DELETE_STORED_LINK_KEY:
      classification = {.activity = Activity::CONTROL, .connection_handle_pos = 0, .address_pos = 3};
      break;
    case hci::OpCode::READ_TRANSMIT_POWER_LEVEL:
      classification = {.activity = Activity::CONTROL, .connection_handle_pos = 3, .address_pos = 0};
      break;

    case hci::OpCode::READ_INQUIRY_SCAN_ACTIVITY:
    case hci::OpCode::WRITE_INQUIRY_SCAN_ACTIVITY:
    case hci::OpCode::READ_INQUIRY_SCAN_TYPE:
    case hci::OpCode::WRITE_INQUIRY_SCAN_TYPE:
    case hci::OpCode::READ_INQUIRY_MODE:
    case hci::OpCode::WRITE_INQUIRY_MODE:
    case hci::OpCode::READ_EXTENDED_INQUIRY_RESPONSE:
    case hci::OpCode::WRITE_EXTENDED_INQUIRY_RESPONSE:
    case hci::OpCode::LE_SET_CIG_PARAMETERS:
    case hci::OpCode::LE_CREATE_CIS:
    case hci::OpCode::LE_REMOVE_CIG:
    case hci::OpCode::LE_ACCEPT_CIS_REQUEST:
    case hci::OpCode::LE_REJECT_CIS_REQUEST:
    case hci::OpCode::LE_CREATE_BIG:
    case hci::OpCode::LE_TERMINATE_BIG:
    case hci::OpCode::LE_BIG_CREATE_SYNC:
    case hci::OpCode::LE_BIG_TERMINATE_SYNC:
    case hci::OpCode::LE_REQUEST_PEER_SCA:
    case hci::OpCode::LE_SETUP_ISO_DATA_PATH:
    case hci::OpCode::LE_REMOVE_ISO_DATA_PATH:
    case hci::OpCode::LE_SET_HOST_FEATURE:
    case hci::OpCode::LE_READ_ISO_LINK_QUALITY:
    case hci::OpCode::LE_ENHANCED_READ_TRANSMIT_POWER_LEVEL:
    case hci::OpCode::LE_READ_REMOTE_TRANSMIT_POWER_LEVEL:
    case hci::OpCode::LE_SET_PATH_LOSS_REPORTING_PARAMETERS:
    case hci::OpCode::LE_SET_PATH_LOSS_REPORTING_ENABLE:
    case hci::OpCode::LE_SET_TRANSMIT_POWER_REPORTING_ENABLE:
    case hci::OpCode::LE_GET_VENDOR_CAPABILITIES:
    case hci::OpCode::LE_MULTI_ADVT:
    case hci::OpCode::LE_BATCH_SCAN:
    case hci::OpCode::LE_ADV_FILTER:
    case hci::OpCode::LE_ENERGY_INFO:
    case hci::OpCode::LE_EXTENDED_SCAN_PARAMS:
    case hci::OpCode::CONTROLLER_DEBUG_INFO:
    case hci::OpCode::CONTROLLER_A2DP_OPCODE:
    case hci::OpCode::CONTROLLER_BQR:
    case hci::OpCode::READ_INQUIRY_RESPONSE_TRANSMIT_POWER_LEVEL:
    case hci::OpCode::WRITE_INQUIRY_TRANSMIT_POWER_LEVEL:
    case hci::OpCode::LE_SET_EXTENDED_SCAN_PARAMETERS:
    case hci::OpCode::LE_SET_EXTENDED_SCAN_ENABLE:
    case hci::OpCode::LE_PERIODIC_ADVERTISING_CREATE_SYNC_CANCEL:
    case hci::OpCode::LE_SET_SCAN_PARAMETERS:
    case hci::OpCode::LE_SET_SCAN_ENABLE:
    case hci::OpCode::LE_SET_DEFAULT_PERIODIC_ADVERTISING_SYNC_TRANSFER_PARAMETERS:
    case hci::OpCode::LE_SET_PERIODIC_ADVERTISING_RECEIVE_ENABLE:
    case hci::OpCode::LE_CLEAR_PERIODIC_ADVERTISING_LIST:
    case hci::OpCode::LE_READ_PERIODIC_ADVERTISING_LIST_SIZE:
    case hci::OpCode::LE_PERIODIC_ADVERTISING_TERMINATE_SYNC:
      classification = {.activity = Activity::SCAN, .connection_handle_pos = 0, .address_pos = 0};
      break;

    case hci::OpCode::LE_READ_ADVERTISING_PHYSICAL_CHANNEL_TX_POWER:
    case hci::OpCode::LE_SET_ADVERTISING_DATA:
    case hci::OpCode::LE_SET_SCAN_RESPONSE_DATA:
    case hci::OpCode::LE_SET_ADVERTISING_ENABLE:
    case hci::OpCode::LE_SET_EXTENDED_ADVERTISING_DATA:
    case hci::OpCode::LE_SET_EXTENDED_ADVERTISING_SCAN_RESPONSE:
    case hci::OpCode::LE_SET_EXTENDED_ADVERTISING_ENABLE:
    case hci::OpCode::LE_READ_MAXIMUM_ADVERTISING_DATA_LENGTH:
    case hci::OpCode::LE_READ_NUMBER_OF_SUPPORTED_ADVERTISING_SETS:
    case hci::OpCode::LE_REMOVE_ADVERTISING_SET:
    case hci::OpCode::LE_CLEAR_ADVERTISING_SETS:
    case hci::OpCode::LE_SET_PERIODIC_ADVERTISING_PARAM:
    case hci::OpCode::LE_SET_PERIODIC_ADVERTISING_DATA:
    case hci::OpCode::LE_SET_PERIODIC_ADVERTISING_ENABLE:
    case hci::OpCode::LE_SET_EXTENDED_ADVERTISING_RANDOM_ADDRESS:
      classification = {.activity = Activity::ADVERTISE, .connection_handle_pos = 0, .address_pos = 0};
      break;

    case hci::OpCode::LE_SET_ADVERTISING_PARAMETERS:
      classification = {.activity = Activity::SCAN, .connection_handle_pos = 0, .address_pos = 10};
      break;
    case hci::OpCode::LE_CREATE_CONNECTION:
      classification = {.activity = Activity::CONNECT, .connection_handle_pos = 0, .address_pos = 9};
      break;
    case hci::OpCode::LE_ADD_DEVICE_TO_CONNECT_LIST:
    case hci::OpCode::LE_READ_CHANNEL_MAP:
      classification = {.activity = Activity::CONNECT, .connection_handle_pos = 4, .address_pos = 0};
      break;

    case hci::OpCode::LE_REMOVE_DEVICE_FROM_CONNECT_LIST:
    case hci::OpCode::LE_ADD_DEVICE_TO_RESOLVING_LIST:
    case hci::OpCode::LE_REMOVE_DEVICE_FROM_RESOLVING_LIST:
    case hci::OpCode::LE_READ_PEER_RESOLVABLE_ADDRESS:
    case hci::OpCode::LE_READ_LOCAL_RESOLVABLE_ADDRESS:
    case hci::OpCode::LE_SET_PRIVACY_MODE:
      classification = {.activity = Activity::CONNECT, .connection_handle_pos = 0, .address_pos = 4};
      break;

    case hci::OpCode::LE_SET_EXTENDED_ADVERTISING_PARAMETERS:
      classification = {.activity = Activity::ADVERTISE, .connection_handle_pos = 0, .address_pos = 15};
      break;
    case hci::OpCode::LE_EXTENDED_CREATE_CONNECTION:
      classification = {.activity = Activity::CONNECT, .connection_handle_pos = 0, .address_pos = 6};
      break;
    case hci::OpCode::LE_PERIODIC_ADVERTISING_CREATE_SYNC:
      classification = {.activity = Activity::SCAN, .connection_handle_pos = 0, .address_pos = 6};
      break;
    case hci::OpCode::LE_ADD_DEVICE_TO_PERIODIC_ADVERTISING_LIST:
    case hci::OpCode::LE_REMOVE_DEVICE_FROM_PERIODIC_ADVERTISING_LIST:
      classification = {.activity = Activity::SCAN, .connection_handle_pos = 0, .address_pos = 4};
      break;
    case hci::OpCode::LE_PERIODIC_ADVERTISING_SYNC_TRANSFER:
    case hci::OpCode::LE_PERIODIC_ADVERTISING_SET_INFO_TRANSFER:
    case hci::OpCode::LE_SET_PERIODIC_ADVERTISING_SYNC_TRANSFER_PARAMETERS:
      classification = {.activity = Activity::SCAN, .connection_handle_pos = 3, .address_pos = 0};
      break;

    default:
      classification = {.activity = Activity::UNKNOWN, .connection_handle_pos = 0, .address_pos = 0};
      break;
  }
  return classification;
}

CmdEvtActivityClassification lookup_event(hci::EventCode event_code) {
  CmdEvtActivityClassification classification = {};
  switch (event_code) {
    case hci::EventCode::INQUIRY_COMPLETE:
      classification = {.activity = Activity::SCAN, .connection_handle_pos = 0, .address_pos = 0};
      break;
    case hci::EventCode::CONNECTION_COMPLETE:
    case hci::EventCode::SYNCHRONOUS_CONNECTION_COMPLETE:
      classification = {.activity = Activity::CONNECT, .connection_handle_pos = 3, .address_pos = 5};
      break;

    case hci::EventCode::CONNECTION_REQUEST:
    case hci::EventCode::PIN_CODE_REQUEST:
    case hci::EventCode::LINK_KEY_REQUEST:
    case hci::EventCode::LINK_KEY_NOTIFICATION:
    case hci::EventCode::USER_PASSKEY_NOTIFICATION:
    case hci::EventCode::KEYPRESS_NOTIFICATION:
    case hci::EventCode::REMOTE_HOST_SUPPORTED_FEATURES_NOTIFICATION:
    case hci::EventCode::IO_CAPABILITY_REQUEST:
    case hci::EventCode::IO_CAPABILITY_RESPONSE:
    case hci::EventCode::USER_CONFIRMATION_REQUEST:
    case hci::EventCode::USER_PASSKEY_REQUEST:
    case hci::EventCode::REMOTE_OOB_DATA_REQUEST:
      classification = {.activity = Activity::CONNECT, .connection_handle_pos = 0, .address_pos = 2};
      break;

    case hci::EventCode::DISCONNECTION_COMPLETE:
    case hci::EventCode::AUTHENTICATION_COMPLETE:
    case hci::EventCode::ENCRYPTION_CHANGE:
    case hci::EventCode::ENCRYPTION_KEY_REFRESH_COMPLETE:
    case hci::EventCode::LINK_SUPERVISION_TIMEOUT_CHANGED:
    case hci::EventCode::CHANGE_CONNECTION_LINK_KEY_COMPLETE:
    case hci::EventCode::CENTRAL_LINK_KEY_COMPLETE:
    case hci::EventCode::READ_REMOTE_SUPPORTED_FEATURES_COMPLETE:
    case hci::EventCode::READ_REMOTE_VERSION_INFORMATION_COMPLETE:
    case hci::EventCode::QOS_SETUP_COMPLETE:
    case hci::EventCode::MODE_CHANGE:
    case hci::EventCode::READ_CLOCK_OFFSET_COMPLETE:
    case hci::EventCode::CONNECTION_PACKET_TYPE_CHANGED:
    case hci::EventCode::FLOW_SPECIFICATION_COMPLETE:
    case hci::EventCode::READ_REMOTE_EXTENDED_FEATURES_COMPLETE:
    case hci::EventCode::SYNCHRONOUS_CONNECTION_CHANGED:
    case hci::EventCode::SNIFF_SUBRATING:
      classification = {.activity = Activity::CONNECT, .connection_handle_pos = 3, .address_pos = 0};
      break;

    case hci::EventCode::REMOTE_NAME_REQUEST_COMPLETE:
    case hci::EventCode::EXTENDED_INQUIRY_RESULT:
      classification = {.activity = Activity::SCAN, .connection_handle_pos = 0, .address_pos = 3};
      break;
    case hci::EventCode::FLUSH_OCCURRED:
    case hci::EventCode::MAX_SLOTS_CHANGE:
    case hci::EventCode::QOS_VIOLATION:
    case hci::EventCode::ENHANCED_FLUSH_COMPLETE:
      classification = {.activity = Activity::CONNECT, .connection_handle_pos = 2, .address_pos = 0};
      break;
    case hci::EventCode::ROLE_CHANGE:
    case hci::EventCode::SIMPLE_PAIRING_COMPLETE:
      classification = {.activity = Activity::CONNECT, .connection_handle_pos = 0, .address_pos = 3};
      break;
    case hci::EventCode::PAGE_SCAN_REPETITION_MODE_CHANGE:
      classification = {.activity = Activity::SCAN, .connection_handle_pos = 0, .address_pos = 2};
      break;

    default:
      classification = {.activity = Activity::UNKNOWN, .connection_handle_pos = 0, .address_pos = 0};
  }
  return classification;
}

CmdEvtActivityClassification lookup_le_event(hci::SubeventCode subevent_code) {
  CmdEvtActivityClassification classification = {};
  switch (subevent_code) {
    case hci::SubeventCode::CONNECTION_COMPLETE:
    case hci::SubeventCode::ENHANCED_CONNECTION_COMPLETE:
      classification = {.activity = Activity::CONNECT, .connection_handle_pos = 4, .address_pos = 7};
      break;

    case hci::SubeventCode::CONNECTION_UPDATE_COMPLETE:
    case hci::SubeventCode::READ_REMOTE_FEATURES_COMPLETE:
    case hci::SubeventCode::PHY_UPDATE_COMPLETE:
    case hci::SubeventCode::CTE_REQUEST_FAILED:
    case hci::SubeventCode::TRANSMIT_POWER_REPORTING:
      classification = {.activity = Activity::CONNECT, .connection_handle_pos = 4, .address_pos = 0};
      break;

    case hci::SubeventCode::LONG_TERM_KEY_REQUEST:
    case hci::SubeventCode::REMOTE_CONNECTION_PARAMETER_REQUEST:
    case hci::SubeventCode::DATA_LENGTH_CHANGE:
    case hci::SubeventCode::CHANNEL_SELECTION_ALGORITHM:
    case hci::SubeventCode::CONNECTION_IQ_REPORT:
    case hci::SubeventCode::PATH_LOSS_THRESHOLD:
      classification = {.activity = Activity::CONNECT, .connection_handle_pos = 3, .address_pos = 0};
      break;

    case hci::SubeventCode::READ_LOCAL_P256_PUBLIC_KEY_COMPLETE:
    case hci::SubeventCode::GENERATE_DHKEY_COMPLETE:
      classification = {.activity = Activity::CONTROL, .connection_handle_pos = 0, .address_pos = 0};
      break;

    case hci::SubeventCode::PERIODIC_ADVERTISING_SYNC_ESTABLISHED:
    case hci::SubeventCode::PERIODIC_ADVERTISING_REPORT:
    case hci::SubeventCode::PERIODIC_ADVERTISING_SYNC_LOST:
    case hci::SubeventCode::ADVERTISING_SET_TERMINATED:
      classification = {.activity = Activity::ADVERTISE, .connection_handle_pos = 0, .address_pos = 0};
      break;

    case hci::SubeventCode::SCAN_TIMEOUT:
    case hci::SubeventCode::BIG_INFO_ADVERTISING_REPORT:
    case hci::SubeventCode::CONNECTIONLESS_IQ_REPORT:
    case hci::SubeventCode::CREATE_BIG_COMPLETE:
    case hci::SubeventCode::TERMINATE_BIG_COMPLETE:
    case hci::SubeventCode::BIG_SYNC_ESTABLISHED:
    case hci::SubeventCode::BIG_SYNC_LOST:
    case hci::SubeventCode::REQUEST_PEER_SCA_COMPLETE:
      classification = {.activity = Activity::SCAN, .connection_handle_pos = 0, .address_pos = 0};
      break;

    case hci::SubeventCode::SCAN_REQUEST_RECEIVED:
      classification = {.activity = Activity::ADVERTISE, .connection_handle_pos = 0, .address_pos = 5};
      break;

    case hci::SubeventCode::PERIODIC_ADVERTISING_SYNC_TRANSFER_RECEIVED:
    case hci::SubeventCode::CIS_ESTABLISHED:
    case hci::SubeventCode::CIS_REQUEST:
      classification = {.activity = Activity::SCAN, .connection_handle_pos = 4, .address_pos = 0};
      break;

    default:
      classification = {.activity = Activity::UNKNOWN, .connection_handle_pos = 0, .address_pos = 0};
  }
  return classification;
}

}  // namespace activity_attribution
}  // namespace bluetooth
