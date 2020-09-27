/*
 * Copyright 2020 The Android Open Source Project
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

/*
 *  Definitions for HCI Error Codes that are passed in the events
 */
#define HCI_SUCCESS 0x00
#define HCI_ERR_ILLEGAL_COMMAND 0x01
#define HCI_ERR_NO_CONNECTION 0x02
#define HCI_ERR_HW_FAILURE 0x03
#define HCI_ERR_PAGE_TIMEOUT 0x04
#define HCI_ERR_AUTH_FAILURE 0x05
#define HCI_ERR_KEY_MISSING 0x06
#define HCI_ERR_MEMORY_FULL 0x07
#define HCI_ERR_CONNECTION_TOUT 0x08
#define HCI_ERR_MAX_NUM_OF_CONNECTIONS 0x09
#define HCI_ERR_MAX_NUM_OF_SCOS 0x0A
#define HCI_ERR_CONNECTION_EXISTS 0x0B
#define HCI_ERR_COMMAND_DISALLOWED 0x0C
#define HCI_ERR_HOST_REJECT_RESOURCES 0x0D
#define HCI_ERR_HOST_REJECT_SECURITY 0x0E
#define HCI_ERR_HOST_REJECT_DEVICE 0x0F
#define HCI_ERR_HOST_TIMEOUT 0x10  // stack/btm/btm_ble_gap
#define HCI_ERR_ILLEGAL_PARAMETER_FMT 0x12
#define HCI_ERR_PEER_USER 0x13
#define HCI_ERR_CONN_CAUSE_LOCAL_HOST 0x16
#define HCI_ERR_REPEATED_ATTEMPTS 0x17
#define HCI_ERR_PAIRING_NOT_ALLOWED 0x18
#define HCI_ERR_UNSUPPORTED_REM_FEATURE 0x1A  // stack/btm/btm_ble_gap
#define HCI_ERR_UNSPECIFIED 0x1F
#define HCI_ERR_LMP_RESPONSE_TIMEOUT 0x22     // GATT_CONN_LMP_TIMEOUT
#define HCI_ERR_LMP_ERR_TRANS_COLLISION 0x23  // TODO remove
#define HCI_ERR_ENCRY_MODE_NOT_ACCEPTABLE 0x25
#define HCI_ERR_UNIT_KEY_USED 0x26
#define HCI_ERR_PAIRING_WITH_UNIT_KEY_NOT_SUPPORTED 0x29
#define HCI_ERR_DIFF_TRANSACTION_COLLISION 0x2A  // stack/btm/btm_sec
#define HCI_ERR_INSUFFCIENT_SECURITY 0x2F        // btif/btu
#define HCI_ERR_ROLE_SWITCH_PENDING 0x32         // stack/btm/btm_sco
#define HCI_ERR_HOST_BUSY_PAIRING 0x38           // stack/btm/btm_sec
#define HCI_ERR_UNACCEPT_CONN_INTERVAL 0x3B      // stack/l2cap/l2c_ble
#define HCI_ERR_ADVERTISING_TIMEOUT 0x3C         // stack/btm/btm_ble
#define HCI_ERR_CONN_FAILED_ESTABLISHMENT 0x3E   // GATT_CONN_FAIL_ESTABLISH
#define HCI_ERR_LIMIT_REACHED 0x43  // stack/btm/btm_ble_multi_adv.cc

#define HCI_ERR_MAX_ERR 0x43  // TODO remove. randomly used

inline std::string hci_error_code_text(uint8_t error_code) {
  switch (error_code) {
    case HCI_SUCCESS:
      return std::string("Success");
    case HCI_ERR_ILLEGAL_COMMAND:
      return std::string("Illegal Command");
    case HCI_ERR_NO_CONNECTION:
      return std::string("Unknown Connection");
    case HCI_ERR_HW_FAILURE:
      return std::string("Hardware Failure");
    case HCI_ERR_PAGE_TIMEOUT:
      return std::string("Page Timeout");
    case HCI_ERR_AUTH_FAILURE:
      return std::string("Authentication Failure");
    case HCI_ERR_KEY_MISSING:
      return std::string("Pin or Key Missing");
    case HCI_ERR_MEMORY_FULL:
      return std::string("Memory Capacity Exceeded");
    case HCI_ERR_CONNECTION_TOUT:
      return std::string("Connection Timeout");
    case HCI_ERR_MAX_NUM_OF_CONNECTIONS:
      return std::string("Connection Limit Exceeded");
    case HCI_ERR_MAX_NUM_OF_SCOS:
      return std::string("Synchronous Connection Limit Exceeded");
    case HCI_ERR_CONNECTION_EXISTS:
      return std::string("Connection Already Exists");
    case HCI_ERR_COMMAND_DISALLOWED:
      return std::string("Command Disallowed");
    case HCI_ERR_HOST_REJECT_RESOURCES:
      return std::string("Connection Rejected Limited Resources");
    case HCI_ERR_HOST_REJECT_SECURITY:
      return std::string("Connection Rejected Security Reasons");
    case HCI_ERR_HOST_REJECT_DEVICE:
      return std::string("Connection Rejected Unacceptable BdAddr");
    case HCI_ERR_HOST_TIMEOUT:
      return std::string("Connection Accept Timeout");
    case HCI_ERR_ILLEGAL_PARAMETER_FMT:
      return std::string("Unsupported Feature or Parameter Value");
    case HCI_ERR_PEER_USER:
      return std::string("Remote Terminated Connection");
    case HCI_ERR_CONN_CAUSE_LOCAL_HOST:
      return std::string("Local Terminated Connection");
    case HCI_ERR_REPEATED_ATTEMPTS:
      return std::string("Repeated Attempts");
    case HCI_ERR_PAIRING_NOT_ALLOWED:
      return std::string("Pairing not Allowed");
    case HCI_ERR_UNSUPPORTED_REM_FEATURE:
      return std::string("Unsupported Remote or Lmp Feature");
    case HCI_ERR_UNSPECIFIED:
      return std::string("Unspecified Error");
    case HCI_ERR_LMP_RESPONSE_TIMEOUT:
      return std::string("Gatt Connection Lmp Timeout");
    case HCI_ERR_LMP_ERR_TRANS_COLLISION:
      return std::string("Link Layer Collision");
    case HCI_ERR_ENCRY_MODE_NOT_ACCEPTABLE:
      return std::string("Encryption Mode not Acceptable");
    case HCI_ERR_UNIT_KEY_USED:
      return std::string("Unit Key Used");
    case HCI_ERR_PAIRING_WITH_UNIT_KEY_NOT_SUPPORTED:
      return std::string("Pairing with Unit Key Unsupported");
    case HCI_ERR_DIFF_TRANSACTION_COLLISION:
      return std::string("Diff Transaction Collision");
    case HCI_ERR_INSUFFCIENT_SECURITY:
      return std::string("Insufficient Security");
    case HCI_ERR_ROLE_SWITCH_PENDING:
      return std::string("Role Switch Pending");
    case HCI_ERR_HOST_BUSY_PAIRING:
      return std::string("Host Busy Pairing");
    case HCI_ERR_UNACCEPT_CONN_INTERVAL:
      return std::string("Unacceptable Connection Interval");
    case HCI_ERR_ADVERTISING_TIMEOUT:
      return std::string("Advertising Timeout");
    case HCI_ERR_CONN_FAILED_ESTABLISHMENT:
      return std::string("Connection Failed Establishment");
    case HCI_ERR_LIMIT_REACHED:
      return std::string("Limit Reached");
    default:
      return std::string("Unknown Error");
  }
}
